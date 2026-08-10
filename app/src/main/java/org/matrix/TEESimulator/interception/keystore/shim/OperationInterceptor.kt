package org.matrix.TEESimulator.interception.keystore.shim

import android.os.IBinder
import android.os.Parcel
import android.os.ServiceSpecificException
import android.system.keystore2.IKeystoreOperation
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.interception.keystore.InterceptorUtils

/**
 * Intercepts calls to an `IKeystoreOperation` service. This is used to log the data manipulation
 * methods of a cryptographic operation.
 *
 * For a forwarded StrongBox operation, [onFinalize] releases the reserved slot. It fires from
 * [onPostTransact] only once the operation has really ended, which is not the same as "the call
 * returned an error". AOSP Keystore2's with_locked_operation() drops the operation when a KM call
 * reports an error, but two cases do not end it and must not release the slot:
 * - OPERATION_BUSY (ResponseCode 19): another thread holds the operation lock, so this call never
 *   entered the operation and the operation is still alive. finish/abort can also report this.
 * - Transport failures (resultCode != 0, e.g. the request never reached keystore2): the operation
 *   may well still be alive, so releasing would undercount it.
 *
 * Release therefore fires on: a successful finish/abort, or an update/updateAad that returns a
 * genuine service error other than OPERATION_BUSY. A successful update/updateAad leaves the
 * operation running and does nothing.
 *
 * Known limitation: a client that abandons the operation with no finish/abort — process death or a
 * dropped binder reference — produces no observable transaction, so its slot is not reclaimed.
 * A non-AEAD synthetic updateAad reply is likewise not treated as terminal, since the underlying
 * HAL operation was never invoked and is still live. Neither a timeout (would reap live
 * user-interactive operations) nor linkToDeath solves this: linkToDeath only observes death of the
 * process hosting the forwarded binder, and does not report that another client abandoned its
 * reference. These are accepted residual cases; if the keystore2 host process itself dies, the
 * whole interceptor state is reset with it, so a leaked slot cannot outlive that.
 */
class OperationInterceptor(
    private val original: IKeystoreOperation,
    private val backdoor: IBinder,
    private val isAead: Boolean,
    private val onFinalize: (() -> Unit)? = null,
) : BinderInterceptor() {

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        val methodName = transactionNames[code] ?: "unknown code=$code"

        // Mirror SoftwareOperation's vendor gate: a real-key op must answer non-AEAD updateAad
        // exactly as the forged-key path does. Samsung and Xiaomi-MTK TEEs accept it; rejecting
        // here while the forged path accepts diverges the two and fingerprints the injection. The
        // underlying operation is not called, so this does not end it and the slot is retained.
        if (code == UPDATE_AAD_TRANSACTION && !isAead) {
            logTransaction(txId, methodName, callingUid, callingPid, true)
            return if (VendorQuirks.nonAeadUpdateAadSucceeds()) {
                InterceptorUtils.createSuccessReply(writeResultCode = false)
            } else {
                InterceptorUtils.createServiceSpecificErrorReply(KeystoreErrorCodes.invalidTag)
            }
        }

        // finish/abort, update, and AEAD updateAad all need the reply to decide whether the
        // operation ended, so run the original call and classify in onPostTransact. keystore2
        // keeps the operation's resources alive until the underlying call returns, so deferring
        // any slot release to the post hook keeps the in-flight accounting honest.
        val needsPostHook =
            code == FINISH_TRANSACTION ||
                code == ABORT_TRANSACTION ||
                code == UPDATE_TRANSACTION ||
                (code == UPDATE_AAD_TRANSACTION && isAead)
        logTransaction(txId, methodName, callingUid, callingPid, !needsPostHook)
        if (needsPostHook) return TransactionResult.Continue

        return TransactionResult.ContinueAndSkipPost
    }

    override fun onPostTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int,
    ): TransactionResult {
        if (operationEnded(code, resultCode, reply)) {
            try {
                KeyMintSecurityLevelInterceptor.removeOperationInterceptor(target, backdoor)
            } finally {
                onFinalize?.invoke()
            }
        }
        return TransactionResult.SkipTransaction
    }

    companion object {
        // ResponseCode.OPERATION_BUSY: the caller tried to advance an operation that another
        // thread is already advancing. The call never entered the operation, so it stays alive.
        private const val RESPONSE_OPERATION_BUSY = 19

        private val UPDATE_AAD_TRANSACTION =
            InterceptorUtils.getTransactCode(IKeystoreOperation.Stub::class.java, "updateAad")
        private val UPDATE_TRANSACTION =
            InterceptorUtils.getTransactCode(IKeystoreOperation.Stub::class.java, "update")
        private val FINISH_TRANSACTION =
            InterceptorUtils.getTransactCode(IKeystoreOperation.Stub::class.java, "finish")
        private val ABORT_TRANSACTION =
            InterceptorUtils.getTransactCode(IKeystoreOperation.Stub::class.java, "abort")

        val INTERCEPTED_CODES =
            intArrayOf(
                UPDATE_AAD_TRANSACTION,
                UPDATE_TRANSACTION,
                FINISH_TRANSACTION,
                ABORT_TRANSACTION,
            )

        /**
         * Decides whether the operation ended, given the transaction code, the native transport
         * [resultCode], and the [reply] parcel. Extracted and internal so it can be unit-tested
         * without a live binder.
         */
        internal fun operationEnded(code: Int, resultCode: Int, reply: Parcel?): Boolean {
            // A transport-level failure is not a KM operation error; the operation may still be
            // alive (the request may not even have reached keystore2). Conservatively retain.
            if (resultCode != 0 || reply == null) return false

            val exception = InterceptorUtils.readExceptionOrNull(reply)

            // OPERATION_BUSY means another thread holds the operation lock; the call never entered
            // the operation, so it is still alive regardless of which method reported it.
            if (
                exception is ServiceSpecificException &&
                    exception.errorCode == RESPONSE_OPERATION_BUSY
            ) {
                return false
            }

            return when (code) {
                // A successful finish/abort ends the operation. (An error other than
                // OPERATION_BUSY also terminates it, and finish/abort never legitimately continue,
                // so treat any non-busy outcome here as terminal.)
                FINISH_TRANSACTION,
                ABORT_TRANSACTION -> true
                // update / AEAD updateAad end the operation only on a genuine service error
                // (other than OPERATION_BUSY, handled above); a successful call keeps it running.
                UPDATE_TRANSACTION,
                UPDATE_AAD_TRANSACTION -> exception != null
                else -> false
            }
        }

        private val transactionNames: Map<Int, String> by lazy {
            IKeystoreOperation.Stub::class
                .java
                .declaredFields
                .filter {
                    it.isAccessible = true
                    it.type == Int::class.java && it.name.startsWith("TRANSACTION_")
                }
                .associate { field -> (field.get(null) as Int) to field.name.split("_")[1] }
        }
    }
}
