package org.matrix.TEESimulator.interception.keystore.shim

import android.os.IBinder
import android.os.Parcel
import android.os.ServiceSpecificException
import android.system.keystore2.IKeystoreOperation
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.interception.keystore.InterceptorUtils

/**
 * Intercepts calls to an `IKeystoreOperation` service.
 *
 * Two jobs:
 * - Non-AEAD `updateAad` vendor gate: a real-key operation must answer a non-AEAD `updateAad`
 *   exactly as the forged-key path does. Samsung and Xiaomi-MTK TEEs accept it; rejecting here while
 *   the forged path accepts would diverge the two and fingerprint the injection. The underlying
 *   operation is never invoked for this synthetic reply.
 * - Self-unregistration: `update`, AEAD `updateAad`, `finish`, and `abort` run against the real
 *   operation and are classified in [onPostTransact] by [operationEnded]. The interceptor removes
 *   itself only once the operation has truly ended. This is deferred to the post hook (rather than
 *   [onPreTransact]) because the reply is needed to tell a terminal outcome from one that is not:
 *   - OPERATION_BUSY (ResponseCode 19): another thread holds the operation lock, so this call never
 *     entered the operation and it is still alive; finish/abort can also report this.
 *   - Transport failures (resultCode != 0, e.g. the request never reached keystore2): the operation
 *     may still be alive.
 *   Unregistering only on a confirmed terminal result avoids dropping interception of a still-live
 *   operation (for example a `finish` that returns OPERATION_BUSY).
 *
 * This interceptor tracks no in-flight accounting: StrongBox concurrency for forwarded operations is
 * enforced by the real HAL, not by the module.
 */
class OperationInterceptor(
    private val original: IKeystoreOperation,
    private val backdoor: IBinder,
    private val isAead: Boolean,
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
        // underlying operation is not called, so this does not end it.
        if (code == UPDATE_AAD_TRANSACTION && !isAead) {
            // This path overrides the reply, so it is an interception, not an observation.
            logTransaction(txId, methodName, callingUid, callingPid, false)
            return if (VendorQuirks.nonAeadUpdateAadSucceeds()) {
                InterceptorUtils.createSuccessReply(writeResultCode = false)
            } else {
                InterceptorUtils.createServiceSpecificErrorReply(KeystoreErrorCodes.invalidTag)
            }
        }

        // finish/abort, update, and AEAD updateAad all need the reply to decide whether the
        // operation ended, so run the original call and classify in onPostTransact. keystore2
        // keeps the operation's resources alive until the underlying call returns, so deferring
        // the unregister decision to the post hook keeps it honest.
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
            KeyMintSecurityLevelInterceptor.removeOperationInterceptor(target, backdoor)
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
