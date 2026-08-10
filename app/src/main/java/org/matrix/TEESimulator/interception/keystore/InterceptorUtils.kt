package org.matrix.TEESimulator.interception.keystore

import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.Tag
import android.os.Parcel
import android.os.Parcelable
import android.security.KeyStore
import android.security.keystore.KeystoreResponse
import android.system.keystore2.Authorization
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.util.AndroidDeviceUtils

data class KeyIdentifier(val uid: Int, val alias: String)

/** A collection of utility functions to support binder interception. */
object InterceptorUtils {

    private const val EX_SERVICE_SPECIFIC = -8

    private const val FLAT_STRIDE_HEADER = 12
    private const val MAX_AUTH_COUNT = 256
    private const val SENTINEL_MODTIME = 4_294_967_297L
    private const val HIGH_MODTIME = 4_999_999_999L

    private fun synthesizeSseMessage(errorCode: Int): String =
        when (errorCode) {
            2 -> "Error::Rc(SYSTEM_ERROR)"
            4 -> "Error::Rc(PERMISSION_DENIED)"
            6 -> "Error::Rc(VALUE_CORRUPTED)"
            7 -> "Error::Rc(KEY_NOT_FOUND)"
            10 -> "Error::Rc(BACKEND_BUSY)"
            -3 -> "Error::Km(UNSUPPORTED_KEY_SIZE)"
            -6 -> "Error::Km(INCOMPATIBLE_PURPOSE)"
            -7 -> "Error::Km(INCOMPATIBLE_ALGORITHM)"
            -29 -> "Error::Km(TOO_MANY_OPERATIONS)"
            -49 -> "Error::Km(UNSUPPORTED_TAG)"
            -75 -> "Error::Km(INVALID_INPUT_LENGTH)"
            -76 -> "Error::Km(INVALID_TAG)"
            else -> if (errorCode > 0) "Error::Rc($errorCode)" else "Error::Km($errorCode)"
        }

    fun createErrorReply(errorCode: Int): BinderInterceptor.TransactionResult.OverrideReply {
        val parcel =
            Parcel.obtain().apply {
                writeInt(EX_SERVICE_SPECIFIC)
                writeString(synthesizeSseMessage(errorCode))
                writeInt(0) // empty remote stack trace header (AOSP Status.cpp:196)
                writeInt(errorCode)
            }
        return BinderInterceptor.TransactionResult.OverrideReply(parcel)
    }

    /**
     * Uses reflection to get the integer transaction code for a given method name from a Stub
     * class. This is necessary for older Android versions where codes are not public constants.
     */
    fun getTransactCode(clazz: Class<*>, method: String): Int {
        return try {
            clazz.getDeclaredField("TRANSACTION_$method").apply { isAccessible = true }.getInt(null)
        } catch (e: Exception) {
            SystemLogger.error(
                "Failed to get transaction code for method '$method' in class '${clazz.simpleName}'.",
                e,
            )
            -1 // Return an invalid code
        }
    }

    /** Creates an `KeystoreResponse` parcel that indicates success with no data. */
    fun createSuccessKeystoreResponse(): KeystoreResponse {
        val parcel = Parcel.obtain()
        try {
            parcel.writeInt(KeyStore.NO_ERROR)
            parcel.writeString("")
            parcel.setDataPosition(0)
            return KeystoreResponse.CREATOR.createFromParcel(parcel)
        } finally {
            parcel.recycle()
        }
    }

    /** Creates an `OverrideReply` parcel that indicates success with no data. */
    fun createSuccessReply(
        writeResultCode: Boolean = true
    ): BinderInterceptor.TransactionResult.OverrideReply {
        val parcel =
            Parcel.obtain().apply {
                writeNoException()
                if (writeResultCode) {
                    writeInt(KeyStore.NO_ERROR)
                }
            }
        return BinderInterceptor.TransactionResult.OverrideReply(parcel)
    }

    /** Creates an `OverrideReply` parcel containing a raw byte array. */
    fun createByteArrayReply(data: ByteArray): BinderInterceptor.TransactionResult.OverrideReply {
        val parcel =
            Parcel.obtain().apply {
                writeNoException()
                writeByteArray(data)
            }
        return BinderInterceptor.TransactionResult.OverrideReply(parcel)
    }

    /** Creates an `OverrideReply` parcel containing a typed array. */
    fun <T : Parcelable> createTypedArrayReply(
        array: Array<T>,
        flags: Int = 0,
    ): BinderInterceptor.TransactionResult.OverrideReply {
        val parcel =
            Parcel.obtain().apply {
                writeNoException()
                writeTypedArray(array, flags)
            }
        return BinderInterceptor.TransactionResult.OverrideReply(parcel)
    }

    /** Correlates a captured reply parcel to the app that triggered it, for [createTypedObjectReply]. */
    data class ReplyDiagnostic(val uid: Int, val txId: Long?, val event: String)

    /** Creates an `OverrideReply` parcel containing a Parcelable object. */
    fun <T : Parcelable?> createTypedObjectReply(
        obj: T,
        flags: Int = 0,
        diagnostic: ReplyDiagnostic? = null,
    ): BinderInterceptor.TransactionResult.OverrideReply {
        val parcel =
            Parcel.obtain().apply {
                writeNoException()
                writeTypedObject(obj, flags)
            }
        if (diagnostic != null && SystemLogger.isUidLogged(diagnostic.uid)) {
            val savedPos = parcel.dataPosition()
            val wire = parcel.marshall()
            parcel.setDataPosition(savedPos)
            SystemLogger.uidLogRaw(diagnostic.uid, diagnostic.txId, diagnostic.event, "len=${wire.size}", wire)
        }
        return BinderInterceptor.TransactionResult.OverrideReply(parcel)
    }

    /**
     * Extracts the base alias from a potentially prefixed alias string. For example, it converts
     * "USRCERT_my_key" to "my_key".
     */
    fun extractAlias(prefixedAlias: String): String {
        val underscoreIndex = prefixedAlias.indexOf('_')
        return if (underscoreIndex != -1) {
            // Return the part of the string after the first underscore.
            prefixedAlias.substring(underscoreIndex + 1)
        } else {
            // If there's no underscore, return the original string.
            prefixedAlias
        }
    }

    /** Checks if a reply parcel contains an exception without consuming it. */
    fun hasException(reply: Parcel): Boolean {
        val exception = runCatching { reply.readException() }.exceptionOrNull()
        if (exception != null) reply.setDataPosition(0)
        return exception != null
    }

    /**
     * Reads the exception a reply parcel carries, if any, without disturbing the caller: the
     * original data position is always restored. Returns the Throwable that `readException()`
     * raised (a ServiceSpecificException for EX_SERVICE_SPECIFIC, so callers can inspect its
     * errorCode) or null when the reply encodes success. Unlike [hasException] this exposes the
     * exception itself, which callers need to distinguish, e.g., OPERATION_BUSY from a terminal
     * error.
     */
    fun readExceptionOrNull(reply: Parcel): Throwable? {
        val savedPos = reply.dataPosition()
        val exception =
            try {
                reply.readException()
                null
            } catch (t: Throwable) {
                t
            }
        reply.setDataPosition(savedPos)
        return exception
    }

    fun createServiceSpecificErrorReply(
        errorCode: Int
    ): BinderInterceptor.TransactionResult.OverrideReply = createErrorReply(errorCode)

    fun normalizeServiceSpecificReply(reply: Parcel): Parcel? {
        reply.setDataPosition(0)
        if (reply.readInt() != EX_SERVICE_SPECIFIC) {
            reply.setDataPosition(0)
            return null
        }
        // Advance position past message and stack header to reach errorCode.
        reply.readString()
        reply.readInt()
        val errorCode = reply.readInt()
        reply.setDataPosition(0)
        return Parcel.obtain().apply {
            writeInt(EX_SERVICE_SPECIFIC)
            writeString(synthesizeSseMessage(errorCode))
            writeInt(0)
            writeInt(errorCode)
        }
    }

    fun patchAuthorizations(
        authorizations: Array<Authorization>?,
        callingUid: Int,
    ): Array<Authorization>? {
        if (authorizations == null) return null

        val osPatch = AndroidDeviceUtils.getPatchLevel(callingUid)
        val vendorPatch = AndroidDeviceUtils.getVendorPatchLevelLong(callingUid)
        val bootPatch = AndroidDeviceUtils.getBootPatchLevelLong(callingUid)

        val patched =
            authorizations.map { auth ->
                val replacement =
                    when (auth.keyParameter.tag) {
                        Tag.OS_PATCHLEVEL ->
                            if (osPatch != AndroidDeviceUtils.DO_NOT_REPORT) osPatch else null
                        Tag.VENDOR_PATCHLEVEL ->
                            if (vendorPatch != AndroidDeviceUtils.DO_NOT_REPORT) vendorPatch
                            else null
                        Tag.BOOT_PATCHLEVEL ->
                            if (bootPatch != AndroidDeviceUtils.DO_NOT_REPORT) bootPatch else null
                        else -> null
                    }
                if (replacement != null) {
                    Authorization().apply {
                        keyParameter =
                            KeyParameter().apply {
                                tag = auth.keyParameter.tag
                                value = KeyParameterValue.integer(replacement)
                            }
                        securityLevel = auth.securityLevel
                    }
                } else {
                    auth
                }
            }
            .toTypedArray()
        return normalizeAuthorizationLayout(patched)
    }

    /**
     * Reorders a generateKey reply's authorizations only when the marshalled reply would read, to a
     * flat 12-byte-stride parcel fingerprint, as the TEE-simulator sentinel: a last slot of
     * securityLevel 4 or 256, tag 1, union 32 with the 0x1_0000_0001 pseudo-timestamp, or any
     * timestamp past [HIGH_MODTIME]. Real Android 16 hardware emits a 13-authorization layout for
     * single-purpose EC keys that lands on that sentinel, so mirroring hardware byte-for-byte is
     * itself flagged. Clients resolve authorizations by tag and the certificate chain is a separate
     * field, so reordering is the minimal capability-preserving way to clear the false positive for
     * any caller. Already-clean replies are returned unchanged.
     */
    fun normalizeAuthorizationLayout(authorizations: Array<Authorization>): Array<Authorization> {
        if (authorizations.size < 2) return authorizations
        if (!flatStrideFingerprintMatches(marshalTypedArray(authorizations))) return authorizations
        val n = authorizations.size
        for (src in 1 until n) {
            val candidate = moveAuthorization(authorizations, src, 0)
            if (!flatStrideFingerprintMatches(marshalTypedArray(candidate))) return candidate
        }
        for (src in 0 until n) {
            for (dst in 0 until n) {
                if (src == dst) continue
                val candidate = moveAuthorization(authorizations, src, dst)
                if (!flatStrideFingerprintMatches(marshalTypedArray(candidate))) return candidate
            }
        }
        return authorizations
    }

    private fun moveAuthorization(
        authorizations: Array<Authorization>,
        src: Int,
        dst: Int,
    ): Array<Authorization> {
        val reordered = authorizations.toMutableList()
        reordered.add(dst, reordered.removeAt(src))
        return reordered.toTypedArray()
    }

    private fun marshalTypedArray(authorizations: Array<Authorization>): ByteArray {
        val parcel = Parcel.obtain()
        return try {
            // keystore2 AIDL compile stubs omit the Parcelable supertype these types carry at runtime.
            parcel.writeTypedArray(authorizations.map { it as Parcelable }.toTypedArray(), 0)
            parcel.marshall()
        } finally {
            parcel.recycle()
        }
    }

    private fun flatStrideFingerprintMatches(marshalled: ByteArray): Boolean =
        runCatching {
            val parcel = ByteBuffer.wrap(marshalled).order(ByteOrder.LITTLE_ENDIAN)
            val count = parcel.getInt(0)
            if (count !in 1..MAX_AUTH_COUNT) return@runCatching false
            var off = 4
            var lastSec = 0L
            var lastTag = 0L
            var lastUnion = 0L
            repeat(count) {
                lastSec = u32(parcel, off)
                lastTag = u32(parcel, off + 4)
                lastUnion = u32(parcel, off + 8)
                off += FLAT_STRIDE_HEADER
                off = alignWord(off + flatPayloadSize(parcel, off, lastUnion))
            }
            off = skipDriftedByteArray(parcel, off)
            off = skipDriftedByteArray(parcel, off)
            val modtime = parcel.getLong(alignWord(off))
            val unknownUnion = lastUnion !in 0..14
            modtime > HIGH_MODTIME ||
                (modtime == SENTINEL_MODTIME &&
                    (lastSec == 4L || lastSec == 256L) &&
                    lastTag == 1L &&
                    lastUnion == 32L &&
                    unknownUnion)
        }.getOrDefault(false)

    private fun flatPayloadSize(parcel: ByteBuffer, off: Int, union: Long): Int =
        when {
            union in 1..11 -> 4
            union == 12L || union == 13L -> 8
            union == 14L -> alignWord(off + 4 + parcel.getInt(off)) - off
            else -> 0
        }

    private fun skipDriftedByteArray(parcel: ByteBuffer, off: Int): Int {
        if (parcel.getInt(off) == 0) return off + 4
        val lengthPos = off + 4
        return alignWord(lengthPos + 4 + parcel.getInt(lengthPos))
    }

    private fun u32(parcel: ByteBuffer, off: Int): Long = parcel.getInt(off).toLong() and 0xFFFFFFFFL

    private fun alignWord(off: Int): Int = (off + 3) and 3.inv()
}
