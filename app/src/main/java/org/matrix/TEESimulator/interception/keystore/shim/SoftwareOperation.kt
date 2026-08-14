package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.BlockMode
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.PaddingMode
import android.hardware.security.keymint.Tag
import android.os.Build
import android.os.ServiceSpecificException
import android.os.SystemProperties
import android.system.keystore2.IKeystoreOperation
import android.system.keystore2.KeyParameters
import java.security.KeyPair
import java.security.Signature
import java.security.SignatureException
import java.util.concurrent.locks.LockSupport
import javax.crypto.Cipher
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.logging.KeyMintParameterLogger
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * Mirrors the per-vendor TEE quirk that Duck Detector's OperationErrorPathProbe checks: real
 * Samsung and Xiaomi-MTK TrustZone return success for updateAad on a non-AEAD operation, while
 * every other vendor rejects it with a service-specific INVALID_TAG. The module reads the same
 * device-identity fields the probe reads, so a forged software operation answers exactly as that
 * vendor's real TEE would.
 */
internal object VendorQuirks {
    private val UPDATE_AAD_ALLOWS_SUCCESS = setOf("samsung")
    private val XIAOMI_BRANDS = setOf("xiaomi", "redmi", "poco")

    fun nonAeadUpdateAadSucceeds(): Boolean {
        val manufacturer = Build.MANUFACTURER.lowercase()
        val brand = Build.BRAND.lowercase()
        if (manufacturer in UPDATE_AAD_ALLOWS_SUCCESS || brand in UPDATE_AAD_ALLOWS_SUCCESS) {
            return true
        }
        if (manufacturer != "xiaomi" && brand !in XIAOMI_BRANDS) return false
        return isMediaTek()
    }

    private fun isMediaTek(): Boolean {
        val roHardware = SystemProperties.get("ro.hardware", "")
        return roHardware.startsWith("mt") || Build.HARDWARE.startsWith("mt", ignoreCase = true)
    }
}

private sealed interface CryptoPrimitive {
    fun updateAad(aadInput: ByteArray?) {
        // Real Samsung / Xiaomi-MTK TEEs accept updateAad on non-AEAD ops; others reject it.
        if (!VendorQuirks.nonAeadUpdateAadSucceeds()) {
            throw ServiceSpecificException(KeystoreErrorCodes.invalidTag)
        }
    }

    fun update(data: ByteArray?): ByteArray?

    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray?

    fun abort()

    fun getBeginParameters(): Array<KeyParameter>? = null
}

private object JcaAlgorithmMapper {
    fun mapSignatureAlgorithm(params: KeyMintAttestation): String {
        val digest =
            when (params.digest.firstOrNull()) {
                Digest.SHA_2_256 -> "SHA256"
                Digest.SHA_2_384 -> "SHA384"
                Digest.SHA_2_512 -> "SHA512"
                else -> "NONE"
            }
        return when (params.algorithm) {
            Algorithm.EC -> "${digest}withECDSA"
            Algorithm.RSA -> {
                val isPss = params.padding.firstOrNull() == PaddingMode.RSA_PSS
                if (isPss) "${digest}withRSA/PSS" else "${digest}withRSA"
            }
            else ->
                throw ServiceSpecificException(
                    KeystoreErrorCodes.incompatibleAlgorithm,
                    "Unsupported signature algorithm: ${params.algorithm}",
                )
        }
    }

    fun mapCipherAlgorithm(params: KeyMintAttestation): String {
        val keyAlgo =
            when (params.algorithm) {
                Algorithm.RSA -> "RSA"
                Algorithm.AES -> "AES"
                else ->
                    throw ServiceSpecificException(
                        KeystoreErrorCodes.incompatibleAlgorithm,
                        "Unsupported cipher algorithm: ${params.algorithm}",
                    )
            }
        val blockMode =
            when (params.blockMode.firstOrNull()) {
                BlockMode.ECB -> "ECB"
                BlockMode.CBC -> "CBC"
                BlockMode.CTR -> "CTR"
                BlockMode.GCM -> "GCM"
                else -> "ECB"
            }
        val padding =
            when (params.padding.firstOrNull()) {
                PaddingMode.NONE -> "NoPadding"
                PaddingMode.PKCS7 -> "PKCS7Padding"
                PaddingMode.RSA_PKCS1_1_5_ENCRYPT -> "PKCS1Padding"
                PaddingMode.RSA_PKCS1_1_5_SIGN -> "PKCS1Padding"
                PaddingMode.RSA_OAEP -> "OAEPPadding"
                else -> "NoPadding"
            }
        return "$keyAlgo/$blockMode/$padding"
    }

    fun mapOaepDigest(digest: Int?): String =
        when (digest) {
            Digest.SHA1 -> "SHA-1"
            Digest.SHA_2_224 -> "SHA-224"
            Digest.SHA_2_256 -> "SHA-256"
            Digest.SHA_2_384 -> "SHA-384"
            Digest.SHA_2_512 -> "SHA-512"
            else -> "SHA-256"
        }

    fun mapMacAlgorithm(params: KeyMintAttestation): String =
        when (params.digest.firstOrNull()) {
            Digest.SHA_2_256 -> "HmacSHA256"
            Digest.SHA_2_384 -> "HmacSHA384"
            Digest.SHA_2_512 -> "HmacSHA512"
            else -> "HmacSHA256"
        }
}

private class Signer(keyPair: KeyPair, params: KeyMintAttestation) : CryptoPrimitive {
    private val signature: Signature =
        Signature.getInstance(JcaAlgorithmMapper.mapSignatureAlgorithm(params)).apply {
            initSign(keyPair.private)
        }

    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) signature.update(data)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray {
        if (data != null) update(data)
        return this.signature.sign()
    }

    override fun abort() {}
}

private class Verifier(keyPair: KeyPair, params: KeyMintAttestation) : CryptoPrimitive {
    private val signature: Signature =
        Signature.getInstance(JcaAlgorithmMapper.mapSignatureAlgorithm(params)).apply {
            initVerify(keyPair.public)
        }

    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) signature.update(data)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        if (data != null) update(data)
        if (signature == null) {
            throw ServiceSpecificException(
                KeystoreErrorCodes.verificationFailed,
                "Signature to verify is null",
            )
        }
        if (!this.signature.verify(signature)) {
            throw ServiceSpecificException(
                KeystoreErrorCodes.verificationFailed,
                "Signature verification failed",
            )
        }
        return null
    }

    override fun abort() {}
}

private class CipherPrimitive(
    cryptoKey: java.security.Key,
    params: KeyMintAttestation,
    private val opMode: Int,
    txId: Long,
) : CryptoPrimitive {
    private val isAead = params.blockMode.firstOrNull() == BlockMode.GCM
    private val cipher: Cipher =
        Cipher.getInstance(JcaAlgorithmMapper.mapCipherAlgorithm(params)).apply {
            val nonce = params.nonce
            if (nonce != null && isAead) {
                init(opMode, cryptoKey, javax.crypto.spec.GCMParameterSpec(128, nonce))
            } else if (nonce != null) {
                init(opMode, cryptoKey, javax.crypto.spec.IvParameterSpec(nonce))
            } else if (params.padding.firstOrNull() == PaddingMode.RSA_OAEP) {
                val mainDigest = JcaAlgorithmMapper.mapOaepDigest(params.digest.firstOrNull())
                val mgfDigest =
                    params.rsaOaepMgfDigest.firstOrNull()?.let {
                        JcaAlgorithmMapper.mapOaepDigest(it)
                    } ?: mainDigest
                init(
                    opMode,
                    cryptoKey,
                    javax.crypto.spec.OAEPParameterSpec(
                        mainDigest,
                        "MGF1",
                        java.security.spec.MGF1ParameterSpec(mgfDigest),
                        javax.crypto.spec.PSource.PSpecified.DEFAULT,
                    ),
                )
                SystemLogger.debug {
                    "[SoftwareOp TX_ID: $txId] oaep-op main=$mainDigest mgf=$mgfDigest " +
                        "mode=${if (opMode == Cipher.DECRYPT_MODE) "decrypt" else "encrypt"}"
                }
            } else {
                init(opMode, cryptoKey)
            }
        }

    override fun updateAad(aadInput: ByteArray?) {
        if (!isAead) {
            if (!VendorQuirks.nonAeadUpdateAadSucceeds()) {
                throw ServiceSpecificException(KeystoreErrorCodes.invalidTag)
            }
            return
        }
        if (aadInput != null) cipher.updateAAD(aadInput)
    }

    override fun update(data: ByteArray?): ByteArray? =
        if (data != null) cipher.update(data) else null

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? =
        if (data != null) cipher.doFinal(data) else cipher.doFinal()

    override fun getBeginParameters(): Array<KeyParameter>? {
        val iv = cipher.iv ?: return null
        return arrayOf(
            KeyParameter().apply {
                tag = Tag.NONCE
                value = KeyParameterValue.blob(iv)
            }
        )
    }

    override fun abort() {}
}

private class KeyAgreementPrimitive(keyPair: KeyPair) : CryptoPrimitive {
    private val agreement: javax.crypto.KeyAgreement =
        javax.crypto.KeyAgreement.getInstance("ECDH").apply { init(keyPair.private) }

    override fun update(data: ByteArray?): ByteArray? = null

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        if (data == null)
            throw ServiceSpecificException(
                KeystoreErrorCodes.invalidArgument,
                "Peer public key required for key agreement",
            )
        val peerKey =
            java.security.KeyFactory.getInstance("EC")
                .generatePublic(java.security.spec.X509EncodedKeySpec(data))
        agreement.doPhase(peerKey, true)
        return agreement.generateSecret()
    }

    override fun abort() {}
}

private class MacPrimitive(
    secretKey: javax.crypto.SecretKey,
    private val params: KeyMintAttestation,
    private val txId: Long,
) : CryptoPrimitive {
    private val mac: javax.crypto.Mac =
        javax.crypto.Mac.getInstance(JcaAlgorithmMapper.mapMacAlgorithm(params)).apply {
            init(secretKey)
        }

    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) mac.update(data)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        if (data != null) mac.update(data)
        val full = mac.doFinal()
        // Tag.MAC_LENGTH is optional on the AndroidKeyStore Mac SPI; default to the
        // full digest length so real Mac use keeps working when it is omitted.
        val tagBytes = (params.macLength ?: (full.size * 8)) / 8
        val tag = full.copyOf(tagBytes)
        if (params.purpose.firstOrNull() == KeyPurpose.VERIFY) {
            if (signature == null) {
                throw ServiceSpecificException(
                    KeystoreErrorCodes.verificationFailed,
                    "MAC to verify is null",
                )
            }
            if (!java.security.MessageDigest.isEqual(tag, signature)) {
                throw ServiceSpecificException(
                    KeystoreErrorCodes.verificationFailed,
                    "MAC verification failed",
                )
            }
            return null
        }
        SystemLogger.debug {
            "[SoftwareOp TX_ID: $txId] hmac-op digest=${params.digest.firstOrNull()} " +
                "macLen=${params.macLength} tag=${tag.size}B result=ok"
        }
        return tag
    }

    override fun abort() {}
}

class SoftwareOperation(
    private val txId: Long,
    keyPair: KeyPair?,
    secretKey: javax.crypto.SecretKey?,
    params: KeyMintAttestation,
    private val latencyFloorMs: Long = 0L,
) {
    private val primitive: CryptoPrimitive
    @Volatile
    var finalized = false
        private set

    var onFinishCallback: (() -> Unit)? = null

    val beginParameters: KeyParameters?
        get() {
            val params = primitive.getBeginParameters() ?: return null
            if (params.isEmpty()) return null
            return KeyParameters().apply { keyParameter = params }
        }

    init {
        val purpose = params.purpose.firstOrNull()
        val purposeName = KeyMintParameterLogger.purposeNames[purpose] ?: "UNKNOWN"
        SystemLogger.debug("[SoftwareOp TX_ID: $txId] Initializing for purpose: $purposeName.")

        if (purpose == null) {
            // Defensive: if params somehow restored without a PURPOSE tag
            // (corrupt v2 metadata, mismatched authorizations array on load,
            // or future format drift) the original code crashed with NPE
            // because Signer/Verifier/Cipher all dereference keyPair!!
            // before checking purpose. Surface a clean keystore error
            // instead so callers see a normal-looking operation failure
            // they can recover from rather than the process appearing to
            // silently corrupt their session.
            SystemLogger.warning(
                "[SoftwareOp TX_ID: $txId] Purpose missing on restored key " +
                    "(authorizations=${params.purpose}, keyPair=${if (keyPair != null) "present" else "null"}, " +
                    "secretKey=${if (secretKey != null) "present" else "null"}). " +
                    "Returning unsupportedPurpose."
            )
            throw ServiceSpecificException(
                KeystoreErrorCodes.unsupportedPurpose,
                "Restored key has no PURPOSE authorization",
            )
        }

        primitive =
            if (params.algorithm == Algorithm.HMAC) {
                // An HMAC key is symmetric (secretKey set, keyPair null), so it must
                // not fall through to the purpose-keyed Signer/Verifier paths, which
                // require a keyPair. secretKey is populated at HMAC keygen and restore,
                // so the throw is a defensive floor, not a live path.
                MacPrimitive(
                    secretKey
                        ?: throw ServiceSpecificException(
                            KeystoreErrorCodes.invalidArgument,
                            "[SoftwareOp TX_ID: $txId] HMAC op but secretKey null",
                        ),
                    params,
                    txId,
                )
            } else {
                when (purpose) {
                    KeyPurpose.SIGN -> {
                        val kp =
                            keyPair
                                ?: throw ServiceSpecificException(
                                    KeystoreErrorCodes.invalidArgument,
                                    "[SoftwareOp TX_ID: $txId] SIGN requested but keyPair is null",
                                )
                        Signer(kp, params)
                    }
                    KeyPurpose.VERIFY -> {
                        val kp =
                            keyPair
                                ?: throw ServiceSpecificException(
                                    KeystoreErrorCodes.invalidArgument,
                                    "[SoftwareOp TX_ID: $txId] VERIFY requested but keyPair is null",
                                )
                        Verifier(kp, params)
                    }
                    KeyPurpose.ENCRYPT -> {
                        val key: java.security.Key =
                            secretKey
                                ?: keyPair?.public
                                ?: throw ServiceSpecificException(
                                    KeystoreErrorCodes.unsupportedPurpose,
                                    "[SoftwareOp TX_ID: $txId] ENCRYPT requires either secretKey or keyPair.public",
                                )
                        CipherPrimitive(key, params, Cipher.ENCRYPT_MODE, txId)
                    }
                    KeyPurpose.DECRYPT -> {
                        val key: java.security.Key =
                            secretKey
                                ?: keyPair?.private
                                ?: throw ServiceSpecificException(
                                    KeystoreErrorCodes.unsupportedPurpose,
                                    "[SoftwareOp TX_ID: $txId] DECRYPT requires either secretKey or keyPair.private",
                                )
                        CipherPrimitive(key, params, Cipher.DECRYPT_MODE, txId)
                    }
                    KeyPurpose.AGREE_KEY -> {
                        val kp =
                            keyPair
                                ?: throw ServiceSpecificException(
                                    KeystoreErrorCodes.invalidArgument,
                                    "[SoftwareOp TX_ID: $txId] AGREE_KEY requested but keyPair is null",
                                )
                        KeyAgreementPrimitive(kp)
                    }
                    else ->
                        throw ServiceSpecificException(
                            KeystoreErrorCodes.unsupportedPurpose,
                            "Unsupported operation purpose: $purpose",
                        )
                }
            }
    }

    private fun checkActive() {
        if (finalized) {
            SystemLogger.debug(
                "[SoftwareOp TX_ID: $txId] Rejected: operation already finalized (pruned or completed)"
            )
            throw ServiceSpecificException(KeystoreErrorCodes.invalidOperationHandle)
        }
    }

    private fun checkInputLength(data: ByteArray?) {
        if (data != null && data.size > MAX_RECEIVE_DATA) {
            SystemLogger.info(
                "[SoftwareOp TX_ID: $txId] Input too large: ${data.size} > $MAX_RECEIVE_DATA, throwing TOO_MUCH_DATA(${KeystoreErrorCodes.tooMuchData})"
            )
            throw ServiceSpecificException(KeystoreErrorCodes.tooMuchData)
        }
    }

    fun updateAad(aadInput: ByteArray?) {
        SystemLogger.info(
            "[SoftwareOp TX_ID: $txId] updateAad() ENTRY inputSize=${aadInput?.size ?: 0} primitive=${primitive::class.simpleName}"
        )
        checkActive()
        checkInputLength(aadInput)
        try {
            primitive.updateAad(aadInput)
            SystemLogger.info(
                "[SoftwareOp TX_ID: $txId] updateAad() RETURNED_NORMALLY (unexpected for non-AEAD)"
            )
        } catch (throwable: Throwable) {
            val top = throwable.stackTrace.firstOrNull()?.toString() ?: "<no-frame>"
            val code = (throwable as? ServiceSpecificException)?.errorCode
            SystemLogger.info(
                "[SoftwareOp TX_ID: $txId] updateAad() THREW class=${throwable::class.java.name} code=$code msg=${throwable.message} top=$top"
            )
            throw throwable
        }
    }

    fun update(data: ByteArray?): ByteArray? {
        SystemLogger.debug("[SoftwareOp TX_ID: $txId] update() inputSize=${data?.size ?: 0}")
        checkActive()
        checkInputLength(data)
        try {
            return primitive.update(data)
        } catch (e: ServiceSpecificException) {
            throw e
        } catch (e: Exception) {
            SystemLogger.error("[SoftwareOp TX_ID: $txId] Failed to update operation.", e)
            throw mapToServiceSpecificException(e)
        }
    }

    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        checkActive()
        checkInputLength(data)
        try {
            val startNs = if (latencyFloorMs > 0) System.nanoTime() else 0L
            val result = primitive.finish(data, signature)
            if (latencyFloorMs > 0) {
                val elapsedMs = (System.nanoTime() - startNs) / 1_000_000
                val delayMs = latencyFloorMs - elapsedMs
                if (delayMs > 0) LockSupport.parkNanos(delayMs * 1_000_000)
            }
            finalized = true
            onFinishCallback?.invoke()
            SystemLogger.info("[SoftwareOp TX_ID: $txId] Finished operation successfully.")
            return result
        } catch (e: ServiceSpecificException) {
            throw e
        } catch (e: Exception) {
            SystemLogger.error("[SoftwareOp TX_ID: $txId] Failed to finish operation.", e)
            throw mapToServiceSpecificException(e)
        }
    }

    fun abort() {
        finalized = true
        primitive.abort()
        SystemLogger.debug("[SoftwareOp TX_ID: $txId] Operation aborted.")
    }

    private fun mapToServiceSpecificException(e: Exception): ServiceSpecificException =
        when (e) {
            is SignatureException ->
                ServiceSpecificException(KeystoreErrorCodes.verificationFailed, e.message)
            is javax.crypto.BadPaddingException ->
                ServiceSpecificException(KeystoreErrorCodes.invalidArgument, e.message)
            is javax.crypto.IllegalBlockSizeException ->
                ServiceSpecificException(KeystoreErrorCodes.invalidInputLength, e.message)
            is java.security.InvalidKeyException ->
                ServiceSpecificException(KeystoreErrorCodes.incompatibleKey, e.message)
            else -> ServiceSpecificException(KeystoreErrorCodes.unknownError, e.message)
        }

    companion object {
        private const val MAX_RECEIVE_DATA = 0x8000
    }
}

internal object KeystoreErrorCodes {
    val tooMuchData: Int by lazy {
        resolveField("android.system.keystore2.ResponseCode", "TOO_MUCH_DATA", 21)
    }

    val invalidOperationHandle: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "INVALID_OPERATION_HANDLE", -28)
    }

    val invalidTag: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "INVALID_TAG", -76)
    }

    val verificationFailed: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "VERIFICATION_FAILED", -30)
    }

    val invalidArgument: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "INVALID_ARGUMENT", -38)
    }

    val invalidInputLength: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "INVALID_INPUT_LENGTH", -21)
    }

    val incompatibleKey: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "INCOMPATIBLE_KEY", -31)
    }

    val incompatiblePurpose: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "INCOMPATIBLE_PURPOSE", -13)
    }

    val unsupportedPurpose: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "UNSUPPORTED_PURPOSE", -14)
    }

    val incompatibleAlgorithm: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "INCOMPATIBLE_ALGORITHM", -18)
    }

    val keyNotYetValid: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "KEY_NOT_YET_VALID", -39)
    }

    val keyExpired: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "KEY_EXPIRED", -40)
    }

    val callerNonceProhibited: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "CALLER_NONCE_PROHIBITED", -55)
    }

    val unknownError: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "UNKNOWN_ERROR", -1000)
    }

    val incompatibleBlockMode: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "INCOMPATIBLE_BLOCK_MODE", -8)
    }

    val incompatiblePaddingMode: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "INCOMPATIBLE_PADDING_MODE", -11)
    }

    val incompatibleDigest: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "INCOMPATIBLE_DIGEST", -13)
    }

    val invalidMacLength: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "INVALID_MAC_LENGTH", -57)
    }

    fun resolveField(className: String, fieldName: String, fallback: Int): Int =
        runCatching { Class.forName(className).getField(fieldName).getInt(null) }
            .getOrElse {
                SystemLogger.debug("Resolved $className.$fieldName via fallback: $fallback")
                fallback
            }
}

class SoftwareOperationBinder(private val operation: SoftwareOperation) :
    IKeystoreOperation.Stub() {

    @Synchronized
    override fun updateAad(aadInput: ByteArray?) {
        SystemLogger.info(
            "[SoftwareOpBinder] updateAad() ENTRY callingUid=${android.os.Binder.getCallingUid()} size=${aadInput?.size ?: 0}"
        )
        try {
            operation.updateAad(aadInput)
            SystemLogger.info("[SoftwareOpBinder] updateAad() RETURNED_NORMALLY")
        } catch (throwable: Throwable) {
            val code = (throwable as? ServiceSpecificException)?.errorCode
            SystemLogger.info(
                "[SoftwareOpBinder] updateAad() PROPAGATING class=${throwable::class.java.name} code=$code msg=${throwable.message}"
            )
            throw throwable
        }
    }

    @Synchronized
    override fun update(input: ByteArray?): ByteArray? {
        return operation.update(input)
    }

    @Synchronized
    override fun finish(input: ByteArray?, signature: ByteArray?): ByteArray? {
        return operation.finish(input, signature)
    }

    @Synchronized
    override fun abort() {
        operation.abort()
    }
}
