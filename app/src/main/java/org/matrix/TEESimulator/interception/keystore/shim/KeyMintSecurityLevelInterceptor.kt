package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.*
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.KeyPair
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.concurrent.ConcurrentHashMap
import org.matrix.TEESimulator.attestation.AttestationPatcher
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.interception.keystore.InterceptorUtils
import org.matrix.TEESimulator.interception.keystore.KeyIdentifier
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateGenerator
import org.matrix.TEESimulator.pki.CertificateHelper

class KeyMintSecurityLevelInterceptor(
    private val original: IKeystoreSecurityLevel,
    private val securityLevel: Int,
) : BinderInterceptor() {

    data class GeneratedKeyInfo(
        val keyPair: KeyPair,
        val nspace: Long,
        val response: KeyEntryResponse,
    )

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        val shouldSkip = ConfigurationManager.shouldSkipUid(callingUid)

        when (code) {
            GENERATE_KEY_TRANSACTION -> {
                logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

                if (!shouldSkip) return handleGenerateKey(callingUid, data)
            }
            CREATE_OPERATION_TRANSACTION -> {
                logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

                if (!shouldSkip) return handleCreateOperation(txId, callingUid, data)
            }
            IMPORT_KEY_TRANSACTION -> {
                logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!
                SystemLogger.info(
                    "[TX_ID: $txId] Forward to post-importKey hook for ${keyDescriptor.alias}[${keyDescriptor.nspace}]"
                )
                return TransactionResult.Continue
            }
        }

        logTransaction(
            txId,
            transactionNames[code] ?: "unknown code=$code",
            callingUid,
            callingPid,
            true,
        )

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
        // We only care about successful transactions.
        if (resultCode != 0 || reply == null || InterceptorUtils.hasException(reply))
            return TransactionResult.SkipTransaction

        if (code == IMPORT_KEY_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.SkipTransaction
            cleanupKeyData(KeyIdentifier(callingUid, keyDescriptor.alias))
        } else if (code == CREATE_OPERATION_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!
            val params = data.createTypedArray(KeyParameter.CREATOR)!!
            val parsedParams = KeyMintAttestation(params)
            val forced = data.readBoolean()
            if (forced)
                SystemLogger.verbose(
                    "[TX_ID: $txId] Current operation has a very high pruning power."
                )
            val response: CreateOperationResponse =
                reply.readTypedObject(CreateOperationResponse.CREATOR)!!
            SystemLogger.verbose(
                "[TX_ID: $txId] CreateOperationResponse: ${response.iOperation} ${response.operationChallenge}"
            )

            // Intercept the IKeystoreOperation binder
            response.iOperation?.let { operation ->
                val operationBinder = operation.asBinder()
                if (!interceptedOperations.containsKey(operationBinder)) {
                    SystemLogger.info("Found new IKeystoreOperation. Registering interceptor...")
                    val backdoor = getBackdoor(target)
                    if (backdoor != null) {
                        val interceptor = OperationInterceptor(operation, backdoor)
                        register(backdoor, operationBinder, interceptor)
                        interceptedOperations[operationBinder] = interceptor
                    } else {
                        SystemLogger.error(
                            "Failed to get backdoor to register OperationInterceptor."
                        )
                    }
                }
            }
        } else if (code == GENERATE_KEY_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            val metadata: KeyMetadata =
                reply.readTypedObject(KeyMetadata.CREATOR)
                    ?: return TransactionResult.SkipTransaction
            val originalChain =
                CertificateHelper.getCertificateChain(metadata)
                    ?: return TransactionResult.SkipTransaction
            if (originalChain.size > 1) {
                val newChain = AttestationPatcher.patchCertificateChain(originalChain, callingUid)

                // Cache the newly patched chain to ensure consistency across subsequent API calls.
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!
                val key = metadata.key!!
                val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)
                CertificateHelper.updateCertificateChain(metadata, newChain).getOrThrow()

                // We must clean up cached generated keys before storing the patched chain
                cleanupKeyData(keyId)
                patchedChains[keyId] = newChain
                SystemLogger.debug(
                    "Cached patched certificate chain for $keyId. (${key.alias} [${key.domain}, ${key.nspace}])"
                )

                return InterceptorUtils.createTypedObjectReply(metadata)
            }
        }
        return TransactionResult.SkipTransaction
    }

    private fun handleCreateOperation(
        txId: Long,
        callingUid: Int,
        data: Parcel,
    ): TransactionResult {
        data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
        val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!

        // An operation must use the KEY_ID domain.
        if (keyDescriptor.domain != Domain.KEY_ID) {
            return TransactionResult.ContinueAndSkipPost
        }

        val nspace = keyDescriptor.nspace
        val generatedKeyInfo = findGeneratedKeyByKeyId(callingUid, nspace)

        if (generatedKeyInfo == null) {
            SystemLogger.debug(
                "[TX_ID: $txId] Operation for unknown/hardware KeyId ($nspace). Forwarding."
            )
            return TransactionResult.Continue
        }

        SystemLogger.info("[TX_ID: $txId] Creating SOFTWARE operation for KeyId $nspace.")

        val params = data.createTypedArray(KeyParameter.CREATOR)!!
        val parsedParams = KeyMintAttestation(params)

        val softwareOperation = SoftwareOperation(txId, generatedKeyInfo.keyPair, parsedParams)
        val operationBinder = SoftwareOperationBinder(softwareOperation)

        val response =
            CreateOperationResponse().apply {
                iOperation = operationBinder
                operationChallenge = null
            }

        return InterceptorUtils.createTypedObjectReply(response)
    }

    private fun handleGenerateKey(callingUid: Int, data: Parcel): TransactionResult {
        return runCatching {
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!
                val attestationKey = data.readTypedObject(KeyDescriptor.CREATOR)

                // Reject oversized aliases to prevent binder buffer exhaustion (Issue #109)
                if (keyDescriptor.alias.length > MAX_ALIAS_LENGTH) {
                    SystemLogger.warning("Rejecting oversized alias: ${keyDescriptor.alias.length} bytes (max: $MAX_ALIAS_LENGTH)")
                    return TransactionResult.ContinueAndSkipPost
                }

                SystemLogger.debug(
                    "Handling generateKey ${keyDescriptor.alias}, attestKey=${attestationKey?.alias}"
                )
                val params = data.createTypedArray(KeyParameter.CREATOR)!!
                val parsedParams = KeyMintAttestation(params)
                val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)
                val isAttestKeyRequest =
                    parsedParams.purpose.size == 1 &&
                        parsedParams.purpose.contains(KeyPurpose.ATTEST_KEY)

                val needsSoftwareGeneration =
                    ConfigurationManager.shouldGenerate(callingUid) ||
                        (ConfigurationManager.shouldPatch(callingUid) && isAttestKeyRequest) ||
                        (attestationKey != null &&
                            isAttestationKey(KeyIdentifier(callingUid, attestationKey.alias)))

                if (needsSoftwareGeneration) {
                    keyDescriptor.nspace = secureRandom.nextLong()
                    SystemLogger.info(
                        "Generating software key for ${keyDescriptor.alias}[${keyDescriptor.nspace}]."
                    )

                    val keyData =
                        CertificateGenerator.generateAttestedKeyPair(
                            callingUid,
                            keyDescriptor.alias,
                            attestationKey?.alias,
                            parsedParams,
                            securityLevel,
                        ) ?: throw Exception("CertificateGenerator failed to create key pair.")

                    cleanupKeyData(keyId)
                    val response =
                        buildKeyEntryResponse(keyData.second, parsedParams, keyDescriptor)
                    generatedKeys[keyId] =
                        GeneratedKeyInfo(keyData.first, keyDescriptor.nspace, response)
                    if (isAttestKeyRequest) attestationKeys.add(keyId)

                    GeneratedKeyPersistence.save(
                        keyId = keyId,
                        keyPair = keyData.first,
                        nspace = keyDescriptor.nspace,
                        securityLevel = securityLevel,
                        certChain = keyData.second.toList(),
                        algorithm = parsedParams.algorithm,
                        keySize = parsedParams.keySize,
                        ecCurve = parsedParams.ecCurve,
                        purposes = parsedParams.purpose,
                        digests = parsedParams.digest,
                        isAttestationKey = isAttestKeyRequest,
                    )

                    return InterceptorUtils.createTypedObjectReply(response.metadata)
                } else if (parsedParams.attestationChallenge != null) {
                    return TransactionResult.Continue
                }

                cleanupKeyData(keyId)
                TransactionResult.ContinueAndSkipPost
            }
            .getOrElse {
                SystemLogger.error("Error during generateKey handling for UID $callingUid.", it)
                TransactionResult.ContinueAndSkipPost
            }
    }

    private fun buildKeyEntryResponse(
        chain: List<Certificate>,
        params: KeyMintAttestation,
        descriptor: KeyDescriptor,
    ): KeyEntryResponse {
        val metadata =
            KeyMetadata().apply {
                keySecurityLevel = securityLevel
                key = descriptor
                CertificateHelper.updateCertificateChain(this, chain.toTypedArray()).getOrThrow()
                authorizations = params.toAuthorizations(securityLevel)
            }
        return KeyEntryResponse().apply {
            this.metadata = metadata
            iSecurityLevel = original
        }
    }

    fun loadPersistedKeys() {
        val records = GeneratedKeyPersistence.loadAll(securityLevel)
        if (records.isEmpty()) {
            SystemLogger.debug("No persisted keys to restore for security level $securityLevel")
            return
        }

        SystemLogger.info("Restoring ${records.size} persisted keys for security level $securityLevel")

        for (record in records) {
            runCatching {
                val keyId = KeyIdentifier(record.uid, record.alias)
                if (generatedKeys.containsKey(keyId)) {
                    SystemLogger.debug("Skipping already-loaded key: $keyId")
                    return@runCatching
                }

                val algorithmName = when (record.algorithm) {
                    Algorithm.EC -> "EC"
                    Algorithm.RSA -> "RSA"
                    else -> throw IllegalArgumentException("Unknown algorithm: ${record.algorithm}")
                }

                val keyFactory = KeyFactory.getInstance(algorithmName)
                val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(record.privateKeyBytes))

                val certFactory = CertificateFactory.getInstance("X.509")
                val certChain = record.certChainBytes.map { bytes ->
                    certFactory.generateCertificate(ByteArrayInputStream(bytes))
                }
                require(certChain.isNotEmpty()) { "Persisted key has empty certificate chain" }

                val publicKey = certChain[0].publicKey
                val keyPair = KeyPair(publicKey, privateKey)

                val descriptor = KeyDescriptor().apply {
                    domain = Domain.APP
                    nspace = record.nspace
                    alias = record.alias
                    blob = null
                }

                val attestation = KeyMintAttestation(
                    keySize = record.keySize,
                    algorithm = record.algorithm,
                    ecCurve = record.ecCurve,
                    ecCurveName = "",
                    blockMode = emptyList(),
                    padding = emptyList(),
                    purpose = record.purposes,
                    digest = record.digests,
                    rsaPublicExponent = null,
                    certificateSerial = null,
                    certificateSubject = null,
                    certificateNotBefore = null,
                    certificateNotAfter = null,
                    attestationChallenge = null,
                    brand = null,
                    device = null,
                    product = null,
                    serial = null,
                    imei = null,
                    meid = null,
                    manufacturer = null,
                    model = null,
                    secondImei = null,
                )

                val response = buildKeyEntryResponse(certChain, attestation, descriptor)
                generatedKeys[keyId] = GeneratedKeyInfo(keyPair, record.nspace, response)
                if (record.isAttestationKey) attestationKeys.add(keyId)

                SystemLogger.debug("Restored persisted key: $keyId")
            }.onFailure {
                SystemLogger.error("Failed to restore key: uid=${record.uid} alias=${record.alias}", it)
            }
        }

        SystemLogger.info("Key restoration complete. Total in memory: ${generatedKeys.size}")
    }

    companion object {
        private val secureRandom = SecureRandom()

        // Maximum alias length to prevent binder buffer exhaustion (Issue #109)
        // Binder buffer is ~1MB; 256KB provides 4x safety margin for transaction overhead
        private const val MAX_ALIAS_LENGTH = 256 * 1024

        private val GENERATE_KEY_TRANSACTION =
            InterceptorUtils.getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "generateKey")
        private val IMPORT_KEY_TRANSACTION =
            InterceptorUtils.getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "importKey")
        private val CREATE_OPERATION_TRANSACTION =
            InterceptorUtils.getTransactCode(
                IKeystoreSecurityLevel.Stub::class.java,
                "createOperation",
            )

        private val transactionNames: Map<Int, String> by lazy {
            IKeystoreSecurityLevel.Stub::class
                .java
                .declaredFields
                .filter {
                    it.isAccessible = true
                    it.type == Int::class.java && it.name.startsWith("TRANSACTION_")
                }
                .associate { field -> (field.get(null) as Int) to field.name.split("_")[1] }
        }

        val generatedKeys = ConcurrentHashMap<KeyIdentifier, GeneratedKeyInfo>()
        // Caches patched chains to prevent re-generation and signature inconsistencies
        private val patchedChains = ConcurrentHashMap<KeyIdentifier, Array<Certificate>>()
        private val attestationKeys = ConcurrentHashMap.newKeySet<KeyIdentifier>()
        private val interceptedOperations = ConcurrentHashMap<IBinder, OperationInterceptor>()

        fun getGeneratedKeyResponse(keyId: KeyIdentifier): KeyEntryResponse? =
            generatedKeys[keyId]?.response

        fun findGeneratedKeyByKeyId(callingUid: Int, nspace: Long?): GeneratedKeyInfo? {
            if (nspace == null || nspace == 0L) return null
            return generatedKeys.entries
                .filter { (keyIdentifier, _) -> keyIdentifier.uid == callingUid }
                .find { (_, info) -> info.nspace == nspace }
                ?.value
        }

        fun getPatchedChain(keyId: KeyIdentifier): Array<Certificate>? = patchedChains[keyId]

        fun isAttestationKey(keyId: KeyIdentifier): Boolean = attestationKeys.contains(keyId)

        fun cleanupKeyData(keyId: KeyIdentifier) {
            if (generatedKeys.remove(keyId) != null) {
                SystemLogger.debug("Remove generated key ${keyId}")
                GeneratedKeyPersistence.delete(keyId)
            }
            if (patchedChains.remove(keyId) != null) {
                SystemLogger.debug("Remove patched chain for ${keyId}")
            }
            if (attestationKeys.remove(keyId)) {
                SystemLogger.debug("Remove cached attestaion key ${keyId}")
            }
        }

        fun removeOperationInterceptor(operationBinder: IBinder, backdoor: IBinder) {
            unregister(backdoor, operationBinder)

            if (interceptedOperations.remove(operationBinder) != null) {
                SystemLogger.debug("Removed operation interceptor for binder: $operationBinder")
            }
        }

        fun invalidatePatchedChains(reason: String? = null) {
            val count = patchedChains.size
            if (count == 0) return
            val reasonMessage = reason?.let { " due to $it" } ?: ""
            patchedChains.clear()
            SystemLogger.info("Invalidated $count patched cert chains$reasonMessage.")
        }

        fun clearAllGeneratedKeys(reason: String? = null) {
            val count = generatedKeys.size
            val reasonMessage = reason?.let { " due to $it" } ?: ""
            generatedKeys.clear()
            patchedChains.clear()
            attestationKeys.clear()
            GeneratedKeyPersistence.deleteAll()
            SystemLogger.info("Cleared all cached keys ($count entries)$reasonMessage.")
        }
    }
}

private fun KeyMintAttestation.toAuthorizations(securityLevel: Int): Array<Authorization> {
    val authList = mutableListOf<Authorization>()

    fun createAuth(tag: Int, value: KeyParameterValue): Authorization {
        val param =
            KeyParameter().apply {
                this.tag = tag
                this.value = value
            }
        return Authorization().apply {
            this.keyParameter = param
            this.securityLevel = securityLevel
        }
    }

    this.purpose.forEach { authList.add(createAuth(Tag.PURPOSE, KeyParameterValue.keyPurpose(it))) }
    this.digest.forEach { authList.add(createAuth(Tag.DIGEST, KeyParameterValue.digest(it))) }

    authList.add(createAuth(Tag.ALGORITHM, KeyParameterValue.algorithm(this.algorithm)))
    authList.add(createAuth(Tag.KEY_SIZE, KeyParameterValue.integer(this.keySize)))
    authList.add(createAuth(Tag.EC_CURVE, KeyParameterValue.ecCurve(this.ecCurve)))
    authList.add(createAuth(Tag.NO_AUTH_REQUIRED, KeyParameterValue.boolValue(true)))

    return authList.toTypedArray()
}
