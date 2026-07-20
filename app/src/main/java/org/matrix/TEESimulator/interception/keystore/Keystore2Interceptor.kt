package org.matrix.TEESimulator.interception.keystore

import android.annotation.SuppressLint
import android.hardware.security.keymint.SecurityLevel
import android.os.Build
import android.os.IBinder
import android.os.Parcel
import android.os.ServiceManager
import android.system.keystore2.Domain
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import java.security.SecureRandom
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap
import org.matrix.TEESimulator.attestation.AttestationPatcher
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.shim.GeneratedKeyPersistence
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.logging.AttestationDossier
import org.matrix.TEESimulator.logging.KeyMintParameterLogger
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateGenerator
import org.matrix.TEESimulator.pki.CertificateHelper

/**
 * Interceptor for the `IKeystoreService` on Android S (API 31) and newer.
 *
 * This version of Keystore delegates most cryptographic operations to `IKeystoreSecurityLevel`
 * sub-services (for TEE, StrongBox, etc.). This interceptor's main role is to set up interceptors
 * for those sub-services and to patch certificate chains on their way out.
 */
@SuppressLint("BlockedPrivateApi")
object Keystore2Interceptor : AbstractKeystoreInterceptor() {
    private val stubBinderClass = IKeystoreService.Stub::class.java

    // Transaction codes for the IKeystoreService interface methods we are interested in.
    private val GET_KEY_ENTRY_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "getKeyEntry")
    private val DELETE_KEY_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "deleteKey")
    private val UPDATE_SUBCOMPONENT_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "updateSubcomponent")
    private val LIST_ENTRIES_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "listEntries")
    private val LIST_ENTRIES_BATCHED_TRANSACTION =
        if (Build.VERSION.SDK_INT >= 34)
            InterceptorUtils.getTransactCode(stubBinderClass, "listEntriesBatched")
        else null
    private val GET_NUMBER_OF_ENTRIES_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "getNumberOfEntries")
    private val GRANT_TRANSACTION = InterceptorUtils.getTransactCode(stubBinderClass, "grant")
    private val UNGRANT_TRANSACTION = InterceptorUtils.getTransactCode(stubBinderClass, "ungrant")

    private val transactionNames: Map<Int, String> by lazy {
        stubBinderClass.declaredFields
            .filter {
                it.isAccessible = true
                it.type == Int::class.java && it.name.startsWith("TRANSACTION_")
            }
            .associate { field -> (field.get(null) as Int) to field.name.split("_")[1] }
    }

    private const val RESPONSE_KEY_NOT_FOUND = 7
    private const val RESPONSE_PERMISSION_DENIED = 6
    private const val KEY_PERMISSION_GET_INFO = 0x4
    private const val KEY_PERMISSION_UPDATE = 0x80

    // KeyStoreManager.grantKeyAccess() became a public app API in Android 16 (API 36). Before that,
    // grant was a hidden API and SELinux denied untrusted_app, so a synthetic-key grant must answer
    // PERMISSION_DENIED pre-36 and a coherent virtualized grant on 36+.
    private const val GRANT_PUBLIC_API_SDK = 36
    private val deletedSoftwareKeys: MutableSet<KeyIdentifier> = ConcurrentHashMap.newKeySet()
    private val userUpdatedKeys = ConcurrentHashMap.newKeySet<KeyIdentifier>()

    fun forgetDeletedKey(keyId: KeyIdentifier) {
        if (deletedSoftwareKeys.remove(keyId)) {
            SystemLogger.debug("Cleared deletion marker for ${keyId.alias}")
        }
    }

    override val serviceName = "android.system.keystore2.IKeystoreService/default"
    override val processName = "keystore2"
    override val injectionCommand = "exec ./inject `pidof keystore2` libTEESimulator.so entry"

    override val interceptedCodes: IntArray by lazy {
        listOfNotNull(
                GET_KEY_ENTRY_TRANSACTION,
                DELETE_KEY_TRANSACTION,
                UPDATE_SUBCOMPONENT_TRANSACTION,
                LIST_ENTRIES_TRANSACTION,
                LIST_ENTRIES_BATCHED_TRANSACTION,
                GET_NUMBER_OF_ENTRIES_TRANSACTION,
                GRANT_TRANSACTION,
                UNGRANT_TRANSACTION,
            )
            .toIntArray()
    }

    /**
     * This method is called once the main service is hooked. It proceeds to find and hook the
     * security level sub-services (e.g., TEE, StrongBox).
     */
    override fun onInterceptorReady(service: IBinder, backdoor: IBinder) {
        val keystoreInterface = IKeystoreService.Stub.asInterface(service)
        setupSecurityLevelInterceptors(keystoreInterface, backdoor)
        setupMaintenanceInterceptor(backdoor)

        // Find camera UIDs and pass them to the C++ hook
        val bypassUids = mutableListOf<Int>()
        try {
            val pm = org.matrix.TEESimulator.App.appContext.packageManager
            val apps = pm.getInstalledApplications(0)
            if (apps != null) {
                for (i in 0 until apps.size) {
                    val app = apps[i]
                    if (app.packageName != null && app.packageName.contains("camera", ignoreCase = true)) {
                        val uid = app.uid
                        if (!bypassUids.contains(uid)) {
                            bypassUids.add(uid)
                        }
                        org.matrix.TEESimulator.logging.SystemLogger.info("Adding dynamic bypass UID $uid for camera package ${app.packageName}")
                    }
                }
            }
        } catch (e: Exception) {
            org.matrix.TEESimulator.logging.SystemLogger.error("Failed to fetch camera UIDs", e)
        }
        if (bypassUids.isNotEmpty()) {
            setBypassUids(backdoor, bypassUids)
        }
    }

    /**
     * Hooks the keystore2 daemon's `android.security.maintenance` binder, which is hosted by the
     * same process, so synthetic key state follows real key-lifecycle events. Best-effort: if the
     * service is absent the synthetic plane simply forgoes lifecycle parity.
     */
    private fun setupMaintenanceInterceptor(backdoor: IBinder) {
        runCatching {
                ServiceManager.getService("android.security.maintenance")?.let { maintenance ->
                    SystemLogger.info("Found maintenance binder. Registering interceptor...")
                    register(
                        backdoor,
                        maintenance,
                        Keystore2MaintenanceInterceptor,
                        Keystore2MaintenanceInterceptor.interceptedCodes,
                    )
                }
                    ?: SystemLogger.warning(
                        "Maintenance binder not found; skipping lifecycle parity."
                    )
            }
            .onFailure { SystemLogger.error("Failed to intercept maintenance binder.", it) }
    }

    private fun setupSecurityLevelInterceptors(service: IKeystoreService, backdoor: IBinder) {
        // Attempt to get and intercept the TEE security level service.
        runCatching {
                service.getSecurityLevel(SecurityLevel.TRUSTED_ENVIRONMENT)?.let { tee ->
                    SystemLogger.info("Found TEE SecurityLevel. Registering interceptor...")
                    val interceptor =
                        KeyMintSecurityLevelInterceptor(tee, SecurityLevel.TRUSTED_ENVIRONMENT)
                    register(
                        backdoor,
                        tee.asBinder(),
                        interceptor,
                        KeyMintSecurityLevelInterceptor.INTERCEPTED_CODES,
                    )
                    interceptor.loadPersistedKeys()
                }
            }
            .onFailure { SystemLogger.error("Failed to intercept TEE SecurityLevel.", it) }

        // Attempt to get and intercept the StrongBox security level service.
        runCatching {
                service.getSecurityLevel(SecurityLevel.STRONGBOX)?.let { strongbox ->
                    SystemLogger.info("Found StrongBox SecurityLevel. Registering interceptor...")
                    val interceptor =
                        KeyMintSecurityLevelInterceptor(strongbox, SecurityLevel.STRONGBOX)
                    register(
                        backdoor,
                        strongbox.asBinder(),
                        interceptor,
                        KeyMintSecurityLevelInterceptor.INTERCEPTED_CODES,
                    )
                    interceptor.loadPersistedKeys()
                }
            }
            .onFailure { SystemLogger.error("Failed to intercept StrongBox SecurityLevel.", it) }
    }

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        if (code == GET_NUMBER_OF_ENTRIES_TRANSACTION) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid, true)
            return if (ConfigurationManager.shouldSkipUid(callingUid))
                TransactionResult.ContinueAndSkipPost
            else TransactionResult.Continue
        } else if (code == LIST_ENTRIES_TRANSACTION || code == LIST_ENTRIES_BATCHED_TRANSACTION) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid, true)

            val packages = ConfigurationManager.getPackagesForUid(callingUid).joinToString()
            val isGMS = packages.contains("com.google.android.gms")

            if (isGMS || ConfigurationManager.shouldSkipUid(callingUid)) {
                return TransactionResult.ContinueAndSkipPost
            }

            return runCatching {
                    val isBatchMode = code == LIST_ENTRIES_BATCHED_TRANSACTION
                    if (ListEntriesHandler.cacheParameters(txId, data, isBatchMode)) {
                        TransactionResult.Continue
                    } else {
                        TransactionResult.ContinueAndSkipPost
                    }
                }
                .getOrElse {
                    SystemLogger.error(
                        "[TX_ID: $txId] Failed to parse parameters for ${transactionNames[code]!!}",
                        it,
                    )
                    TransactionResult.ContinueAndSkipPost
                }
        } else if (
            code == GET_KEY_ENTRY_TRANSACTION ||
                code == DELETE_KEY_TRANSACTION ||
                code == UPDATE_SUBCOMPONENT_TRANSACTION
        ) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

            if (code == UPDATE_SUBCOMPONENT_TRANSACTION) {
                if (ConfigurationManager.shouldSkipUid(callingUid))
                    return TransactionResult.ContinueAndSkipPost
                return handleUpdateSubcomponent(callingUid, data)
            }

            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val descriptor =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.ContinueAndSkipPost

            // Domain.GRANT read (Android 16+ KeyStoreManager grant). Served for ANY grantee uid —
            // including isolated services (bindIsolatedService) with no package mapping — so
            // resolve
            // it before the package-scoped skip; caller-binding in resolveGrant() is the real
            // access
            // gate. On Android <= 15 no grants are ever issued (grant() denies), so softwareGrants
            // is
            // empty and this falls through to the real keystore2.
            if (code == GET_KEY_ENTRY_TRANSACTION && descriptor.domain == Domain.GRANT) {
                val grant =
                    KeyMintSecurityLevelInterceptor.resolveGrant(descriptor.nspace, callingUid)
                if (grant == null) {
                    // Ours but wrong caller -> KEY_NOT_FOUND (caller-binding); not ours -> real
                    // keystore2.
                    return if (
                        KeyMintSecurityLevelInterceptor.softwareGrants.containsKey(
                            descriptor.nspace
                        )
                    )
                        InterceptorUtils.createErrorReply(RESPONSE_KEY_NOT_FOUND)
                    else TransactionResult.ContinueAndSkipPost
                }
                if ((grant.accessVector and KEY_PERMISSION_GET_INFO) == 0) {
                    return InterceptorUtils.createErrorReply(RESPONSE_PERMISSION_DENIED)
                }
                val response =
                    KeyMintSecurityLevelInterceptor.getGeneratedKeyResponse(grant.ownerKeyId)
                        ?: return InterceptorUtils.createErrorReply(RESPONSE_KEY_NOT_FOUND)
                // Same object the owner read returns -> coherent chain across planes.
                return InterceptorUtils.createTypedObjectReply(response)
            }

            // generateKey force-forges attest/device-id keys even for skipped UIDs; getKeyEntry
            // must serve them back or the framework's attestKeyAlias lookup gets KEY_NOT_FOUND.
            if (code != GET_KEY_ENTRY_TRANSACTION && ConfigurationManager.shouldSkipUid(callingUid))
                return TransactionResult.ContinueAndSkipPost

            if (code == DELETE_KEY_TRANSACTION) {
                val keyId =
                    if (descriptor.alias != null) {
                        KeyIdentifier(callingUid, descriptor.alias)
                    } else if (descriptor.domain == Domain.KEY_ID) {
                        KeyMintSecurityLevelInterceptor.findGeneratedKeyByKeyId(
                                callingUid,
                                descriptor.nspace,
                            )
                            ?.let { info ->
                                KeyMintSecurityLevelInterceptor.generatedKeys.entries
                                    .find {
                                        it.value.nspace == info.nspace && it.key.uid == callingUid
                                    }
                                    ?.key
                            }
                    } else null

                if (keyId != null) {
                    val isSoftwareKey =
                        KeyMintSecurityLevelInterceptor.generatedKeys.containsKey(keyId)
                    KeyMintSecurityLevelInterceptor.cleanupKeyData(keyId)
                    if (isSoftwareKey) {
                        deletedSoftwareKeys.add(keyId)
                        SystemLogger.info(
                            "[TX_ID: $txId] Deleted cached keypair ${keyId.alias}, replying with empty response."
                        )
                        return InterceptorUtils.createSuccessReply(writeResultCode = false)
                    }
                }
                return TransactionResult.ContinueAndSkipPost
            }

            if (descriptor.alias == null) {
                if (descriptor.domain == Domain.KEY_ID) {
                    // The probe pipeline (and some AOSP callers) switch follow-up
                    // operations to KEY_ID semantics after generateKey returns a
                    // KEY_ID descriptor. Without this branch, our software keys
                    // are invisible to KEY_ID-based getKeyEntry calls and the
                    // request falls through to the real keystore2 daemon, which
                    // legitimately responds with KEY_NOT_FOUND. Duck Detector's
                    // TimingSideChannelProbe captures that exception during its
                    // warmup phase and surfaces it as
                    // "Captured private binder exception during timing skip".
                    // Resolving by KEY_ID and returning the cached response keeps
                    // the call on the happy path, eliminating the warmup signal.
                    val info =
                        KeyMintSecurityLevelInterceptor.findGeneratedKeyByKeyId(
                            callingUid,
                            descriptor.nspace,
                        )
                    if (info?.response != null) {
                        SystemLogger.info(
                            "[TX_ID: $txId] Found generated response via KEY_ID nspace=${descriptor.nspace}"
                        )
                        logServedChain(callingUid, txId, "keyid:${descriptor.nspace}", info.response)
                        return InterceptorUtils.createTypedObjectReply(info.response)
                    }
                    val teeResp =
                        KeyMintSecurityLevelInterceptor.findTeeResponseByKeyId(
                            callingUid,
                            descriptor.nspace,
                        )
                    if (teeResp != null) {
                        SystemLogger.info(
                            "[TX_ID: $txId] Found TEE response via KEY_ID nspace=${descriptor.nspace}"
                        )
                        logServedChain(callingUid, txId, "keyid:${descriptor.nspace}", teeResp)
                        return InterceptorUtils.createTypedObjectReply(teeResp)
                    }
                }
                // Domain.GRANT is handled earlier (before the package-scoped skip); an alias-less
                // read reaching here is KEY_ID or unknown, so it falls through to the real
                // keystore2.
                return TransactionResult.ContinueAndSkipPost
            }
            val keyId = KeyIdentifier(callingUid, descriptor.alias)

            val response = KeyMintSecurityLevelInterceptor.getGeneratedKeyResponse(keyId)
            if (response == null) {
                if (deletedSoftwareKeys.remove(keyId)) {
                    SystemLogger.info(
                        "[TX_ID: $txId] Returning KEY_NOT_FOUND for deleted key ${descriptor.alias}"
                    )
                    return InterceptorUtils.createErrorReply(RESPONSE_KEY_NOT_FOUND)
                }
                // Owned keys were served above; for a skipped UID a non-owned key must still skip
                // post-processing so we never patch an un-targeted app's real key.
                return if (ConfigurationManager.shouldSkipUid(callingUid))
                    TransactionResult.ContinueAndSkipPost
                else TransactionResult.Continue
            }

            if (KeyMintSecurityLevelInterceptor.isAttestationKey(keyId))
                SystemLogger.info("${descriptor.alias} was an attestation key")

            SystemLogger.info("[TX_ID: $txId] Found generated response for ${descriptor.alias}:")
            response.metadata?.authorizations?.forEach {
                KeyMintParameterLogger.logParameter(callingUid, txId, it.keyParameter)
            }
            logServedChain(callingUid, txId, descriptor.alias, response)
            return InterceptorUtils.createTypedObjectReply(response)
        } else if (code == GRANT_TRANSACTION) {
            logTransaction(txId, transactionNames[code] ?: "grant", callingUid, callingPid)
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val key =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.ContinueAndSkipPost
            val granteeUid = data.readInt()
            val accessVector = data.readInt()
            // Synthetic (generatedKeys) AND patch-mode (teeResponses) keys are ours; both must
            // grant
            // coherently so the Domain.GRANT readback returns the same chain the owner read
            // returns.
            // Real hardware keys fall through to the real keystore2, which applies the same SELinux
            // gate the platform would.
            val ownerKeyId =
                resolveOwnerKeyId(key, callingUid)?.takeIf {
                    KeyMintSecurityLevelInterceptor.ownsKeyResponse(it)
                } ?: return TransactionResult.ContinueAndSkipPost
            // Version-gated to mirror the real TEE 1:1. Pre-Android-16, grant was a hidden API and
            // SELinux denied untrusted_app, so keystore2 returns PERMISSION_DENIED. Android 16
            // (API 36) exposes KeyStoreManager.grantKeyAccess(), so an app grants its own key:
            // issue a coherent, caller-bound, access-vector-carrying grant whose Domain.GRANT read
            // returns the owner's chain.
            if (Build.VERSION.SDK_INT < GRANT_PUBLIC_API_SDK) {
                return InterceptorUtils.createErrorReply(RESPONSE_PERMISSION_DENIED)
            }
            val grantId =
                KeyMintSecurityLevelInterceptor.issueGrant(ownerKeyId, granteeUid, accessVector)
            val reply =
                KeyDescriptor().apply {
                    domain = Domain.GRANT
                    nspace = grantId
                    alias = null
                    blob = null
                }
            return InterceptorUtils.createTypedObjectReply(reply)
        } else if (code == UNGRANT_TRANSACTION) {
            logTransaction(txId, transactionNames[code] ?: "ungrant", callingUid, callingPid)
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val key =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.ContinueAndSkipPost
            val granteeUid = data.readInt()
            val ownerKeyId =
                resolveOwnerKeyId(key, callingUid)?.takeIf {
                    KeyMintSecurityLevelInterceptor.ownsKeyResponse(it)
                } ?: return TransactionResult.ContinueAndSkipPost
            // Same version gate as grant(): denied pre-36, revoke the virtualized grant on 36+.
            if (Build.VERSION.SDK_INT < GRANT_PUBLIC_API_SDK) {
                return InterceptorUtils.createErrorReply(RESPONSE_PERMISSION_DENIED)
            }
            KeyMintSecurityLevelInterceptor.revokeGrant(ownerKeyId, granteeUid)
            return InterceptorUtils.createSuccessReply(writeResultCode = false)
        } else {
            logTransaction(
                txId,
                transactionNames[code] ?: "unknown code=$code",
                callingUid,
                callingPid,
                true,
            )
        }

        // Let most calls go through to the real service.
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
        if (target != keystoreService || reply == null) return TransactionResult.SkipTransaction
        if (InterceptorUtils.hasException(reply)) {
            val normalized = InterceptorUtils.normalizeServiceSpecificReply(reply)
            return if (normalized != null) TransactionResult.OverrideReply(normalized)
            else TransactionResult.SkipTransaction
        }

        if (code == GET_NUMBER_OF_ENTRIES_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)
            return runCatching {
                    val hardwareCount = reply.readInt()
                    val softwareCount =
                        KeyMintSecurityLevelInterceptor.generatedKeys.keys.count {
                            it.uid == callingUid
                        }
                    val totalCount = hardwareCount + softwareCount
                    val parcel =
                        Parcel.obtain().apply {
                            writeNoException()
                            writeInt(totalCount)
                        }
                    TransactionResult.OverrideReply(parcel)
                }
                .getOrElse {
                    SystemLogger.error("[TX_ID: $txId] Failed to modify getNumberOfEntries.", it)
                    TransactionResult.SkipTransaction
                }
        } else if (code == LIST_ENTRIES_TRANSACTION || code == LIST_ENTRIES_BATCHED_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            return runCatching {
                    val updatedKeyDescriptors =
                        ListEntriesHandler.injectGeneratedKeys(txId, callingUid, reply)
                    InterceptorUtils.createTypedArrayReply(updatedKeyDescriptors)
                }
                .getOrElse {
                    SystemLogger.error(
                        "[TX_ID: $txId] Failed to update the result of ${transactionNames[code]!!}.",
                        it,
                    )
                    TransactionResult.SkipTransaction
                }
        } else if (code == GET_KEY_ENTRY_TRANSACTION) {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val keyDescriptor =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.SkipTransaction

            logTransaction(
                txId,
                "post-${transactionNames[code]!!} ${keyDescriptor.alias}",
                callingUid,
                callingPid,
            )

            if (!ConfigurationManager.shouldPatch(callingUid))
                return TransactionResult.SkipTransaction

            runCatching {
                    val response = reply.readTypedObject(KeyEntryResponse.CREATOR)!!
                    val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)

                    if (userUpdatedKeys.remove(keyId)) {
                        SystemLogger.trace {
                            "[TRACE-$txId] getKeyEntry $keyId: userUpdated=true, skipping patch"
                        }
                        SystemLogger.debug(
                            "[TX_ID: $txId] Skipping cert patch for user-updated key $keyId."
                        )
                        return TransactionResult.SkipTransaction
                    }

                    val authorizations = response.metadata.authorizations
                    val parsedParameters =
                        KeyMintAttestation(
                            authorizations?.map { it.keyParameter }?.toTypedArray() ?: emptyArray()
                        )

                    SystemLogger.trace {
                        "[TRACE-$txId] getKeyEntry $keyId: isImport=${parsedParameters.isImportKey()} origin=${parsedParameters.origin} inImportedKeys=${KeyMintSecurityLevelInterceptor.importedKeys.contains(keyId)} hasPatchedChain=${KeyMintSecurityLevelInterceptor.getPatchedChain(keyId) != null} isAttestKey=${parsedParameters.isAttestKey()}"
                    }

                    if (parsedParameters.isImportKey()) {
                        val retainedChain = KeyMintSecurityLevelInterceptor.getPatchedChain(keyId)
                        if (retainedChain == null) {
                            SystemLogger.trace {
                                "[TRACE-$txId] getKeyEntry $keyId: imported, no retained chain, skip"
                            }
                            SystemLogger.info(
                                "[TX_ID: $txId] Skip patching for imported key (no prior attestation)."
                            )
                            return TransactionResult.SkipTransaction
                        }
                        SystemLogger.trace {
                            "[TRACE-$txId] getKeyEntry $keyId: imported, SERVING RETAINED CHAIN (detection vector!)"
                        }
                        SystemLogger.info(
                            "[TX_ID: $txId] Imported key overwrote attested alias, serving retained chain for $keyId"
                        )
                        CertificateHelper.updateCertificateChain(response.metadata, retainedChain)
                            .getOrThrow()
                        response.metadata.authorizations =
                            InterceptorUtils.patchAuthorizations(
                                response.metadata.authorizations,
                                callingUid,
                            )
                        return InterceptorUtils.createTypedObjectReply(response)
                    }

                    if (KeyMintSecurityLevelInterceptor.importedKeys.contains(keyId)) {
                        SystemLogger.trace {
                            "[TRACE-$txId] getKeyEntry $keyId: in importedKeys set, skip"
                        }
                        SystemLogger.debug(
                            "[TX_ID: $txId] Skipping attest-key override for imported key $keyId"
                        )
                        return TransactionResult.SkipTransaction
                    }

                    if (parsedParameters.isAttestKey()) {
                        SystemLogger.warning(
                            "[TX_ID: $txId] Found hardware attest key ${keyId.alias} in the reply."
                        )
                        val keyData =
                            CertificateGenerator.generateAttestedKeyPair(
                                callingUid,
                                keyId.alias,
                                null,
                                parsedParameters,
                                response.metadata.keySecurityLevel,
                            ) ?: throw Exception("Failed to create overriding attest key pair.")

                        CertificateHelper.updateCertificateChain(
                                response.metadata,
                                keyData.second.toTypedArray(),
                            )
                            .getOrThrow()
                        response.metadata.authorizations =
                            InterceptorUtils.patchAuthorizations(
                                response.metadata.authorizations,
                                callingUid,
                            )

                        val newNspace = SecureRandom().nextLong()
                        response.metadata.key?.let { it.nspace = newNspace }
                        KeyMintSecurityLevelInterceptor.generatedKeys[keyId] =
                            KeyMintSecurityLevelInterceptor.GeneratedKeyInfo(
                                keyData.first,
                                null,
                                newNspace,
                                response,
                                parsedParameters,
                            )
                        KeyMintSecurityLevelInterceptor.attestationKeys.add(keyId)

                        // Snapshot metadata bytes for the same reason as the
                        // primary doSoftwareKeyGen path — loss-less restore
                        // after reboot.
                        val metadataBytesForPersist =
                            response.metadata?.let { md ->
                                runCatching {
                                        val parcel = android.os.Parcel.obtain()
                                        try {
                                            md.writeToParcel(parcel, 0)
                                            parcel.marshall()
                                        } finally {
                                            parcel.recycle()
                                        }
                                    }
                                    .getOrNull()
                            }
                        GeneratedKeyPersistence.save(
                            keyId = keyId,
                            keyPair = keyData.first,
                            secretKey = null,
                            nspace = newNspace,
                            securityLevel = response.metadata.keySecurityLevel,
                            certChain = keyData.second,
                            algorithm = parsedParameters.algorithm,
                            keySize = parsedParameters.keySize,
                            ecCurve = parsedParameters.ecCurve ?: 0,
                            purposes = parsedParameters.purpose,
                            digests = parsedParameters.digest,
                            isAttestationKey = true,
                            metadataBytes = metadataBytesForPersist,
                        )

                        return InterceptorUtils.createTypedObjectReply(response)
                    }

                    val originalChain = CertificateHelper.getCertificateChain(response)

                    if (originalChain == null || originalChain.size < 2) {
                        SystemLogger.info(
                            "[TX_ID: $txId] Skip patching short certificate chain of length ${originalChain?.size}."
                        )
                        return TransactionResult.SkipTransaction
                    }

                    val cachedChain = KeyMintSecurityLevelInterceptor.getPatchedChain(keyId)

                    val finalChain: Array<Certificate>
                    if (cachedChain != null) {
                        SystemLogger.debug(
                            "[TX_ID: $txId] Using cached patched certificate chain for $keyId."
                        )
                        finalChain = cachedChain
                    } else {
                        SystemLogger.info(
                            "[TX_ID: $txId] No cached chain for $keyId. Performing live patch as a fallback."
                        )
                        finalChain =
                            AttestationPatcher.patchCertificateChain(originalChain, callingUid)
                        KeyMintSecurityLevelInterceptor.patchedChains[keyId] = finalChain
                    }

                    CertificateHelper.updateCertificateChain(response.metadata, finalChain)
                        .getOrThrow()
                    response.metadata.authorizations =
                        InterceptorUtils.patchAuthorizations(
                            response.metadata.authorizations,
                            callingUid,
                        )

                    // PATCH decode point: the patched chain actually served back to the app on
                    // getKeyEntry — the ground truth a patch-mode detector reads.
                    AttestationDossier.log(callingUid, txId, "PATCH", finalChain.asList())

                    return InterceptorUtils.createTypedObjectReply(response)
                }
                .onFailure {
                    SystemLogger.error(
                        "[TX_ID: $txId] Failed to modify hardware KeyEntryResponse.",
                        it,
                    )
                    return TransactionResult.SkipTransaction
                }
        }
        return TransactionResult.SkipTransaction
    }

    /**
     * Resolves the owner [KeyIdentifier] a grant/ungrant call targets. APP/alias keys map directly;
     * KEY_ID keys are looked up by nspace (mirrors the deleteKey resolver). Returns null for
     * anything not addressable, so callers fall through to the real keystore2.
     */
    private fun resolveOwnerKeyId(descriptor: KeyDescriptor, callingUid: Int): KeyIdentifier? =
        when {
            descriptor.alias != null -> KeyIdentifier(callingUid, descriptor.alias)
            descriptor.domain == Domain.KEY_ID ->
                KeyMintSecurityLevelInterceptor.findGeneratedKeyByKeyId(
                        callingUid,
                        descriptor.nspace,
                    )
                    ?.let { info ->
                        KeyMintSecurityLevelInterceptor.generatedKeys.entries
                            .firstOrNull {
                                it.value.nspace == info.nspace && it.key.uid == callingUid
                            }
                            ?.key
                    }
            else -> null
        }

    /**
     * Records the certificate chain actually served back to [uid] on a getKeyEntry, keyed by
     * [alias]. The app reassembles its final chain from these served chains (the leaf alias plus
     * the attest-key alias), so logging each one with key sizes and a per-edge verification makes a
     * verification failure in the app's combined chain reproducible from the log, not inferred.
     */
    private fun logServedChain(uid: Int, txId: Long, alias: String, response: KeyEntryResponse?) {
        if (response == null || !SystemLogger.isUidLogged(uid)) return
        val chain = CertificateHelper.getCertificateChain(response)?.asList() ?: return
        SystemLogger.uidLog(uid, txId, "served", "alias=$alias depth=${chain.size}")
        SystemLogger.uidLog(uid, txId, "served-keys", AttestationPatcher.formatChainKeys(chain))
        SystemLogger.uidLog(uid, txId, "served-verify", AttestationPatcher.formatChainVerification(chain))
    }

    private fun handleUpdateSubcomponent(callingUid: Int, data: Parcel): TransactionResult {
        data.enforceInterface(IKeystoreService.DESCRIPTOR)
        val descriptor =
            data.readTypedObject(KeyDescriptor.CREATOR)
                ?: return TransactionResult.ContinueAndSkipPost

        if (descriptor.domain == Domain.GRANT) {
            val grant =
                KeyMintSecurityLevelInterceptor.resolveGrant(descriptor.nspace, callingUid)
            if (grant == null) {
                return if (
                    KeyMintSecurityLevelInterceptor.softwareGrants.containsKey(descriptor.nspace)
                )
                    InterceptorUtils.createErrorReply(RESPONSE_KEY_NOT_FOUND)
                else TransactionResult.ContinueAndSkipPost
            }
            if ((grant.accessVector and KEY_PERMISSION_UPDATE) == 0) {
                return InterceptorUtils.createErrorReply(RESPONSE_PERMISSION_DENIED)
            }

            val generatedKeyInfo =
                KeyMintSecurityLevelInterceptor.generatedKeys[grant.ownerKeyId]
            val response =
                generatedKeyInfo?.response
                    ?: KeyMintSecurityLevelInterceptor.getGeneratedKeyResponse(grant.ownerKeyId)
                    ?: return InterceptorUtils.createErrorReply(RESPONSE_KEY_NOT_FOUND)
            return updateResponseSubcomponent(
                response = response,
                publicCert = data.createByteArray(),
                certificateChain = data.createByteArray(),
                persist = {
                    if (generatedKeyInfo != null) {
                        GeneratedKeyPersistence.rePersistIfNeeded(
                            grant.ownerKeyId.uid,
                            generatedKeyInfo,
                        )
                    }
                },
                label = "grant[${descriptor.nspace}] -> ${grant.ownerKeyId}",
            )
        }

        val generatedKeyInfo =
            when (descriptor.domain) {
                Domain.KEY_ID ->
                    KeyMintSecurityLevelInterceptor.findGeneratedKeyByKeyId(
                        callingUid,
                        descriptor.nspace,
                    )
                Domain.APP ->
                    descriptor.alias?.let {
                        KeyMintSecurityLevelInterceptor.generatedKeys[KeyIdentifier(callingUid, it)]
                    }
                else -> null
            }

        if (generatedKeyInfo == null) {
            // Patch-mode key (cached in teeResponses, not generatedKeys): the real keystore2
            // applies
            // the update, so drop our stale cached chain. Otherwise getKeyEntry replays the
            // pre-update generated attestation (duck STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE).
            when (descriptor.domain) {
                Domain.KEY_ID ->
                    KeyMintSecurityLevelInterceptor.evictTeeResponseByKeyId(
                        callingUid,
                        descriptor.nspace,
                    )
                Domain.APP ->
                    descriptor.alias?.let {
                        KeyMintSecurityLevelInterceptor.evictTeeResponse(
                            KeyIdentifier(callingUid, it)
                        )
                    }
                else -> {}
            }
            descriptor.alias?.let {
                val kid = KeyIdentifier(callingUid, it)
                userUpdatedKeys.add(kid)
                SystemLogger.trace {
                    "[TRACE] updateSubcomponent $kid: not generated key, added to userUpdatedKeys"
                }
            }
            return TransactionResult.ContinueAndSkipPost
        }

        return updateResponseSubcomponent(
            response = generatedKeyInfo.response,
            publicCert = data.createByteArray(),
            certificateChain = data.createByteArray(),
            persist = {
                GeneratedKeyPersistence.rePersistIfNeeded(callingUid, generatedKeyInfo)
            },
            label = "key[${generatedKeyInfo.nspace}]",
        )
    }

    private fun updateResponseSubcomponent(
        response: KeyEntryResponse,
        publicCert: ByteArray?,
        certificateChain: ByteArray?,
        persist: () -> Unit,
        label: String,
    ): TransactionResult {
        SystemLogger.info("Updating sub-component with $label")
        val metadata = response.metadata
        metadata.certificate = publicCert
        metadata.certificateChain = certificateChain

        persist()

        SystemLogger.verbose(
            "Key updated with sizes: [publicCert, certificateChain] = [${publicCert?.size}, ${certificateChain?.size}]"
        )

        return InterceptorUtils.createSuccessReply(writeResultCode = false)
    }
}
