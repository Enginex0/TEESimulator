package org.matrix.TEESimulator.util

import android.os.Build
import android.os.SystemProperties
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.time.LocalDate
import java.util.concurrent.ThreadLocalRandom
import javax.xml.parsers.DocumentBuilderFactory
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.matrix.TEESimulator.attestation.DeviceAttestationService
import org.matrix.TEESimulator.config.BootStateManager
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.logging.SystemLogger
import org.w3c.dom.Element

/**
 * Provides utility functions for accessing Android system properties and device-specific
 * information that is critical for generating valid attestations.
 */
object AndroidDeviceUtils {

    /**
     * Internal constant to signify that a patch level should not be included in the attestation.
     */
    internal const val DO_NOT_REPORT = -1

    // --- Boot Key and Verified Boot Hash ---

    /**
     * Lazily initializes and retrieves the verified boot key digest. The value is sourced in the
     * following order:
     * 1. From the `ro.boot.vbmeta.public_key_digest` system property.
     * 2. From a cached TEE attestation record.
     * 3. As a randomly generated 32-byte value (fallback).
     */
    val bootKey: ByteArray by lazy {
        initializeBootProperty(
            propertyName = "ro.boot.vbmeta.public_key_digest",
            attestationValueProvider = {
                DeviceAttestationService.CachedAttestationData?.verifiedBootKey
            },
            expectedSize = 32,
            recordSource = { bootKeySource = it },
        )
    }

    /**
     * Lazily initializes and retrieves the verified boot hash (vbmeta digest). The value is sourced
     * in the following order:
     * 1. From the `ro.boot.vbmeta.digest` system property.
     * 2. From a cached TEE attestation record.
     * 3. As a randomly generated 32-byte value (fallback).
     */
    val bootHash: ByteArray by lazy {
        initializeBootProperty(
            propertyName = "ro.boot.vbmeta.digest",
            attestationValueProvider = {
                DeviceAttestationService.CachedAttestationData?.verifiedBootHash
            },
            expectedSize = 32,
            recordSource = { bootHashSource = it },
        )
    }

    // Records which fallback tier supplied bootKey/bootHash so the diagnostic dossier can flag a
    // random-fallback value — a real verifiedBootKey that resolves to random bytes is a textbook
    // simulated-TEE tell. Populated by initializeBootProperty on first access.
    @Volatile private var bootKeySource: String = "uninitialized"
    @Volatile private var bootHashSource: String = "uninitialized"

    /**
     * Public function to explicitly trigger the initialization of the boot key and hash. Accessing
     * these properties here ensures they are set up before they might be needed elsewhere.
     */
    fun setupBootKeyAndHash() {
        SystemLogger.debug("Triggering initialization of boot key and hash...")
        // Accessing the properties will trigger their `lazy` initialization logic.
        bootKey
        bootHash
        SystemLogger.debug("Boot key and hash initialization complete.")
    }

    /**
     * Generic initializer for boot properties like the key and hash. It attempts to read from a
     * system property first, then from a TEE attestation, and finally falls back to a random value
     * if neither is available.
     *
     * @param propertyName The name of the system property (e.g., "ro.boot.vbmeta.digest").
     * @param attestationValueProvider A function that supplies the value from a cached attestation.
     * @param expectedSize The expected length of the byte array (e.g., 32 for a SHA-256 digest).
     * @return The resulting byte array for the property.
     */
    private fun initializeBootProperty(
        propertyName: String,
        attestationValueProvider: () -> ByteArray?,
        expectedSize: Int,
        recordSource: (String) -> Unit,
    ): ByteArray {
        getProperty(propertyName, expectedSize)?.let {
            SystemLogger.debug("Using $propertyName from system property: ${it.toHex()}")
            recordSource("system-prop")
            persistToFile(propertyName, it)
            return it
        }

        try {
            attestationValueProvider()?.let {
                SystemLogger.debug("Using $propertyName from TEE attestation: ${it.toHex()}")
                recordSource("tee-attestation")
                setBootProperty(propertyName, it)
                persistToFile(propertyName, it)
                return it
            }
        } catch (e: Exception) {
            SystemLogger.error("Failed to get $propertyName from attestation.", e)
        }

        readFromFile(propertyName, expectedSize)?.let {
            SystemLogger.debug("Using $propertyName from persistent file: ${it.toHex()}")
            recordSource("persistent-file")
            setBootProperty(propertyName, it)
            return it
        }

        return generateRandomBytes(expectedSize).also {
            SystemLogger.debug("Using randomly generated $propertyName: ${it.toHex()}")
            recordSource("random-fallback")
            setBootProperty(propertyName, it)
            persistToFile(propertyName, it)
        }
    }

    /**
     * Retrieves a system property and validates its format.
     *
     * @param name The name of the system property.
     * @param expectedSize The expected byte length of the property (e.g., 32 for a 64-char hex
     *   string).
     * @return The property value as a ByteArray, or null if not found or invalid.
     */
    @OptIn(ExperimentalStdlibApi::class)
    private fun getProperty(name: String, expectedSize: Int): ByteArray? {
        val value = SystemProperties.get(name, null)
        if (value.isNullOrBlank()) {
            return null
        }
        // A valid digest is (2 * size) hex characters.
        return if (value.length == expectedSize * 2) value.hexToByteArray() else null
    }

    /**
     * Sets a system property using the `resetprop` command.
     *
     * @param name The name of the property to set.
     * @param bytes The value to set, which will be converted to a hex string.
     */
    private fun setProperty(name: String, bytes: ByteArray) {
        val hex = bytes.toHex()
        try {
            SystemLogger.debug("Setting system property '$name' to: $hex")
            val command = if (java.io.File("/data/adb/tricky_store/resetprop-rs").exists()) {
                arrayOf("/data/adb/tricky_store/resetprop-rs", "--stealth", name, hex)
            } else {
                arrayOf("resetprop", name, hex)
            }
            val process = Runtime.getRuntime().exec(command)
            val exitCode = process.waitFor()

            if (exitCode != 0) {
                val errorOutput = process.errorStream.bufferedReader().readText()
                SystemLogger.error(
                    "resetprop for '$name' failed with exit code $exitCode: $errorOutput"
                )
            }
        } catch (e: Exception) {
            SystemLogger.error("Failed to set '$name' property via resetprop.", e)
        }
    }

    private fun setBootProperty(name: String, bytes: ByteArray) {
        if (!BootStateManager.shouldSpoofBootProps()) {
            SystemLogger.info("Skipping system property '$name' because boot prop spoofing is disabled")
            return
        }
        setProperty(name, bytes)
    }

    internal fun setProperty(name: String, value: String) {
        try {
            SystemLogger.debug("Setting system property '$name' to: $value")
            val command = if (java.io.File("/data/adb/tricky_store/resetprop-rs").exists()) {
                arrayOf("/data/adb/tricky_store/resetprop-rs", "--stealth", name, value)
            } else {
                arrayOf("resetprop", name, value)
            }
            val process = Runtime.getRuntime().exec(command)
            val exitCode = process.waitFor()

            if (exitCode != 0) {
                val errorOutput = process.errorStream.bufferedReader().readText()
                SystemLogger.error(
                    "resetprop for '$name' failed with exit code $exitCode: $errorOutput"
                )
            }
        } catch (e: Exception) {
            SystemLogger.error("Failed to set '$name' property via resetprop.", e)
        }
    }

    private fun generateRandomBytes(size: Int): ByteArray =
        ByteArray(size).also { ThreadLocalRandom.current().nextBytes(it) }

    private val PERSIST_DIR = File("/data/adb/tricky_store")

    private fun fileForProperty(propertyName: String): File =
        when (propertyName) {
            "ro.boot.vbmeta.digest" -> File(PERSIST_DIR, "boot_hash.bin")
            "ro.boot.vbmeta.public_key_digest" -> File(PERSIST_DIR, "boot_key.bin")
            else -> File(PERSIST_DIR, "${propertyName.replace('.', '_')}.bin")
        }

    private fun persistToFile(propertyName: String, bytes: ByteArray) {
        try {
            fileForProperty(propertyName).writeBytes(bytes)
        } catch (e: Exception) {
            SystemLogger.error("Failed to persist $propertyName to file.", e)
        }
    }

    private fun readFromFile(propertyName: String, expectedSize: Int): ByteArray? {
        return try {
            val file = fileForProperty(propertyName)
            if (!file.exists()) return null
            val bytes = file.readBytes()
            if (bytes.size == expectedSize) bytes else null
        } catch (e: Exception) {
            SystemLogger.error("Failed to read $propertyName from file.", e)
            null
        }
    }

    // --- Patch Level Properties ---

    fun getPatchLevel(uid: Int): Int {
        val custom = getCustomPatchLevelFor(uid, "system", isLong = false)
        return custom ?: getRealDevicePatchLevelInt("system", isLong = false)
    }

    fun getVendorPatchLevelLong(uid: Int): Int {
        val custom = getCustomPatchLevelFor(uid, "vendor", isLong = true)
        return custom ?: getRealDevicePatchLevelInt("vendor", isLong = true)
    }

    fun getBootPatchLevelLong(uid: Int): Int {
        val custom = getCustomPatchLevelFor(uid, "boot", isLong = true)
        return custom ?: getRealDevicePatchLevelInt("boot", isLong = true)
    }

    /**
     * Summarises, for a targeted [uid], the device values that feed attestation and where each came
     * from. This is what exposes attested-versus-live mismatches: a random-fallback verifiedBootKey,
     * a patch level overridden away from the live prop, or an OS version pulled from a stale cache.
     */
    fun describeSources(uid: Int): String {
        val customPatchLevel = ConfigurationManager.getPatchLevelForUid(uid) != null
        val osVersionSource =
            if (DeviceAttestationService.CachedAttestationData?.osVersion != null) "cache" else "map"
        return "osVersion=$osVersion(src=$osVersionSource) " +
            "osPatch=${getPatchLevel(uid)} vendorPatch=${getVendorPatchLevelLong(uid)} " +
            "bootPatch=${getBootPatchLevelLong(uid)} customPatchLevel=$customPatchLevel " +
            "bootKey=${bootKey.toHex()}(src=$bootKeySource) " +
            "bootHash=${bootHash.toHex()}(src=$bootHashSource) " +
            "teeCacheData=${DeviceAttestationService.CachedAttestationData != null}"
    }

    /**
     * Retrieves the definitive device patch level integer for a given component. This function
     * encapsulates the entire fallback chain and guarantees a non-null return.
     *
     * Fallback Priority:
     * 1. Cached TEE attestation data.
     * 2. Specific system property (e.g., ro.vendor.build.security_patch).
     * 3. Default system patch level from Build.VERSION.SECURITY_PATCH.
     *
     * @param component The component ("system", "vendor", "boot").
     * @param isLong Whether the final integer should be in YYYYMMDD format.
     * @return The patch level as a guaranteed non-null Integer.
     */
    private fun getRealDevicePatchLevelInt(component: String, isLong: Boolean): Int {
        // Get value from cached TEE attestation data
        DeviceAttestationService.CachedAttestationData?.let { data ->
            val value =
                when (component) {
                    "system" -> data.osPatchLevel
                    "vendor" -> data.vendorPatchLevel
                    "boot" -> data.bootPatchLevel
                    else -> null
                }
            if (value != null) return value
        }

        // We only check the specific vendor property, as the boot one is non-existent.
        if (component == "vendor") {
            val propValue = SystemProperties.get("ro.vendor.build.security_patch", "")
            if (!propValue.isNullOrBlank()) {
                parsePatchLevelValue(propValue, isLong)?.let { parsedValue ->
                    return parsedValue
                }
            }
        }

        return Build.VERSION.SECURITY_PATCH.toPatchLevelInt(isLong)
    }

    /**
     * Retrieves a custom patch level from the configuration if available for a specific UID.
     *
     * @param uid The UID of the calling application.
     * @param component The component to get the patch level for ("system", "vendor", "boot").
     * @param isLong Whether to return the patch level in `YYYYMMDD` or `YYYYMM` format.
     * @return The custom patch level, or null if not configured.
     */
    private fun getCustomPatchLevelFor(uid: Int, component: String, isLong: Boolean): Int? {
        val config = ConfigurationManager.getPatchLevelForUid(uid) ?: return null
        val value =
            when (component) {
                "system" -> config.system ?: config.all
                "vendor" -> config.vendor ?: config.all
                "boot" -> config.boot ?: config.all
                else -> config.all
            } ?: return null

        // First, resolve dynamic keywords and templates into a concrete date string.
        val resolvedValue = resolveDateKeywords(value)

        return when {
            resolvedValue.equals("device_default", ignoreCase = true) -> null
            // Resolve from live system prop — matches what detectors see via getprop,
            // even when PIF has spoofed ro.build.version.security_patch via resetprop
            resolvedValue.equals("prop", ignoreCase = true) ->
                parsePatchLevelValue(
                    SystemProperties.get("ro.build.version.security_patch", ""),
                    isLong,
                )
            resolvedValue.equals("no", ignoreCase = true) -> DO_NOT_REPORT
            else -> parsePatchLevelValue(resolvedValue, isLong)
        }
    }

    /**
     * Resolves special date keywords and templates into a concrete "YYYY-MM-DD" date string.
     *
     * @param value The configuration value string (e.g., "today", "YYYY-MM-01").
     * @return A concrete date string, or the original value if it's not a dynamic date keyword.
     */
    private fun resolveDateKeywords(value: String): String {
        // Handle the "today" keyword.
        if (value.equals("today", ignoreCase = true)) {
            return LocalDate.now().toString() // Returns "YYYY-MM-DD" format
        }

        // Handle date templates like "YYYY-MM-01" or "2025-MM-DD".
        if (
            value.contains("YYYY", ignoreCase = true) ||
                value.contains("MM", ignoreCase = true) ||
                value.contains("DD", ignoreCase = true)
        ) {

            val now = LocalDate.now()
            // Chain replacements for YYYY, MM, and DD placeholders.
            return value
                .replace("YYYY", now.year.toString(), ignoreCase = true)
                .replace("MM", String.format("%02d", now.monthValue), ignoreCase = true)
                .replace("DD", String.format("%02d", now.dayOfMonth), ignoreCase = true)
        }

        // If it's not a dynamic keyword or template, return the original value.
        return value
    }

    /** Parses a patch level string (e.g., "2025-11-01") into an integer format. */
    private fun parsePatchLevelValue(value: String, isLong: Boolean): Int? {
        val normalized = value.replace("-", "")
        return try {
            when (normalized.length) {
                8 -> { // YYYYMMDD
                    val year = normalized.substring(0, 4).toInt()
                    val month = normalized.substring(4, 6).toInt()
                    val day = normalized.substring(6, 8).toInt()
                    if (isLong) year * 10000 + month * 100 + day else year * 100 + month
                }
                6 -> { // YYYYMM
                    val year = normalized.substring(0, 4).toInt()
                    val month = normalized.substring(4, 6).toInt()
                    // Synthesizing day=01 from YYYY-MM disagrees with real device bulletins;
                    // propagate null so callers fall back to a YYYY-MM-DD source.
                    if (isLong) null else year * 100 + month
                }
                else -> null
            }
        } catch (e: NumberFormatException) {
            SystemLogger.warning("Could not parse patch level value: $value", e)
            null
        }
    }

    /** Converts a security patch string (e.g., "2025-11-01") to an integer representation. */
    private fun String.toPatchLevelInt(isLong: Boolean): Int {
        return parsePatchLevelValue(this, isLong) ?: 20240401 // Fallback
    }

    // --- OS and Attestation Version Properties ---

    private val osVersionMap =
        mapOf(
            Build.VERSION_CODES.BAKLAVA to 160000,
            Build.VERSION_CODES.VANILLA_ICE_CREAM to 150000,
            Build.VERSION_CODES.UPSIDE_DOWN_CAKE to 140000,
            Build.VERSION_CODES.TIRAMISU to 130000,
            Build.VERSION_CODES.S_V2 to 120100,
            Build.VERSION_CODES.S to 120000,
            Build.VERSION_CODES.R to 110000,
            Build.VERSION_CODES.Q to 100000,
        )

    val osVersion: Int
        get() =
            DeviceAttestationService.CachedAttestationData?.osVersion
                ?: osVersionMap[Build.VERSION.SDK_INT]
                ?: 160000 // Default to a recent version

    private val attestVersionMap =
        mapOf(
            Build.VERSION_CODES.Q to 4, // Keymaster 4.1
            Build.VERSION_CODES.R to 4, // Keymaster 4.1
            Build.VERSION_CODES.S to 100, // KeyMint 1.0
            Build.VERSION_CODES.S_V2 to 100, // KeyMint 1.0
            Build.VERSION_CODES.TIRAMISU to 200, // KeyMint 2.0
            Build.VERSION_CODES.UPSIDE_DOWN_CAKE to 300, // KeyMint 3.0
            Build.VERSION_CODES.VANILLA_ICE_CREAM to 300, // KeyMint 3.0
            Build.VERSION_CODES.BAKLAVA to 400, // KeyMint 4.0
        )

    /** AOSP-mandated attestation version for the running OS, or null when the SDK is unmapped. */
    internal val aospAttestVersion: Int?
        get() = attestVersionMap[Build.VERSION.SDK_INT]

    /**
     * Retrieves the attestation version for the given security level. A readable KeyMint VINTF
     * declaration wins first, so local probes that compare the attested version against the
     * device's manifest see a coherent pair. Otherwise the legacy chain applies: cached attestation
     * data, then attestVersionMap[SDK_INT], then 400 as last resort.
     *
     * @param securityLevel The security level of the attestation (1 for TEE, 2 for StrongBox).
     * @return The appropriate attestation version number.
     */
    fun getAttestVersion(securityLevel: Int): Int {
        vintfKeyMintVersion?.let { version ->
            SystemLogger.debug(
                "attestVersion=${version.attestationVersion} source=vintf securityLevel=$securityLevel"
            )
            return version.attestationVersion
        }

        val cached = DeviceAttestationService.CachedAttestationData?.attestVersion
        val version =
            cached ?: attestVersionMap[Build.VERSION.SDK_INT] ?: 400 // Default to a recent version
        val source =
            when {
                cached != null -> "cache"
                attestVersionMap.containsKey(Build.VERSION.SDK_INT) -> "map"
                else -> "default"
            }
        SystemLogger.debug("attestVersion=$version source=$source securityLevel=$securityLevel")
        SystemLogger.debug(
            "vintf-version attest=$version keymaster=$version source=$source securityLevel=$securityLevel"
        )
        return version
    }

    /**
     * Retrieves the Keymaster/KeyMint version. A readable KeyMint VINTF declaration is
     * authoritative because recent local detectors compare the attested version directly against
     * the manifest declaration.
     *
     * @param securityLevel The security level, used to determine the correct attestation version.
     * @return The appropriate Keymaster or KeyMint version number.
     */
    fun getKeymasterVersion(securityLevel: Int): Int {
        vintfKeyMintVersion?.let { version ->
            SystemLogger.debug(
                "keymasterVersion=${version.keymasterVersion} source=vintf securityLevel=$securityLevel"
            )
            return version.keymasterVersion
        }
        return getAttestVersion(securityLevel)
    }

    /**
     * KeyMint/Keymaster version pair resolved from a device VINTF manifest. [attestationVersion] is
     * the value written into the attestation record; [keymasterVersion] is the HAL version field.
     * They coincide for AIDL KeyMint and diverge only for legacy HIDL Keymaster.
     */
    private data class VintfKeyMintVersion(
        val attestationVersion: Int,
        val keymasterVersion: Int,
        val sourcePath: String,
    )

    /**
     * KeyMint version derived from the device's VINTF manifests, or null when none is readable.
     * Resolved lazily so the manifest scan happens once, off the attestation hot path.
     */
    private val vintfKeyMintVersion: VintfKeyMintVersion? by lazy {
        readVintfKeyMintVersion().also { version ->
            if (version != null) {
                SystemLogger.info(
                    "Using KeyMint version from VINTF: attestation=${version.attestationVersion}, " +
                        "keymaster=${version.keymasterVersion}, source=${version.sourcePath}"
                )
            } else {
                SystemLogger.debug(
                    "No usable KeyMint VINTF declaration found; using attestation fallback"
                )
            }
        }
    }

    private fun readVintfKeyMintVersion(): VintfKeyMintVersion? {
        val files = linkedMapOf<String, File>()

        VINTF_MANIFEST_DIRS.forEach { path ->
            val dir = File(path)
            if (!dir.exists() || !dir.isDirectory) return@forEach
            val listed =
                runCatching {
                        dir.listFiles { file ->
                            file.isFile && file.name.endsWith(".xml", ignoreCase = true)
                        }
                    }
                    .getOrElse { throwable ->
                        SystemLogger.debug("Unable to list VINTF dir $path: ${throwable.message}")
                        null
                    }
            listed?.forEach { file -> files[file.absolutePath] = file }
        }

        VINTF_MANIFEST_FILES.forEach { path ->
            val file = File(path)
            if (file.exists() && file.isFile) {
                files[file.absolutePath] = file
            }
        }

        return files.values
            .flatMap { file ->
                runCatching { parseKeyMintVersions(file) }
                    .getOrElse { throwable ->
                        SystemLogger.debug(
                            "Unable to parse KeyMint VINTF ${file.absolutePath}: ${throwable.message}"
                        )
                        emptyList()
                    }
            }
            .maxByOrNull { it.attestationVersion }
    }

    private fun parseKeyMintVersions(file: File): List<VintfKeyMintVersion> {
        val document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file)
        val root = document.documentElement ?: return emptyList()

        return directChildElements(root, "hal").flatMap { hal ->
            val halName = directChildTexts(hal, "name").firstOrNull().orEmpty()
            val versions = directChildTexts(hal, "version")
            val fqnames = directChildTexts(hal, "fqname")
            val interfaces =
                directChildElements(hal, "interface").associate { interfaceElement ->
                    val name = directChildTexts(interfaceElement, "name").firstOrNull().orEmpty()
                    val instances = directChildTexts(interfaceElement, "instance").toSet()
                    name to instances
                }

            when (halName) {
                KEYMINT_HAL_NAME ->
                    if (hasDefaultInstance(fqnames, interfaces, KEYMINT_INTERFACE_NAME)) {
                        versions.mapNotNull { version ->
                            version
                                .toIntOrNull()
                                ?.takeIf { it > 0 }
                                ?.let { aidlVersion ->
                                    val attestationVersion = aidlVersion * 100
                                    VintfKeyMintVersion(
                                        attestationVersion = attestationVersion,
                                        keymasterVersion = attestationVersion,
                                        sourcePath = file.absolutePath,
                                    )
                                }
                        }
                    } else {
                        emptyList()
                    }
                KEYMASTER_HAL_NAME ->
                    if (hasDefaultInstance(fqnames, interfaces, KEYMASTER_INTERFACE_NAME)) {
                        (versions.flatMap(::expandHidlVersions) +
                                fqnames.mapNotNull(::versionFromFqname))
                            .distinct()
                            .mapNotNull { version ->
                                expectedLegacyVersions(version)?.let { expected ->
                                    VintfKeyMintVersion(
                                        attestationVersion = expected.second,
                                        keymasterVersion = expected.first,
                                        sourcePath = file.absolutePath,
                                    )
                                }
                            }
                    } else {
                        emptyList()
                    }
                else -> emptyList()
            }
        }
    }

    private fun directChildElements(parent: Element, tagName: String): List<Element> = buildList {
        val children = parent.childNodes
        for (index in 0 until children.length) {
            val child = children.item(index)
            if (child is Element && child.tagName == tagName) {
                add(child)
            }
        }
    }

    private fun directChildTexts(parent: Element, tagName: String): List<String> =
        directChildElements(parent, tagName)
            .map { it.textContent.trim() }
            .filter { it.isNotEmpty() }

    private fun hasDefaultInstance(
        fqnames: List<String>,
        interfaces: Map<String, Set<String>>,
        interfaceName: String,
    ): Boolean =
        fqnames.any { fqname ->
            fqname.substringAfter("::", fqname).substringBefore("/") == interfaceName &&
                fqname.substringAfter("/", "") == DEFAULT_INSTANCE
        } || interfaces[interfaceName]?.contains(DEFAULT_INSTANCE) == true

    private fun versionFromFqname(fqname: String): String? =
        FQNAME_VERSION_REGEX.find(fqname)?.groupValues?.getOrNull(1)

    private fun expectedLegacyVersions(version: String): Pair<Int, Int>? =
        when (version) {
            "3.0" -> 3 to 2
            "4.0" -> 4 to 3
            "4.1" -> 41 to 4
            else -> null
        }

    private fun expandHidlVersions(version: String): List<String> {
        val range = HIDL_VERSION_RANGE_REGEX.matchEntire(version) ?: return listOf(version)
        val major = range.groupValues[1]
        val firstMinor = range.groupValues[2].toInt()
        val lastMinor = range.groupValues[3].toInt()
        return (firstMinor..lastMinor).map { minor -> "$major.$minor" }
    }

    private val VINTF_MANIFEST_DIRS =
        listOf(
            "/system/etc/vintf/manifest",
            "/system_ext/etc/vintf/manifest",
            "/product/etc/vintf/manifest",
            "/vendor/etc/vintf/manifest",
            "/odm/etc/vintf/manifest",
        )
    private val VINTF_MANIFEST_FILES =
        listOf(
            "/system/etc/vintf/manifest.xml",
            "/system_ext/etc/vintf/manifest.xml",
            "/product/etc/vintf/manifest.xml",
            "/vendor/etc/vintf/manifest.xml",
            "/odm/etc/vintf/manifest.xml",
        )
    private const val KEYMINT_HAL_NAME = "android.hardware.security.keymint"
    private const val KEYMASTER_HAL_NAME = "android.hardware.keymaster"
    private const val KEYMINT_INTERFACE_NAME = "IKeyMintDevice"
    private const val KEYMASTER_INTERFACE_NAME = "IKeymasterDevice"
    private const val DEFAULT_INSTANCE = "default"
    private val FQNAME_VERSION_REGEX = Regex("^@([0-9]+(?:\\.[0-9]+)?)::")
    private val HIDL_VERSION_RANGE_REGEX = Regex("^([0-9]+)\\.([0-9]+)-([0-9]+)$")

    // --- APEX and Module Hash Properties ---

    // Minimal protobuf parser for apex_manifest.pb (field 1: name, field 2: version)
    private class MinimalApexManifestParser(private val data: ByteArray) {
        var pos = 0

        fun parse(): Pair<String, Long>? {
            var name: String? = null
            var version: Long? = null

            while (pos < data.size) {
                val tag = readVarint()
                val fieldNum = tag ushr 3
                val wireType = (tag and 0x07).toInt()

                when (fieldNum) {
                    1L -> {
                        val length = readVarint().toInt()
                        if (pos + length > data.size) return null
                        name = String(data, pos, length, Charsets.UTF_8)
                        pos += length
                    }
                    2L -> {
                        version = readVarint()
                    }
                    else -> skipField(wireType)
                }
            }

            return if (name != null && version != null) {
                name to version
            } else {
                null
            }
        }

        private fun readVarint(): Long {
            var value = 0L
            var shift = 0
            while (pos < data.size) {
                val b = data[pos++].toInt()
                value = value or ((b and 0x7F).toLong() shl shift)
                if ((b and 0x80) == 0) return value
                shift += 7
            }
            return value
        }

        private fun skipField(wireType: Int) {
            when (wireType) {
                0 -> readVarint()
                1 -> pos += 8
                2 -> {
                    val len = readVarint().toInt()
                    pos += len
                }
                5 -> pos += 4
                else -> throw IllegalStateException("Unknown wire type $wireType")
            }
        }
    }

    private val apexInfos: List<Pair<String, Long>> by lazy {
        val results = mutableListOf<Pair<String, Long>>()
        val apexRoot = File("/apex")

        if (!apexRoot.exists() || !apexRoot.isDirectory) {
            return@lazy emptyList()
        }

        apexRoot.listFiles()?.forEach { file ->
            if (!file.isDirectory) return@forEach
            val name = file.name

            if (name.startsWith(".")) return@forEach
            if (name.contains("@")) return@forEach
            if (name == "sharedlibs") return@forEach

            val manifestFile = File(file, "apex_manifest.pb")
            if (manifestFile.exists()) {
                runCatching {
                    val bytes = FileInputStream(manifestFile).use { it.readBytes() }
                    val parser = MinimalApexManifestParser(bytes)
                    parser.parse()?.let { (pkgName, version) -> results.add(pkgName to version) }
                }
            }
        }

        results.distinctBy { it.first }
    }

    val moduleHash: ByteArray by lazy {
        DeviceAttestationService.CachedAttestationData?.moduleHash
            ?.also { SystemLogger.debug { "module-hash source=cache hash=${it.toHex().take(8)}" } }
            ?: supplementaryModuleHash()?.also {
                SystemLogger.debug { "module-hash source=framework-api hash=${it.toHex().take(8)}" }
            }
            ?: runCatching {
                    data class ModuleEntry(val nameEncoded: ByteArray, val fullEncoded: ByteArray)

                    val modules =
                        apexInfos.map { (packageName, versionCode) ->
                            val nameOctet = DEROctetString(packageName.toByteArray(Charsets.UTF_8))
                            val versionInt = ASN1Integer(versionCode)

                            val vec = ASN1EncodableVector()
                            vec.add(nameOctet)
                            vec.add(versionInt)
                            val sequence = DERSequence(vec)

                            // AOSP sorts by encoded name only, not full sequence
                            ModuleEntry(
                                nameEncoded = nameOctet.encoded,
                                fullEncoded = sequence.encoded,
                            )
                        }

                    val sortedModules =
                        modules.sortedWith { m1, m2 ->
                            compareByteArrays(m1.nameEncoded, m2.nameEncoded)
                        }

                    val payloadStream = ByteArrayOutputStream()
                    sortedModules.forEach { payloadStream.write(it.fullEncoded) }
                    val payload = payloadStream.toByteArray()

                    // Wrap in DER SET tag manually — DERSet() re-sorts by full encoding
                    val finalDerSet = encodeAsDerSet(payload)

                    MessageDigest.getInstance("SHA-256").digest(finalDerSet)
                }
                .onSuccess {
                    SystemLogger.debug { "module-hash source=rederive hash=${it.toHex().take(8)}" }
                }
                .onFailure { SystemLogger.debug { "module-hash source=zero hash=00000000" } }
                .getOrElse {
                    SystemLogger.error("Failed to compute module hash.", it)
                    ByteArray(32)
                }
    }

    /**
     * Reads the module-hash DER pre-image straight from the framework's own KeyStoreManager and
     * SHA-256's it, so the value byte-matches what a verifier derives from the same
     * getSupplementaryAttestationInfo call. Returns null on any failure (e.g. the API is
     * unreachable from this process) so the caller falls back to local re-derivation.
     */
    private fun supplementaryModuleHash(): ByteArray? =
        runCatching {
                // @SystemApi surface added in Android 16, absent from the compile SDK, so reflect.
                val managerClass = Class.forName("android.security.keystore.KeyStoreManager")
                val manager = managerClass.getMethod("getInstance").invoke(null)
                // MODULE_HASH is the KeyMint tag (TagType.BYTES | 724 = 0x900002D4), read from the
                // framework so it matches the verifier's argument exactly.
                val moduleHashTag = managerClass.getField("MODULE_HASH").getInt(null)
                val derPreImage =
                    managerClass
                        .getMethod("getSupplementaryAttestationInfo", Int::class.java)
                        .invoke(manager, moduleHashTag) as ByteArray
                MessageDigest.getInstance("SHA-256").digest(derPreImage)
            }
            .getOrNull()

    private fun compareByteArrays(a: ByteArray, b: ByteArray): Int {
        val length = minOf(a.size, b.size)
        for (i in 0 until length) {
            val byteA = a[i].toInt() and 0xFF
            val byteB = b[i].toInt() and 0xFF
            if (byteA != byteB) {
                return byteA - byteB
            }
        }
        return a.size - b.size
    }

    private fun encodeAsDerSet(payload: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(0x31)
        writeDerLength(out, payload.size)
        out.write(payload)
        return out.toByteArray()
    }

    private fun writeDerLength(out: ByteArrayOutputStream, length: Int) {
        if (length < 128) {
            out.write(length)
        } else {
            var size = length
            val bytes = ArrayList<Byte>()
            while (size > 0) {
                bytes.add((size and 0xFF).toByte())
                size = size ushr 8
            }
            out.write(0x80 or bytes.size)
            for (i in bytes.indices.reversed()) {
                out.write(bytes[i].toInt())
            }
        }
    }
}
