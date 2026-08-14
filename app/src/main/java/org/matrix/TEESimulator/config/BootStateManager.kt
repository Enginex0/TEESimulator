package org.matrix.TEESimulator.config

import android.os.SystemProperties
import java.io.File
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.util.AndroidDeviceUtils

object BootStateManager {
    private const val CONFIG_PATH = "/data/adb/tricky_store"
    private const val BOOT_PROPS_MODE_FILE = "boot_props_mode"

    private enum class BootPropsMode {
        AUTO,
        FORCE,
        DISABLE,
    }

    private val targets =
        linkedMapOf(
            "ro.boot.verifiedbootstate" to "green",
            "ro.boot.flash.locked" to "1",
            "ro.boot.veritymode" to "enforcing",
            "ro.boot.vbmeta.device_state" to "locked",
        )

    private val fillIfAbsent =
        linkedMapOf(
            "ro.boot.vbmeta.invalidate_on_error" to "yes",
            "ro.boot.vbmeta.avb_version" to "1.2",
            "ro.boot.vbmeta.hash_alg" to "sha256",
            "ro.boot.vbmeta.size" to "11904",
        )

    fun apply() {
        val mode = readBootPropsMode()
        when (mode) {
            BootPropsMode.DISABLE -> {
                SystemLogger.info("BootStateManager: disabled by $BOOT_PROPS_MODE_FILE")
                return
            }
            BootPropsMode.AUTO -> {
                if (isOplusFamilyDevice()) {
                    SystemLogger.warning(
                        "BootStateManager: skipping boot-state prop spoofing on Oplus-family device in auto mode"
                    )
                    return
                }
            }
            BootPropsMode.FORCE -> {
                SystemLogger.info("BootStateManager: force-enabled by $BOOT_PROPS_MODE_FILE")
            }
        }

        for ((name, target) in targets) {
            val current = SystemProperties.get(name, "")
            if (current.isEmpty()) {
                SystemLogger.debug("BootStateManager: $name absent on this device, skip")
                continue
            }
            if (current == target) {
                SystemLogger.debug("BootStateManager: $name already $target, skip")
                continue
            }
            SystemLogger.info("BootStateManager: setting $name=$target (was: '$current')")
            AndroidDeviceUtils.setProperty(name, target)
        }
        for ((name, value) in fillIfAbsent) {
            val current = SystemProperties.get(name, "")
            if (current.isNotEmpty()) {
                SystemLogger.debug("BootStateManager: $name already '$current', skip")
                continue
            }
            SystemLogger.info("BootStateManager: filling absent $name=$value")
            AndroidDeviceUtils.setProperty(name, value)
        }
    }

    fun shouldSpoofBootProps(): Boolean =
        when (readBootPropsMode()) {
            BootPropsMode.DISABLE -> false
            BootPropsMode.AUTO -> !isOplusFamilyDevice()
            BootPropsMode.FORCE -> true
        }

    private fun readBootPropsMode(): BootPropsMode {
        val file = File(CONFIG_PATH, BOOT_PROPS_MODE_FILE)
        if (!file.exists()) return BootPropsMode.AUTO

        val raw =
            runCatching { file.readText().trim().lowercase() }
                .getOrElse {
                    SystemLogger.warning("BootStateManager: failed to read ${file.absolutePath}", it)
                    return BootPropsMode.AUTO
                }

        return when (raw) {
            "1", "true", "on", "enable", "enabled", "force" -> BootPropsMode.FORCE
            "0", "false", "off", "disable", "disabled", "none" -> BootPropsMode.DISABLE
            else -> BootPropsMode.AUTO
        }
    }

    private fun isOplusFamilyDevice(): Boolean {
        val props =
            listOf(
                "ro.product.manufacturer",
                "ro.product.brand",
                "ro.product.vendor.manufacturer",
                "ro.product.vendor.brand",
                "ro.product.odm.manufacturer",
                "ro.product.odm.brand",
                "ro.boot.hardware.sku",
                "ro.boot.project_name",
            )

        val joined =
            props.joinToString(separator = " ") { name ->
                SystemProperties.get(name, "")
            }.lowercase()

        return listOf("oneplus", "oplus", "oppo", "realme").any { joined.contains(it) }
    }
}
