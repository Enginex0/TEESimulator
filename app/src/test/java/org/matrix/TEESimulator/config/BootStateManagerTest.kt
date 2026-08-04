package org.matrix.TEESimulator.config

import org.junit.Assert.assertEquals
import org.junit.Test

class BootStateManagerTest {
    @Test
    fun `covers Xiaomi secure boot aliases`() {
        assertEquals("1", BootStateManager.targetOverrides["ro.boot.secureboot"])
        assertEquals("1", BootStateManager.targetOverrides["ro.secureboot.devicelock"])
        assertEquals("locked", BootStateManager.targetOverrides["ro.secureboot.lockstate"])
    }
}
