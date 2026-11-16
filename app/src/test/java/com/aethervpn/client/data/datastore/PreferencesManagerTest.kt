package com.aethervpn.client.data.datastore

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PreferencesManagerTest {

    @Test
    fun bypassProfileCodecRoundTripsAndSanitizesEntries() {
        val original = mapOf(
            "cellular" to "TCP_FRAGMENTATION",
            "wifi" to "DIRECT_IP_NO_SNI",
            "bad key!" to "DROP_ME"
        )
        val encoded = PreferencesManager.encodeBypassProfiles(original)
        assertEquals("CELLULAR=TCP_FRAGMENTATION;WIFI=DIRECT_IP_NO_SNI", encoded)

        val decoded = PreferencesManager.parseBypassProfiles("CELLULAR=TCP_FRAGMENTATION;;WIFI=DIRECT_IP_NO_SNI;invalid")
        assertEquals(2, decoded.size)
        assertEquals("TCP_FRAGMENTATION", decoded["CELLULAR"])
        assertEquals("DIRECT_IP_NO_SNI", decoded["WIFI"])
        assertTrue(PreferencesManager.parseBypassProfiles("").isEmpty())
    }
}

