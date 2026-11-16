package com.aethervpn.client.data.routing

import com.aethervpn.vpncore.tun.Ipv4RouteCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.net.InetAddress

class IranRoutingRulesTest {

    @Test
    fun isIranDomainMatchesIrAndDomesticHostsWithoutFalsePositives() {
        assertTrue(IranRoutingRules.isIranDomain("shaparak.ir"))
        assertTrue(IranRoutingRules.isIranDomain("portal.bmi.ir."))
        assertTrue(IranRoutingRules.isIranDomain("api.digikala.com"))
        assertTrue(IranRoutingRules.isIranDomain("www.aparat.com"))
        assertTrue(IranRoutingRules.isIranDomain("eitaa.com"))

        // Foreign / tricky suffix lookalikes must stay in VPN tunnel
        assertFalse(IranRoutingRules.isIranDomain("instagram.com"))
        assertFalse(IranRoutingRules.isIranDomain("telegram.org"))
        assertFalse(IranRoutingRules.isIranDomain("nir.com"))
        assertFalse(IranRoutingRules.isIranDomain("ir.google.com"))
        assertFalse(IranRoutingRules.isIranDomain("myaparat.com"))
        assertFalse(IranRoutingRules.isIranDomain(""))
        assertFalse(IranRoutingRules.isIranDomain(null))
    }

    @Test
    fun bundledIranCidrAssetCoversMajorIranServicesAndExcludesForeign() {
        val assetFile = listOf(
            File("src/main/assets/iran_ipv4.cidr"),
            File("app/src/main/assets/iran_ipv4.cidr")
        ).first { it.exists() }

        val parsed = assetFile.inputStream().use { IranRoutingRules.parseCidrStream(it) }
        assertTrue("Expected > 1000 coalesced Iran CIDRs, got ${parsed.size}", parsed.size > 1000)

        // Known live Iranian endpoints verified in this session
        val iranIps = listOf(
            "185.188.107.12", // digikala.com
            "185.147.179.11", // aparat.com
            "185.167.73.34",  // shaparak.ir
            "185.143.234.133",// bmi.ir
            "2.189.58.6",     // eitaa.com
            "5.106.8.151"     // rubika.ir
        )
        for (ip in iranIps) {
            assertTrue("Expected $ip matched by iran_ipv4.cidr", Ipv4RouteCalculator.containsIp(parsed, InetAddress.getByName(ip)))
        }

        // Foreign & VPN services must NOT match Iran CIDRs
        val foreignIps = listOf(
            "1.1.1.1",
            "8.8.8.8",
            "149.154.167.91", // Telegram DC2
            "157.240.1.174",  // Instagram/Meta
            "219.100.37.87"   // VPN Gate Japan
        )
        for (ip in foreignIps) {
            assertFalse("Expected $ip NOT matched by iran_ipv4.cidr", Ipv4RouteCalculator.containsIp(parsed, InetAddress.getByName(ip)))
        }
    }

    @Test
    fun parseCustomRulesHandlesDomainsWildcardsSingleIpsAndCidrs() {
        val raw = """
            # Work & local bypass rules
            *.mycompany.com, intranet.local; 5.6.7.8
            172.20.0.0/16 # office subnet
            invalid_token
        """.trimIndent()

        val rules = IranRoutingRules.parseCustomRules(raw)
        assertTrue("mycompany.com" in rules.domains)
        assertTrue("intranet.local" in rules.domains)
        assertTrue(rules.cidrs.any { it.hostAddress == "5.6.7.8" && it.prefixLen == 32 })
        assertTrue(rules.cidrs.any { it.hostAddress == "172.20.0.0" && it.prefixLen == 16 })

        assertTrue(IranRoutingRules.isIranDomain("api.mycompany.com", rules.domains, includeBuiltinIran = false))
        assertTrue(IranRoutingRules.isIranDomain("snapp.taxi"))
        assertTrue(IranRoutingRules.isIranDomain("pay.zarinpal.com"))
        assertFalse(IranRoutingRules.isIranDomain("instagram.com", rules.domains, includeBuiltinIran = true))
    }

    @Test
    fun parseRemoteCidrResponseHandlesRipeJsonAndRejectsPoisonedTables() {
        val assetFile = listOf(
            File("src/main/assets/iran_ipv4.cidr"),
            File("app/src/main/assets/iran_ipv4.cidr")
        ).first { it.exists() }
        val realCidrs = assetFile.inputStream().use { IranRoutingRules.parseCidrStream(it) }
        assertTrue(IranRoutingRules.validateIranCidrUpdate(realCidrs))

        val sampleJson = """
            {"data":{"resources":{"ipv4":["185.188.107.0/24","185.147.179.0/24"]}}}
        """.trimIndent()
        val parsedJson = IranRoutingRules.parseRemoteCidrResponse(sampleJson)
        assertEquals(2, parsedJson.size)
        // Too small (<500) must be rejected
        assertFalse(IranRoutingRules.validateIranCidrUpdate(parsedJson))

        // Table swallowing 0.0.0.0/1 or foreign IPs must be rejected
        val poisoned = realCidrs + listOfNotNull(com.aethervpn.vpncore.tun.Ipv4Cidr.parse("149.154.167.0/24"))
        assertFalse(IranRoutingRules.validateIranCidrUpdate(poisoned))
    }
}

