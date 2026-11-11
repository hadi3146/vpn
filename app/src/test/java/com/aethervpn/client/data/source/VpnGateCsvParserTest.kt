package com.aethervpn.client.data.source

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class VpnGateCsvParserTest {

    @Test
    fun testParseCsvRowWithQuotes() {
        val row = "vg123.opengw.net,1.2.3.4,1000,50,1000000,\"United States, NY\",US,10,100,50,500,2w,\"Operator, Team\",\"Message, with comma\",base64config"
        val parsed = VpnGateCsvParser.parseCsvRow(row)

        assertEquals("vg123.opengw.net", parsed[0])
        assertEquals("1.2.3.4", parsed[1])
        assertEquals("United States, NY", parsed[5])
        assertEquals("US", parsed[6])
        assertEquals("Operator, Team", parsed[12])
        assertEquals("Message, with comma", parsed[13])
    }

    @Test
    fun testParseFullCsv() {
        val csv = """
            *vpn_servers
            #HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64
            public-vpn-1.opengw.net,219.100.37.1,99999,12,50000000,Japan,JP,100,100000,5000,1000000,2w,Volunteer,Hello,
            public-vpn-2.opengw.net,103.1.2.3,88888,25,30000000,United States,US,50,50000,2000,500000,2w,Volunteer,World,
            *
        """.trimIndent()

        val servers = VpnGateCsvParser.parse(ByteArrayInputStream(csv.toByteArray(Charsets.UTF_8)))
        assertEquals(2, servers.size)

        assertEquals("public-vpn-1.opengw.net", servers[0].hostName)
        assertEquals("219.100.37.1", servers[0].ip)
        assertEquals(99999L, servers[0].score)
        assertEquals(12, servers[0].ping)
        assertEquals("Japan", servers[0].countryLong)
        assertEquals("JP", servers[0].countryShort)
        assertTrue(servers[0].sstpSupported)

        assertEquals("public-vpn-2.opengw.net", servers[1].hostName)
        assertEquals("United States", servers[1].countryLong)
    }
}

