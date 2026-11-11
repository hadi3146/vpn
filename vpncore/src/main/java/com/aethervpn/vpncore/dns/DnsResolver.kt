package com.aethervpn.vpncore.dns

data class DnsResolver(
    val id: String,
    val name: String,
    val host: String,
    val ip: String,
    val port: Int = 853,
    val description: String = ""
) {
    companion object {
        val CLOUDFLARE = DnsResolver(
            id = "cloudflare",
            name = "Cloudflare",
            host = "one.one.one.one",
            ip = "1.1.1.1",
            description = "Fast, privacy-focused (1.1.1.1)"
        )
        val GOOGLE = DnsResolver(
            id = "google",
            name = "Google Public DNS",
            host = "dns.google",
            ip = "8.8.8.8",
            description = "Reliable, global (8.8.8.8)"
        )
        val QUAD9 = DnsResolver(
            id = "quad9",
            name = "Quad9",
            host = "dns.quad9.net",
            ip = "9.9.9.9",
            description = "Malware & phishing blocking (9.9.9.9)"
        )
        val ADGUARD = DnsResolver(
            id = "adguard",
            name = "AdGuard DNS",
            host = "dns.adguard-dns.com",
            ip = "94.140.14.14",
            description = "Ad and tracker blocking"
        )
        val OPENDNS = DnsResolver(
            id = "opendns",
            name = "OpenDNS",
            host = "dns.opendns.com",
            ip = "208.67.222.222",
            description = "Cisco OpenDNS security"
        )
        val CLEANBROWSING = DnsResolver(
            id = "cleanbrowsing",
            name = "CleanBrowsing",
            host = "security-filter-dns.cleanbrowsing.org",
            ip = "185.228.168.9",
            description = "Security & malware filter"
        )
        val YANDEX = DnsResolver(
            id = "yandex",
            name = "Yandex DNS",
            host = "common.dot.dns.yandex.net",
            ip = "77.88.8.8",
            description = "Standard Yandex resolver"
        )

        val ALL_PRESETS = listOf(
            CLOUDFLARE,
            GOOGLE,
            QUAD9,
            ADGUARD,
            OPENDNS,
            CLEANBROWSING,
            YANDEX
        )

        fun findById(id: String): DnsResolver {
            return ALL_PRESETS.firstOrNull { it.id.equals(id, ignoreCase = true) } ?: CLOUDFLARE
        }
    }
}

