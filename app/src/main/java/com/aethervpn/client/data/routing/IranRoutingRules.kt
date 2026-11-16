package com.aethervpn.client.data.routing

import android.content.Context
import com.aethervpn.vpncore.tun.Ipv4Cidr
import com.aethervpn.vpncore.tun.Ipv4RouteCalculator
import java.io.BufferedReader
import java.io.File
import java.io.InputStream
import java.io.InputStreamReader
import java.net.InetAddress

/**
 * Loads bundled or updated Iran IPv4 CIDR allocations and provides domain & IP matching helpers
 * for splitting domestic Iranian traffic directly onto the physical ISP interface.
 */
object IranRoutingRules {

    private const val ASSET_IRAN_CIDRS = "iran_ipv4.cidr"
    private const val OVERRIDE_IRAN_CIDRS = "iran_ipv4_override.cidr"
    internal const val MIN_VALID_REMOTE_CIDRS = 500
    internal const val DEFAULT_RIPE_IR_URL =
        "https://stat.ripe.net/data/country-resource-list/data.json?resource=IR&v4_format=prefix"

    data class CidrSourceInfo(
        val count: Int,
        val isCustomUpdated: Boolean,
        val updatedAtMs: Long
    )

    @Volatile
    private var cachedIranCidrs: List<Ipv4Cidr>? = null

    @Volatile
    private var cachedExcludedWithIran: List<Ipv4Cidr>? = null

    private val loadLock = Any()

    data class CustomBypassRules(
        val domains: Set<String> = emptySet(),
        val cidrs: List<Ipv4Cidr> = emptyList()
    )

    // Major domestic Iranian services on non-.ir TLDs whose IPs or Geo-DNS belong inside Iran
    private val DOMESTIC_NON_IR_DOMAINS = setOf(
        "aparat.com",
        "arvancloud.com",
        "bale.ai",
        "banimode.com",
        "basalam.com",
        "behpardakht.com",
        "digikala.com",
        "digikalajet.com",
        "divarcdn.com",
        "downloadha.com",
        "eitaa.com",
        "filimo.com",
        "flightio.com",
        "igap.net",
        "neshan.org",
        "okala.com",
        "pasargadbank.com",
        "samanepay.com",
        "sb24.com",
        "sheypoor.com",
        "snapp.taxi",
        "snappfood.com",
        "tamasha.com",
        "tarafdari.com",
        "telewebion.com",
        "torob.com",
        "varzesh3.com",
        "yasdl.com",
        "zarinpal.com",
        "zoodex.com"
    )

    private val IPV4_LITERAL_REGEX = Regex("""^\d{1,3}(?:\.\d{1,3}){3}$""")
    private val IPV4_CIDR_TOKEN_REGEX = Regex("""\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b""")
    private val DOMAIN_LABEL_REGEX = Regex("""^[a-z0-9-]+(\.[a-z0-9-]+)+$""")

    fun loadIranCidrs(context: Context): List<Ipv4Cidr> {
        cachedIranCidrs?.let { return it }
        synchronized(loadLock) {
            cachedIranCidrs?.let { return it }
            val overrideFile = File(context.filesDir, OVERRIDE_IRAN_CIDRS)
            val fromOverride = if (overrideFile.isFile) {
                runCatching {
                    overrideFile.inputStream().use { parseCidrStream(it) }
                }.getOrNull()?.takeIf { validateIranCidrUpdate(it) }
            } else {
                null
            }
            val parsed = fromOverride ?: context.assets.open(ASSET_IRAN_CIDRS).use { parseCidrStream(it) }
            cachedIranCidrs = parsed
            return parsed
        }
    }

    fun getCidrSourceInfo(context: Context): CidrSourceInfo {
        val cidrs = loadIranCidrs(context)
        val overrideFile = File(context.filesDir, OVERRIDE_IRAN_CIDRS)
        val usingOverride = overrideFile.isFile && runCatching {
            overrideFile.inputStream().use { parseCidrStream(it) }
        }.getOrNull()?.let { validateIranCidrUpdate(it) } == true
        return CidrSourceInfo(
            count = cidrs.size,
            isCustomUpdated = usingOverride,
            updatedAtMs = if (usingOverride) overrideFile.lastModified() else 0L
        )
    }

    fun saveRemoteIranCidrs(context: Context, responseBody: String): Int {
        val parsed = parseRemoteCidrResponse(responseBody)
        require(validateIranCidrUpdate(parsed)) {
            "Downloaded IR CIDR list failed safety validation (${parsed.size} prefixes)"
        }
        val overrideFile = File(context.filesDir, OVERRIDE_IRAN_CIDRS)
        val tempFile = File(context.filesDir, "$OVERRIDE_IRAN_CIDRS.tmp")
        tempFile.writeText(
            parsed.joinToString("\n") { "${it.hostAddress}/${it.prefixLen}" } + "\n",
            Charsets.UTF_8
        )
        if (!tempFile.renameTo(overrideFile)) {
            tempFile.copyTo(overrideFile, overwrite = true)
            tempFile.delete()
        }
        synchronized(loadLock) {
            cachedIranCidrs = parsed
            cachedExcludedWithIran = null
        }
        return parsed.size
    }

    fun resetIranCidrsToBundled(context: Context): Int {
        val overrideFile = File(context.filesDir, OVERRIDE_IRAN_CIDRS)
        if (overrideFile.exists()) {
            overrideFile.delete()
        }
        synchronized(loadLock) {
            cachedIranCidrs = null
            cachedExcludedWithIran = null
        }
        return loadIranCidrs(context).size
    }

    /**
     * Extracts IPv4 CIDRs from either plain line-based `.cidr` text or RIPEstat JSON payloads.
     */
    fun parseRemoteCidrResponse(body: String): List<Ipv4Cidr> {
        if (body.isBlank()) return emptyList()
        val parsed = ArrayList<Ipv4Cidr>(2048)
        for (match in IPV4_CIDR_TOKEN_REGEX.findAll(body)) {
            Ipv4Cidr.parse(match.value)?.let { parsed.add(it) }
        }
        return Ipv4RouteCalculator.coalesce(parsed)
    }

    /**
     * Guards routing integrity by ensuring an updated IR prefix table contains substantial IR coverage
     * and never swallows wildcard/default or global foreign service IPs.
     */
    fun validateIranCidrUpdate(cidrs: List<Ipv4Cidr>): Boolean {
        val normalized = Ipv4RouteCalculator.coalesce(cidrs)
        if (normalized.size < MIN_VALID_REMOTE_CIDRS) return false
        if (normalized.any { it.prefixLen <= 4 }) return false
        val requiredIranIps = listOf("185.188.107.12", "185.147.179.11")
        val blockedForeignIps = listOf("1.1.1.1", "8.8.8.8", "149.154.167.91", "157.240.1.174")
        return try {
            requiredIranIps.all { ip -> Ipv4RouteCalculator.containsIp(normalized, InetAddress.getByName(ip)) } &&
                blockedForeignIps.none { ip -> Ipv4RouteCalculator.containsIp(normalized, InetAddress.getByName(ip)) }
        } catch (_: Exception) {
            false
        }
    }

    fun getExcludedRoutes(
        context: Context,
        bypassIran: Boolean,
        extraCidrs: List<Ipv4Cidr> = emptyList()
    ): List<Ipv4Cidr> {
        if (!bypassIran && extraCidrs.isEmpty()) return Ipv4RouteCalculator.LAN_AND_MULTICAST_EXCLUDES
        if (bypassIran && extraCidrs.isEmpty()) {
            cachedExcludedWithIran?.let { return it }
            synchronized(loadLock) {
                cachedExcludedWithIran?.let { return it }
                val merged = Ipv4RouteCalculator.coalesce(
                    Ipv4RouteCalculator.LAN_AND_MULTICAST_EXCLUDES + loadIranCidrs(context)
                )
                cachedExcludedWithIran = merged
                return merged
            }
        }
        val base = if (bypassIran) {
            getExcludedRoutes(context, bypassIran = true)
        } else {
            Ipv4RouteCalculator.LAN_AND_MULTICAST_EXCLUDES
        }
        return Ipv4RouteCalculator.coalesce(base + extraCidrs)
    }

    fun getAllowedRoutesPreApi33(
        context: Context,
        bypassIran: Boolean,
        extraCidrs: List<Ipv4Cidr> = emptyList()
    ): List<Ipv4Cidr> {
        return Ipv4RouteCalculator.computeAllowedRoutes(getExcludedRoutes(context, bypassIran, extraCidrs))
    }

    fun parseCustomRules(raw: String): CustomBypassRules {
        if (raw.isBlank()) return CustomBypassRules()
        val domains = LinkedHashSet<String>()
        val cidrs = ArrayList<Ipv4Cidr>()
        for (rawLine in raw.lineSequence()) {
            val withoutComment = rawLine.substringBefore('#').trim()
            if (withoutComment.isEmpty()) continue
            val tokens = withoutComment.split(',', ';', ' ', '\t')
            for (tokenRaw in tokens) {
                val token = tokenRaw.trim()
                if (token.isEmpty()) continue
                val cidr = when {
                    '/' in token -> Ipv4Cidr.parse(token)
                    IPV4_LITERAL_REGEX.matches(token) -> Ipv4Cidr.parse("$token/32")
                    else -> null
                }
                if (cidr != null) {
                    cidrs.add(cidr)
                } else {
                    val host = token.removePrefix("*.").trim('.').lowercase()
                    if (DOMAIN_LABEL_REGEX.matches(host)) {
                        domains.add(host)
                    }
                }
            }
        }
        return CustomBypassRules(
            domains = domains,
            cidrs = Ipv4RouteCalculator.coalesce(cidrs)
        )
    }

    fun parseCidrStream(input: InputStream): List<Ipv4Cidr> {
        val list = ArrayList<Ipv4Cidr>(2048)
        BufferedReader(InputStreamReader(input, Charsets.UTF_8)).use { reader ->
            var line = reader.readLine()
            while (line != null) {
                Ipv4Cidr.parse(line)?.let { list.add(it) }
                line = reader.readLine()
            }
        }
        return Ipv4RouteCalculator.coalesce(list)
    }

    fun isIranIp(context: Context, addr: InetAddress): Boolean {
        return Ipv4RouteCalculator.containsIp(loadIranCidrs(context), addr)
    }

    /**
     * Returns true when [domain] is an `.ir` domain, a curated domestic Iranian host,
     * or matches any user-configured [customDomains] suffix when direct bypass is active.
     */
    fun isIranDomain(domain: String?, customDomains: Set<String> = emptySet(), includeBuiltinIran: Boolean = true): Boolean {
        val clean = domain?.trim()?.trimEnd('.')?.lowercase().orEmpty()
        if (clean.isEmpty()) return false
        for (custom in customDomains) {
            if (clean == custom || clean.endsWith(".$custom")) {
                return true
            }
        }
        if (!includeBuiltinIran) return false
        if (clean == "ir" || clean.endsWith(".ir")) return true
        for (domestic in DOMESTIC_NON_IR_DOMAINS) {
            if (clean == domestic || clean.endsWith(".$domestic")) {
                return true
            }
        }
        return false
    }
}

