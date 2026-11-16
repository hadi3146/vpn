package com.aethervpn.client.data.model

import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

object SstpUriCodec {

    /**
     * Parses an SSTP, VLESS, Shadowsocks, Trojan, WireGuard, or generic URI into a [VpnServer] entity.
     * Supported formats:
     * - `sstp://user:pass@host:port?sni=decoy.com#ServerName`
     * - `vless://uuid@host:port?security=reality&sni=decoy.com#ServerName`
     * - `ss://base64@host:port#ServerName` or `ss://method:pass@host:port#ServerName`
     * - `trojan://password@host:port?sni=decoy.com#ServerName`
     * - `warp://host:port#ServerName` / `wg://key@host:port#ServerName`
     * - Plain `host:port`
     */
    fun parse(rawUri: String): VpnServer? {
        val trimmed = rawUri.trim()
        if (trimmed.isBlank()) return null

        // Handle raw Shadowsocks format `ss://BASE64(method:pass@host:port)#Tag`
        if (trimmed.startsWith("ss://", ignoreCase = true) && !trimmed.substring(5).contains("@") && trimmed.contains("#")) {
            val withoutScheme = trimmed.substring(5)
            val b64Part = withoutScheme.substringBefore("#")
            val tag = withoutScheme.substringAfter("#", "")
            val decoded = decodeBase64Safe(b64Part)
            if (decoded != null && decoded.contains("@")) {
                return parse("ss://$decoded#$tag")
            }
        }

        val uriString = if (!trimmed.contains("://")) {
            "sstp://$trimmed"
        } else trimmed

        return try {
            val uri = URI(uriString)
            val scheme = uri.scheme?.lowercase() ?: return null

            val validSchemes = setOf("sstp", "https", "vless", "ss", "trojan", "wg", "wireguard", "warp")
            if (scheme !in validSchemes) return null

            val host = uri.host ?: return null
            if (host.isBlank()) return null

            val port = if (uri.port != -1) {
                uri.port
            } else when (scheme) {
                "trojan", "vless", "https", "sstp" -> 443
                "ss" -> 8388
                "wg", "wireguard", "warp" -> 2408
                else -> 443
            }

            var username = "vpn"
            var password = "vpn"
            var protocolTag = scheme.uppercase()

            val userInfo = uri.userInfo
            if (!userInfo.isNullOrBlank()) {
                when (scheme) {
                    "vless" -> {
                        username = URLDecoder.decode(userInfo, "UTF-8")
                        password = username
                        protocolTag = "VLESS"
                    }
                    "trojan" -> {
                        password = URLDecoder.decode(userInfo, "UTF-8")
                        username = "trojan"
                        protocolTag = "TROJAN"
                    }
                    "ss" -> {
                        protocolTag = "SHADOWSOCKS"
                        val decodedInfo = decodeBase64Safe(userInfo) ?: userInfo
                        val parts = decodedInfo.split(":", limit = 2)
                        username = URLDecoder.decode(parts[0], "UTF-8")
                        if (parts.size > 1) {
                            password = URLDecoder.decode(parts[1], "UTF-8")
                        }
                    }
                    "wg", "wireguard", "warp" -> {
                        username = URLDecoder.decode(userInfo, "UTF-8")
                        password = username
                        protocolTag = "WARP"
                    }
                    else -> {
                        val parts = userInfo.split(":", limit = 2)
                        username = URLDecoder.decode(parts[0], "UTF-8")
                        if (parts.size > 1) {
                            password = URLDecoder.decode(parts[1], "UTF-8")
                        }
                    }
                }
            }

            var customSni: String? = null
            val rawQuery = uri.rawQuery
            if (!rawQuery.isNullOrBlank()) {
                val params = rawQuery.split("&")
                for (p in params) {
                    val kv = p.split("=", limit = 2)
                    val k = kv[0].lowercase()
                    if ((k == "sni" || k == "host" || k == "peer") && kv.size > 1) {
                        customSni = URLDecoder.decode(kv[1], "UTF-8").takeIf { it.isNotBlank() }
                    }
                }
            }

            var label = uri.fragment?.let { runCatching { URLDecoder.decode(it, "UTF-8") }.getOrNull() }
            if (label.isNullOrBlank()) {
                label = "$protocolTag - $host"
            }

            VpnServer(
                hostName = host,
                ip = host,
                countryLong = label,
                countryShort = protocolTag.take(4),
                isCustom = true,
                customPort = port,
                customUsername = username,
                customPassword = password,
                customSni = customSni,
                sstpSupported = (scheme == "sstp" || scheme == "https"),
                logType = protocolTag
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun decodeBase64Safe(str: String): String? {
        val cleaned = str.trim().replace('-', '+').replace('_', '/')
        val padLen = (4 - (cleaned.length % 4)) % 4
        val padded = cleaned + "=".repeat(padLen)
        return try {
            val bytes = java.util.Base64.getDecoder().decode(padded)
            String(bytes, StandardCharsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Serializes a [VpnServer] into an `sstp://` link.
     */
    fun encode(server: VpnServer): String {
        val userPart = if (server.customUsername != "vpn" || server.customPassword != "vpn") {
            val u = URLEncoder.encode(server.customUsername, "UTF-8")
            val p = URLEncoder.encode(server.customPassword, "UTF-8")
            "$u:$p@"
        } else ""

        val host = server.hostName.ifBlank { server.ip }
        val portPart = if (server.customPort != 443) ":${server.customPort}" else ""
        val queryPart = if (!server.customSni.isNullOrBlank()) {
            "?sni=" + URLEncoder.encode(server.customSni, "UTF-8")
        } else ""

        val name = server.countryLong.ifBlank { host }
        val fragmentPart = "#" + URLEncoder.encode(name, "UTF-8")

        return "sstp://$userPart$host$portPart$queryPart$fragmentPart"
    }
}

