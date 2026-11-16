package com.aethervpn.client.data.source

import com.aethervpn.client.data.model.VpnServer
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader

object VpnGateCsvParser {

    /**
     * Parses the CSV stream from VPN Gate (e.g. https://www.vpngate.net/api/iphone/).
     * Handles comments, headers, malformed lines, and extracts server metadata.
     */
    fun parse(inputStream: InputStream): List<VpnServer> {
        val servers = mutableListOf<VpnServer>()
        val reader = BufferedReader(InputStreamReader(inputStream, Charsets.UTF_8))
        var line: String?

        var headerFound = false
        var headers = emptyList<String>()

        while (reader.readLine().also { line = it } != null) {
            val current = line?.trim() ?: continue
            if (current.isEmpty() || current == "*") continue
            if (current.startsWith("*vpn_servers")) continue

            if (current.startsWith("#")) {
                // Header line: #HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64
                val headerContent = current.substring(1)
                headers = parseCsvRow(headerContent)
                headerFound = true
                continue
            }

            if (!headerFound) continue

            try {
                val values = parseCsvRow(current)
                if (values.size < 7) continue

                val map = mutableMapOf<String, String>()
                for (i in values.indices) {
                    if (i < headers.size) {
                        map[headers[i].lowercase()] = values[i]
                    }
                }

                val hostName = map["hostname"] ?: continue
                val ip = map["ip"] ?: continue
                if (hostName.isBlank() || ip.isBlank()) continue

                val score = map["score"]?.toLongOrNull() ?: 0L
                val ping = map["ping"]?.toIntOrNull() ?: -1
                val speed = map["speed"]?.toLongOrNull() ?: 0L
                val countryLong = map["countrylong"] ?: ""
                val countryShort = map["countryshort"] ?: ""
                val numSessions = map["numvpnsessions"]?.toLongOrNull() ?: 0L
                val uptime = map["uptime"]?.toLongOrNull() ?: 0L
                val totalUsers = map["totalusers"]?.toLongOrNull() ?: 0L
                val totalTraffic = map["totaltraffic"]?.toLongOrNull() ?: 0L
                val logType = map["logtype"] ?: ""
                val operator = map["operator"] ?: ""
                val message = map["message"] ?: ""
                val openvpnB64 = map["openvpn_configdata_base64"] ?: ""
                val discoveredPort = extractPortFromOpenVpnConfig(openvpnB64) ?: 443

                servers.add(
                    VpnServer(
                        hostName = hostName,
                        ip = ip,
                        score = score,
                        ping = ping,
                        speed = speed,
                        countryLong = countryLong,
                        countryShort = countryShort,
                        numVpnSessions = numSessions,
                        uptime = uptime,
                        totalUsers = totalUsers,
                        totalTraffic = totalTraffic,
                        logType = logType,
                        operator = operator,
                        message = message,
                        sstpSupported = true,
                        isCustom = false,
                        customPort = discoveredPort
                    )
                )
            } catch (_: Exception) {
                // Skip malformed row
            }
        }

        return servers
    }

    /**
     * Splits a CSV line taking quotes and commas into account.
     */
    fun parseCsvRow(line: String): List<String> {
        val tokens = mutableListOf<String>()
        val sb = StringBuilder()
        var inQuotes = false
        var i = 0
        while (i < line.length) {
            val c = line[i]
            when {
                c == '\"' -> {
                    if (inQuotes && i + 1 < line.length && line[i + 1] == '\"') {
                        sb.append('\"')
                        i++ // Skip escaped quote
                    } else {
                        inQuotes = !inQuotes
                    }
                }
                c == ',' && !inQuotes -> {
                    tokens.add(sb.toString().trim())
                    sb.clear()
                }
                else -> sb.append(c)
            }
            i++
        }
        tokens.add(sb.toString().trim())
        return tokens
    }

    /**
     * Extracts the port number from base64-encoded OpenVPN config if present in `remote <host> <port>`.
     */
    fun extractPortFromOpenVpnConfig(base64Config: String): Int? {
        if (base64Config.isBlank()) return null
        val bytes = decodeBase64Safe(base64Config) ?: return null
        val configText = String(bytes, Charsets.UTF_8)
        val regex = Regex("""(?m)^\s*remote\s+\S+\s+(\d+)""", RegexOption.IGNORE_CASE)
        val match = regex.find(configText)
        val port = match?.groupValues?.get(1)?.toIntOrNull()
        return if (port != null && port in 1..65535) port else null
    }

    /**
     * Safely decodes base64 strings across Android versions (API 24+) and JVM test runners.
     */
    fun decodeBase64Safe(input: String): ByteArray? {
        if (input.isBlank()) return null
        // 1. Try standard java.util.Base64 MIME decoder (standard on JVM and Android API 26+)
        try {
            return java.util.Base64.getMimeDecoder().decode(input)
        } catch (_: Throwable) {
            // Fall through
        }

        // 2. Fallback via reflection to android.util.Base64 for Android API 24/25 devices
        try {
            val clazz = Class.forName("android.util.Base64")
            val method = clazz.getMethod("decode", String::class.java, Int::class.javaPrimitiveType)
            return method.invoke(null, input, 0) as? ByteArray
        } catch (_: Throwable) {
            // Fall through
        }

        return null
    }
}

