package com.aethervpn.vpncore.warp

import com.wireguard.crypto.KeyPair
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import okhttp3.Dns
import java.net.InetAddress
import java.util.concurrent.TimeUnit

object WarpRegistrar {
    private const val API_ENDPOINT = "https://api.cloudflareclient.com/v0a2158/reg"
    private val JSON_MEDIA_TYPE = "application/json; charset=UTF-8".toMediaType()

    private val resilientDns = object : Dns {
        override fun lookup(hostname: String): List<InetAddress> {
            if (hostname.equals("api.cloudflareclient.com", ignoreCase = true)) {
                val resolved = runCatching { Dns.SYSTEM.lookup(hostname) }.getOrNull().orEmpty()
                val validPublic = resolved.filter { addr ->
                    val ip = addr.hostAddress.orEmpty()
                    !ip.startsWith("10.") && !ip.startsWith("127.") && !ip.startsWith("192.168.")
                }
                return if (validPublic.isNotEmpty()) {
                    validPublic
                } else {
                    listOf(
                        InetAddress.getByAddress("api.cloudflareclient.com", byteArrayOf(162.toByte(), 159.toByte(), 192.toByte(), 1)),
                        InetAddress.getByAddress("api.cloudflareclient.com", byteArrayOf(162.toByte(), 159.toByte(), 193.toByte(), 1)),
                        InetAddress.getByAddress("api.cloudflareclient.com", byteArrayOf(188.toByte(), 114.toByte(), 97.toByte(), 1)),
                        InetAddress.getByAddress("api.cloudflareclient.com", byteArrayOf(188.toByte(), 114.toByte(), 98.toByte(), 1))
                    )
                }
            } else {
                return Dns.SYSTEM.lookup(hostname)
            }
        }
    }

    private val httpClient by lazy {
        OkHttpClient.Builder()
            .dns(resilientDns)
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .callTimeout(15, TimeUnit.SECONDS)
            .build()
    }

    suspend fun registerAccount(existingClient: OkHttpClient? = null): WarpAccount = withContext(Dispatchers.IO) {
        val client = existingClient ?: httpClient
        val keyPair = KeyPair()
        val privateKeyB64 = keyPair.privateKey.toBase64()
        val publicKeyB64 = keyPair.publicKey.toBase64()

        val sdf = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        val tosTime = sdf.format(Date())

        val regBody = JSONObject().apply {
            put("key", publicKeyB64)
            put("install_id", "")
            put("fcm_token", "")
            put("tos", tosTime)
            put("model", "Android")
            put("serial_number", "")
            put("locale", "en_US")
        }

        val request = Request.Builder()
            .url(API_ENDPOINT)
            .post(regBody.toString().toRequestBody(JSON_MEDIA_TYPE))
            .header("User-Agent", "okhttp/4.12.0")
            .build()

        val response = client.newCall(request).execute()
        if (!response.isSuccessful) {
            val errBody = response.body?.string().orEmpty()
            throw IllegalStateException("Cloudflare WARP registration failed (code=${response.code}): $errBody")
        }

        val respStr = response.body?.string() ?: throw IllegalStateException("Empty response from Cloudflare")
        val root = JSONObject(respStr)

        val id = root.getString("id")
        val token = root.getString("token")

        var assignedIpv4 = "172.16.0.2"
        var assignedIpv6: String? = null
        if (root.has("config")) {
            val configObj = root.getJSONObject("config")
            if (configObj.has("interface")) {
                val ifaceObj = configObj.getJSONObject("interface")
                if (ifaceObj.has("addresses")) {
                    val addrs = ifaceObj.getJSONObject("addresses")
                    if (addrs.has("v4")) assignedIpv4 = addrs.getString("v4")
                    if (addrs.has("v6")) assignedIpv6 = addrs.getString("v6")
                }
            }
        }

        var license: String? = null
        var isWarpPlus = false
        if (root.has("account")) {
            val acc = root.getJSONObject("account")
            if (acc.has("license")) license = acc.optString("license")
            if (acc.has("warp_plus")) isWarpPlus = acc.optBoolean("warp_plus", false)
        }

        // Enable WARP on the account
        try {
            val patchBody = JSONObject().apply { put("warp_enabled", true) }
            val patchReq = Request.Builder()
                .url("$API_ENDPOINT/$id")
                .patch(patchBody.toString().toRequestBody(JSON_MEDIA_TYPE))
                .header("Authorization", "Bearer $token")
                .header("User-Agent", "okhttp/4.12.0")
                .build()
            client.newCall(patchReq).execute().close()
        } catch (_: Exception) {
            // Non-fatal if patch fails, account is still valid
        }

        WarpAccount(
            id = id,
            privateKey = privateKeyB64,
            publicKey = publicKeyB64,
            token = token,
            assignedIpv4 = assignedIpv4,
            assignedIpv6 = assignedIpv6,
            license = license,
            isWarpPlus = isWarpPlus
        )
    }
}

