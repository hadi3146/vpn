package com.aethervpn.vpncore.warp

import org.json.JSONObject

data class WarpAccount(
    val id: String,
    val privateKey: String,
    val publicKey: String,
    val token: String,
    val assignedIpv4: String = "172.16.0.2",
    val assignedIpv6: String? = null,
    val license: String? = null,
    val isWarpPlus: Boolean = false
) {
    fun toJson(): String {
        return JSONObject().apply {
            put("id", id)
            put("privateKey", privateKey)
            put("publicKey", publicKey)
            put("token", token)
            put("assignedIpv4", assignedIpv4)
            if (assignedIpv6 != null) put("assignedIpv6", assignedIpv6)
            if (license != null) put("license", license)
            put("isWarpPlus", isWarpPlus)
        }.toString()
    }

    companion object {
        const val CLOUDFLARE_PEER_PUBLIC_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

        fun fromJson(raw: String): WarpAccount? {
            if (raw.isBlank()) return null
            return try {
                val obj = JSONObject(raw)
                WarpAccount(
                    id = obj.getString("id"),
                    privateKey = obj.getString("privateKey"),
                    publicKey = obj.getString("publicKey"),
                    token = obj.getString("token"),
                    assignedIpv4 = obj.optString("assignedIpv4", "172.16.0.2"),
                    assignedIpv6 = obj.optString("assignedIpv6").takeIf { !it.isNullOrBlank() },
                    license = obj.optString("license").takeIf { !it.isNullOrBlank() },
                    isWarpPlus = obj.optBoolean("isWarpPlus", false)
                )
            } catch (_: Exception) {
                null
            }
        }
    }
}

