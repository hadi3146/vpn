package com.aethervpn.vpncore.transport

enum class SniStrategy(val id: Int, val displayName: String) {
    DISABLED(0, "Direct / No Bypass"),
    DIRECT_IP_NO_SNI(1, "Connect by IP (No SNI)"),
    TCP_FRAGMENTATION(2, "TCP ClientHello Fragmentation"),
    TLS_RECORD_FRAGMENTATION(3, "TLS Record Fragmentation"),
    CUSTOM_SNI(4, "Custom / Fake SNI");

    companion object {
        fun fromId(id: Int): SniStrategy = entries.firstOrNull { it.id == id } ?: DIRECT_IP_NO_SNI
    }
}

