package com.aethervpn.vpncore.softether

/**
 * Protocol constants and wire signatures for SoftEther VPN Native Protocol (Cedar Engine).
 */
object SoftEtherConstants {
    const val COMPATIBLE_VERSION: Int = 444
    const val COMPATIBLE_BUILD: Int = 9807

    // PACK element types (from Mayaqua/Pack.h)
    const val VALUE_INT: Int = 0
    const val VALUE_DATA: Int = 1
    const val VALUE_STR: Int = 2
    const val VALUE_UNISTR: Int = 3
    const val VALUE_INT64: Int = 4

    // HTTP Endpoints & Headers
    const val HTTP_CONNECT_TARGET: String = "/vpnsvc/connect.cgi"
    const val HTTP_VPN_TARGET: String = "/vpnsvc/vpn.cgi"
    const val HTTP_DEFAULT_USER_AGENT: String = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SoftEtherVPN/4.44"
    const val HTTP_KEEP_ALIVE: String = "timeout=15; max=19"

    // Property names (from Cedar/Protocol.h)
    const val SEP_BUILD: String = "build"
    const val SEP_VERSION: String = "version"
    const val SEP_UNIQUE_ID_CAMEL: String = "UniqueId"
    const val SEP_UNIQUE_ID_SNAKE: String = "unique_id"
    const val SEP_CLIENT_BUILD: String = "client_build"
    const val SEP_CLIENT_ID: String = "client_id"
    const val SEP_CLIENT_STR: String = "client_str"
    const val SEP_CLIENT_VER: String = "client_ver"
    const val SEP_CLIENT_HOSTNAME: String = "ClientHostname"
    const val SEP_CLIENT_IP_ADDRESS: String = "ClientIpAddress"
    const val SEP_CLIENT_OS_NAME: String = "ClientOsName"
    const val SEP_CLIENT_OS_VER: String = "ClientOsVer"
    const val SEP_CLIENT_PORT: String = "ClientPort"
    const val SEP_CLIENT_PRODUCT_BUILD: String = "ClientProductBuild"
    const val SEP_CLIENT_PRODUCT_NAME: String = "ClientProductName"
    const val SEP_CLIENT_PRODUCT_VER: String = "ClientProductVer"
    const val SEP_HELLO: String = "hello"

    const val SEP_PROXY_PORT: String = "ProxyPort"
    const val SEP_PROXY_IP_ADDRESS: String = "ProxyIpAddress"

    const val SEP_SERVER_HOSTNAME: String = "ServerHostname"
    const val SEP_SERVER_IP_ADDRESS: String = "ServerIpAddress"
    const val SEP_SERVER_PORT2: String = "ServerPort2"
    const val SEP_SERVER_PRODUCT_BUILD: String = "ServerProductBuild"
    const val SEP_SERVER_PRODUCT_NAME: String = "ServerProductName"
    const val SEP_SERVER_PRODUCT_VER: String = "ServerProductVer"

    const val SEP_METHOD: String = "method"
    const val SEP_AUTH_TYPE: String = "authtype"
    const val SEP_USERNAME: String = "username"
    const val SEP_SECURE_PASSWORD: String = "secure_password"
    const val SEP_PROTOCOL: String = "protocol"
    const val SEP_HUB_NAME: String = "hubname"
    const val SEP_USE_ENCRYPT: String = "use_encrypt"
    const val SEP_USE_COMPRESS: String = "use_compress"
    const val SEP_MAX_CONNECTION: String = "max_connection"
    const val SEP_HALF_CONNECTION: String = "half_connection"
    const val SEP_SESSION_KEY: String = "session_key"

    const val SEP_RANDOM: String = "random"
    const val SEP_PEN_CORE: String = "pencore"
    const val SEP_ERROR: String = "error"

    // Methods
    const val METHOD_LOGIN: String = "login"
    const val METHOD_ADDITIONAL_CONNECT: String = "additional_connect"

    // Default connection limits
    const val DEFAULT_MAX_CONNECTIONS: Int = 8
    const val MIN_CONNECTIONS: Int = 1
    const val MAX_SUPPORTED_CONNECTIONS: Int = 16

    // SoftEther VPNCONNECT Handshake Signature (standard HTTP POST body for /vpnsvc/connect.cgi)
    val VPNCONNECT_BODY: ByteArray = "VPNCONNECT".toByteArray(Charsets.US_ASCII)

    // SoftEther GIF Watermark Signature (Cedar protocol disguise)
    val WATERMARK: ByteArray = byteArrayOf(
        0x47.toByte(), 0x49.toByte(), 0x46.toByte(), 0x38.toByte(), 0x39.toByte(), 0x61.toByte(), 0xC8.toByte(), 0x00.toByte(),
        0x33.toByte(), 0x00.toByte(), 0xF2.toByte(), 0x00.toByte(), 0x00.toByte(), 0x36.toByte(), 0x37.toByte(), 0x34.toByte(),
        0x79.toByte(), 0x68.toByte(), 0x54.toByte(), 0x80.toByte(), 0x80.toByte(), 0x80.toByte(), 0xAF.toByte(), 0x7F.toByte(),
        0x5B.toByte(), 0xB3.toByte(), 0xA8.toByte(), 0x9D.toByte(), 0xD5.toByte(), 0xD5.toByte(), 0xD4.toByte(), 0xFF.toByte(),
        0xFF.toByte(), 0xFF.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x2C.toByte(), 0x00.toByte(), 0x00.toByte(),
        0x00.toByte(), 0x00.toByte(), 0xC8.toByte(), 0x00.toByte(), 0x33.toByte(), 0x00.toByte(), 0x00.toByte(), 0x03.toByte(),
        0xFE.toByte(), 0x08.toByte(), 0x1A.toByte(), 0xDC.toByte(), 0x34.toByte(), 0x0A.toByte(), 0x04.toByte(), 0x41.toByte(),
        0x6B.toByte(), 0x65.toByte(), 0x31.toByte(), 0x4F.toByte(), 0x11.toByte(), 0x80.toByte(), 0xF9.toByte(), 0x60.toByte(),
        0x28.toByte(), 0x8E.toByte(), 0x64.toByte(), 0x69.toByte(), 0x9E.toByte(), 0x68.toByte(), 0xAA.toByte(), 0xAE.toByte(),
        0x6C.toByte(), 0xEB.toByte(), 0x9A.toByte(), 0x4B.toByte(), 0xE3.toByte(), 0x0C.toByte(), 0x0C.toByte(), 0x25.toByte(),
        0x6F.toByte(), 0x56.toByte(), 0xA7.toByte(), 0xE9.toByte(), 0xD2.toByte(), 0xEB.toByte(), 0xFF.toByte(), 0xC0.toByte(),
        0xA0.toByte(), 0x70.toByte(), 0xC8.toByte(), 0x8A.toByte(), 0xDC.toByte(), 0x2C.toByte(), 0x9C.toByte(), 0xC6.toByte(),
        0x05.toByte(), 0xC7.toByte(), 0x31.toByte(), 0x66.toByte(), 0x24.toByte(), 0x04.toByte(), 0xA2.toByte(), 0x74.toByte(),
        0x4A.toByte(), 0xAD.toByte(), 0x4E.toByte(), 0x05.toByte(), 0xB1.toByte(), 0x0D.toByte(), 0x61.toByte(), 0xCB.toByte(),
        0x25.toByte(), 0xD4.toByte(), 0xB8.toByte(), 0x49.toByte(), 0x1B.toByte(), 0xE6.toByte(), 0x19.toByte(), 0xB1.toByte(),
        0x9A.toByte(), 0xCF.toByte(), 0xE8.toByte(), 0xF4.toByte(), 0x07.toByte(), 0x2B.toByte(), 0x11.toByte(), 0x74.toByte(),
        0x09.toByte(), 0x85.toByte(), 0x78.toByte(), 0xFC.toByte(), 0x0D.toByte(), 0x6E.toByte(), 0x90.toByte(), 0x9F.toByte(),
        0xEA.toByte(), 0x02.toByte(), 0x81.toByte(), 0x12.toByte(), 0x35.toByte(), 0xEF.toByte(), 0x29.toByte(), 0x6A.toByte(),
        0x81.toByte(), 0x2C.toByte(), 0x04.toByte(), 0x0A.toByte(), 0x6E.toByte(), 0x5C.toByte(), 0x72.toByte(), 0x88.toByte(),
        0x7A.toByte(), 0x7A.toByte(), 0x6F.toByte(), 0x4D.toByte(), 0x77.toByte(), 0x19.toByte(), 0x25.toByte(), 0x71.toByte(),
        0x16.toByte(), 0x71.toByte(), 0x2F.toByte(), 0x05.toByte(), 0x92.toByte(), 0x06.toByte(), 0x95.toByte(), 0x80.toByte(),
        0x22.toByte(), 0x48.toByte(), 0x16.toByte(), 0x7D.toByte(), 0x98.toByte(), 0x02.toByte(), 0x9A.toByte(), 0x7C.toByte(),
        0x82.toByte(), 0x06.toByte(), 0x16.toByte(), 0x23.toByte(), 0x7F.toByte(), 0x02.toByte(), 0x05.toByte(), 0x6B.toByte(),
        0x48.toByte(), 0x70.toByte(), 0x23.toByte(), 0x15.toByte(), 0x7D.toByte(), 0x1F.toByte(), 0x98.toByte(), 0xA8.toByte(),
        0x21.toByte(), 0x7F.toByte(), 0x87.toByte(), 0x89.toByte(), 0xB5.toByte(), 0x8B.toByte(), 0x7C.toByte(), 0x7B.toByte(),
        0x3C.toByte(), 0x8E.toByte(), 0x23.toByte(), 0x9E.toByte(), 0x9B.toByte(), 0xAE.toByte(), 0x2B.toByte(), 0xAD.toByte(),
        0x20.toByte(), 0xA6.toByte(), 0xAC.toByte(), 0x9B.toByte(), 0x14.toByte(), 0xB1.toByte(), 0xC3.toByte(), 0x21.toByte(),
        0x15.toByte(), 0xB1.toByte(), 0x81.toByte(), 0x9E.toByte(), 0x22.toByte(), 0x9E.toByte(), 0xAE.toByte(), 0xC5.toByte(),
        0x99.toByte(), 0x20.toByte(), 0x96.toByte(), 0xAF.toByte(), 0xC6.toByte(), 0xA0.toByte(), 0x70.toByte(), 0xB6.toByte(),
        0xB6.toByte(), 0x5B.toByte(), 0x03.toByte(), 0x1C.toByte(), 0x16.toByte(), 0x8E.toByte(), 0x65.toByte(), 0x21.toByte(),
        0xBD.toByte(), 0x9B.toByte(), 0xCB.toByte(), 0x2A.toByte(), 0x9E.toByte(), 0xCB.toByte(), 0xC1.toByte(), 0xE1.toByte(),
        0xD1.toByte(), 0xA7.toByte(), 0xA9.toByte(), 0x6E.toByte(), 0xE9.toByte(), 0xD6.toByte(), 0x82.toByte(), 0xCD.toByte(),
        0xC9.toByte(), 0xCA.toByte(), 0xD5.toByte(), 0xD1.toByte(), 0xAE.toByte(), 0xBD.toByte(), 0xCB.toByte(), 0x7F.toByte(),
        0xAC.toByte(), 0xB4.toByte(), 0xD9.toByte(), 0x73.toByte(), 0x34.toByte(), 0x37.toByte(), 0x76.toByte(), 0xDF.toByte()
    )
}

