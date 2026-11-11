package com.aethervpn.vpncore.sstp

import com.aethervpn.vpncore.crypto.CryptoBinding
import com.aethervpn.vpncore.crypto.MsChapV2
import com.aethervpn.vpncore.ppp.ChapPacket
import com.aethervpn.vpncore.ppp.IpcpOption
import com.aethervpn.vpncore.ppp.IpcpPacket
import com.aethervpn.vpncore.ppp.LcpOption
import com.aethervpn.vpncore.ppp.LcpPacket
import com.aethervpn.vpncore.ppp.PppFrame
import com.aethervpn.vpncore.transport.SniBypassSocketFactory
import com.aethervpn.vpncore.transport.SniStrategy
import com.aethervpn.vpncore.transport.SocketProtector
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.SSLSocket

data class SstpConfig(
    val host: String,
    val ipAddress: InetAddress,
    val port: Int = 443,
    val username: String = "vpn",
    val password: String = "vpn",
    val mtu: Int = 1400,
    val keepaliveIntervalSec: Int = 30,
    val strictCert: Boolean = false,
    val sniStrategy: SniStrategy = SniStrategy.DIRECT_IP_NO_SNI,
    val customSni: String? = null
)

data class VpnParameters(
    val clientIp: String,
    val gatewayIp: String,
    val primaryDns: String,
    val secondaryDns: String,
    val mtu: Int
)

interface SstpEventListener {
    fun onStateChanged(state: SstpState, message: String? = null)
    fun onParametersEstablished(params: VpnParameters)
    fun onDataPacketReceived(packet: ByteArray)
    fun onBytesTransferred(txBytesDelta: Long, rxBytesDelta: Long)
    fun onError(t: Throwable)
}

enum class SstpState {
    DISCONNECTED,
    CONNECTING_TCP,
    TLS_HANDSHAKE,
    HTTP_HANDSHAKE,
    SSTP_CONNECTING,
    PPP_LCP,
    PPP_AUTH,
    PPP_IPCP,
    CONNECTED,
    DISCONNECTING
}

class SstpClient(
    private val config: SstpConfig,
    private val socketProtector: SocketProtector?,
    private val listener: SstpEventListener
) {
    private val isRunning = AtomicBoolean(false)
    private var sslSocket: SSLSocket? = null
    private var inputStream: InputStream? = null
    private var outputStream: OutputStream? = null

    private var serverCert: X509Certificate? = null
    private var serverNonce: ByteArray? = null
    private var masterKey: ByteArray? = null

    private var clientIp = "10.0.0.2"
    private var gatewayIp = "10.0.0.1"
    private var primaryDns = "8.8.8.8"
    private var secondaryDns = "8.8.4.4"

    private val txBytes = AtomicLong(0)
    private val rxBytes = AtomicLong(0)

    private var echoJob: Job? = null

    suspend fun start(scope: CoroutineScope) = withContext(Dispatchers.IO) {
        if (!isRunning.compareAndSet(false, true)) return@withContext
        try {
            listener.onStateChanged(SstpState.CONNECTING_TCP, "Connecting to ${config.host}:${config.port}...")

            val socketFactory = SniBypassSocketFactory(
                strategy = config.sniStrategy,
                customSni = config.customSni,
                strictCert = config.strictCert,
                socketProtector = socketProtector,
                onCertificateCaptured = { cert ->
                    serverCert = cert
                }
            )

            listener.onStateChanged(SstpState.TLS_HANDSHAKE, "Performing TLS handshake...")
            val socket = socketFactory.createAndConnectSocket(
                host = config.host,
                ipAddress = config.ipAddress,
                port = config.port
            )
            sslSocket = socket
            val bis = BufferedInputStream(socket.inputStream, 16384)
            val bos = BufferedOutputStream(socket.outputStream, 16384)
            inputStream = bis
            outputStream = bos

            // HTTP Handshake
            listener.onStateChanged(SstpState.HTTP_HANDSHAKE, "Sending SSTP HTTP duplex post...")
            performHttpHandshake(bis, bos)

            // SSTP Call Connect Request
            listener.onStateChanged(SstpState.SSTP_CONNECTING, "Initiating SSTP connection...")
            sendSstpConnectRequest(bos)

            // Read SSTP Call Connect Ack
            readSstpConnectAck(bis)

            // LCP Phase
            listener.onStateChanged(SstpState.PPP_LCP, "Negotiating PPP LCP...")
            negotiateLcp(bis, bos)

            // Authentication Phase
            listener.onStateChanged(SstpState.PPP_AUTH, "Authenticating with MS-CHAPv2...")
            authenticateMsChap(bis, bos)

            // SSTP Call Connected with Crypto Binding
            sendCallConnected(bos)

            // IPCP Phase
            listener.onStateChanged(SstpState.PPP_IPCP, "Negotiating IPCP network settings...")
            negotiateIpcp(bis, bos)

            val vpnParams = VpnParameters(
                clientIp = clientIp,
                gatewayIp = gatewayIp,
                primaryDns = primaryDns,
                secondaryDns = secondaryDns,
                mtu = config.mtu
            )
            listener.onParametersEstablished(vpnParams)
            listener.onStateChanged(SstpState.CONNECTED, "Connected ($clientIp)")

            // Start Echo Keepalive job
            echoJob = scope.launch {
                keepaliveLoop(bos)
            }

            // Enter Data Pump Loop
            dataPumpLoop(bis)

        } catch (e: Exception) {
            if (e !is CancellationException && isRunning.get()) {
                listener.onError(e)
            }
        } finally {
            close()
        }
    }

    private fun performHttpHandshake(input: InputStream, output: OutputStream) {
        val correlationId = UUID.randomUUID().toString().uppercase()
        val httpRequest = "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n" +
                "SSTPCORRELATIONID: {$correlationId}\r\n" +
                "Content-Length: 18446744073709551615\r\n" +
                "Host: ${config.host}\r\n" +
                "\r\n"

        val reqBytes = httpRequest.toByteArray(StandardCharsets.US_ASCII)
        output.write(reqBytes)
        output.flush()

        // Read HTTP response status line
        val responseLine = readLine(input)
        if (!responseLine.contains("200")) {
            throw IllegalStateException("SSTP HTTP handshake failed: $responseLine")
        }

        // Read remaining headers until blank line
        while (true) {
            val header = readLine(input)
            if (header.isEmpty()) break
        }
    }

    private fun readLine(input: InputStream): String {
        val sb = java.lang.StringBuilder()
        var prev = -1
        while (true) {
            val b = input.read()
            if (b == -1) throw IllegalStateException("EOF while reading HTTP response")
            if (b == '\n'.code && prev == '\r'.code) {
                return sb.substring(0, sb.length - 1)
            }
            sb.append(b.toChar())
            prev = b
        }
    }

    private fun sendSstpConnectRequest(output: OutputStream) {
        val req = SstpPacket.ControlPacket(
            messageType = SstpPacket.MSG_CALL_CONNECT_REQUEST,
            attributes = listOf(SstpAttribute.encapsulatedPpp())
        )
        val bytes = req.encode()
        output.write(bytes)
        output.flush()
    }

    private fun readSstpConnectAck(input: InputStream) {
        val packet = readNextSstpPacket(input)
        if (packet !is SstpPacket.ControlPacket || packet.messageType != SstpPacket.MSG_CALL_CONNECT_ACK) {
            throw IllegalStateException("Expected SSTP CALL_CONNECT_ACK, got $packet")
        }
        for (attr in packet.attributes) {
            if (attr.id == SstpAttribute.ATTRIB_CRYPTO_BINDING_REQ) {
                // Nonce starts at offset 4 of attribute value
                if (attr.value.size >= 36) {
                    val nonce = ByteArray(32)
                    System.arraycopy(attr.value, 4, nonce, 0, 32)
                    serverNonce = nonce
                }
            }
        }
        if (serverNonce == null) {
            // Default 32-byte zeroes if not supplied
            serverNonce = ByteArray(32)
        }
    }

    private fun negotiateLcp(input: InputStream, output: OutputStream) {
        val myMagic = (System.currentTimeMillis() and 0xFFFFFFFFL).toInt()
        val clientReq = LcpPacket(
            code = LcpPacket.CODE_CONFIGURE_REQUEST,
            identifier = 1,
            options = listOf(
                LcpOption.mru(config.mtu),
                LcpOption.magicNumber(myMagic)
            )
        )
        val pppClientReq = PppFrame(PppFrame.PROTO_LCP, clientReq.encode())
        val sstpClientReq = SstpPacket.DataPacket(pppClientReq.encode())
        output.write(sstpClientReq.encode())
        output.flush()

        var clientAcked = false
        var serverAcked = false

        while (!clientAcked || !serverAcked) {
            val pkt = readNextSstpPacket(input)
            if (pkt !is SstpPacket.DataPacket) continue
            val ppp = PppFrame.decode(pkt.payload)
            if (ppp.protocol != PppFrame.PROTO_LCP) continue
            val lcp = LcpPacket.decode(ppp.payload)

            when (lcp.code) {
                LcpPacket.CODE_CONFIGURE_REQUEST -> {
                    // Ack the server's options
                    val ack = LcpPacket(LcpPacket.CODE_CONFIGURE_ACK, lcp.identifier, lcp.options)
                    val sstpAck = SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_LCP, ack.encode()).encode())
                    output.write(sstpAck.encode())
                    output.flush()
                    serverAcked = true
                }
                LcpPacket.CODE_CONFIGURE_ACK -> {
                    clientAcked = true
                }
                LcpPacket.CODE_CONFIGURE_NAK -> {
                    // Resend request with adjusted values
                    val resend = LcpPacket(LcpPacket.CODE_CONFIGURE_REQUEST, (lcp.identifier + 1).toByte(), lcp.options)
                    val sstpResend = SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_LCP, resend.encode()).encode())
                    output.write(sstpResend.encode())
                    output.flush()
                }
            }
        }
    }

    private fun authenticateMsChap(input: InputStream, output: OutputStream) {
        while (true) {
            val pkt = readNextSstpPacket(input)
            if (pkt !is SstpPacket.DataPacket) continue
            val ppp = PppFrame.decode(pkt.payload)
            if (ppp.protocol != PppFrame.PROTO_CHAP) continue

            val chap = ChapPacket.decode(ppp.payload)
            if (chap.code == ChapPacket.CODE_CHALLENGE) {
                val valSize = chap.data[0].toInt() and 0xFF
                val authChallenge = ByteArray(valSize)
                System.arraycopy(chap.data, 1, authChallenge, 0, valSize)

                val peerChallenge = MsChapV2.generatePeerChallenge()
                val ntResponse = MsChapV2.generateNtResponse(
                    authChallenge = authChallenge,
                    peerChallenge = peerChallenge,
                    userName = config.username,
                    password = config.password
                )

                // Derive keys for crypto binding
                val pwhash = MsChapV2.ntPasswordHash(config.password)
                val pwhashhash = MsChapV2.hashNtPasswordHash(pwhash)
                masterKey = MsChapV2.getMasterKey(pwhashhash, ntResponse)

                val chapResp = ChapPacket.buildMsChapV2Response(
                    id = chap.identifier,
                    peerChallenge = peerChallenge,
                    ntResponse = ntResponse,
                    userName = config.username
                )
                val sstpChapResp = SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_CHAP, chapResp.encode()).encode())
                output.write(sstpChapResp.encode())
                output.flush()
            } else if (chap.code == ChapPacket.CODE_SUCCESS) {
                // Auth succeeded
                break
            } else if (chap.code == ChapPacket.CODE_FAILURE) {
                val msg = String(chap.data, StandardCharsets.US_ASCII)
                throw IllegalStateException("MS-CHAPv2 authentication rejected: $msg")
            }
        }
    }

    private fun sendCallConnected(output: OutputStream) {
        val cert = serverCert
        val sha256 = if (cert != null) CryptoBinding.computeCertHashSha256(cert.encoded) else ByteArray(32)
        val sha1 = if (cert != null) CryptoBinding.computeCertHashSha1(cert.encoded) else ByteArray(20)

        val cryptoBindingAttr = CryptoBinding.buildCryptoBindingAttribute(
            nonce = serverNonce ?: ByteArray(32),
            serverCertSha256 = sha256,
            serverCertSha1 = sha1,
            useSha256 = true
        )

        val callConnected = SstpPacket.ControlPacket(
            messageType = SstpPacket.MSG_CALL_CONNECTED,
            attributes = listOf(SstpAttribute(CryptoBinding.SSTP_ATTRIB_CRYPTO_BINDING, cryptoBindingAttr.copyOfRange(4, cryptoBindingAttr.size)))
        )
        val encoded = callConnected.encode()

        // Insert Compound MAC
        val cmKey = CryptoBinding.deriveCompoundMacKey(masterKey ?: ByteArray(16))
        // Attribute offset in ControlPacket: header is 8 bytes, attribute header is 4 bytes, nonce is 4+32=36 bytes -> CMAC is at offset 8 + 4 + 4 + 32 = 48
        val cmacOffset = 8 + 4 + 4 + 32
        if (encoded.size >= cmacOffset + 32) {
            CryptoBinding.computeAndInsertCompoundMac(encoded, cmKey, cmacOffset)
        }

        output.write(encoded)
        output.flush()
    }

    private fun negotiateIpcp(input: InputStream, output: OutputStream) {
        // Request IP 0.0.0.0 and DNS 0.0.0.0
        val req = IpcpPacket(
            code = IpcpPacket.CODE_CONFIGURE_REQUEST,
            identifier = 1,
            options = listOf(
                IpcpOption.ipAddress(ByteArray(4)),
                IpcpOption.primaryDns(ByteArray(4)),
                IpcpOption.secondaryDns(ByteArray(4))
            )
        )
        val pppReq = PppFrame(PppFrame.PROTO_IPCP, req.encode())
        output.write(SstpPacket.DataPacket(pppReq.encode()).encode())
        output.flush()

        var clientAcked = false
        var serverAcked = false

        while (!clientAcked || !serverAcked) {
            val pkt = readNextSstpPacket(input)
            if (pkt !is SstpPacket.DataPacket) continue
            val ppp = PppFrame.decode(pkt.payload)
            if (ppp.protocol != PppFrame.PROTO_IPCP) continue

            val ipcp = IpcpPacket.decode(ppp.payload)
            when (ipcp.code) {
                IpcpPacket.CODE_CONFIGURE_REQUEST -> {
                    // Gateway IP
                    for (opt in ipcp.options) {
                        if (opt.type == IpcpOption.OPTION_IP_ADDRESS && opt.value.size == 4) {
                            gatewayIp = InetAddress.getByAddress(opt.value).hostAddress ?: "10.0.0.1"
                        }
                    }
                    val ack = IpcpPacket(IpcpPacket.CODE_CONFIGURE_ACK, ipcp.identifier, ipcp.options)
                    output.write(SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_IPCP, ack.encode()).encode()).encode())
                    output.flush()
                    serverAcked = true
                }
                IpcpPacket.CODE_CONFIGURE_NAK -> {
                    // Extract suggested IP and DNS
                    for (opt in ipcp.options) {
                        if (opt.type == IpcpOption.OPTION_IP_ADDRESS && opt.value.size == 4) {
                            clientIp = InetAddress.getByAddress(opt.value).hostAddress ?: "10.0.0.2"
                        } else if (opt.type == IpcpOption.OPTION_PRIMARY_DNS && opt.value.size == 4) {
                            primaryDns = InetAddress.getByAddress(opt.value).hostAddress ?: "8.8.8.8"
                        } else if (opt.type == IpcpOption.OPTION_SECONDARY_DNS && opt.value.size == 4) {
                            secondaryDns = InetAddress.getByAddress(opt.value).hostAddress ?: "8.8.4.4"
                        }
                    }
                    // Resend request with configured options
                    val resend = IpcpPacket(IpcpPacket.CODE_CONFIGURE_REQUEST, (ipcp.identifier + 1).toByte(), ipcp.options)
                    output.write(SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_IPCP, resend.encode()).encode()).encode())
                    output.flush()
                }
                IpcpPacket.CODE_CONFIGURE_ACK -> {
                    clientAcked = true
                }
            }
        }
    }

    private suspend fun keepaliveLoop(output: OutputStream) {
        val echoReq = SstpPacket.ControlPacket(messageType = SstpPacket.MSG_ECHO_REQUEST).encode()
        while (isRunning.get()) {
            delay(config.keepaliveIntervalSec * 1000L)
            try {
                synchronized(output) {
                    output.write(echoReq)
                    output.flush()
                }
            } catch (_: Exception) {
                break
            }
        }
    }

    private fun dataPumpLoop(input: InputStream) {
        while (isRunning.get()) {
            val pkt = readNextSstpPacket(input)
            if (pkt is SstpPacket.DataPacket) {
                val ppp = PppFrame.decode(pkt.payload)
                if (ppp.protocol == PppFrame.PROTO_IP) {
                    rxBytes.addAndGet(ppp.payload.size.toLong())
                    listener.onBytesTransferred(0, ppp.payload.size.toLong())
                    listener.onDataPacketReceived(ppp.payload)
                }
            } else if (pkt is SstpPacket.ControlPacket) {
                if (pkt.messageType == SstpPacket.MSG_ECHO_REQUEST) {
                    val echoResp = SstpPacket.ControlPacket(messageType = SstpPacket.MSG_ECHO_RESPONSE).encode()
                    outputStream?.let { os ->
                        synchronized(os) {
                            os.write(echoResp)
                            os.flush()
                        }
                    }
                } else if (pkt.messageType == SstpPacket.MSG_CALL_DISCONNECT || pkt.messageType == SstpPacket.MSG_CALL_ABORT) {
                    break
                }
            }
        }
    }

    /**
     * Sends an IPv4 packet through the tunnel (encapsulated into PPP -> SSTP data packet).
     */
    fun sendIpPacket(packet: ByteArray, length: Int) {
        if (!isRunning.get()) return
        val os = outputStream ?: return
        val pppPayload = if (length == packet.size) packet else packet.copyOf(length)
        val pppFrame = PppFrame(PppFrame.PROTO_IP, pppPayload)
        val sstpData = SstpPacket.DataPacket(pppFrame.encode())
        val bytes = sstpData.encode()
        synchronized(os) {
            os.write(bytes)
            os.flush()
        }
        txBytes.addAndGet(length.toLong())
        listener.onBytesTransferred(length.toLong(), 0)
    }

    private fun readNextSstpPacket(input: InputStream): SstpPacket {
        val header = ByteArray(4)
        var readTotal = 0
        while (readTotal < 4) {
            val count = input.read(header, readTotal, 4 - readTotal)
            if (count == -1) throw IllegalStateException("Connection closed by server")
            readTotal += count
        }
        val len = ((header[2].toInt() and 0x0F) shl 8) or (header[3].toInt() and 0xFF)
        if (len < 4) throw IllegalStateException("Invalid SSTP packet length: $len")

        val full = ByteArray(len)
        System.arraycopy(header, 0, full, 0, 4)
        while (readTotal < len) {
            val count = input.read(full, readTotal, len - readTotal)
            if (count == -1) throw IllegalStateException("EOF while reading packet body")
            readTotal += count
        }
        return SstpPacket.decode(full)
    }

    fun close() {
        if (isRunning.compareAndSet(true, false)) {
            echoJob?.cancel()
            listener.onStateChanged(SstpState.DISCONNECTING, "Disconnecting...")
            try {
                outputStream?.let { os ->
                    val disconnect = SstpPacket.ControlPacket(messageType = SstpPacket.MSG_CALL_DISCONNECT).encode()
                    os.write(disconnect)
                    os.flush()
                }
            } catch (_: Exception) {}
            try { sslSocket?.close() } catch (_: Exception) {}
            listener.onStateChanged(SstpState.DISCONNECTED, "Disconnected")
        }
    }
}

