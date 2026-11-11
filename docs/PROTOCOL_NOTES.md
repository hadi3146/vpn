# Aether VPN Protocol Notes: SSTP, PPP, SNI Bypass & DoT

## 1. MS-SSTP Architecture & Handshake

MS-SSTP (Secure Socket Tunneling Protocol) encapsulates PPP frames over a TLS connection (typically port 443).

### Step 1: HTTP Duplex Post Handshake
The client issues an HTTP POST request with method `SSTP_DUPLEX_POST`:
```http
SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n
SSTPCORRELATIONID: {<UUID>}\r\n
Content-Length: 18446744073709551615\r\n
Host: <hostname>\r\n
\r\n
```
The server answers with `HTTP/1.1 200 OK`. Immediately following the HTTP header separator (`\r\n\r\n`), both endpoints transition to raw SSTP binary packet framing.

### Step 2: SSTP Packet Structure
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |   Reserved  |C|            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Message Type            |       Num Attributes          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
- **Version**: `0x10` (SSTP v1.0).
- **Control Flag (C)**: `0x01` for Control packets, `0x00` for Data packets.
- **Length**: 12-bit integer indicating total packet size (including 4-byte header).
- **Data Packets**: Direct encapsulation of higher-layer PPP packets without message type or attributes.

### Step 3: Crypto Binding & Compound MAC
To protect against Man-in-the-Middle (MitM) attacks where an attacker terminates the TLS connection independently of the PPP credentials, SSTP enforces Crypto Binding:
1. Server supplies a 32-byte `Nonce` in `SSTP_MSG_CALL_CONNECT_ACK`.
2. Client hashes server's leaf X.509 certificate using SHA-256 and SHA-1.
3. Client derives Compound MAC Key (CMK) from the MS-CHAPv2 Master Key:
   `CMK = HMAC_SHA256(MasterKey, "SSTP inner method key derivation")`
4. Client forms `SSTP_MSG_CALL_CONNECTED` packet with 104-byte Crypto Binding attribute:
   - Attribute Header (4 bytes)
   - Hash Protocol Bitmask (1 byte: `0x02` for SHA-256)
   - Nonce (32 bytes)
   - Compound MAC placeholder (32 bytes of `0x00`)
   - Certificate Hash (32 bytes)
5. Client computes `HMAC_SHA256(CMK, CallConnectedPacket)` and writes the 32-byte digest into the Compound MAC placeholder.

---

## 2. PPP State Machine

1. **LCP (Link Control Protocol - 0xC021)**:
   - Client sends `Configure-Request` with MRU (1400) and Magic Number.
   - Server responds with `Configure-Request` negotiating `MS-CHAPv2` (`0xC223`, algorithm `0x81`).
   - Mutual `Configure-Ack` confirms options.
2. **Authentication (MS-CHAPv2 - 0xC223)**:
   - Server sends `Challenge` (16 bytes).
   - Client generates 16-byte `PeerChallenge` and computes 24-byte `NT-Response` via DES operations on 8-byte `ChallengeHash` (RFC 2759).
   - Client responds with 49-byte CHAP payload.
   - Server returns `Success` with `AuthenticatorResponse` (`S=<40 hex digits>`).
3. **IPCP (IP Control Protocol - 0x8021)**:
   - Client sends `Configure-Request` requesting IP `0.0.0.0` and DNS `0.0.0.0`.
   - Server responds with `Configure-Nak` containing assigned client IP, Primary DNS, and Secondary DNS.
   - Client acks and establishes tunnel interface (`VpnService.Builder.establish()`).

---

## 3. SNI-Blocking Bypass Strategies

Deep Packet Inspection (DPI) censorship equipment monitors the unencrypted `Server Name Indication` (SNI) extension inside the initial TLS `ClientHello` segment. Aether VPN defeats this via three automatic fallback strategies:

1. **Direct IP / No SNI (`DIRECT_IP_NO_SNI`)**:
   Connects directly to the IP without populating the TLS SNI extension. SoftEther servers host SSTP by default on their IP endpoint and do not require SNI.
2. **TCP ClientHello Fragmentation (`TCP_FRAGMENTATION`)**:
   Splits the initial TLS ClientHello across two separate TCP packets with a brief timing delay (10ms) and `TCP_NODELAY`. Because censorship middleboxes perform stateless inspection or have small reassembly buffers, the split SNI domain name evades detection while the destination server's TCP stack reassembles the stream transparently.
3. **TLS Record Fragmentation (`TLS_RECORD_FRAGMENTATION`)**:
   Splits the ClientHello handshake payload across two distinct TLS Handshake records (`ContentType: 0x16`). Conforming TLS implementations (RFC 5246 Section 6.2.1) reassemble multi-record handshake messages before processing.
4. **Custom / Fake SNI (`CUSTOM_SNI`)**:
   Replaces the SNI hostname with an unblocked domain name while preserving connection to the destination server IP.

---

## 4. DNS over TLS (RFC 7858) Interceptor

1. The TUN interface intercepts outbound IPv4 UDP packets destined for port 53.
2. The packet payload (DNS wire format) is forwarded over an established TLS connection on port 853 to the user's selected DoT resolver (Cloudflare, Google, Quad9, AdGuard).
3. The resolver's response is encapsulated into a synthesized IPv4 UDP packet matching the client's original query port and written back to the TUN descriptor.
4. In **DNS-Only Mode**, the VPN routes only the dummy DNS address (`10.254.254.254/32`), allowing all general app traffic to bypass the VPN tunnel entirely.

