# Radin VPN (`رادین وی‌پی‌ان`) — Project Progress & Engineering Roadmap

**Last Updated:** 2026-11-18  
**Current Version:** `v1.9.0` (`versionCode = 35`)  
**Active APK:** `app/build/outputs/apk/debug/RadinVpn 1.9.0-debug.apk`  
**Modules:**
- `:vpncore`: Pure Kotlin protocol library (SoftEther Native Multi-TCP protocol, userspace MS-SSTP, PPP, LCP, RFC 2759 MS-CHAPv2, Crypto Binding CMAC, IPCP, DoT/DoH, CensorshipDetector, MultiServerRacer, SniBypassSocketFactory, TunnelPackets, WireGuard/Cloudflare WARP engine).
- `:app`: Android application layer (Jetpack Compose, Material 3, Hilt DI, KSP, Room DB, Preferences DataStore, AetherVpnService, WarpService, AetherTileService, BootReceiver, IranRoutingRules).
**Package ID:** `com.aethervpn.client` (debug: `com.aethervpn.client.debug`, preserved for zero-wipe in-place upgrades).

---

## 1. Version Progression History

| Version | Build | Date | Core Milestone & Key Technical Additions |
| :--- | :---: | :---: | :--- |
| **`v1.9.0`** | `35` | 2026-11-18 | **SoftEther Native Multi-TCP Engine, Zero-Allocation Data Pump & High-BDP Latency Tuning**: <br>• **Native SoftEther Cedar Protocol (`SoftEtherClient` & `SoftEtherChannel`)**: Full userspace implementation of the native SoftEther protocol (`/vpn/connect.cgi` HTTP 1.1 handshake, `VPNCONNECT` JPEG signature, `SoftEtherPack` RPC encoder/decoder, and SHA0/MD4 password authentication). <br>• **Multi-TCP Channel Bonding**: Concurrent multi-stream TCP connection bonding (2 channels default, scalable to 32) with 5-tuple flow hashing (`computeFlowHash`) to preserve TCP packet sequence ordering across links while aggregating bandwidth. <br>• **Zero-Allocation Fast-Path Data Pump**: Decodes Ethernet frames in-place with zero heap allocations; encapsulates outbound IPv4 packets directly into `ByteBuffer txBuffer` without intermediate `ByteArray` or `System.arraycopy` allocations. Pre-allocated 512KB stream buffers matching high-BDP performance. <br>• **Virtual Layer-2 Switch / NAT Networking**: RFC 826 ARP discovery and reply engine with standard 60-byte minimum Ethernet frame padding; dynamic Gateway MAC address learning from incoming Ethernet traffic; Virtual DHCP client with Option 61 (Client Identifier) support for Japanese and international VPN Gate hubs. <br>• **TCP_NODELAY & Fast 2s Reconnect**: Enabled `TCP_NODELAY` on all SoftEther TLS sockets (disabling Nagle's algorithm for low-latency interactive traffic); reduced channel supervision loop to 2 seconds for instantaneous dead-channel recovery without tunnel resets; calibrated stall watchdog and expanded DNS cache TTL to 30 minutes (`1800L`). Live verified on Samsung Galaxy A54 5G (`SM_A546E`). |
| **`v1.8.3`** | `28` | 2026-11-15 | **Extreme Censorship Fortification (Universal Custom Configs, WARP Multi-Port Rotation & Emergency Bootstrap)**: <br>• **Cloudflare WARP Multi-Port & In-Flight Rotation**: Expanded Anycast IP candidate pool in `CloudflareCleanIpScanner` to 40+ verified Anycast IPs. Re-architected `WarpService` to execute candidate probe loops across diverse bypass ports (`2408`, `500`, `1701`, `443`, `880`) with automatic in-flight rotation before failing over. Added resilient DNS in `WarpRegistrar` bypassing SNI/DNS poisoning on `api.cloudflareclient.com`. <br>• **Universal Custom Server & Bridge Config Import**: Upgraded `SstpUriCodec` to parse standard modern links: VLESS (`vless://`), Shadowsocks (`ss://` with Base64 and plaintext), Trojan (`trojan://`), WireGuard/WARP (`wg://`, `warp://`), and SSTP. Displays protocol badges (`[VLESS]`, `[SHADOWSOCKS]`, `[TROJAN]`, `[WARP]`) in `ServersScreen`. <br>• **Emergency Directory Bootstrap**: Multi-tier DNS resolution in `ServerRepository` chaining System DNS -> DoT -> DoH with SNI Bypass -> Emergency Core Anycast Direct-IP fallback for core mirror domains during total DNS blackouts. Verified on Samsung Galaxy A54 (`SM_A546E`). |
| **`v1.8.2`** | `27` | 2026-11-15 | **Video Download & High-BDP Throughput Optimization for Telegram & Instagram**: <br>• **Zero-Allocation Fast Path Data Pump**: Eliminated 3 `ByteArray` allocations and multiple `System.arraycopy` calls per downlink frame in `SstpClient.dataPumpLoop`. Incoming IPv4 data frames (`FF 03 00 21` or `FF 03 21`) are decoded in-place and streamed directly to TUN via `tunOutputStream.write(buf, offset, length)` with 0 heap allocations, completely eliminating Android GC pauses during 4K/HD video downloads. <br>• **TCP Window Scale & Buffer Expansion**: Pre-connect `rawSocket.receiveBufferSize = 2 * 1024 * 1024` (2MB) and `sendBufferSize = 1 * 1024 * 1024` (1MB) to negotiate dynamic TCP Window Scaling during initial SYN handshake. Set `IPTOS_THROUGHPUT` (`0x08`) traffic class. Expanded `SslEngineTransport` internal buffers from 16KB to 64KB. <br>• **Fast-Exit MSS Clamping**: Bypass option parsing for non-SYN TCP packets in `MssClamper.clampMss`. <br>• **Atomic Fast TX Packaging**: Single-write frame assembly in `sendIpPacket` via `txFastBuf` to prevent fragmented TCP ACK writes. <br>• **European CDN Prioritization & Auto-Quarantine Failover**: Prioritized European servers (Amsterdam/Frankfurt) to minimize round-trip latency to Telegram DCs and Instagram edge CDNs. Built-in active verification (`TG=true, IG=true, HTTP=true`) automatically blacklists/quarantines nodes that pass handshake but drop social media traffic. Verified live on Samsung Galaxy A54 (`SM_A546E`). |
| **`v1.8.1`** | `26` | 2026-11-15 | **BDP Buffering & European Route Sorting Foundation**: Initial integration of European route preference and socket buffer scaling. |
| **`v1.8.0`** | `25` | 2026-11-15 | **Persian UX Polish, Navigation Stack Fix & Cloudflare Multi-ISP Stability**: <br>• **Connecting Animation**: Added smooth pulsing connection indicator with localized Persian status banner ("درحال تلاش برای عبور از فیلترینگ"). <br>• **Navigation Back-Stack Fix**: Fixed Compose Navigation issue where switching between `ServersScreen` and `HomeScreen` could stall or lose state; integrated `popUpTo(NavRoutes.Home.route) { saveState = true }`. <br>• **Cloudflare Multi-ISP Resilience**: Resolved Cloudflare WARP handshake failure on cellular/Wi-Fi networks by adding clean endpoint rotation and dynamic port fallback. |
| **`v1.7.5`** | `20` | 2026-11-15 | **Telegram & Instagram In-Tunnel Health Verification**: Added active TCP probing to Telegram Middle East/Europe DCs and Instagram CDN edge points directly inside the newly established tunnel. Discards blackhole nodes that spoof HTTP success but drop messaging traffic. |
| **`v1.7.4`** | `19` | 2026-11-14 | **Battery Optimization & Network Switch Handover**: Minimized foreground wake locks during idle VPN state; added seamless physical network handover (Wi-Fi to Cellular and vice-versa) with learned bypass strategy retention. |
| **`v1.7.3`** | `18` | 2026-11-14 | **Cloudflare WARP Engine Integration**: Embedded pure WireGuard / Cloudflare WARP engine (`WarpService.kt`, `vpncore/warp`) as an alternative tunnel protocol to SoftEther SSTP. |
| **`v1.7.2`** | `17` | 2026-11-14 | **Adaptive Keepalive Throttling**: Throttled SSTP echo requests during device screen-off to significantly extend mobile battery life. |
| **`v1.7.1`** | `16` | 2026-11-14 | **Major Upgrade (Phases 1, 2, & 3 — Performance, Multi-Port, & Censorship-Resilience Engine)**: Live installed and verified on Samsung Galaxy A54 (`SM_A546E`). <br>• **Phase 1 (Optimization)**: Zero-Copy Framing in `SstpClient` (eliminated 6 allocations per packet); removed redundant `tun.flush()`; composite Room database indices (`MIGRATION_2_3`); full migration to KSP (`2.0.21-1.0.28`). <br>• **Phase 2 (Discovery & Visuals)**: Multi-port SoftEther discovery from OpenVPN config data (995, 1495, 1512, 1571, etc.); candidate port failover probe with Room persistence; batch ping with `Semaphore(6)` and live progress card; Compose `Canvas` Live Speed Graph with 30s rolling dual-gradient curves. <br>• **Phase 3 (Smart Sorting, `sstp://` Codec, CDN Mirrors, Multi-Port Racing, & Decoy SNI)**: (1) Dynamic Server Sorting Chips (`DEFAULT`, `PING`, `SPEED`, `SCORE`, `SESSIONS`) in `ServersScreen`. (2) `SstpUriCodec` with standard URI parsing/generation (`sstp://user:pass@host:port?sni=...#Name`), 1-tap clipboard share on custom servers, and link import in dialog. (3) Multi-tier Censorship-Resistant CDN Mirrors (jsDelivr, GitHub raw, fallback mirrors) with automatic HTML block-page rejection (`isValidVpnGateCsv`) and 1-tap default mirror restore in settings. (4) Multi-port parallel candidate racing across ports 443, 992, and 5555 in `AetherVpnService` with auto-winner port persistence. (5) Enterprise Decoy SNI presets (`teams.microsoft.com`, `gateway.icloud.com`, `cdn.samsung.com`) with instant suggestion chips in settings. |
| **`v1.7.0`** | `15` | 2026-11-13 | **Phase 1 Performance & KSP Foundation**: Initial zero-copy SSTP pump and KSP migration release. |
| **`v1.6.7`** | `14` | 2026-11-13 | **SSTP/PPP Stability & TCP Window Auto-Tuning**: Diagnosed connection drops on high-latency international links (Japan/Europe ~700ms RTT). Removed artificial 1460-byte receive buffer clamp in `SniBypassSocketFactory` to eliminate SoftEther 1s PPP timer expiration. Refined `isNonTransportFailure` guard in `AetherVpnService` to prevent false-positive auth aborts, guaranteeing `DIRECT_IP_NO_SNI` fallback. Live verified on Samsung `SM_A546E`: instant handshake, IPCP assigned `10.238.239.64`, public IP verified to `219.100.37.238` (Japan), and sustained live traffic confirmed. |
| **`v1.6.6`** | `13` | 2026-11-12 | **Deep Censorship Diagnostics & Packet Tracing**: Added granular LCP/IPCP packet tracing, timing instrumentation, and detailed error mapping in `AetherVpnService` to isolate transport vs authentication failures. |
| **`v1.6.5`** | `12` | 2026-11-12 | **Zapret & ByeDPI Style TCP Desync Integration**: Added `ZAPRET_SPLIT1_DESYNC` (1-byte split with out-of-order pacing) and `WINDOW_ALPN_MICRO_DESYNC` for middlebox evasion. |
| **`v1.6.4`** | `11` | 2026-11-12 | **Anti-Blackhole Fast Failover Heuristics**: Improved consecutive failure counters and intelligent candidate switching to prevent connection stalls on dead volunteer nodes. |
| **`v1.6.3`** | `10` | 2026-11-12 | **Tsukuba University High-Bandwidth Core Ranking**: Prioritized official high-capacity academic SoftEther servers with verified DHCP/SecureNAT pools in server catalog. |
| **`v1.6.2`** | `9` | 2026-11-12 | **Europe & Global Catalog Filters**: Added interactive regional filter chips, real-time RTT sorting, and live Room database query optimizations in `ServersScreen`. |
| **`v1.6.1`** | `8` | 2026-11-12 | **UI & Diagnostics Polish**: Improved status banner telemetry, dynamic speed measurement cards, and wireless ADB live debugging support. |
| **`v1.6.0`** | `7` | 2026-11-12 | **TLS Header + SNI Desync & Parallel 3-Server Racer**: Added `TLS_HEADER_DESYNC` 2-byte record split + SNI midpoint segmentation; eliminated `MULTI_CHUNK_FRAGMENTATION` timeout via surgical 3-record split; integrated `MultiServerRacer` for country/subnet-diverse parallel racing. |
| **`v1.5.0`** | `6` | 2026-11-12 | **Radin VPN Rebrand & Censorship Detector (`AUTO_SMART`)**: Rebranded to **Radin VPN / رادین وی‌پی‌ان**; parallel detector classifying `IP_OR_PORT_BLOCKED`, `OPEN_NO_FILTER`, `SNI_DPI_ACTIVE`, and `DEEP_CLIENTHELLO_DPI`; SNI-midpoint fragmentation; on-demand Smart Bypass Scan. |
| **`v1.4.0`** | `5` | 2026-11-11 | **Live Connection Diagnostics Telemetry & Remote IR CIDR Refresh**: Expandable diagnostics card (link type, split routes, DNS cache hit-rate), RIPEstat remote CIDR updater with safety validation, and in-place custom server editing. |
| **`v1.3.0`** | `4` | 2026-11-11 | **IPv6 Leak Guard & Per-Network Profiles**: `::/0` fail-fast ICMPv6 Prohibited responder; `WIFI`/`CELLULAR` learned bypass persistence; bounded TTL+LRU DNS cache; custom domain/IP direct bypass rules. |
| **`v1.2.0`** | `3` | 2026-11-10 | **Iran Split Routing & Split DNS**: 1,747 bundled RIPE Iran IPv4 CIDRs via `excludeRoute` / 32-bit trie; direct ISP DNS for `.ir` and domestic services; unlimited mid-session failover. |
| **`v1.1.0`** | `2` | 2026-11-10 | **Anti-Blackhole Verification & Adaptive Icon**: In-tunnel HTTP trace verification; 20m Room quarantine; 2-window keepalive watchdog; QUIC UDP:443 ICMP fallback; adaptive app icon. |
| **`v1.0.0`** | `1` | 2026-11-09 | **Initial Userspace MS-SSTP Engine**: Full SSTP client, MS-CHAPv2 + CryptoBinding, VPN Gate directory browser, DoT DNS changer, per-app split tunnel, EN/FA Material 3 UI. |

---

## 2. Root Cause Analysis & Technical Resolutions (`v1.9.0` SoftEther Native Engine)

During integration and field testing of the native SoftEther multi-TCP protocol stack on Samsung Galaxy A54 (`SM_A546E`), several critical issues were identified and resolved:

### Root Cause 1: Socket Timeout Expiration on Idle Channels
- **The Bug:** `SniBypassSocketFactory` configured a default `soTimeout = 10000` (10 seconds) for handshakes. Once the tunnel was established and traffic paused, `readLoop` threw `SocketTimeoutException: Read timed out`, causing the channel reader thread to abort and mark the channel disconnected.
- **The Mechanism:** Idle periods between network interactions caused all channels to exit simultaneously, triggering `"All SoftEther channels disconnected"` after 10-20 seconds.
- **The Fix:** Configured `t.setSoTimeout(0)` (infinite timeout) immediately after handshake completion on both primary and secondary channels. Additionally, caught `SocketTimeoutException` inside `readLoop` with `continue` to guarantee infinite channel lifetime during idle state.

### Root Cause 2: Gateway MAC Resolution & Undersized ARP Frames
- **The Bug:** Fallback DHCP used a static or broadcast MAC address, and initial ARP reply frames were formatted at 42 bytes.
- **The Mechanism:** Ethernet standards require a minimum frame length of 60 bytes (excluding 4-byte FCS, total 64 bytes on the wire). Virtual switches dropped undersized 42-byte frames, preventing bidirectional gateway communication. Furthermore, when DHCP did not reply with a gateway MAC, unicast frames could not reach the Virtual NAT router.
- **The Fix:** Padded all ARP frames to the standard 60-byte minimum. Implemented dynamic Gateway MAC learning from the first incoming IPv4 Ethernet frame whenever `gatewayMac` is still broadcast, ensuring reliable Layer-2 packet routing.

### Root Cause 3: DHCP Failure on Academic & Japanese VPN Gate Hubs
- **The Bug:** Virtual DHCP `DISCOVER` and `REQUEST` packets omitted DHCP Option 61 (Client Identifier).
- **The Mechanism:** Many SoftEther Virtual Hubs running on academic networks (such as Tsukuba University) ignore DHCP requests lacking hardware client identification (`Option 61: hwType=1, MAC`).
- **The Fix:** Added Option 61 to both `DISCOVER` and `REQUEST` packet builders in `SoftEtherDhcp.kt`.

### Root Cause 4: Interactive Latency & Buffer Bloat
- **The Bug:** Nagle's algorithm was enabled by default on underlying TCP sockets, and `txBuffer` allocated intermediate arrays on every transmission.
- **The Mechanism:** Nagle's algorithm buffered small TCP ACK packets up to 40ms before transmission, making Telegram chat sync and Instagram story loading sluggish.
- **The Fix:** Enabled `TCP_NODELAY` across all active SoftEther channels. Replaced all intermediate array allocations with direct `ByteBuffer` framing (`sendIpPacketAsFrame`), pre-buffered streams with 512KB buffers, and reduced supervisor loop interval from 10s to 2s for immediate channel heal.

---

## 3. Root Cause Analysis & Technical Resolutions (`v1.6.7`)

In versions `v1.6.5`–`v1.6.6`, live testing on the user's phone (`SM_A546E`) under Iran's network environment showed intermittent connection failures where the client reached the server but was abruptly disconnected with errors such as:
- `LCP terminated by server during MS-CHAPv2 authentication`
- `Server disconnected during IPCP negotiation`
- `Server rejected SSTP/auth; skipping remaining SNI retries`

### Root Cause 1: TCP Receive Window Clamping on High-RTT International Links
- **The Bug:** In `vpncore/src/main/java/com/aethervpn/vpncore/transport/SniBypassSocketFactory.kt` (line 85), `receiveBufferSizeBytes` was clamped to `1460` bytes (1 MSS) for `ZAPRET_SPLIT1_DESYNC` and `WINDOW_ALPN_MICRO_DESYNC`.
- **The Mechanism:** On high-latency international connections (Iran to Japan RTT is typically 600–750 ms), restricting the TCP receive window to 1 MSS limits TCP throughput to `Window / RTT = 1460 bytes / 0.7s ≈ 2 KB/s`. Any packet loss or jitter caused TCP retransmission stalls.
- **The Impact on SoftEther:** SoftEther VPN Server's PPP state machine (`Proto_SSTP.c` and `Proto_PPP.c`) operates on strict 1-second timer ticks. When authentication responses or IPCP Configure-Requests were delayed beyond the timer, the server sent an `LCP Terminate-Request` or `SSTP_MSG_CALL_DISCONNECT`.
- **The Fix:** Removed the `receiveBufferSizeBytes = 1460` clamp, returning it to `null` to allow Android Linux kernel's dynamic TCP receive window auto-tuning (`tcp_rmem`).

### Root Cause 2: Premature Auth Abort (False-Positive NonTransport Failure)
- **The Bug:** In `app/src/main/java/com/aethervpn/client/service/AetherVpnService.kt`, `isNonTransportFailure` matched the string `"during MS-CHAPv2 authentication"` and immediately aborted the server with:
  `Server rejected SSTP/auth; skipping remaining SNI retries`
- **The Mechanism:** When the server terminated LCP due to a desync timing delay, the client misclassified this transport/timing issue as a definitive authentication rejection (wrong username/password). Consequently, the remaining bypass strategies—crucially `DIRECT_IP_NO_SNI` and `DISABLED`—were skipped completely, and the server was abandoned.
- **The Fix:** Added an `isDefinitiveAuthFailure` guard: only abort remaining strategies if the failure occurred on a direct transport (`DIRECT_IP_NO_SNI` or `DISABLED`). If a desync strategy timed out, fallback to `DIRECT_IP_NO_SNI` is preserved.

### Root Cause 3: Inverted Strategy Priority Order
- **The Bug:** `SniStrategy.concreteFallbackOrder` prioritized experimental desync strategies (`ZAPRET_SPLIT1_DESYNC`) over direct IP transport.
- **The Mechanism:** SoftEther servers listen directly on their public IP and do not host multi-tenant virtual domains requiring an SNI extension. Connecting directly to the server IP with no SNI extension (`DIRECT_IP_NO_SNI`) produces an unblocked ClientHello (no domain for DPI to match) without mangling TCP segments or introducing packet delays.
- **The Fix:** Placed `DIRECT_IP_NO_SNI` at index 0 of `concreteFallbackOrder` whenever `hasCustomSni == false`.

---

## 4. Verified Hardware Baseline (Live Test Results)

- **Device:** Samsung Galaxy A54 5G (`SM_A546E`), Android 16 (API 36 / One UI).
- **Network Interface:** Wireless ADB (`192.168.100.20:5555`), Iranian domestic Wi-Fi / Cellular.
- **Tested Build:** `RadinVpn 1.9.0-debug.apk` (`versionCode = 35`).
- **Live Connection & Multi-TCP Verification:**
  - Active Protocol: **SoftEther Native Multi-TCP Protocol** (Cedar engine).
  - Active Channel Topology: 2 concurrent TCP connections (`targetConnections = 2`) bonded under single Virtual Hub session (`VPNGATE`).
  - Active Node: Romania (`217.138.212.62:443`) and Japan Tsukuba (`221.71.128.44:1735`).
  - Strategy: `WIFI • DIRECT_IP_NO_SNI` with `TCP_NODELAY = true`.
  - Tunnel Stability: Verified sustained connection exceeding 7+ minutes without disconnects (`Duration: 07:24`).
  - Telegram & Social Media: Telegram chats, real-time incoming messages, and full-resolution media/stories downloaded instantaneously at high throughput with zero stalls.
  - Data Pump & Low-Latency Fast Path:
    - Zero-allocation Ethernet framing active (`ByteBuffer txBuffer` contiguous writes).
    - Dynamic Gateway MAC learning active.
    - 512KB stream buffers and 2s fast supervisor active.

---

## 4. Installed Circumvention Benchmark Analysis

In-depth reverse engineering of circumvention architectures installed on the test device (`SM_A546E`) provided key insights for upcoming Radin VPN capabilities:

| App / Package | Architecture & Engine | Key Mechanism | Applicability to Radin VPN |
| :--- | :--- | :--- | :--- |
| **Oblivion** (`org.bepass.oblivion`) | Go (`libgojni.so`) + Cloudflare WARP WireGuard | Clean-IP scanning + random noise padding (AmneziaWG style) | Can provide server-less free tunnels when SoftEther TCP:443 is throttled. |
| **MahsaNG** (`com.MahsaNet.MahsaNG`) | Xray-core / V2Ray + WARP | Multiplexed VLESS/VMess with clean IP rotation and gRPC/WS | Reference for multi-transport failover and subscription parsing. |
| **DNSTT / Slipstream** (`xyz.dnstt.app`, `app.slipnet`) | Go (`libslipstream.so`, `libmasterdns.so`) | DNS tunneling over UDP:53 and DoH/DoT | Ideal for emergency bootstrap to fetch fresh mirror lists during total internet blackouts. |
| **SEVPN** (`com.giamping.sevpn`) | SoftEther + OpenVPN (`libopenvpn.so`, `libgojni.so`) | SoftEther protocol over multiple ports (`992`, `5555`, `1194`) | Free VPN Gate directory offers non-443 ports; adding port scanning expands reachable servers. |
| **ArgoVPN** (`com.filtershekanha.argovpn`) | Custom proxy + Falcon / Bridges | Clean Cloudflare fronting and domain-fronted bridges | Confirms effectiveness of direct-IP and decoy SNI strategies. |

---

## 5. Engineering Roadmap & Next Steps

When continuing in a new chat, the following milestones represent the highest-priority enhancements:

### Milestone 1: Server-Less WireGuard / Cloudflare WARP Engine (Free & Resilient)
- **Goal:** Enable users to connect without relying solely on SoftEther/VPN Gate volunteer nodes.
- **Design:**
  - Embed a lightweight WireGuard/WARP client in `:vpncore`.
  - Implement a clean-IP endpoint scanner that tests Cloudflare Anycast IPs (e.g. `162.159.192.0/24`, `188.114.96.0/24`) for low packet loss and zero handshake blocking.
  - Implement AmneziaWG-style junk packet noise padding (random payload header bytes) to defeat WireGuard protocol fingerprinting.

### Milestone 2: Multi-Port SoftEther & OpenVPN-TCP Support
- **Goal:** Utilize alternative ports published in the VPN Gate directory.
- **Design:**
  - Many VPN Gate nodes listen on ports `992`, `5555`, `1194`, and dynamic high ports in addition to `443`.
  - Enable port-probing in `ServerRepository` so when port 443 is blocked on an IP, alternative ports are tried automatically.

### Milestone 3: Emergency DNS Tunneling Bootstrap
- **Goal:** Survive total network whitelisting ("Melli Internet").
- **Design:**
  - Integrate a lightweight DNSTT/DoH resolver client strictly for emergency directory bootstrap.
  - Allows downloading fresh server lists and clean IPs even when all direct foreign TCP/UDP connections are dropped.

### Milestone 4: Production Signed Release Pipeline
- **Goal:** Produce signed, R8-minified release APKs.
- **Design:**
  - Automate APK signing using `keystore.properties`.
  - Verify ProGuard/R8 rules to ensure no reflection-based crashes in Hilt, Room, or Compose.

---

## 2026-11-15 - v1.8.4 (Build 29): Mobile Operator DPI Bypass & Provincial Gateway Resilience (Isfahan/MCI/Irancell)

### 1. Root Cause Analysis (Why Fixed Mokhaberat/Shatel Worked, but Isfahan / Mobile Failed)
1. **Strict "No-SNI = Drop/RST" Rule on Mobile / Provincial Gateways**:
   - Fixed-line broadband (TCI/Mokhaberat, Shatel in Tehran) historically enforces SNI domain blacklists only (`youtube.com`, `instagram.com`). If a TLS ClientHello omits the SNI extension (`DIRECT_IP_NO_SNI`), the packet passes freely.
   - On Iranian mobile carriers (MCI, Irancell, Rightel) and provincial TIC gateways (such as Isfahan), DPI equipment (Huawei/ZTE/Sandvine) actively enforces a strict heuristic: modern browsers and OS network stacks always send an SNI extension. TLS ClientHellos lacking SNI are classified as unauthorized proxies or bots and dropped or reset (`TCP RST`).
2. **Missing Decoy SNI in Fragmentation & Desync Bypass Strategies**:
   - In `SniBypassSocketFactory.kt`, `resolveTargetSni` only populated a decoy SNI for `DECOY_SNI_FRAGMENT`. For `ZAPRET_SPLIT1_DESYNC`, `TLS_HEADER_DESYNC`, and `MULTI_CHUNK_FRAGMENTATION`, when connecting by IP, `resolveTargetSni` returned `null`, which resulted in NO SNI being sent.
   - On strict networks, `CensorshipDetector` thus saw all bypass attempts fail, concluding "All bypass strategies blocked".
3. **Port 443 Throttling vs. Alternative SoftEther Ports (992 / 5555)**:
   - When port 443 was blocked by the ISP, the connection immediately aborted without probing SoftEther's native listeners on ports `992` (SSL-VPN) and `5555` (SoftEther default), which are frequently unblocked.
4. **Stale/Sparse Initial Fallback CSV**:
   - On fresh installs in restricted provinces where `vpngate.net` was unreachable, the bundled catalog had only 31 servers (dominated by academic nodes filtered by `isRestrictedAcademicSubnet`).

### 2. Implementation Details in v1.8.4
1. **Universal Decoy SNI Default (`SniBypassSocketFactory.kt`)**:
   - `resolveTargetSni` now automatically injects `DEFAULT_DECOY_SNIS.first()` (`teams.microsoft.com`) whenever connecting by IP or to unconfigured VPN Gate nodes for all bypass strategies (`ZAPRET_SPLIT1_DESYNC`, `TLS_HEADER_DESYNC`, `WINDOW_ALPN_MICRO_DESYNC`, `MULTI_CHUNK_FRAGMENTATION`).
   - Prioritized unblocked decoys in `SniStrategy.DEFAULT_DECOY_SNIS`: `teams.microsoft.com`, `gateway.icloud.com`, `dl.google.com`, `speed.cloudflare.com`.
2. **Network-Aware Profile Connection (`AetherVpnService.kt`)**:
   - On `CELLULAR` profiles, skips `tryDirectFirst` (which always fails on MCI/Irancell) and immediately invokes multi-server racing and smart bypass with Zapret split-1.
   - Reduced `DIRECT_SSTP_FIRST_TIMEOUT_MS` from 4500ms to 2200ms for faster Wi-Fi fallback.
3. **Alternative Port Probing (992 / 5555) on ISP Block**:
   - When port 443 returns `IP_OR_PORT_BLOCKED`, `AetherVpnService` automatically probes ports `992` and `5555` on the candidate server before failing over.
4. **Enriched 97-Server Active Catalog (`vpngate_fallback.csv`)**:
   - Updated bundled cache from 31 to 97 verified live high-speed servers across Japan, South Korea, Europe, and Asia.
   - `ServerRepository.ensureInitialized` automatically upgrades devices with `< 40` servers to the new 97-server catalog.
5. **Compilation, Testing & Deployment**:
   - All 50 unit test tasks passed (`./gradlew.bat testDebugUnitTest`).
   - Built `RadinVpn 1.8.4-debug.apk` (`versionCode = 29`).
   - Installed and verified live on Samsung Galaxy A54 5G (`192.168.100.20:5555`).
