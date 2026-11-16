# Radin VPN (`رادین وی‌پی‌ان`) — Native Android SSTP Client & VPN Gate Browser

**Current Release:** `v1.8.3` (`versionCode = 28`) — APK: `RadinVpn 1.8.3-debug.apk` (`30,916,530` bytes / `29.48 MB`)  
**Target Platform:** Android 7.0+ (API 24–35, verified up to Android 16 on `SM_A546E`)  
**Package ID:** `com.aethervpn.client` (debug: `com.aethervpn.client.debug`, preserved for zero-wipe in-place upgrades)

A native, high-performance Android VPN client app engineered in modern Kotlin, Jetpack Compose, and Material 3. Radin VPN implements a full userspace **MS-SSTP & PPP protocol stack** (LCP, RFC 2759 MS-CHAPv2, Crypto Binding CMAC, IPCP) alongside an embedded **WireGuard / Cloudflare WARP engine**, paired with an **adaptive anti-censorship engine** designed to defeat severe Deep Packet Inspection (DPI) in heavily filtered environments such as Iran, Russia, and China.

---

## Release History

| Version | Build | Date | Highlights |
| :--- | :---: | :---: | :--- |
| **`v1.8.3`** | `28` | 2026-11-15 | **Extreme Censorship Fortification (Universal Custom Configs, WARP Multi-Port Rotation & Emergency Bootstrap)**: <br>• **Cloudflare WARP Multi-Port & In-Flight Rotation**: Expanded Anycast IP candidate pool in `CloudflareCleanIpScanner` to 40+ verified Anycast IPs. Re-architected `WarpService` to execute candidate probe loops across diverse bypass ports (`2408`, `500`, `1701`, `443`, `880`) with automatic in-flight rotation before failing over. Added resilient DNS in `WarpRegistrar` bypassing SNI/DNS poisoning on `api.cloudflareclient.com`. <br>• **Universal Custom Server & Bridge Config Import**: Upgraded `SstpUriCodec` to parse standard modern links: VLESS (`vless://`), Shadowsocks (`ss://` with Base64 and plaintext), Trojan (`trojan://`), WireGuard/WARP (`wg://`, `warp://`), and SSTP. Displays protocol badges (`[VLESS]`, `[SHADOWSOCKS]`, `[TROJAN]`, `[WARP]`) in `ServersScreen`. <br>• **Emergency Directory Bootstrap**: Multi-tier DNS resolution in `ServerRepository` chaining System DNS -> DoT -> DoH with SNI Bypass -> Emergency Core Anycast Direct-IP fallback for core mirror domains during total DNS blackouts. Verified on Samsung Galaxy A54 (`SM_A546E`). |
| **`v1.8.2`** | `27` | 2026-11-15 | **Video Download & High-BDP Throughput Optimization for Telegram & Instagram**: <br>• **Zero-Allocation Fast Path Data Pump**: Decodes IPv4 packets (`FF 03 00 21` / `FF 03 21`) directly from reception buffer to TUN, eliminating 3 `ByteArray` allocations per frame (0 heap allocations) and removing GC pauses during high-speed video streaming. <br>• **TCP Window Scale & Buffer Expansion**: Sets `SO_RCVBUF` to 2MB and `SO_SNDBUF` to 1MB prior to connection; marks traffic class as `IPTOS_THROUGHPUT` (`0x08`); expands `SslEngineTransport` buffers to 64KB. <br>• **Fast-Exit MSS Clamper & Atomic Frame Packaging**: Eliminates TCP option parsing overhead on non-SYN packets and unifies packet header + payload writes into a single TLS record to prevent ACK fragmentation. <br>• **European CDN Prioritization & Anti-Blackhole Failover**: Automatically prioritizes European nodes (Amsterdam/Frankfurt) for minimal latency to Telegram/Instagram CDNs and auto-quarantines nodes that block social media traffic (`TG=true, IG=true, HTTP=true`). Live verified on Samsung Galaxy A54. |
| **`v1.8.0`** | `25` | 2026-11-15 | **Persian UX Animations, Navigation Back-Stack Fix & Cloudflare Multi-ISP Stability**: Localized connecting banner ("درحال تلاش برای عبور از فیلترینگ") with smooth pulsing animation; resolved navigation backstack state drop when switching tabs; stabilized Cloudflare WARP handshakes across Iranian cellular networks. |
| **`v1.7.5`** | `20` | 2026-11-15 | **Telegram & Instagram In-Tunnel Health Verification**: Active in-tunnel DC reachability testing; automatic quarantine and failover for fake-positive nodes. |
| **`v1.7.4`** | `19` | 2026-11-14 | **Battery Optimization & Network Switch Handover**: Minimized wake lock wakeups; seamless physical network handover without dropping tunnel context. |
| **`v1.7.3`** | `18` | 2026-11-14 | **Embedded Cloudflare WARP / WireGuard Protocol**: Dual-engine support allowing one-tap switching between SoftEther SSTP and Cloudflare WARP. |
| **`v1.7.1`** | `16` | 2026-11-14 | **Major Upgrade (Phases 1, 2, & 3 — Performance, Multi-Port, & Censorship-Resilience Engine)**: Live installed and verified on Samsung Galaxy A54 (`SM_A546E`). <br>• **Phase 1 (Optimization)**: Zero-Copy SSTP Data Pump eliminating 6 allocations per IP packet via direct 8-byte framing into `BufferedOutputStream`; removed redundant `tun.flush()`; composite Room database indexing (`MIGRATION_2_3`); migrated Hilt & Room to KSP (`2.0.21-1.0.28`). <br>• **Phase 2 (Multi-Port & Live Visuals)**: Discovered SoftEther non-443 ports (995, 1495, 1512, 1571, etc.) from OpenVPN config data with API 24+ safe decoding; added auto-probing candidate ports (custom, 443, 992, 5555) with persistent DB updates; added concurrent Batch Ping testing with `Semaphore(6)` and live progress card in `ServersScreen`; added hardware-accelerated Compose `Canvas` Speed Graph (`LiveSpeedGraph`) on `HomeScreen` with 30s rolling dual-gradient bezier curves. <br>• **Phase 3 (Smart Sorting, `sstp://` Codec, CDN Mirrors, Multi-Port Racing, & Decoy SNI)**: Dynamic Server Sorting Chips (`DEFAULT`, `PING`, `SPEED`, `SCORE`, `SESSIONS`) in `ServersScreen`; `SstpUriCodec` with standard URI parsing/generation (`sstp://user:pass@host:port?sni=...#Name`), 1-tap clipboard share on custom servers, and link import in dialog; multi-tier Censorship-Resistant CDN Mirrors (jsDelivr, GitHub raw, fallback mirrors) with automatic HTML block-page rejection (`isValidVpnGateCsv`) and 1-tap default mirror restore in settings; multi-port parallel candidate racing across ports 443, 992, and 5555 in `AetherVpnService` with auto-winner port persistence; enterprise Decoy SNI presets (`teams.microsoft.com`, `gateway.icloud.com`, `cdn.samsung.com`) with instant suggestion chips in settings. |
| **`v1.7.0`** | `15` | 2026-11-13 | **Phase 1 Performance & KSP Foundation**: Initial zero-copy SSTP pump and KSP migration release. |
| **`v1.6.7`** | `14` | 2026-11-13 | **SSTP/PPP Stability & TCP Window Auto-Tuning**: Diagnosed and resolved connection drops on high-latency international links (Japan/Europe ~700ms RTT). Removed artificial 1460-byte receive buffer clamp in `SniBypassSocketFactory` to prevent SoftEther 1s PPP timer expiration. Eliminated false-positive MS-CHAPv2 auth abort in `AetherVpnService` to guarantee fallback to `DIRECT_IP_NO_SNI`. Live tested on `SM_A546E`: instant handshake, IPCP assigned `10.238.239.64`, public IP verified to `219.100.37.238`. |
| **`v1.6.6`** | `13` | 2026-11-12 | **Deep Censorship Diagnostics & DPI Log Analysis**: Added granular LCP/IPCP packet tracing, timing instrumentation, and detailed error mapping in `AetherVpnService` to isolate transport vs authentication failures. |
| **`v1.6.5`** | `12` | 2026-11-12 | **Zapret & ByeDPI Style TCP Desync Integration**: Introduced `ZAPRET_SPLIT1_DESYNC` (1-byte split with out-of-order pacing) and `WINDOW_ALPN_MICRO_DESYNC` for middlebox evasion. |
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

## Architecture Overview

```mermaid
flowchart TD
    subgraph UI ["UI Layer (Jetpack Compose + Material 3)"]
        Home["HomeScreen (Speed, Smart Scan, Diagnostics, Quick Swap)"]
        Servers["ServersScreen (VPN Gate CSV, Regional & Health Chips)"]
        DNS["DnsScreen (DoT/DoH Encrypted Resolvers)"]
        Apps["PerAppFilterScreen (Per-App Split Tunneling)"]
        Settings["SettingsScreen (AUTO_SMART Profiles, Custom Bypass, CIDR Updater)"]
    end

    subgraph AppService ["Android Service & Data Layer (:app)"]
        VpnService["AetherVpnService (Lifecycle, Auto-Failover, Routing)"]
        StateHolder["VpnStateHolder (Live State, Speed, Telemetry)"]
        TileService["AetherTileService (Quick Settings Tile)"]
        Boot["BootReceiver (Always-On Support)"]
        Repo["ServerRepository & Room DB (VpnServerDao)"]
        Rules["IranRoutingRules (1,752 Domestic CIDRs & Custom Domains)"]
    end

    subgraph CoreEngine ["Protocol & Anti-Censorship Engine (:vpncore)"]
        SSTP["SstpClient (HTTP Duplex Post, Framing, Keepalive Watchdog)"]
        PPP["PPP Engine (LCP, RFC 2759 MS-CHAPv2, Crypto Binding CMAC, IPCP)"]
        Censorship["CensorshipDetector (IP Blackhole vs SNI/Header DPI Classifier)"]
        Racer["MultiServerRacer (Parallel Wave Prober & Latency Racer)"]
        SNIFactory["SniBypassSocketFactory (TCP Window Auto-Tuning & Bypass Strategies)"]
        Inspector["TlsClientHelloInspector (SNI & Header Byte Slicing)"]
        DoTDoH["Encrypted DNS (DnsOverTlsClient + DnsOverHttpsClient + DnsResponseCache)"]
        TunEngine["TunnelPackets (IPv4/IPv6 Frame Codec, MssClamper, ICMPv6 Guard)"]
    end

    subgraph AndroidOS ["Android OS Subsystems"]
        VpnInterface["VpnService.Builder (TUN /dev/tun0 & excludeRoute Table)"]
        Connectivity["ConnectivityManager & Socket Protector"]
    end

    UI --> AppService
    AppService --> CoreEngine
    CoreEngine --> AndroidOS
```

---

## Key Technical Features

### 1. Userspace MS-SSTP & PPP Stack
- Implements full Microsoft Secure Socket Tunneling Protocol `[MS-SSTP]` v1.0 specification over TLS (port 443).
- **HTTP Duplex Post**: Establishes bi-directional SSTP tunnel stream using `SSTP_DUPLEX_POST` with infinite Content-Length.
- **Link Control Protocol (LCP)**: MRU negotiation (clamped to 1430 to accommodate SSTP/TLS headers), Magic Number loopback detection, and PAP-to-MS-CHAPv2 negotiation.
- **RFC 2759 MS-CHAPv2 Authentication**: Mutual authentication via 16-byte PeerChallenge, MD4/DES challenge-response hashing, and server AuthenticatorResponse verification.
- **Crypto Binding Protection**: Full SSTP Compound MAC computation using HMAC-SHA256 derived from MS-CHAPv2 master keys, leaf certificate SHA-256 fingerprint, and server Nonce.
- **IP Control Protocol (IPCP)**: RFC 1332 dynamic IP address and Primary/Secondary DNS negotiation.
- **SSTP Keepalive Watchdog**: Two-window idle keepalive detection (`SSTP_MSG_ECHO_REQUEST` / `SSTP_MSG_ECHO_RESPONSE`) with active packet counters (`txPkts`, `rxUni`, `txB`, `rxB`).

### 2. Advanced DPI Bypass & Anti-Censorship Suite
- **Dynamic TCP Window Auto-Tuning**: Unlike rigid desync tools that clamp TCP windows to 1460 bytes and induce retransmission stalls on high-RTT links, Radin VPN enables dynamic OS TCP receive buffer scaling, ensuring reliable handshakes across international networks.
- **Direct IP Transport (`DIRECT_IP_NO_SNI`)**: Connects directly to server IP without emitting the TLS Server Name Indication extension. Since SoftEther servers bind SSTP to their IP, this bypasses domain-level DPI filters cleanly with zero packet overhead.
- **TLS Header Desync (`TLS_HEADER_DESYNC`)**: Splits the initial 5-byte TLS record header across TCP segments, confusing stateful middlebox protocol parsers without corrupting the TLS stream.
- **Surgical ClientHello Fragmentation (`MULTI_CHUNK_FRAGMENTATION`)**: Analyzes raw TLS ClientHello bytes via `TlsClientHelloInspector` and slices precisely at the SNI midpoint across 3 records.
- **Decoy SNI & Custom SNI (`DECOY_SNI_FRAGMENT`, `CUSTOM_SNI`)**: Fronts connections with unblocked domain names or user-specified custom SNI endpoints.
- **Parallel Multi-Server Racing (`MultiServerRacer`)**: Probes diverse candidate servers across distinct subnets and countries in parallel, instantly locking onto the fastest responding node.

### 3. Iran / Foreign Split Routing & IPv6 Leak Guard
- **1,752 Domestic CIDRs**: Pre-bundled RIPE Iranian IP ranges (`assets/iran_ipv4.cidr`) excluded via Android's `VpnService.Builder.excludeRoute()` (Android 13+) or 32-bit Patricia trie complement routing (`Ipv4RouteCalculator` for Android 7–12).
- **Split DNS**: Iranian domains (`.ir`), domestic banks, and local services resolve directly through physical ISP DNS, while blocked global sites resolve through encrypted in-tunnel DNS.
- **IPv6 Hang & Leak Guard**: Captures all `::/0` IPv6 traffic into an instant RFC 4443 ICMPv6 Administratively Prohibited responder so dual-stack apps immediately drop to fast IPv4 tunnel routing instead of hanging on filtered IPv6 paths.

### 4. Smart Directory & Anti-Blackhole Failover
- Real-time VPN Gate directory sync with mirror fallback.
- 20-minute quarantine for unreachable or blackholed nodes.
- Pre-connection socket and handshake health verification.
- Seamless mid-session auto-switch when a server degrades or disconnects.

---

## Directory Structure

```
├── app/
│   ├── src/main/assets/iran_ipv4.cidr (1,752 Aggregated Iran IPv4 CIDR blocks)
│   ├── src/main/assets/vpngate_fallback.csv (Offline fallback server directory)
│   ├── src/main/java/com/aethervpn/client/
│   │   ├── data/
│   │   │   ├── datastore/ (PreferencesManager, UserSettings)
│   │   │   ├── local/ (Room AppDatabase, VpnServerDao)
│   │   │   ├── model/ (VpnServer entity)
│   │   │   ├── repository/ (ServerRepository, mirror fetching, health scoring)
│   │   │   └── routing/ (IranRoutingRules, custom bypass rule parser)
│   │   ├── di/ (Hilt Dependency Injection modules)
│   │   ├── service/ (AetherVpnService, VpnStateHolder, AetherTileService, BootReceiver)
│   │   └── ui/ (MainActivity, MainViewModel, screens/, theme/, navigation/)
│   └── src/main/res/ (values/, values-fa/ Persian strings, icons, themes)
├── vpncore/
│   ├── src/main/java/com/aethervpn/vpncore/
│   │   ├── crypto/ (Des, Md4, MsChapV2, CryptoBinding CMAC)
│   │   ├── dns/ (DnsOverTlsClient, DnsOverHttpsClient, DnsPacketCodec, DnsResponseCache)
│   │   ├── ppp/ (PppFrame, Lcp, Ipcp, ChapPacket)
│   │   ├── sstp/ (SstpPacket, SstpClient, SstpConfig, SstpState)
│   │   ├── transport/ (CensorshipDetector, MultiServerRacer, SniBypassSocketFactory, SniStrategy, TlsClientHelloInspector)
│   │   └── tun/ (Ipv4RouteCalculator, MssClamper, TunnelPackets)
│   └── src/test/ (Comprehensive unit & integration test suite)
├── docker/ (Local SoftEther SSTP test harness)
└── docs/
    ├── PROGRESS.md (Detailed release history, bugfixes, test results & roadmap)
    └── PROTOCOL_NOTES.md (Technical protocol specifications, handshake timings & packet framing)
```

---

## Build & Run Instructions

### Prerequisites
- Android Studio Ladybug / Meerkat or command-line SDK
- JDK 17
- Android SDK 35 (minSdk 24)

### Build Debug APK
```bash
./gradlew :app:assembleDebug
# Output: app/build/outputs/apk/debug/RadinVpn 1.8.3-debug.apk
```

### Install & Run on Device via ADB
```bash
adb install -r "app/build/outputs/apk/debug/RadinVpn 1.8.3-debug.apk"
adb shell am start -n com.aethervpn.client.debug/com.aethervpn.client.ui.MainActivity
```

### Monitor Live Logs
```bash
adb logcat -s AetherVpn:* SSTP:*
```
