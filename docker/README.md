# Local SoftEther SSTP Server Test Harness

This test harness runs a containerized SoftEther VPN server with MS-SSTP enabled on TCP port 443 for local integration testing.

## Prerequisites
- Docker & Docker Compose

## Quick Start
```bash
cd docker
docker-compose up -d
```

## Default Credentials
- **Host**: `10.0.2.2` (Android Emulator loopback to host) or your LAN IP for physical device.
- **Port**: `443`
- **Username**: `vpn`
- **Password**: `vpn`
- **Strict Certificate Validation**: Set to **OFF** in app settings when testing self-signed server certs.

## Verification
You can verify SSTP readiness using curl:
```bash
curl -k -i -X SSTP_DUPLEX_POST https://localhost/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ \
  -H "SSTPCORRELATIONID: {00000000-0000-0000-0000-000000000000}" \
  -H "Content-Length: 18446744073709551615"
```
Server should respond with `HTTP/1.1 200 OK` (or 200 with blank line awaiting SSTP control frames).

