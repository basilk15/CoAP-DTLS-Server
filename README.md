# CoAP over DTLS: PSK path + Certificate path

Two complete DTLS modes live here: PSK and certificate-based. Each includes a Go server and an ESP32 (mbedTLS) client.

```
.
├── server.go                 # Go DTLS-PSK server (localhost demo)
├── client.go                 # Go DTLS-PSK client
├── AWS EC2 + ESP32/          # PSK flow for cloud+edge
│   ├── server.go             # Go DTLS-PSK server (EC2-ready)
│   └── coap_client_go.ino    # ESP32 DTLS-PSK client
└── AWS EC2 + ESP32 (certs)/  # Certificate flow
    ├── server.go             # Go DTLS (cert) server
    └── coap_client_go.ino    # ESP32 DTLS (cert) client with verification
```

## Requirements

- Go 1.23+
- Arduino IDE with ESP32 board support (for the `.ino` sketches)

---

## PSK path (fast start)

**Server (local demo)**
- File: `server.go`
- Run: `go run ./server.go`
- Listens on UDP `:5684`, handler `/test` (GET/POST/PUT), cipher `TLS_PSK_WITH_AES_128_CCM_8`.

**Client (local demo)**
- File: `client.go`
- Run: `go run ./client.go`
- Performs DTLS-PSK handshake and issues a PUT to `/test`.

**Customize PSK**
- Edit `identity` and `pskHex` in both `server.go` and `client.go` (32-byte hex). Keep them identical.

**ESP32 PSK variant (cloud)**
- Folder: `AWS EC2 + ESP32`
- Server: `go run "./AWS EC2 + ESP32/server.go"` (or build with `GOOS=linux GOARCH=amd64` for EC2)
- ESP32 sketch: `AWS EC2 + ESP32/coap_client_go.ino`
  - Set `ssid`/`password`, `coapServer`, `coapPort`
  - Set `pskIdentity` and `psk[]` to match the Go server
  - Upload, open Serial Monitor (115200) → watch Wi-Fi → DTLS handshake → CoAP GET/POST/PUT logs

**AWS EC2 quick checklist (PSK)**
1) Security Group allows UDP/5684 inbound
2) Build/upload server binary, run inside `screen`/`tmux`
3) Point ESP32 `coapServer` to EC2 public IP/DNS

**EC2 build/run (PSK)**
```bash
# on your workstation (Linux/amd64 target)
GOOS=linux GOARCH=amd64 go build -o server "./AWS EC2 + ESP32/server.go"
scp server ec2:~/coap-server/

# on EC2
sudo yum update -y    # or apt
cd ~/coap-server
./server              # runs DTLS-PSK CoAP on UDP 5684
```

---

## Certificate path (authenticated server)

You generate a self-signed server cert and use it on both sides.

**Generate cert/key (self-signed)**
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

**Server (certificate)**
- Folder: `AWS EC2 + ESP32 (certs)`
- File: `server.go`
- Place `cert.pem` and `key.pem` next to `server.go`
- Run: `go run "./AWS EC2 + ESP32 (certs)/server.go"`
- Config: loads the key pair, `ClientAuth: dtls.NoClientCert` (one-way auth), CoAP `/test` handlers unchanged.

**ESP32 client (certificate, verified)**
- Folder: `AWS EC2 + ESP32 (certs)`
- File: `coap_client_go.ino`
- What changed:
  - `MBEDTLS_SSL_VERIFY_REQUIRED` enforces server verification
  - `mbedtls_x509_crt_parse` loads the trusted CA (the same `cert.pem` content)
  - `mbedtls_ssl_conf_ca_chain` sets the CA; RSA DTLS ciphers preferred
- To use:
  1) Paste your `cert.pem` (including BEGIN/END) into `server_ca_pem` in the sketch
  2) Set `ssid`/`password`, `coapServer`, `coapPort`
  3) Optional: add hostname check by setting `coapServer` to the cert CN/SAN and calling `mbedtls_ssl_set_hostname(&ssl, coapServer);` before `mbedtls_ssl_handshake`
  4) Upload to ESP32, open Serial Monitor → expect verified DTLS handshake then CoAP GET/POST/PUT

**AWS EC2 quick checklist (certs)**
1) Security Group allows UDP/5684 inbound
2) Copy `cert.pem` and `key.pem` to the server folder on EC2
3) Run `server.go` from `AWS EC2 + ESP32 (certs)`
4) Ensure ESP32 sketch contains the exact `cert.pem` PEM block

**EC2 build/run (certs)**
```bash
# generate certs locally (or on EC2)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# build for EC2
GOOS=linux GOARCH=amd64 go build -o server "./AWS EC2 + ESP32 (certs)/server.go"
scp server cert.pem key.pem ec2:~/coap-server-certs/

# on EC2
sudo yum update -y    # or apt
cd ~/coap-server-certs
./server              # runs DTLS (cert) CoAP on UDP 5684
```

---

## Troubleshooting (both modes)
- UDP blocked? Open SG/firewall for UDP/5684.
- Handshake fails (PSK): identity/PSK mismatch or wrong cipher.
- Handshake fails (cert): PEM not parsed or hostname/CA mismatch. Re-paste full BEGIN/END block.
- Timeouts: confirm `coapServer` IP/DNS is reachable from ESP32 Wi-Fi.
- After changing keys/certs, reboot ESP32 to clear DTLS state.

---

## Build notes
- Binaries: `go build -o server ./server.go` and `go build -o client ./client.go` (adjust paths for EC2 variants).
- Cross-compile for EC2: `GOOS=linux GOARCH=amd64 go build -o server "./AWS EC2 + ESP32/server.go"`.

---

## Security posture
- PSK mode: simple and lightweight, but shared key management is manual.
- Cert mode: proper server authentication; ESP32 rejects unknown/tampered certs.
