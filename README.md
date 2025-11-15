# CoAP DTLS Server and Client

This repository demonstrates how to secure a CoAP deployment with DTLS in Go using a pre‑shared key (PSK). It contains:

- `server.go`: a DTLS-PSK CoAP server that exposes `/test` and accepts GET/POST/PUT requests.
- `client.go`: a matching DTLS client that performs a handshake, issues a PUT to `/test`, and prints the response.

The shared identity (`"myserver"`) and key (hex string decoded to bytes) live in both programs so the DTLS layer can authenticate peers without certificates.

## Requirements

- Go 1.23 or later.

## Running the server

```bash
go run ./server.go
```

You should see a log entry that the DTLS-PSK server is listening on UDP port `5684`.

To produce the standalone binary:

```bash
go build -o server ./server.go
```

## Running the client

Start the server first, then run:

```bash
go run ./client.go
```

The client will perform the DTLS handshake using the PSK identity and key, send a PUT request to `/test`, and print the server’s plain-text response.

To build the client binary:

```bash
go build -o client ./client.go
```

## Customizing the PSK

Update both `pskHex` values in `server.go` and `client.go` with your own 32-byte hex string (matching on both sides). Adjust `identity` if you want to differentiate multiple clients or servers.  
If you use the ESP32 sketch described below, mirror the same identity/PSK in `AWS EC2 + ESP32/coap_client_go.ino`.

# AWS EC2 server + ESP32 client

The `AWS EC2 + ESP32` folder contains `coap_client_go.ino`. It implements an ESP32 DTLS client with mbedTLS primitives (`mbedtls_ssl`, `mbedtls_net`, `mbedtls_ctr_drbg`, etc.) so the microcontroller can speak directly to the Go server with the same PSK identity (`"myserver"`) and 32-byte key.  
The sketch builds raw CoAP packets (configurable method, token, Uri-Path, payload) and sends them over the encrypted DTLS channel.

### Architecture

- **Cloud**: Go server running on an EC2 instance (public IP, UDP port 5684 open).  
- **Edge**: ESP32 on Wi-Fi initiating DTLS handshake, using PSK to authenticate the EC2 server.  
- **Protocol flow**: Wi-Fi → DTLS handshake (PSK) → CoAP confirmable message to `/test` → server response (ACK + payload).

### Prerequisites

- EC2 instance with outbound internet and a security group allowing inbound UDP/5684.  
- ESP32 board support in Arduino IDE (Tools → Board → ESP32).  
- Wi-Fi credentials the ESP32 can reach.  
- Optional: Serial monitor at 115200 baud to inspect logs (handshake status, CoAP message IDs, errors).

### Suggested workflow

1. **Provision the server on EC2**  
   - Build the binary (`go build -o server ./server.go`) and copy it to the instance (SCP, SSM, etc.).  
   - Ensure `sudo ufw allow 5684/udp` (or the cloud firewall equivalent) so clients can reach it.  
   - Run the binary in a tmux/screen session (`./server`); verify logs show `DTLS-PSK CoAP v2 server running on port 5684`.
2. **Configure the ESP32 sketch**  
   - Open `AWS EC2 + ESP32/coap_client_go.ino` in Arduino IDE.  
   - Set `ssid`/`password`, `coapServer` (EC2 public IP/DNS), and confirm `coapPort` matches the server.  
   - Replace `pskIdentity`/`psk` with your chosen credentials; they must match the Go server and any other clients.  
   - Optional: tweak the payload inside `buildCoapPacket` to send sensor readings.
3. **Deploy to the ESP32**  
   - Select the correct board/port and upload the sketch.  
   - Open Serial Monitor (115200) to follow the sequence: Wi-Fi connect → “Initializing DTLS…” → “DTLS handshake completed!” → CoAP request/response logs.
4. **Verify end-to-end**  
   - On the EC2 server log, confirm the ESP32 requests appear under the `/test` handler.  
   - Optionally run `tcpdump -i eth0 udp port 5684` on EC2 to watch DTLS traffic (encrypted).  
   - If the connection stalls, confirm the instance’s public IP and UDP reachability, then reboot the ESP32 to retry.

### Troubleshooting tips

- mbedTLS errors like `-0x4280` typically indicate PSK mismatch or cipher negotiation issues; double-check identity/key values.  
- Connection timeouts often stem from blocked UDP in AWS security groups or local firewalls.  
- Resetting the ESP32 after changing PSK values helps clear cached DTLS state.

## Notes

- The cipher suite is restricted to `TLS_PSK_WITH_AES_128_CCM_8` for simplicity.
- The default server address is `localhost:5684`; change it in `client.go` to reach a remote endpoint.
