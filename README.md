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

## AWS EC2 server + ESP32 client

The `AWS EC2 + ESP32` folder contains `coap_client_go.ino`. It implements an ESP32 DTLS client using mbedTLS that speaks to this Go CoAP server with the same PSK identity (`"myserver"`) and 32-byte key.

Suggested workflow:

1. **Provision the server on EC2**  
   - Build the binary (`go build -o server ./server.go`) and copy it to your EC2 instance.  
   - Open UDP port `5684` in the instance security group.  
   - Run the binary (for example `./server`) so it listens on the public interface.
2. **Configure the ESP32 sketch**  
   - Open `AWS EC2 + ESP32/coap_client_go.ino` in the Arduino IDE.  
   - Update `ssid`/`password` with your Wi-Fi network, set `coapServer` to the EC2 public IP, and keep `coapPort` at `"5684"` unless you changed it on the Go server.  
   - Replace `pskIdentity` and the `psk` byte array if you generated new credentials for the Go apps.
3. **Deploy to the ESP32**  
   - Select the correct board/port in the IDE and upload the sketch.  
   - Monitor the serial console to confirm the DTLS handshake succeeds and that CoAP PUTs to `/test` return the server response.

## Notes

- The cipher suite is restricted to `TLS_PSK_WITH_AES_128_CCM_8` for simplicity.
- The default server address is `localhost:5684`; change it in `client.go` to reach a remote endpoint.
