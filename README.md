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

## Running the client

Start the server first, then run:

```bash
go run ./client.go
```

The client will perform the DTLS handshake using the PSK identity and key, send a PUT request to `/test`, and print the server’s plain-text response.

## Customizing the PSK

Update both `pskHex` values in `server.go` and `client.go` with your own 32-byte hex string (matching on both sides). Adjust `identity` if you want to differentiate multiple clients or servers.

## Notes

- The cipher suite is restricted to `TLS_PSK_WITH_AES_128_CCM_8` for simplicity.
- The default server address is `localhost:5684`; change it in `client.go` to reach a remote endpoint.
