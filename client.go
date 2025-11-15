package main

import (
    "bytes"
    "context"
    "encoding/hex"
    "fmt"
    "log"

    piondtls "github.com/pion/dtls/v2"
    coapdtls "github.com/plgd-dev/go-coap/v2/dtls"
    "github.com/plgd-dev/go-coap/v2/message"
)

var identity = []byte("myserver")

var pskHex = "466d59d2654e3f612a4d4aee24adf02114c56e3d9b6c6083d0efc0f696d9bf06"
var psk, _ = hex.DecodeString(pskHex)

func main() {

    serverAddr := "localhost:5684"

    cfg := &piondtls.Config{
        PSK: func(hint []byte) ([]byte, error) {
            return psk, nil
        },
        PSKIdentityHint: identity,
        CipherSuites: []piondtls.CipherSuiteID{
            piondtls.TLS_PSK_WITH_AES_128_CCM_8,
        },
    }

    conn, err := coapdtls.Dial(serverAddr, cfg)
    if err != nil {
        log.Fatalf("Dial failed: %v", err)
    }
    defer conn.Close()

    fmt.Println("DTLS Handshake Success!")

    payload := []byte("hello-from-go-client")
    body := bytes.NewReader(payload)

    // REQUIRED: Add context
    ctx := context.Background()

    resp, err := conn.Put(ctx, "/test", message.TextPlain, body)
    if err != nil {
        log.Fatalf("PUT failed: %v", err)
    }

    responseBody, _ := resp.ReadBody()
    fmt.Println("Server response:", string(responseBody))
}
