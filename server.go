package main

import (
    "bytes"
    "encoding/hex"
    "io/ioutil"
    "log"

    coap "github.com/plgd-dev/go-coap/v2"
    "github.com/plgd-dev/go-coap/v2/message"
    "github.com/plgd-dev/go-coap/v2/message/codes"
    "github.com/plgd-dev/go-coap/v2/mux"

    "github.com/pion/dtls/v2"
)
 
var identity = []byte("myserver")

// Your PSK (hex → bytes)
var pskHex = "466d59d2654e3f612a4d4aee24adf02114c56e3d9b6c6083d0efc0f696d9bf06"
var psk, _ = hex.DecodeString(pskHex)

func main() {

    // Router
    r := mux.NewRouter()

    // Handler for /test
    r.Handle("/test", mux.HandlerFunc(func(w mux.ResponseWriter, req *mux.Message) {

        switch req.Code {

        case codes.GET:
            log.Println("GET /test")
            w.SetResponse(codes.Content, message.TextPlain,
                bytes.NewReader([]byte("Hello from Go DTLS v2 server!")))

        case codes.POST:
            body, _ := ioutil.ReadAll(req.Body)
            log.Println("POST /test payload:", string(body))
            w.SetResponse(codes.Changed, message.TextPlain,
                bytes.NewReader([]byte("POST received securely")))

        case codes.PUT:
            body, _ := ioutil.ReadAll(req.Body)
            log.Println("PUT /test payload:", string(body))
            w.SetResponse(codes.Changed, message.TextPlain,
                bytes.NewReader([]byte("PUT received securely")))

        default:
            w.SetResponse(codes.MethodNotAllowed, message.TextPlain,
                bytes.NewReader([]byte("Not allowed")))
        }
    }))

    // DTLS config
    dtlsCfg := &dtls.Config{
        PSK: func(hint []byte) ([]byte, error) {
            return psk, nil
        },
        PSKIdentityHint: identity,
        CipherSuites: []dtls.CipherSuiteID{
            dtls.TLS_PSK_WITH_AES_128_CCM_8,
        },
    }

    log.Println("DTLS-PSK CoAP v2 server running on port 5684...")

    // DTLS server
    err := coap.ListenAndServeDTLS("udp", ":5684", dtlsCfg, r)
    if err != nil {
        log.Fatalf("Server error: %v", err)
    }
}
