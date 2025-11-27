#include <WiFi.h>
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/timing.h"
#include "mbedtls/x509_crt.h"

// WiFi credentials
const char* ssid = "pop-os";
const char* password = "111222333";

// CoAP Server settings
const char* coapServer = "13.210.144.240";  // Your Go server IP
const char* coapPort = "5684";  // DTLS CoAP port as string

// Trusted CA certificate (use cert.pem from your server). Keep the BEGIN/END lines.
// Replace the placeholder text with the actual PEM contents.
const char server_ca_pem[] = R"PEM(-----BEGIN CERTIFICATE-----
MIIFAjCCAuqgAwIBAgIUdRGoAx8ozlvBeEbH6euXZF3fO98wDQYJKoZIhvcNAQEL
BQAwGTEXMBUGA1UEAwwOMTMuMjEwLjE0NC4yNDAwHhcNMjUxMTI3MTkyMDI0WhcN
MjYxMTI3MTkyMDI0WjAZMRcwFQYDVQQDDA4xMy4yMTAuMTQ0LjI0MDCCAiIwDQYJ
KoZIhvcNAQEBBQADggIPADCCAgoCggIBANMprRi5TwSWJWmktAXPgOzh8bf8lrgg
Q2WG5pRIDMDkuX/U5zNxyo8tt/OwqVzw7GpqqBMUJB46PzHu2Yiuxwvw88oQPYku
gLUX4F2vIix1x52Niigk+4M0BqY+v3WlI2BKXWjhzbzq2VYWXdeHNWmpYGgXR59e
cwaqwlxcDMVGQk88ZkYyVzRn+HmRvGMdisqnHB2GixqvOIzXkFq/l9WZgf4uiNvG
kYqxN5c/0yHR1+t+v+mn76KuP00+5AyjdcsBuYaFVjM1402tyJKNm8iH6DoG+Of5
DjMsmuqiUedOrzKRS746F8R8XY8h2U2nGiq7lfcis0yMM6xHT+iSvHcA0GY3YRos
Krx2fMTIOPn2CfHxcQFObY3clxhIqqPBL3i9r8ZNWbAevhQBF3WXn4/DjhxH4dc7
gr7YIJFuX+W61A5JAyyw16SI7CPRFyxP/ve1n+A5NMEkvRfscUqYB4RZmf/iLE0c
BjkE3GcAyFNWTItfRi9nNLiDCmJTat5ITPWYJUHYmA9n3qK9fpFIMIgb/BUShsBB
dE0197MK8T4W9VWEh9NkE/65mn03sL1b8ksRe/QVCtuq/MDk7OKyN1GZkRBEtfAT
mswlrAMvpcmbkJ7pIdT3iVfDFV7IjbXafRHqfn4I6m/KJpNaUFcMpvsLuJNFeRUk
a78xxtyo/yqLAgMBAAGjQjBAMB8GA1UdEQQYMBaHBA3SkPCCDjEzLjIxMC4xNDQu
MjQwMB0GA1UdDgQWBBSTBmLY24f0v5M5T1Nc9ZI9J10i1zANBgkqhkiG9w0BAQsF
AAOCAgEAkFr5rLkWX9xq3/B3jXw9w7Q049Oz0Cyc6/xSrGT5MucU2qOb+Yky45li
D6fsNvKiWgQQIJEh0BWQrhVS9eMETgrpydbvVRlveNqR5q+fUj16f1U5Qcv3P2eB
QlDEu8++mXy0qvDy72FTNPf3CsycOvFZd/n/EufJXFGQ1VoW5v0+5MpcUxOnesj6
32fRay2kn2GhuqwTGVylTA4ONBLLC43d+WJ/ltTFJjcZskWSbinusGJnVrmIO36O
H4FDNP1eUxm8Unxyv6nCCussoeERDDPfoshGglD55fpRiDZgcRhd5r23dNYm+eNv
s9b7In8e9BjPbNFgG2jwF9gcUY6k7uS2x4d56C4u84yOnBzqlXchSL8Xo0tuYr9u
L81mnyOocEUWtd4kZHfToTwLmxqRa5bKAGGfbIvBL228xJe4wq78Q5MhpOQPEw5F
w0KEq4/3wGVb+BlAZ/v3p2Z1d2pqUK7ORloddXFKGQq6gP50j/f0Gqe3xyLOZOiA
n3IWoqeo0idzVMHWjQri8HaVHdynjEXT9kzreDw/VOZPQRzrlsWCkQMrNwsjoBWy
xElLnCBbpe0nAUhW34Ts23KzrSqTLO4wiGHe2k1w333Ih8R9UKu3FU1XA344BUX/
7/KTUFAfYLHxQ6+emRL7tHh8wxbzPuXxgJnt1z5IMdScAYftczo=
-----END CERTIFICATE-----
)PEM";

// mbedTLS structures
mbedtls_net_context server_fd;
mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_entropy_context entropy;
mbedtls_timing_delay_context timer;
mbedtls_x509_crt ca;

bool dtlsConnected = false;
uint16_t messageId = 1;

// CoAP codes
#define COAP_CODE_GET    0x01
#define COAP_CODE_POST   0x02
#define COAP_CODE_PUT    0x03

void printMbedTLSError(int ret) {
  char error_buf[100];
  mbedtls_strerror(ret, error_buf, sizeof(error_buf));
  Serial.printf("mbedTLS error: -0x%04X - %s\n", -ret, error_buf);
}

bool initDTLS() {
  int ret;
  Serial.println("Initializing DTLS...");

  // Initialize contexts
  mbedtls_net_init(&server_fd);
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);
  mbedtls_x509_crt_init(&ca);

  // Seed random number generator
  const char* pers = "esp32_dtls_client_cert";
  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char*)pers, strlen(pers));
  if (ret != 0) {
    Serial.println("Failed to seed RNG");
    printMbedTLSError(ret);
    return false;
  }

  // Setup SSL/DTLS config
  ret = mbedtls_ssl_config_defaults(&conf,
                                     MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) {
    Serial.println("Failed to set SSL config defaults");
    printMbedTLSError(ret);
    return false;
  }

  // Parse CA (self-signed server cert) and require server verification
  ret = mbedtls_x509_crt_parse(&ca, (const unsigned char*)server_ca_pem, sizeof(server_ca_pem));
  if (ret < 0) {
    Serial.println("Failed to parse CA certificate");
    printMbedTLSError(ret);
    return false;
  }

  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain(&conf, &ca, NULL);

  // Prefer RSA certificate ciphers (matches Go DTLS server using cert.pem/key.pem)
  static const int ciphersuites[] = {
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    0
  };
  mbedtls_ssl_conf_ciphersuites(&conf, ciphersuites);

  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

  // Setup SSL context
  ret = mbedtls_ssl_setup(&ssl, &conf);
  if (ret != 0) {
    Serial.println("Failed to setup SSL");
    printMbedTLSError(ret);
    return false;
  }
  mbedtls_ssl_set_hostname(&ssl, "13.210.144.240"); //added after hostname error

  // Set timer callbacks for DTLS
  mbedtls_ssl_set_timer_cb(&ssl, &timer,
                           mbedtls_timing_set_delay,
                           mbedtls_timing_get_delay);

  Serial.println("DTLS initialized successfully");
  return true;
}

bool connectDTLS() {
  int ret;
  Serial.println("Connecting to DTLS server...");

  // Connect to server
  ret = mbedtls_net_connect(&server_fd, coapServer, coapPort, MBEDTLS_NET_PROTO_UDP);
  if (ret != 0) {
    Serial.println("Failed to connect to server");
    printMbedTLSError(ret);
    return false;
  }

  Serial.println("UDP connection established");

  mbedtls_ssl_set_bio(&ssl, &server_fd,
                      mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

  // Set timeout for handshake
  mbedtls_ssl_conf_read_timeout(&conf, 10000);

  // Perform DTLS handshake
  Serial.println("Starting DTLS handshake...");
  while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      Serial.println("DTLS handshake failed");
      printMbedTLSError(ret);
      return false;
    }
  }

  Serial.println("DTLS handshake completed!");
  Serial.print("Cipher suite: ");
  Serial.println(mbedtls_ssl_get_ciphersuite(&ssl));

  dtlsConnected = true;
  return true;
}

void disconnectDTLS() {
  if (dtlsConnected) {
    mbedtls_ssl_close_notify(&ssl);
    dtlsConnected = false;
  }
  mbedtls_net_free(&server_fd);
}

void cleanupDTLS() {
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  mbedtls_x509_crt_free(&ca);
}

size_t buildCoapPacket(uint8_t* buffer, uint8_t method, const char* path,
                       const char* payload = NULL, uint16_t payloadLen = 0) {
  size_t index = 0;

  // Header: version(2), type(2), token length(4)
  buffer[index++] = 0x40 | 0x00 | 0x04;  // Version 1, CON, Token Len 4
  buffer[index++] = method;

  // Message ID
  buffer[index++] = (messageId >> 8) & 0xFF;
  buffer[index++] = messageId & 0xFF;
  messageId++;

  // Token (4 bytes)
  buffer[index++] = random(256);
  buffer[index++] = random(256);
  buffer[index++] = random(256);
  buffer[index++] = random(256);

  // Uri-Path option
  String pathStr = String(path);
  if (pathStr.startsWith("/")) {
    pathStr = pathStr.substring(1);
  }

  int start = 0;
  int slashPos = pathStr.indexOf('/');
  uint8_t lastOption = 0;

  while (start < pathStr.length()) {
    String segment;
    if (slashPos == -1) {
      segment = pathStr.substring(start);
      start = pathStr.length();
    } else {
      segment = pathStr.substring(start, slashPos);
      start = slashPos + 1;
      slashPos = pathStr.indexOf('/', start);
    }

    if (segment.length() > 0) {
      uint8_t optionDelta = 11 - lastOption;
      lastOption = 11;

      buffer[index++] = (optionDelta << 4) | segment.length();
      memcpy(&buffer[index], segment.c_str(), segment.length());
      index += segment.length();
    }
  }

  // Payload
  if (payload && payloadLen > 0) {
    buffer[index++] = 0xFF;
    memcpy(&buffer[index], payload, payloadLen);
    index += payloadLen;
  }

  return index;
}

void parseCoapResponse(uint8_t* buffer, size_t len) {
  if (len < 4) return;

  uint8_t code = buffer[1];
  uint8_t tokenLen = buffer[0] & 0x0F;

  Serial.println("\n=== CoAP Response ===");
  Serial.printf("Code: %d.%02d\n", (code >> 5) & 0x07, code & 0x1F);

  size_t index = 4 + tokenLen;

  // Skip options
  while (index < len && buffer[index] != 0xFF) {
    uint8_t optionHeader = buffer[index++];
    uint8_t optionLen = optionHeader & 0x0F;

    if (optionLen == 13) optionLen = buffer[index++] + 13;
    else if (optionLen == 14) {
      optionLen = ((buffer[index] << 8) | buffer[index + 1]) + 269;
      index += 2;
    }

    index += optionLen;
  }

  // Print payload
  if (index < len && buffer[index] == 0xFF) {
    index++;
    Serial.print("Payload: ");
    for (size_t i = index; i < len; i++) {
      Serial.print((char)buffer[i]);
    }
    Serial.println();
  }
  Serial.println("====================\n");
}

bool sendCoapRequest(uint8_t method, const char* path, const char* payload = NULL) {
  if (!dtlsConnected) {
    Serial.println("Not connected to DTLS server");
    return false;
  }

  uint8_t buffer[512];
  uint16_t payloadLen = (payload) ? strlen(payload) : 0;

  size_t packetLen = buildCoapPacket(buffer, method, path, payload, payloadLen);

  Serial.print("Sending CoAP ");
  switch(method) {
    case COAP_CODE_GET: Serial.print("GET"); break;
    case COAP_CODE_POST: Serial.print("POST"); break;
    case COAP_CODE_PUT: Serial.print("PUT"); break;
  }
  Serial.print(" to ");
  Serial.println(path);

  if (payload) {
    Serial.print("Payload: ");
    Serial.println(payload);
  }

  // Send over DTLS
  int ret = mbedtls_ssl_write(&ssl, buffer, packetLen);
  if (ret < 0) {
    Serial.println("Failed to send CoAP request");
    printMbedTLSError(ret);
    return false;
  }

  Serial.printf("Sent %d bytes\n", ret);

  // Receive response
  uint8_t responseBuffer[512];
  ret = mbedtls_ssl_read(&ssl, responseBuffer, sizeof(responseBuffer));

  if (ret > 0) {
    Serial.printf("Received %d bytes\n", ret);
    parseCoapResponse(responseBuffer, ret);
    return true;
  } else if (ret == MBEDTLS_ERR_SSL_TIMEOUT) {
    Serial.println("Response timeout");
  } else {
    Serial.println("Failed to receive response");
    printMbedTLSError(ret);
  }

  return false;
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("\n=== ESP32 CoAP DTLS (cert) Client ===");

  // Connect to WiFi
  Serial.print("Connecting to WiFi");
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\nWiFi connected!");
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());

  // Initialize DTLS
  if (!initDTLS()) {
    Serial.println("DTLS initialization failed!");
    return;
  }

  // Connect to server
  if (!connectDTLS()) {
    Serial.println("DTLS connection failed!");
    return;
  }

  Serial.println("Ready to send CoAP requests!\n");
  delay(2000);
}

void loop() {
  if (!dtlsConnected) {
    Serial.println("Attempting to reconnect...");
    if (connectDTLS()) {
      Serial.println("Reconnected!");
    } else {
      delay(5000);
      return;
    }
  }

  // Test GET
  Serial.println("--- Testing GET ---");
  sendCoapRequest(COAP_CODE_GET, "/test");
  delay(3000);

  // Test POST
  Serial.println("--- Testing POST ---");
  sendCoapRequest(COAP_CODE_POST, "/test", "Hello from ESP32!");
  delay(3000);

  // Test PUT
  Serial.println("--- Testing PUT ---");
  sendCoapRequest(COAP_CODE_PUT, "/test", "{\"temp\":25.5}");
  delay(10000);
}
