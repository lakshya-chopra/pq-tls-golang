package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
)

func main() {
	// Load server certificate and key

	absPathServerCrt, err := filepath.Abs("../certs/server/cert.pem")
	absPathServerKey, err := filepath.Abs("../certs/server/key.pem")

	absPathClientCrt, err := filepath.Abs("../certs/client/cert.pem")

	clientCACert, err := ioutil.ReadFile(absPathClientCrt)
	if err != nil {
		log.Fatalf("failed to read client CA certificate: %s", err)
	}

	clientCertPool := x509.NewCertPool()
	if ok := clientCertPool.AppendCertsFromPEM(clientCACert); !ok {
		log.Fatal("failed to parse client CA certificate")
	}

	cert, err := tls.LoadX509KeyPair(absPathServerCrt, absPathServerKey)
	if err != nil {
		log.Fatalf("failed to load server certificate and key: %s", err)
	}

	// Custom function to log ClientHelloInfo
	getCertificate := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		clientHelloJson, err := json.MarshalIndent(hello, "", "  ")
		if err != nil {
			log.Printf("Failed to marshal ClientHelloInfo: %s", err)
		} else {
			log.Printf("ClientHelloInfo: %s", string(clientHelloJson))
		}
		return &cert, nil
	}

	// Create TLS config with mutual TLS (mTLS) and custom certificate callback
	tlsConfig := &tls.Config{
		ClientAuth:                tls.RequireAndVerifyClientCert,
		ClientCAs:                 clientCertPool,
		PreferServerCipherSuites:  true,
		MinVersion:                tls.VersionTLS13,
		GetCertificate:            getCertificate,
		PQSignatureSchemesEnabled: true,
		// CurvePreferences:          []tls.CurveID{tls.CurveID(tls.CurveP384)},
		// ECHEnabled: true,
	}
	// Create HTTPS server
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
		Handler:   http.HandlerFunc(handler),
	}

	// Start HTTPS server
	log.Println("Starting server on https://localhost:8443")
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatalf("server failed to start: %s", err)
	}
}

// Handler function
func handler(w http.ResponseWriter, r *http.Request) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		clientCert := r.TLS.PeerCertificates[0]
		fmt.Fprintf(w, "Hello, %s!\n", clientCert.Subject.CommonName)
		log.Printf("Authenticated client: %s", clientCert.Subject.CommonName)

		connState := r.TLS
		connStateJson, err := json.MarshalIndent(connState, "", "  ")
		if err != nil {
			http.Error(w, "Failed to marshal connection state", http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Connection State:\n%s\n", string(connStateJson))
		log.Printf("Connection state: %s", string(connStateJson))
	} else {
		http.Error(w, "Client certificate required", http.StatusUnauthorized)
	}
}
