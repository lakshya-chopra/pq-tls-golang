package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	// "net/http"
	"path/filepath"
)

func handleError(err error) {
	if err != nil {
		log.Fatal("Fatal", err)
	}
}

func PrintCertificateDetails(cert *x509.Certificate) {
	fmt.Printf("Subject: %s\n", cert.Subject)
	fmt.Printf("Issuer: %s\n", cert.Issuer)
	fmt.Printf("Serial Number: %s\n", cert.SerialNumber)
	fmt.Printf("Not Before: %s\n", cert.NotBefore)
	fmt.Printf("Not After: %s\n", cert.NotAfter)
	fmt.Printf("Key Usage: %x\n", cert.KeyUsage)
	fmt.Printf("Ext Key Usage: %v\n", cert.ExtKeyUsage)
	fmt.Printf("DNS Names: %v\n", cert.DNSNames)
	fmt.Printf("Email Addresses: %v\n", cert.EmailAddresses)
	fmt.Printf("IP Addresses: %v\n", cert.IPAddresses)
	fmt.Printf("URIs: %v\n", cert.URIs)
	fmt.Printf("Signature Algorithm: %s\n", cert.SignatureAlgorithm)
}

func ReadCertificate(filename string) (*x509.Certificate, error) {
	// Read the certificate file
	certPEM, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	// Decode the PEM block
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

func main() {
	absPathClientCrt, err := filepath.Abs("../certs/client/cert.pem")
	handleError(err)
	absPathClientKey, err := filepath.Abs("../certs/client/key.pem")
	handleError(err)
	absPathServerCrt, err := filepath.Abs("../certs/server/cert.pem")
	handleError(err)

	cert, err := tls.LoadX509KeyPair(absPathClientCrt, absPathClientKey)
	if err != nil {
		log.Fatalln("Unable to load cert", err)
	}

	roots := x509.NewCertPool()

	// We're going to load the server cert and add all the intermediates and CA from that.
	// Alternatively if we have the CA directly we could call AppendCertificate method
	fakeCA, err := ioutil.ReadFile(absPathServerCrt)
	if err != nil {
		log.Println(err)
		return
	}

	ok := roots.AppendCertsFromPEM([]byte(fakeCA))
	if !ok {
		panic("failed to parse root certificate")
	}

	cert2, err := ReadCertificate(absPathClientCrt)
	if err != nil {
		log.Fatal("error reading cert")
	}
	PrintCertificateDetails(cert2)

	tlsConf := &tls.Config{
		Certificates:              []tls.Certificate{cert},
		RootCAs:                   roots,
		InsecureSkipVerify:        false,
		MinVersion:                tls.VersionTLS13,
		PQSignatureSchemesEnabled: true, //if false then Server cant use PQ certs
		ServerName:                "localhost",
		CurvePreferences:          []tls.CurveID{tls.CurveID(tls.X25519Kyber768Draft00), tls.CurveID(tls.CurveP256)},
		// ECHEnabled: true,
	}
	tr := &http.Transport{TLSClientConfig: tlsConf}
	client := &http.Client{Transport: tr}

	resp, err := client.Get("https://localhost:8443")
	if err != nil {
		log.Println(err)
		return
	}

	fmt.Println(resp.Status)

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return
	}

	fmt.Println(string(body))
	// conn, err := tls.Dial("tcp", "localhost:8443", tlsConf)
	// if err != nil {
	// 	log.Fatalf("TLS connection failed: %s", err)
	// }

	// err2 := conn.Handshake()
	// if err2 != nil {
	// 	log.Fatalf("TLS connection failed: %s", err)
	// }

	// _, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost:8443 \r\n\r\n"))
	// if err != nil {
	// 	log.Fatalf("failed to write to TLS connection: %s", err)
	// }

	// // Read response from server
	// buf := make([]byte, 1024)
	// n, err := conn.Read(buf)
	// if err != nil {
	// 	log.Fatalf("failed to read from TLS connection: %s", err)
	// }
	// fmt.Printf("Server says: %s\n", string(buf[:n]))

	// defer conn.Close()
}
