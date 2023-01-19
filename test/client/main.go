package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
)

func main() {
	certPool := x509.NewCertPool()
	pem, err := os.ReadFile("../cert-maker/certs/ca.crt")
	if err != nil {
		log.Fatalf("1 %s\n", err)
	}
	certPool.AppendCertsFromPEM(pem)

	conn, err := tls.Dial("tcp", "localhost:8443", &tls.Config{
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS11,
		MaxVersion: tls.VersionTLS11,
	})
	if err != nil {
		log.Fatalf("2: %s", err)
	}
	defer conn.Close()
	conn.Write([]byte("Hello World"))
	fmt.Println("我们还行吧")
}
