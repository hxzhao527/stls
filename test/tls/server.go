package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
)

func main() {
	log.SetFlags(log.Lshortfile)

	cer, err := tls.LoadX509KeyPair("../server.crt", "../server.key")
	if err != nil {
		log.Println(err)
		return
	}

	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	ln, err := tls.Listen("tcp", "127.0.0.1:8443", config)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()

	log.Println("running")
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)

	req, err := http.ReadRequest(r)
	if err != nil {
		log.Println(err)
		return
	}

	fmt.Println(req)

	n, err := conn.Write(response)
	if err != nil {
		log.Println(n, err)
		return
	}

}

var response []byte

func init() {
	var buf bytes.Buffer
	header := http.Header{}
	header.Set("Server", "Self-TLS")
	resp := http.Response{
		Status:     http.StatusText(http.StatusOK),
		StatusCode: http.StatusOK,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Body:       io.NopCloser(bytes.NewBufferString("Hello World")),
		Header:     header,
	}
	resp.Write(&buf)
	response = buf.Bytes()
}
