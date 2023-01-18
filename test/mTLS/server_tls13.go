package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"

	"github.com/hxzhao527/stls/stls"
)

func main() {
	caCertPool := x509.NewCertPool()
	caCertFile, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		log.Fatalf("加载ca失败了 %s", err)
	}
	caCertPool.AppendCertsFromPEM(caCertFile)

	cer, err := stls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Println(err)
		return
	}
	config := &stls.Config{
		Certificates: []stls.Certificate{cer},
		ClientCAs:    caCertPool,
		MinVersion:   stls.VersionTLS13,
		ClientAuth:   stls.RequireAndVerifyClientCert, // 声明需要客户端证书
	}

	listen, err := net.Listen("tcp", "127.0.0.1:8443")
	if err != nil {
		log.Fatalf("listen error %s", err)
	}
	defer listen.Close()

	ctx, can := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer can()

	log.Println("running")
	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Printf("accept error %s", err)
			continue
		}
		go process(ctx, conn, config)
	}

}

func process(ctx context.Context, conn net.Conn, conf *stls.Config) {
	defer conn.Close()

	log.Printf("got conn from %s", conn.RemoteAddr())
	tls := stls.Server(nil, conf)

	var buf [1024]byte

	for {
		n, err := conn.Read(buf[:])
		if err != nil {
			log.Printf("read error %s", err)
			return
		}

		got, send, err := tls.Eat(buf[:n])
		if err != nil {
			log.Printf("tls error %s", err)
		}
		if len(send) != 0 {
			log.Printf("send %d", len(send))
			_, err = conn.Write(send)
			if err != nil {
				log.Printf("write error %s", err)
			}
		}
		if len(got) != 0 {
			log.Printf("got %s", string(got))
			output, err := tls.Out(response)
			if err != nil {
				log.Printf("encrypt failed: %s", err)
				continue
			}
			conn.Write(output)
			return
		}
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
