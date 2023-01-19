package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"

	"github.com/hxzhao527/stls/stls"
)

func main() {
	cer, err := stls.LoadX509KeyPair("../cert-maker/certs/server.crt", "../cert-maker/certs/server.key")
	if err != nil {
		log.Println(err)
		return
	}
	config := &stls.Config{Certificates: []stls.Certificate{cer}}

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

/*
1.3
curl -v --cacert test/server.crt --tlsv1.3 --location  https://127.0.0.1:8443

1.2
curl -v --cacert test/server.crt --tlsv1.2 --tls-max 1.2  --location  https://127.0.0.1:8443

1.1
curl -v --cacert test/server.crt --tlsv1.1 --tls-max 1.1  --location  https://127.0.0.1:8443
*/
