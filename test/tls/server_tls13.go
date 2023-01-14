package main

import (
	"bufio"

	"log"
	"net"

	"github.com/hxzhao527/stls/stls"
)

func main() {
	log.SetFlags(log.Lshortfile)

	cer, err := stls.LoadX509KeyPair("../server.crt", "../server.key")
	if err != nil {
		log.Println(err)
		return
	}

	config := &stls.Config{Certificates: []stls.Certificate{cer}}
	ln, err := stls.Listen("tcp", "192.168.1.11:8443", config)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()

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
	for {
		msg, err := r.ReadString('\n')
		if err != nil {
			log.Println(err)
			return
		}

		println(msg)

		n, err := conn.Write([]byte("world\n"))
		if err != nil {
			log.Println(n, err)
			return
		}
	}
}
