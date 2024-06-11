package main

import (
	"crypto/tls"
	"fmt"
	"github.com/wanmei002/tls/private_key"
	"io"
)

func main() {
	ca, err := private_key.NewCA("zzh")
	if err != nil {
		panic(err)
	}
	// create tls cert
	serviceCert, err := tls.X509KeyPair(ca.CertPem(), ca.KeyPerm())
	if err != nil {
		panic(err)
	}
	tlsServiceConfig := &tls.Config{
		Certificates: []tls.Certificate{
			serviceCert,
		},
	}

	ln, err := tls.Listen("tcp", ":21111", tlsServiceConfig)
	if err != nil {
		panic(err)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		go func() {
			defer conn.Close()
			buf := make([]byte, 1024)
			for {
				_, err := conn.Read(buf)
				if err != nil && err != io.EOF {
					panic(err)
				}
				fmt.Println(string(buf))
				_, err = conn.Write([]byte("Hello"))
				if err != nil {
					panic(err)
				}
			}
		}()
	}
}
