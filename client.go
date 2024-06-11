package main

import (
	"crypto/tls"
	"fmt"
	"sync"
)

func main() {
	conn, err := tls.Dial("tcp", "127.0.0.1:21111", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		panic(err)
	}

	defer conn.Close()
	_, err = conn.Write([]byte("hello world"))
	if err != nil {
		panic(err)
	}
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			buf := make([]byte, 1024)
			_, err = conn.Read(buf)
			if err != nil {
				panic(err)
			}
			fmt.Println(string(buf))
		}
	}()

	wg.Wait()
}
