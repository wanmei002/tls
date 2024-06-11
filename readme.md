## 生成根证书
### 创建一个 struct 来保存私钥等信息
```go
type CA struct {
	key       *rsa.PrivateKey
	publicKey rsa.PublicKey
	ca        []byte
	keyPerm   []byte
	certPem   []byte
}
```
### 生成私钥
```go
func (ca *CA) genPrivateKey() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Println("generate private key err:", err)
		return err
	}
	ca.key = privateKey
	ca.publicKey = privateKey.PublicKey
	return nil
}
```
### 生成根证书
```go
func (ca *CA) genCertificate(serviceName string) error {
	maxInt := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, maxInt)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
		return err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ZZH Co. Ltd"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{serviceName},
	}
	ca.ca, err = x509.CreateCertificate(rand.Reader, &template, &template, &ca.publicKey, ca.key)
	if err != nil {
		return err
	}

	ca.keyPerm = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ca.key)})
	ca.certPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.ca})
	return nil
}
```
### NewCA
```go
func NewCA(serviceName string) (*CA, error) {
	ca := &CA{}
	err := ca.genPrivateKey()
	if err != nil {
		return nil, err
	}
	err = ca.genCertificate(serviceName)
	if err != nil {
		return nil, err
	}
	return ca, nil
}
```

### 基于根证书生成 服务器 证书
```go
ca, err := private_key.NewCA("example.com")
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
```

### 服务端tls监听端口
```go
package main

import (
	"crypto/tls"
	"fmt"
	"github.com/wanmei002/tls/private_key"
	"io"
)

func main() {
	ca, err := private_key.NewCA("example.com")
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
```

### 客户端 tls 请求
```go
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
```


