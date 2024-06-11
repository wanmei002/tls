package private_key

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"time"
)

type CA struct {
	key       *rsa.PrivateKey
	publicKey rsa.PublicKey
	ca        []byte
	keyPerm   []byte
	certPem   []byte
}

func (ca *CA) KeyPerm() []byte {
	return ca.keyPerm
}

func (ca *CA) CertPem() []byte {
	return ca.certPem
}

func (ca *CA) PrivateKey() *rsa.PrivateKey {
	return ca.key
}

func (ca *CA) PublicKey() rsa.PublicKey {
	return ca.publicKey
}

func (ca *CA) CA() []byte {
	return ca.ca
}

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
