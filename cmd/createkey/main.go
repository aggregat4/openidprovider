package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	// Store private key in PEM file
	privateFile, err := os.Create("private.pem")
	if err != nil {
		panic(err)
	}
	pem.Encode(privateFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	privateFile.Close()
	// Store public key in PEM file
	publicKey := privateKey.PublicKey
	publicFile, err := os.Create("public.pem")
	if err != nil {
		panic(err)
	}
	pem.Encode(publicFile, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&publicKey)})
	publicFile.Close()
}
