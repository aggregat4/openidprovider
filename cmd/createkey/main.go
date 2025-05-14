package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"os"
)

func main() {
	var privateKeyFile string
	var publicKeyFile string
	flag.StringVar(&privateKeyFile, "private", "private.pem", "Output file for private key")
	flag.StringVar(&publicKeyFile, "public", "public.pem", "Output file for public key")
	flag.Parse()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	// Store private key in PEM file
	privateFile, err := os.Create(privateKeyFile)
	if err != nil {
		panic(err)
	}
	err = pem.Encode(privateFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err != nil {
		panic(err)
	}
	defer privateFile.Close()
	// Store public key in PEM file
	publicKey := privateKey.PublicKey
	publicFile, err := os.Create(publicKeyFile)
	if err != nil {
		panic(err)
	}
	err = pem.Encode(publicFile, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&publicKey)})
	if err != nil {
		panic(err)
	}
	defer publicFile.Close()
}
