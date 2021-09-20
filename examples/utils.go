package examples

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func ParsePrivateKey(in []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(in)
	keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf(`x509.ParsePKCS8PrivateKey(block.Bytes) %w`, err)
	}

	pkey, ok := keyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not RSA private key")
	}

	pkey.Precompute()
	if err := pkey.Validate(); err != nil {
		return nil, fmt.Errorf(`pkey.Validate() %w`, err)
	}

	return pkey, nil
}
