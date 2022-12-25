package convert

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"software.sslmate.com/src/go-pkcs12"
)

func ConvertToPfx(certRaw, chainRaw, keyRaw []byte, password string) ([]byte, error) {
	// Read in certificate bytes block and parse it in as a x509 certificate
	certData, _ := pem.Decode(certRaw)
	cert, err := x509.ParseCertificate(certData.Bytes)
	if err != nil {
		return nil, err
	}

	// Load in key bytes as a private key type
	key, err := loadPrivateKey(keyRaw)
	if err != nil {
		return nil, err
	}

	// Read in all the certificate blocks in the chain
	caCerts, err := readCACerts(chainRaw)
	if err != nil {
		return nil, err
	}

	// Convert key, cert and chain to a pfx type
	pfxBytes, err := pkcs12.Encode(rand.Reader, key, cert, caCerts, password)
	if err != nil {
		return nil, err
	}

	// Decode again to validate that its worked
	_, _, _, err = pkcs12.DecodeChain(pfxBytes, password)
	if err != nil {
		return nil, err
	}

	return pfxBytes, nil
}

func readCACerts(data []byte) ([]*x509.Certificate, error) {
	var rawData = data

	var caCerts = make([]*x509.Certificate, 0)
	for {
		block, rest := pem.Decode(rawData)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			caCert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			caCerts = append(caCerts, caCert)
		} else {
			return nil, fmt.Errorf("unexpected type")
		}

		rawData = rest
	}

	return caCerts, nil
}

func loadPrivateKey(data []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no data")
	}

	return parsePrivateKey(block.Bytes)
}

func parsePrivateKey(data []byte) (crypto.PrivateKey, error) {
	parsedKey, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, err
	}

	switch key := parsedKey.(type) {
	case *rsa.PrivateKey:
		return key, nil
	default:
		return nil, fmt.Errorf("unexpected private key type")
	}
}
