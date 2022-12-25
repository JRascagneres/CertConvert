package convert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"software.sslmate.com/src/go-pkcs12"
)

func ConvertToPfx(certRaw, chainRaw, keyRaw []byte) ([]byte, error) {
	certData, _ := pem.Decode(certRaw)

	cert, err := x509.ParseCertificate(certData.Bytes)
	if err != nil {
		return nil, err
	}

	key, err := loadPrivateKey(keyRaw)
	if err != nil {
		return nil, err
	}

	caCertsData, err := readCACerts(chainRaw)
	if err != nil {
		return nil, err
	}

	var caCerts []*x509.Certificate
	for _, caCertData := range caCertsData {
		var caCert *x509.Certificate
		caCert, err = x509.ParseCertificate(caCertData)
		if err != nil {
			return nil, err
		}
		caCerts = append(caCerts, caCert)
	}

	pfxBytes, err := pkcs12.Encode(rand.Reader, key, cert, caCerts, pkcs12.DefaultPassword)
	if err != nil {
		return nil, err
	}

	// Decode again to validate that its worked
	_, _, _, err = pkcs12.DecodeChain(pfxBytes, pkcs12.DefaultPassword)
	if err != nil {
		return nil, err
	}

	return pfxBytes, nil
}

func readCACerts(data []byte) ([][]byte, error) {
	var rawData = data

	var caCerts = make([][]byte, 0)
	for {
		block, rest := pem.Decode(rawData)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			caCerts = append(caCerts, block.Bytes)
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
	if key, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil

		default:
			return nil, fmt.Errorf("error 1")
		}
	}

	return nil, fmt.Errorf("error")
}
