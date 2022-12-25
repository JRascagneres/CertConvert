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

func PemToPfx(certRaw, chainRaw, keyRaw []byte, password string) ([]byte, error) {
	// Load in key bytes as a private key type
	key, err := loadPrivateKey(keyRaw)
	if err != nil {
		return nil, err
	}

	// Load in cert bytes as a certificate type
	cert, err := loadCert(certRaw)
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

// readCACerts reads the raw data from the chain file. We iterate through each block in the chain file and parse them
// adding them to a slice for return.
// We return errors in two cases, if the parsing of the certificate fails, or if the block type is incorrect.
func readCACerts(data []byte) ([]*x509.Certificate, error) {
	var caCerts = make([]*x509.Certificate, 0)
	for {
		block, rest := pem.Decode(data)
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

		data = rest
	}

	return caCerts, nil
}

// loadCert reads in the raw data from the cert file. This reads in the single expected block and parses it as a
// certificate.
// We return errors in a number of cases, if data is nil, if there is more than a single block of data or if the data is
// not a certificate type.
func loadCert(data []byte) (*x509.Certificate, error) {
	blockBytes, err := readBlock(data, "CERTIFICATE")
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(blockBytes)
}

// loadPrivateKey reads in the raw data from the key file. This reads in the single expected block and parses it as a
// private key.
// We return errors in a number of cases, if data is nil, if there is more than a single block of data or if the data is
// not a private key type.
func loadPrivateKey(data []byte) (crypto.PrivateKey, error) {
	blockBytes, err := readBlock(data, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}

	return parsePrivateKey(blockBytes)
}

// readBlock reads in a file where a single block is expected and verifies its type, returning its bytes.
func readBlock(data []byte, expectedBlockType string) ([]byte, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no data")
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf("unexpected cert data remaining")
	}

	if block.Type != expectedBlockType {
		return nil, fmt.Errorf("unexpected block type")
	}

	return block.Bytes, nil
}

// parsePrivateKey reads in a raw private key block and parses it as a private key type.
// We return errors if the private key parse fails or if the key type is unexpected.
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
