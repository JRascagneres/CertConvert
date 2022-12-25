package main

import (
	"CertConversion/convert"
	"io/ioutil"
	"os"
)

func main() {
	// In reality this is likely to come from another source such as cloud secret. Temporarily testing based on file
	// contents.
	certRaw, chainRaw, keyRaw, err := readCertData()
	if err != nil {
		panic(err)
	}

	// Convert cert, key and chain to a pfx file
	pfxBytes, err := convert.ConvertToPfx(certRaw, chainRaw, keyRaw)
	if err != nil {
		panic(err)
	}

	// Write result to file, mostly for testing
	if err = ioutil.WriteFile("cert.pfx", pfxBytes, os.ModePerm); err != nil {
		panic(err)
	}
}

func readCertData() ([]byte, []byte, []byte, error) {
	certFolderLocation := "C:/Users/Jacques/Desktop/SecretCerts"

	certPath := certFolderLocation + "/cert.txt"
	chainPath := certFolderLocation + "/chain_cert.txt"
	key := certFolderLocation + "/key.txt"

	certData, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, nil, nil, err
	}

	chainData, err := ioutil.ReadFile(chainPath)
	if err != nil {
		return nil, nil, nil, err
	}

	keyData, err := ioutil.ReadFile(key)
	if err != nil {
		return nil, nil, nil, err
	}

	return certData, chainData, keyData, nil
}
