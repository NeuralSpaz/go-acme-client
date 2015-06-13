package utils

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

const pemTypeCertificate = "CERTIFICATE"

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

type CertificateParameters struct {
	SigningKey                interface{}
	ParentCertificate         *x509.Certificate
	PublicKey                 interface{}
	DefaultSignatureAlgorithm x509.SignatureAlgorithm
	Subject                   pkix.Name
	Duration                  time.Duration
	DNSNames                  []string
	SerialNumber              *big.Int
}

func MakeSerialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, serialNumberLimit)
}

func MakeCertificate(parameters CertificateParameters) (*pem.Block, error) {
	if nil == parameters.SigningKey {
		return nil, fmt.Errorf("Missing signing key")
	}
	if nil == parameters.PublicKey {
		if pubKey, err := PublicKey(parameters.SigningKey); nil != err {
			return nil, err
		} else {
			parameters.PublicKey = pubKey // default to self-signed
		}
	}
	if x509.UnknownSignatureAlgorithm == parameters.DefaultSignatureAlgorithm {
		parameters.DefaultSignatureAlgorithm = x509.SHA512WithRSA
	}
	sigAlg := PickSignatureAlgorithm(parameters.SigningKey, parameters.DefaultSignatureAlgorithm)
	if 0 == len(parameters.Subject.CommonName) {
		if 0 == len(parameters.DNSNames) {
			return nil, fmt.Errorf("Need either CommonName or at least one domain for certificate")
		}
		parameters.Subject.CommonName = parameters.DNSNames[0]
	}
	if 0 == parameters.Duration {
		parameters.Duration = 365 * 86400 * time.Second // one year
	}
	if nil == parameters.SerialNumber {

		if serial, err := MakeSerialNumber(); nil != err {
			return nil, err
		} else {
			parameters.SerialNumber = serial
		}
	}

	var now = time.Now()

	csr := x509.Certificate{
		SignatureAlgorithm:    sigAlg,
		SerialNumber:          parameters.SerialNumber,
		Subject:               parameters.Subject,
		NotBefore:             now,
		NotAfter:              now.Add(parameters.Duration),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                        false,
		MaxPathLen:                  0,
		DNSNames:                    parameters.DNSNames,
		PermittedDNSDomainsCritical: false,
		PermittedDNSDomains:         []string{},
	}

	parent := parameters.ParentCertificate
	if nil == parent {
		parent = &csr
	}

	cert_data, err := x509.CreateCertificate(rand.Reader, &csr, parent, parameters.PublicKey, parameters.SigningKey)
	if err != nil {
		return nil, err
	}
	return &pem.Block{
		Type:  pemTypeCertificate,
		Bytes: cert_data,
	}, nil
}
