package utils

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
)

const pemTypeCertificateRequest = "CERTIFICATE REQUEST"

type CertificateRequestParameters struct {
	PrivateKey                interface{}
	DefaultSignatureAlgorithm x509.SignatureAlgorithm
	Subject                   pkix.Name
	DNSNames                  []string
}

func MakeCertificateRequest(parameters CertificateRequestParameters) (*pem.Block, error) {
	publicKey, err := PublicKey(parameters.PrivateKey)
	if nil != err {
		return nil, err
	}
	if x509.UnknownSignatureAlgorithm == parameters.DefaultSignatureAlgorithm {
		parameters.DefaultSignatureAlgorithm = x509.SHA256WithRSA
	}
	sigAlg := PickSignatureAlgorithm(parameters.PrivateKey, parameters.DefaultSignatureAlgorithm)

	if 0 == len(parameters.Subject.CommonName) {
		if 0 != len(parameters.DNSNames) {
			parameters.Subject.CommonName = parameters.DNSNames[0]
		}
	}

	req := x509.CertificateRequest{
		SignatureAlgorithm: sigAlg,
		PublicKey:          publicKey,
		Subject:            parameters.Subject,
		DNSNames:           parameters.DNSNames,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &req, parameters.PrivateKey)
	if nil != err {
		return nil, err
	}

	return &pem.Block{
		Bytes: csr,
		Type:  pemTypeCertificateRequest,
	}, nil
}
