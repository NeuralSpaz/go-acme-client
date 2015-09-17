package types

import (
	"encoding/pem"
	"github.com/stbuehler/go-acme-client/utils"
)

type CertificateExport struct {
	CertificatePem []byte
	PrivateKeyPem  []byte
	Location       string
	LinkIssuer     string
}

func (cert *Certificate) Import(export CertificateExport, prompt PasswordPrompt) error {
	certificateBlock, err := importPem(export.CertificatePem, prompt, pemTypeCertificate)
	if nil != err {
		return err
	}
	var privateKeyBlock *pem.Block
	if nil != export.PrivateKeyPem {
		privateKeyBlock, err = importPem(export.PrivateKeyPem, prompt, pemTypeEcPrivateKey, pemTypeRsaPrivateKey)
		if nil != err {
			return err
		}
	}

	cert.Certificate = certificateBlock
	cert.PrivateKey = privateKeyBlock
	cert.Location = export.Location
	cert.LinkIssuer = export.LinkIssuer

	return nil
}

func (cert Certificate) Export(password string) (*CertificateExport, error) {
	var privateKeyBlob []byte
	if nil != cert.PrivateKey {
		privateKeyBlock := *cert.PrivateKey
		if err := utils.EncryptPemBlock(&privateKeyBlock, password, utils.PemDefaultCipher); nil != err {
			return nil, err
		}
		privateKeyBlob = pem.EncodeToMemory(&privateKeyBlock)
	}

	return &CertificateExport{
		CertificatePem: pem.EncodeToMemory(cert.Certificate),
		PrivateKeyPem:  privateKeyBlob,
		Location:       cert.Location,
		LinkIssuer:     cert.LinkIssuer,
	}, nil
}
