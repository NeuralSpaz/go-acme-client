package storage

import (
	"encoding/pem"
	"errors"
	"github.com/stbuehler/go-acme-client/utils"
)

var NotASinglePemBlock = errors.New("Expected single PEM block")
var UnexpectedPemBlock = errors.New("Unexpected PEM block")

const pemTypeEcPrivateKey = "EC PRIVATE KEY"
const pemTypeRsaPrivateKey = "RSA PRIVATE KEY"
const pemTypePublicKey = "PUBLIC KEY"
const pemTypeCertificate = "CERTIFICATE"
const pemTypeAcmeJsonRegistration = "ACME JSON REGISTRATION"
const pemTypeAcmeJsonAuthorization = "ACME JSON AUTHORIZATION"

func (storage Storage) loadPem(pemData []byte, types ...string) (*pem.Block, error) {
	block, pemData := pem.Decode(pemData)
	block2, _ := pem.Decode(pemData)
	if nil == block || nil != block2 {
		return nil, NotASinglePemBlock
	}

	validType := false
	for _, t := range types {
		if t == block.Type {
			validType = true
			break
		}
	}
	if !validType {
		return nil, UnexpectedPemBlock
	}

	if err := utils.DecryptPemBlock(block, storage.passwordPrompt); nil != err {
		return nil, err
	}
	return block, nil
}
