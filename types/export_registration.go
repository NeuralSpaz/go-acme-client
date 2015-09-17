package types

import (
	"encoding/json"
	"encoding/pem"
	"github.com/stbuehler/go-acme-client/utils"
)

type RegistrationExport struct {
	JsonPem       []byte
	SigningKeyPem []byte
	Location      string
	Name          string
}

type rawRegistrationExportJson struct {
	Resource           RegistrationResource
	LinkTermsOfService string
	RecoveryToken      string
}

func (reg Registration) Export(password string) (*RegistrationExport, error) {
	keyBlock, err := reg.SigningKey.EncryptPrivateKey(password, utils.PemDefaultCipher)
	if nil != err {
		return nil, err
	}
	jsonBytes, err := json.Marshal(rawRegistrationExportJson{
		Resource:           reg.Resource,
		LinkTermsOfService: reg.LinkTermsOfService,
		RecoveryToken:      reg.RecoveryToken,
	})
	if nil != err {
		return nil, err
	}
	jsonBlock := &pem.Block{
		Type:  pemTypeAcmeJsonRegistration,
		Bytes: jsonBytes,
	}
	if err := utils.EncryptPemBlock(jsonBlock, password, utils.PemDefaultCipher); nil != err {
		return nil, err
	}
	return &RegistrationExport{
		JsonPem:       pem.EncodeToMemory(jsonBlock),
		SigningKeyPem: pem.EncodeToMemory(keyBlock),
		Location:      reg.Location,
		Name:          reg.Name,
	}, nil
}

func (reg *Registration) Import(export RegistrationExport, prompt PasswordPrompt) error {
	jsonBlock, err := importPem(export.JsonPem, prompt, pemTypeAcmeJsonRegistration)
	if nil != err {
		return err
	}
	keyBlock, err := importPem(export.SigningKeyPem, prompt, pemTypeEcPrivateKey, pemTypeRsaPrivateKey)
	if nil != err {
		return err
	}

	var rawReg rawRegistrationExportJson
	if err := json.Unmarshal(jsonBlock.Bytes, &rawReg); nil != err {
		return err
	}
	signingKey, err := LoadSigningKey(*keyBlock)
	if nil != err {
		return err
	}

	reg.Resource = rawReg.Resource
	reg.SigningKey = signingKey
	reg.Location = export.Location
	reg.LinkTermsOfService = rawReg.LinkTermsOfService
	reg.RecoveryToken = rawReg.RecoveryToken
	reg.Name = export.Name

	return nil
}
