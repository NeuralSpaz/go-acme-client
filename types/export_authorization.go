package types

import (
	"encoding/json"
	"encoding/pem"
	"github.com/stbuehler/go-acme-client/utils"
)

type AuthorizationExport struct {
	JsonPem []byte
}

func (auth *Authorization) Import(export AuthorizationExport, prompt PasswordPrompt) error {
	if jsonBlock, err := importPem(export.JsonPem, prompt, pemTypeAcmeJsonAuthorization); nil != err {
		return err
	} else {
		var importedAuth Authorization
		if err := json.Unmarshal(jsonBlock.Bytes, &importedAuth); nil != err {
			return err
		}
		*auth = importedAuth
		return nil
	}
}

func (auth Authorization) Export(password string) (*AuthorizationExport, error) {
	if jsonBytes, err := json.Marshal(auth); nil != err {
		return nil, err
	} else {
		jsonBlock := &pem.Block{
			Type:  pemTypeAcmeJsonAuthorization,
			Bytes: jsonBytes,
		}
		if err := utils.EncryptPemBlock(jsonBlock, password, utils.PemDefaultCipher); nil != err {
			return nil, err
		}
		return &AuthorizationExport{
			JsonPem: pem.EncodeToMemory(jsonBlock),
		}, nil
	}
}
