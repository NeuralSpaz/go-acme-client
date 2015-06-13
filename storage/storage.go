package storage

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/stbuehler/go-acme-client/requests"
	"github.com/stbuehler/go-acme-client/utils"
	"io"
	"os"
)

var TooManyKeys = errors.New("Storage containts more than one key")
var EmptyStorage = errors.New("Storage didn't contain registration or key")

const pemTypeAcmeJsonRegistration = "ACME JSON REGISTRATION"
const pemTypeAcmeJsonAuthorization = "ACME JSON AUTHORIZATION"
const pemTypeEcPrivateKey = "EC PRIVATE KEY"
const pemTypeRsaPrivateKey = "RSA PRIVATE KEY"

type Storage struct {
	StoragePassword  string
	RegistrationData *requests.Registration
	RegistrationKey  utils.SigningKey
	Authorizations   []requests.Authorization
}

func LoadStorageFile(filename string, prompt func() (string, error)) (*Storage, error) {
	if file, err := os.Open(filename); os.IsNotExist(err) {
		// not existing file is not an error - just no storage
		return nil, nil
	} else if nil != err {
		return nil, err
	} else {
		defer file.Close()
		return LoadStorage(file, prompt)
	}
}

func LoadStorage(r io.Reader, prompt func() (string, error)) (*Storage, error) {
	var storage = new(Storage)

	blocks, err := utils.LoadPemBlocks(r, func() (string, error) {
		pw, err := prompt()
		if nil == err {
			storage.StoragePassword = pw
		}
		return pw, err
	})
	if nil != err {
		return nil, err
	}

	var pemRegistration *pem.Block
	var pemKey *pem.Block
	var pemAuthorizations []*pem.Block

	for _, block := range blocks {
		if pemTypeAcmeJsonRegistration == block.Type {
			if nil != pemRegistration {
				return nil, TooManyKeys
			}
			pemRegistration = block
		} else if pemTypeEcPrivateKey == block.Type || pemTypeRsaPrivateKey == block.Type {
			if nil != pemKey {
				return nil, TooManyKeys
			}
			pemKey = block
		} else if pemTypeAcmeJsonAuthorization == block.Type {
			pemAuthorizations = append(pemAuthorizations, block)
		}
	}

	if nil == pemKey || nil == pemRegistration {
		return nil, EmptyStorage
	}

	storage.RegistrationKey, err = utils.LoadSigningKey(*pemKey)
	if nil != err {
		return nil, err
	}

	err = json.Unmarshal(pemRegistration.Bytes, &storage.RegistrationData)
	if nil != err {
		return nil, fmt.Errorf("%s section contains invalid JSON: %s", pemTypeAcmeJsonRegistration, err)
	}

	for _, block := range pemAuthorizations {
		var auth requests.Authorization
		if err = json.Unmarshal(block.Bytes, &auth); nil != err {
			return nil, fmt.Errorf("%s section contains invalid JSON: %s", pemTypeAcmeJsonAuthorization, err)
		}
		storage.Authorizations = append(storage.Authorizations, auth)
	}

	return storage, nil
}

func SaveStorageFile(filename string, storage *Storage) error {
	if file, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600); nil != err {
		return err
	} else {
		defer file.Close()
		return SaveStorage(file, storage)
	}
}

func SaveStorage(w io.Writer, storage *Storage) error {
	regDataHead := map[string]string{"Location": storage.RegistrationData.UrlSelf}
	if data, err := json.Marshal(storage.RegistrationData); nil != err {
		return err
	} else if err = pem.Encode(w, &pem.Block{Bytes: data, Type: pemTypeAcmeJsonRegistration, Headers: regDataHead}); nil != err {
		return err
	}

	if block, err := storage.RegistrationKey.EncryptPrivateKey(storage.StoragePassword, x509.PEMCipherAES256); nil != err {
		return err
	} else if err = pem.Encode(w, block); nil != err {
		return err
	}

	for _, auth := range storage.Authorizations {
		blockHead := map[string]string{"Location": auth.UrlSelf, "DNSIdentifier": auth.DNSIdentifier}
		if data, err := json.Marshal(auth); nil != err {
			return err
		} else if err = pem.Encode(w, &pem.Block{Bytes: data, Type: pemTypeAcmeJsonAuthorization, Headers: blockHead}); nil != err {
			return err
		}
	}

	return nil
}
