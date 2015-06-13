package storage

import (
	"encoding/json"
	"encoding/pem"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/utils"
)

type StorageRegistration struct {
	storage      Storage
	id           int64
	AccountName  string
	SigningKey   types.SigningKey
	Registration types.Registration
}

func (storage Storage) checkRegistrationTable() error {
	_, err := storage.db.Exec(
		`CREATE TABLE IF NOT EXISTS registration (
			id INTEGER PRIMARY KEY,
			accountName TEXT NOT NULL,
			location TEXT NOT NULL,
			jsonPem BLOB NOT NULL,
			keyPem BLOB NOT NULL)`)
	return err
}

func (storage Storage) RegistrationList() (map[string]string, error) {
	rows, err := storage.db.Query("SELECT accountName, location FROM registration")
	if nil != err {
		return nil, err
	}
	defer rows.Close()
	regs := make(map[string]string)
	for rows.Next() {
		var accountName string
		var location string
		if err := rows.Scan(&accountName, &location); nil != err {
			return nil, err
		}
		regs[accountName] = location
	}
	return regs, nil
}

func (storage Storage) LoadRegistration(accountName string) (*StorageRegistration, error) {
	rows, err := storage.db.Query("SELECT id, jsonPem, keyPem FROM registration WHERE accountName = $1", accountName)
	if nil != err {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}

	var id int64
	var jsonPem []byte
	var keyPem []byte
	if err := rows.Scan(&id, &jsonPem, &keyPem); nil != err {
		return nil, err
	}
	jsonBlock, err := storage.loadPem(jsonPem, pemTypeAcmeJsonRegistration)
	if nil != err {
		return nil, err
	}
	keyBlock, err := storage.loadPem(keyPem, pemTypeEcPrivateKey, pemTypeRsaPrivateKey)
	if nil != err {
		return nil, err
	}

	var reg types.Registration
	if err := json.Unmarshal(jsonBlock.Bytes, &reg); nil != err {
		return nil, err
	}
	signingKey, err := types.LoadSigningKey(*keyBlock)
	if nil != err {
		return nil, err
	}

	return &StorageRegistration{
		storage:      storage,
		id:           id,
		AccountName:  accountName,
		SigningKey:   signingKey,
		Registration: reg,
	}, nil
}

func (sreg StorageRegistration) Save() error {
	keyBlock, err := sreg.SigningKey.EncryptPrivateKey(sreg.storage.lastPassword(), utils.PemDefaultCipher)
	if nil != err {
		return err
	}
	jsonBytes, err := json.Marshal(sreg.Registration)
	if nil != err {
		return err
	}
	jsonBlock := &pem.Block{
		Type:  pemTypeAcmeJsonRegistration,
		Bytes: jsonBytes,
	}
	if err := utils.EncryptPemBlock(jsonBlock, sreg.storage.lastPassword(), utils.PemDefaultCipher); nil != err {
		return err
	}

	_, err = sreg.storage.db.Exec(
		"INSERT OR REPLACE INTO registration (id, accountName, location, jsonPem, keyPem) VALUES ($1, $2, $3, $4, $5)",
		sreg.id, sreg.AccountName, sreg.Registration.Location, pem.EncodeToMemory(jsonBlock), pem.EncodeToMemory(keyBlock))

	return err
}

func (storage Storage) NewRegistration(accountName string, signingKey types.SigningKey, registration types.Registration) (*StorageRegistration, error) {
	keyBlock, err := signingKey.EncryptPrivateKey(storage.lastPassword(), utils.PemDefaultCipher)
	if nil != err {
		return nil, err
	}
	jsonBytes, err := json.Marshal(registration)
	if nil != err {
		return nil, err
	}
	jsonBlock := &pem.Block{
		Type:  pemTypeAcmeJsonRegistration,
		Bytes: jsonBytes,
	}
	if err := utils.EncryptPemBlock(jsonBlock, storage.lastPassword(), utils.PemDefaultCipher); nil != err {
		return nil, err
	}

	_, err = storage.db.Exec(
		"INSERT INTO registration (accountName, location, jsonPem, keyPem) VALUES ($1, $2, $3, $4)",
		accountName, registration.Location, pem.EncodeToMemory(jsonBlock), pem.EncodeToMemory(keyBlock))

	if nil != err {
		return nil, err
	}

	return storage.LoadRegistration(accountName)
}
