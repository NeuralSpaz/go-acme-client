package storage

import (
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/utils"
	"time"
)

type StorageAuthorization struct {
	storage         Storage
	registration_id int64
	id              int64
	Authorization   types.Authorization
}

type AuthorizationInfo struct {
	DNSName  string
	Location string
	Status   types.AuthorizationStatus
	Expires  *time.Time
}

func (storage Storage) checkAuthorizationTable() error {
	_, err := storage.db.Exec(
		`CREATE TABLE IF NOT EXISTS authorization (
			id INTEGER PRIMARY KEY,
			registration_id INT NOT NULL,
			dnsName TEXT NOT NULL,
			location TEXT NOT NULL,
			status TEXT NOT NULL,
			expires TEXT,
			jsonPem BLOB NOT NULL,
			FOREIGN KEY(registration_id) REFERENCES registration(id),
			UNIQUE (registration_id, location)
		)`)
	return err
}

func authInfoListFromRows(rows *sql.Rows) (map[string][]AuthorizationInfo, error) {
	regs := make(map[string][]AuthorizationInfo)
	for rows.Next() {
		var dnsName string
		var location string
		var status string
		var expiresString sql.NullString
		if err := rows.Scan(&dnsName, &location, &status, &expiresString); nil != err {
			return nil, err
		}
		var expires *time.Time
		// oO.. use json to convert NULLable column to time...
		if expiresString.Valid {
			expires = &time.Time{}
			if expiresJson, err := json.Marshal(expiresString.String); nil != err {
				return nil, err
			} else if err := json.Unmarshal(expiresJson, expires); nil != err {
				return nil, err
			}
		}
		regs[dnsName] = append(regs[dnsName], AuthorizationInfo{
			DNSName:  dnsName,
			Location: location,
			Status:   types.AuthorizationStatus(status),
			Expires:  expires,
		})
	}
	return regs, nil
}

func (registration StorageRegistration) AuthorizationList() (map[string][]AuthorizationInfo, error) {
	rows, err := registration.storage.db.Query(
		`SELECT dnsName, location, status, strftime('%Y-%m-%dT%H:%M:%fZ', expires) FROM authorization WHERE registration_id = $1 ORDER BY id DESC`,
		registration.id)
	if nil != err {
		return nil, err
	}
	defer rows.Close()
	return authInfoListFromRows(rows)
}

func (registration StorageRegistration) AuthorizationListWithStatus(status types.AuthorizationStatus) (map[string][]AuthorizationInfo, error) {
	rows, err := registration.storage.db.Query(
		`SELECT dnsName, location, status, strftime('%Y-%m-%dT%H:%M:%fZ', expires) FROM authorization WHERE registration_id = $1 AND status = $2 ORDER BY id DESC`,
		registration.id, string(status))
	if nil != err {
		return nil, err
	}
	defer rows.Close()
	return authInfoListFromRows(rows)
}

func (registration StorageRegistration) LoadAuthorization(locationOrDnsName string) (*StorageAuthorization, error) {
	rows, err := registration.storage.db.Query("SELECT id, jsonPem FROM authorization WHERE registration_id = $1 AND location = $2", registration.id, locationOrDnsName)
	if nil != err {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		rows, err = registration.storage.db.Query("SELECT id, jsonPem FROM authorization WHERE registration_id = $1 AND dnsName = $2 ORDER BY id DESC LIMIT 1", registration.id, locationOrDnsName)
		if nil != err {
			return nil, err
		}
		defer rows.Close()
		if !rows.Next() {
			return nil, nil
		}
	}

	var id int64
	var jsonPem []byte
	if err := rows.Scan(&id, &jsonPem); nil != err {
		return nil, err
	}
	jsonBlock, err := registration.storage.loadPem(jsonPem, pemTypeAcmeJsonAuthorization)
	if nil != err {
		return nil, err
	}

	var auth types.Authorization
	if err := json.Unmarshal(jsonBlock.Bytes, &auth); nil != err {
		return nil, err
	}

	return &StorageAuthorization{
		storage:         registration.storage,
		registration_id: registration.id,
		id:              id,
		Authorization:   auth,
	}, nil
}

func (sauth StorageAuthorization) Save() error {
	jsonBytes, err := json.Marshal(sauth.Authorization)
	if nil != err {
		return err
	}
	jsonBlock := &pem.Block{
		Type:  pemTypeAcmeJsonAuthorization,
		Bytes: jsonBytes,
	}
	if err := utils.EncryptPemBlock(jsonBlock, sauth.storage.lastPassword(), utils.PemDefaultCipher); nil != err {
		return err
	}

	_, err = sauth.storage.db.Exec(
		`INSERT OR REPLACE INTO authorization (id, registration_id, dnsName, location, status, expires, jsonPem) VALUES
			($1, $2, $3, $4, $5, $6, $7)`,
		sauth.id, sauth.registration_id, sauth.Authorization.DNSIdentifier, sauth.Authorization.Location,
		string(sauth.Authorization.Status), sauth.Authorization.Expires, pem.EncodeToMemory(jsonBlock))

	return err
}

func (registration StorageRegistration) NewAuthorization(authorization types.Authorization) (*StorageAuthorization, error) {
	jsonBytes, err := json.Marshal(authorization)
	if nil != err {
		return nil, err
	}
	jsonBlock := &pem.Block{
		Type:  pemTypeAcmeJsonAuthorization,
		Bytes: jsonBytes,
	}
	if err := utils.EncryptPemBlock(jsonBlock, registration.storage.lastPassword(), utils.PemDefaultCipher); nil != err {
		return nil, err
	}

	_, err = registration.storage.db.Exec(
		`INSERT INTO authorization (registration_id, dnsName, location, status, expires, jsonPem) VALUES
			($1, $2, $3, $4, $5, $6)`,
		registration.id, authorization.DNSIdentifier, authorization.Location,
		string(authorization.Status), authorization.Expires, pem.EncodeToMemory(jsonBlock))
	if nil != err {
		return nil, err
	}

	return registration.LoadAuthorization(authorization.Location)
}
