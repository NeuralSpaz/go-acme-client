package storage_sql

import (
	"database/sql"
	"fmt"
	i "github.com/stbuehler/go-acme-client/storage_interface"
	"github.com/stbuehler/go-acme-client/types"
)

// --------------------------------------------------------------------
// implementations for i.StorageRegistration
// --------------------------------------------------------------------

func (sreg *sqlStorageRegistration) Storage() i.Storage {
	return sreg.storage
}

func (sreg *sqlStorageRegistration) StorageDirectory() i.StorageDirectory {
	return sreg.directory
}

func (sreg *sqlStorageRegistration) Directory() *types.Directory {
	return sreg.directory.Directory()
}

func (sreg *sqlStorageRegistration) StorageRegistration() i.StorageRegistration {
	return sreg
}

func (sreg *sqlStorageRegistration) Registration() *types.Registration {
	return &sreg.registration
}

func (sreg *sqlStorageRegistration) SetRegistration(registration types.Registration) error {
	if err := sreg.storage.saveRegistration(sreg.id, sreg.directory.id, registration); nil != err {
		return err
	}
	sreg.registration = registration
	return nil
}

// in authorization.go
// func (sreg *sqlStorageRegistration) NewAuthorization(auth types.Authorization) (i.StorageAuthorization, error)
// func (sreg *sqlStorageRegistration) AuthorizationInfos() (i.AuthorizationInfos, error)
// func (sreg *sqlStorageRegistration) AuthorizationInfosWithStatus(status types.AuthorizationStatus) (i.AuthorizationInfos, error)
// func (sreg *sqlStorageRegistration) Authorizations() ([]i.StorageAuthorization, error)
// func (sreg *sqlStorageRegistration) LoadAuthorization(locationOrDnsIdentifier string) (i.StorageAuthorization, error)
// func (sreg *sqlStorageRegistration) LoadAuthorizationByURL(authorizationURL string) (i.StorageAuthorization, error)
// func (sreg *sqlStorageRegistration) LoadAuthorizationByDNS(dnsIdentifier string) (i.StorageAuthorization, error)

// in certificate.go
// func (sreg *sqlStorageRegistration) NewCertificate(cert types.Certificate) (i.StorageCertificate, error)
// func (sreg *sqlStorageRegistration) CertificateInfos() ([]CertificateInfo, error)
// func (sreg *sqlStorageRegistration) Certificates() ([]i.StorageCertificate, error)
// func (sreg *sqlStorageRegistration) LoadCertificate(location string) (i.StorageCertificate, error)

func (sreg *sqlStorageRegistration) Delete() error {
	if _, err := sreg.storage.db.Exec("DELETE FROM registration WHERE id = $1", sreg.id); nil != err {
		return err
	}
	sreg.id = -1
	sreg.registration = types.Registration{}
	return nil
}

// --------------------------------------------------------------------
// end [implementations for i.StorageRegistration]
// --------------------------------------------------------------------

// --------------------------------------------------------------------
// implementations for i.Storage
// --------------------------------------------------------------------

func (storage *sqlStorage) RegistrationList() (i.RegistrationList, error) {
	rows, err := storage.db.Query("SELECT name, location FROM registration")
	if nil != err {
		return nil, err
	}
	return registrationListFromSql(rows)
}

func (storage *sqlStorage) LoadRegistration(name string) (i.StorageRegistration, error) {
	if sreg, err := storage.loadRegistrationByName(name, nil); nil != err || nil == sreg {
		// make sure to create a nil interface from the nil pointer!
		return nil, err
	} else {
		return sreg, nil
	}
}

// --------------------------------------------------------------------
// end [implementations for i.Storage]
// --------------------------------------------------------------------

// --------------------------------------------------------------------
// implementations for i.StorageDirectory
// --------------------------------------------------------------------

func (sdir *sqlStorageDirectory) NewRegistration(registration types.Registration) (i.StorageRegistration, error) {
	export, err := registration.Export(sdir.storage.lastPassword())

	_, err = sdir.storage.db.Exec(
		"INSERT INTO registration (directory_id, name, location, jsonPem, keyPem) VALUES ($1, $2, $3, $4, $5)",
		sdir.id, export.Name, export.Location, export.JsonPem, export.SigningKeyPem)

	if nil != err {
		return nil, err
	}

	return sdir.LoadRegistration(registration.Name)
}

func (sdir *sqlStorageDirectory) RegistrationList() (i.RegistrationList, error) {
	rows, err := sdir.storage.db.Query("SELECT name, location FROM registration WHERE directory_id = $1", sdir.id)
	if nil != err {
		return nil, err
	}
	return registrationListFromSql(rows)
}

func (sdir *sqlStorageDirectory) LoadRegistration(name string) (i.StorageRegistration, error) {
	if sreg, err := sdir.storage.loadRegistrationByName(name, sdir); nil != err || nil == sreg {
		// make sure to create a nil interface from the nil pointer!
		return nil, err
	} else if sreg.directory != sdir {
		// not found in this directory, and names are unique across directories
		return nil, nil
	} else {
		return sreg, nil
	}
}

// --------------------------------------------------------------------
// end [implementations for i.StorageDirectory]
// --------------------------------------------------------------------

type sqlStorageRegistration struct {
	storage      *sqlStorage
	directory    *sqlStorageDirectory
	id           int64
	registration types.Registration
}

func (storage *sqlStorage) checkRegistrationTable() error {
	_, err := storage.db.Exec(
		`CREATE TABLE IF NOT EXISTS registration (
			id INTEGER PRIMARY KEY,
			directory_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			location TEXT NOT NULL,
			jsonPem BLOB NOT NULL,
			keyPem BLOB NOT NULL,
			FOREIGN KEY(directory_id) REFERENCES directory(id),
			UNIQUE (name))`)
	return err
}

func registrationListFromSql(rows *sql.Rows) (i.RegistrationList, error) {
	defer rows.Close()
	regs := make(map[string]string)
	for rows.Next() {
		var name string
		var location string
		if err := rows.Scan(&name, &location); nil != err {
			return nil, err
		}
		regs[name] = location
	}
	return i.RegistrationList(regs), nil
}

func (storage *sqlStorage) loadRegistrationFromSql(rows *sql.Rows, sdirHint *sqlStorageDirectory) (*sqlStorageRegistration, error) {
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}

	var id, directory_id int64
	var name, location string
	var jsonPem, keyPem []byte
	if err := rows.Scan(&id, &directory_id, &name, &location, &jsonPem, &keyPem); nil != err {
		return nil, err
	}

	if nil == sdirHint || directory_id != sdirHint.id {
		if sdir, err := storage.loadDirectoryById(directory_id); nil != err {
			return nil, err
		} else if nil == sdir {
			return nil, fmt.Errorf("Couldn't find directory %d for registration", directory_id)
		} else {
			sdirHint = sdir
		}
	}

	reg := &sqlStorageRegistration{
		storage:   storage,
		directory: sdirHint,
		id:        id,
	}

	if err := reg.registration.Import(
		types.RegistrationExport{
			JsonPem:       jsonPem,
			SigningKeyPem: keyPem,
			Location:      location,
			Name:          name,
		}, storage.passwordPrompt); nil != err {
		return nil, err
	}

	return reg, nil
}

func (storage *sqlStorage) loadRegistrationByName(name string, sdirHint *sqlStorageDirectory) (*sqlStorageRegistration, error) {
	rows, err := storage.db.Query("SELECT id, directory_id, name, location, jsonPem, keyPem FROM registration WHERE name = $1", name)
	if nil != err {
		return nil, err
	}
	return storage.loadRegistrationFromSql(rows, sdirHint)
}

func (storage *sqlStorage) loadRegistrationById(registration_id int64, sdirHint *sqlStorageDirectory) (*sqlStorageRegistration, error) {
	rows, err := storage.db.Query("SELECT id, directory_id, name, location, jsonPem, keyPem FROM registration WHERE id = $1", registration_id)
	if nil != err {
		return nil, err
	}
	return storage.loadRegistrationFromSql(rows, sdirHint)
}

func (storage *sqlStorage) saveRegistration(id int64, directory_id int64, reg types.Registration) error {
	export, err := reg.Export(storage.lastPassword())
	if nil != err {
		return err
	}

	_, err = storage.db.Exec(
		`UPDATE registration SET
			directory_id = $1, name = $2, location = $3,
			jsonPem = $4, keyPem = $5
		WHERE id = $6`,
		directory_id,
		export.Name, export.Location, export.JsonPem, export.SigningKeyPem,
		id)

	return err
}
