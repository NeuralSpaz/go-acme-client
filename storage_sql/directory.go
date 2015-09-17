package storage_sql

import (
	"database/sql"
	"fmt"
	i "github.com/stbuehler/go-acme-client/storage_interface"
	"github.com/stbuehler/go-acme-client/types"
)

// --------------------------------------------------------------------
// implementations for i.StorageDirectory
// --------------------------------------------------------------------

func (sdir *sqlStorageDirectory) Storage() i.Storage {
	return sdir.storage
}

func (sdir *sqlStorageDirectory) StorageDirectory() i.StorageDirectory {
	return sdir
}

func (sdir *sqlStorageDirectory) Directory() *types.Directory {
	return &sdir.directory
}

func (sdir *sqlStorageDirectory) SetDirectory(directory types.Directory) error {
	if err := sdir.check(); nil != err {
		return err
	}
	if _, err := sdir.storage.db.Exec("UPDATE directory SET "+
		"rootURL=$1,"+
		"newRegistration = $2, "+
		"recoverRegistration = $3, "+
		"newAuthorization = $4, "+
		"newCertificate = $5, "+
		"revokeCertificate = $6 "+
		"WHERE id = $7",
		directory.RootURL,
		directory.Resource.NewRegistration,
		directory.Resource.RecoverRegistration,
		directory.Resource.NewAuthorization,
		directory.Resource.NewCertificate,
		directory.Resource.RevokeCertificate,
		sdir.id); nil != err {
		return err
	}
	sdir.directory = directory
	return nil
}

// in registration.go:
// func (sdir *sqlStorageDirectory) NewRegistration(registration types.Registration) (i.StorageRegistration, error)
// func (sdir *sqlStorageDirectory) RegistrationList() (i.RegistrationList, error)
// func (sdir *sqlStorageDirectory) LoadRegistration(name string) (i.StorageRegistration, error)

func (sdir *sqlStorageDirectory) Delete() error {
	if err := sdir.check(); nil != err {
		return err
	}
	if _, err := sdir.storage.db.Exec("DELETE FROM directory WHERE id = $1", sdir.id); nil != err {
		return err
	}
	sdir.id = -1
	sdir.directory = types.Directory{}
	return nil
}

// --------------------------------------------------------------------
// end [implementations for i.StorageDirectory]
// --------------------------------------------------------------------

// --------------------------------------------------------------------
// implementations for i.Storage
// --------------------------------------------------------------------

func (storage *sqlStorage) LoadDirectory(rootURL string) (i.StorageDirectory, error) {
	rows, err := storage.db.Query("SELECT id, rootURL, newRegistration, "+
		"recoverRegistration, newAuthorization, newCertificate, revokeCertificate "+
		"FROM directory WHERE rootURL = $1", rootURL)
	if nil != err {
		return nil, err
	}
	if sdir, err := storage.loadDirectoryFromSql(rows); nil != err || nil == sdir {
		// make sure to create a nil interface from the nil pointer!
		return nil, err
	} else {
		return sdir, nil
	}
}

func (storage *sqlStorage) NewDirectory(directory types.Directory) (i.StorageDirectory, error) {
	if _, err := storage.db.Exec("INSERT INTO directory (rootURL, newRegistration, "+
		"recoverRegistration, newAuthorization, newCertificate, revokeCertificate "+
		") VALUES ($1, $2, $3, $4, $5, $6)", directory.RootURL,
		directory.Resource.NewRegistration,
		directory.Resource.RecoverRegistration,
		directory.Resource.NewAuthorization,
		directory.Resource.NewCertificate,
		directory.Resource.RevokeCertificate); nil != err {
		return nil, err
	}
	return storage.LoadDirectory(directory.RootURL)
}

// --------------------------------------------------------------------
// end [implementations for i.Storage]
// --------------------------------------------------------------------

type sqlStorageDirectory struct {
	storage   *sqlStorage
	id        int64
	rootURL   string
	directory types.Directory
}

func (storage *sqlStorage) checkDirectoryTable() error {
	_, err := storage.db.Exec(
		`CREATE TABLE IF NOT EXISTS directory (
			id INTEGER PRIMARY KEY,
			rootURL TEXT NOT NULL,
			newRegistration TEXT NOT NULL,
			recoverRegistration TEXT NOT NULL,
			newAuthorization TEXT NOT NULL,
			newCertificate TEXT NOT NULL,
			revokeCertificate TEXT NOT NULL)`)
	return err
}

func (sdir *sqlStorageDirectory) check() error {
	if 0 == len(sdir.rootURL) {
		return fmt.Errorf("Directory has no root url, cannot be saved")
	}
	if sdir.id <= 0 {
		return fmt.Errorf("Directory has invalid id %d, cannot be saved", sdir.id)
	}
	return nil
}

func (storage *sqlStorage) loadDirectoryFromSql(rows *sql.Rows) (*sqlStorageDirectory, error) {
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}

	var id int64
	var rootURL, newRegistration, recoverRegistration, newAuthorization, newCertificate, revokeCertificate string
	if err := rows.Scan(&id, &rootURL, &newRegistration, &recoverRegistration, &newAuthorization, &newCertificate, &revokeCertificate); nil != err {
		return nil, err
	}

	return &sqlStorageDirectory{
		storage: storage,
		id:      id,
		directory: types.Directory{
			Resource: types.DirectoryResource{
				NewRegistration:     newRegistration,
				RecoverRegistration: recoverRegistration,
				NewAuthorization:    newAuthorization,
				NewCertificate:      newCertificate,
				RevokeCertificate:   revokeCertificate,
			},
			RootURL: rootURL,
		},
	}, nil
}

func (storage *sqlStorage) loadDirectoryById(directory_id int64) (*sqlStorageDirectory, error) {
	rows, err := storage.db.Query("SELECT id, rootURL, newRegistration, "+
		"recoverRegistration, newAuthorization, newCertificate, revokeCertificate "+
		"FROM directory WHERE id = $1", directory_id)
	if nil != err {
		return nil, err
	}
	return storage.loadDirectoryFromSql(rows)
}
