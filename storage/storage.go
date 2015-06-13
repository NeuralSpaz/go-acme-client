package storage

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stbuehler/go-acme-client/ui"
)

type Storage struct {
	db             *sql.DB
	passwordPrompt func() (string, error)
	lastPassword   func() string
}

func OpenSQLite(UI ui.UserInterface, filename string) (Storage, error) {
	db, err := sql.Open("sqlite3", filename)
	if nil != err {
		return Storage{}, err
	}
	return Open(UI, db)
}

func Open(UI ui.UserInterface, db *sql.DB) (Storage, error) {
	pwPrompt, lastPassword := UI.PasswordPromptOnce("Enter storage password")
	storage := Storage{
		db:             db,
		passwordPrompt: pwPrompt,
		lastPassword:   lastPassword,
	}
	if err := storage.checkRegistrationTable(); nil != err {
		return Storage{}, err
	}
	if err := storage.checkAuthorizationTable(); nil != err {
		return Storage{}, err
	}
	if err := storage.checkCertificateTable(); nil != err {
		return Storage{}, err
	}

	return storage, nil
}

func (storage *Storage) SetPassword(password string) {
	storage.passwordPrompt = func() (string, error) {
		return password, nil
	}
	storage.lastPassword = func() string {
		return password
	}
}
