package storage_interface

import (
	"github.com/stbuehler/go-acme-client/types"
)

// map (local) registration name to URL
type RegistrationList map[string]string

type Storage interface {
	SetPassword(password string)

	LoadDirectory(rootURL string) (StorageDirectory, error)
	NewDirectory(directory types.Directory) (StorageDirectory, error)

	RegistrationList() (RegistrationList, error)
	LoadRegistration(name string) (StorageRegistration, error)
}
