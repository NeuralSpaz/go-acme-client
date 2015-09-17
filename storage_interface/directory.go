package storage_interface

import (
	"github.com/stbuehler/go-acme-client/types"
)

type StorageComponent interface {
	Storage() Storage
	StorageDirectory() StorageDirectory

	Directory() *types.Directory
}

type StorageDirectory interface {
	StorageComponent

	SetDirectory(directory types.Directory) error

	NewRegistration(registration types.Registration) (StorageRegistration, error)
	RegistrationList() (RegistrationList, error)
	LoadRegistration(name string) (StorageRegistration, error)

	Delete() error
}
