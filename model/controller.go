package model

import (
	"github.com/stbuehler/go-acme-client/storage_interface"
)

type Controller interface {
	GetDirectory(rootURL string, refresh bool) (DirectoryModel, error)

	LoadRegistration(name string) (RegistrationModel, error)
}

type controller struct {
	storage storage_interface.Storage
}

func MakeController(storage storage_interface.Storage) Controller {
	return &controller{
		storage: storage,
	}
}
