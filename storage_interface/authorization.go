package storage_interface

import (
	"github.com/stbuehler/go-acme-client/types"
)

type StorageAuthorization interface {
	StorageRegistrationComponent

	Authorization() *types.Authorization
	SetAuthorization(authorization types.Authorization) error

	Delete() error
}
