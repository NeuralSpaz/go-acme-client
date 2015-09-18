package storage_interface

import (
	"github.com/stbuehler/go-acme-client/types"
)

type StorageCertificate interface {
	StorageRegistrationComponent

	Certificate() *types.Certificate
	SetCertificate(certificate types.Certificate) error
	Delete() error
}
