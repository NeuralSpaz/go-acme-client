package storage_interface

import (
	"github.com/stbuehler/go-acme-client/types"
	"time"
)

type AuthorizationInfo struct {
	DNSIdentifier string
	Location      string
	Status        types.AuthorizationStatus
	Expires       *time.Time
}

// maps DNSIdentifier to list of authorizations
type AuthorizationInfos map[string][]AuthorizationInfo

type CertificateInfo struct {
	Location   string
	LinkIssuer string
}

type StorageRegistrationComponent interface {
	StorageComponent
	StorageRegistration() StorageRegistration
}

type StorageRegistration interface {
	StorageComponent

	Registration() *types.Registration
	SetRegistration(registration types.Registration) error

	NewAuthorization(auth types.Authorization) (StorageAuthorization, error)
	AuthorizationInfos() (AuthorizationInfos, error)
	AuthorizationInfosWithStatus(status types.AuthorizationStatus) (AuthorizationInfos, error)
	Authorizations() ([]StorageAuthorization, error)
	LoadAuthorization(locationOrDnsIdentifier string) (StorageAuthorization, error)
	LoadAuthorizationByURL(authorizationURL string) (StorageAuthorization, error)
	// finds only newest not expired, valid, processing or pending authorization
	LoadAuthorizationByDNS(dnsIdentifier string) (StorageAuthorization, error)

	NewCertificate(cert types.Certificate) (StorageCertificate, error)
	CertificateInfos() ([]CertificateInfo, error)
	Certificates() ([]StorageCertificate, error)
	LoadCertificate(location string) (StorageCertificate, error)

	Delete() error
}
