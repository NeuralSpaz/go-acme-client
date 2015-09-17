package model

import (
	"fmt"
	"github.com/stbuehler/go-acme-client/requests"
	"github.com/stbuehler/go-acme-client/storage_interface"
	"github.com/stbuehler/go-acme-client/types"
)

type RegistrationModel interface {
	Registration() types.Registration
	Refresh() error
	Update(contact []string, AgreementURL *string) error

	AuthorizationInfos() (storage_interface.AuthorizationInfos, error)
	AuthorizationInfosWithStatus(status types.AuthorizationStatus) (storage_interface.AuthorizationInfos, error)
	Authorizations() ([]AuthorizationModel, error)
	LoadAuthorizationByURL(authURL string) (AuthorizationModel, error)

	FetchAllAuthorizations(updateAll bool) error
	GetAuthorizationByURL(authURL string, refresh bool) (AuthorizationModel, error)
	GetAuthorizationByDNS(dnsIdentifier string, refresh bool) (AuthorizationModel, error)
	NewAuthorization(dnsIdentifier string) (AuthorizationModel, error)
	AuthorizeDNS(dnsIdentifier string) (AuthorizationModel, error)
}

type registration struct {
	dir  *directory
	sreg storage_interface.StorageRegistration
}

func (reg *registration) Registration() types.Registration {
	return *reg.sreg.Registration()
}

func (reg *registration) Refresh() error {
	if newReg, err := requests.FetchRegistration(reg.sreg.Registration()); nil != err {
		return err
	} else {
		return reg.sreg.SetRegistration(*newReg)
	}
}

func (reg *registration) Update(contact []string, AgreementURL *string) error {
	if nil == contact && nil == AgreementURL {
		// no changes
		return nil
	}
	// make a new copy and modify it
	var newData types.Registration = *reg.sreg.Registration()
	if nil != contact {
		newData.Resource.Contact = contact
	}
	if nil != AgreementURL {
		newData.Resource.AgreementURL = *AgreementURL
	}

	if newReg, err := requests.UpdateRegistration(&newData); nil != err {
		return err
	} else {
		return reg.sreg.SetRegistration(*newReg)
	}
}

func (dir *directory) newRegistration(name string, signingKey types.SigningKey, contact []string) (*registration, error) {
	if reg, err := dir.sdir.Storage().LoadRegistration(name); nil != err {
		return nil, err
	} else if nil != reg {
		return nil, fmt.Errorf("There already is a registration with name %#v", name)
	}

	reg, err := requests.NewRegistration(dir.sdir.Directory(), signingKey, contact)
	if nil != err {
		return nil, err
	}
	reg.Name = name

	if sreg, err := dir.sdir.NewRegistration(*reg); nil != err || nil == sreg {
		return nil, err
	} else {
		return &registration{
			dir:  dir,
			sreg: sreg,
		}, nil
	}
}

func (dir *directory) NewRegistration(name string, signingKey types.SigningKey, contact []string) (RegistrationModel, error) {
	if reg, err := dir.newRegistration(name, signingKey, contact); nil != err || nil == reg {
		// make sure to create a nil interface from the nil pointer!
		return nil, err
	} else {
		return reg, nil
	}
}

func (c *controller) LoadRegistration(name string) (RegistrationModel, error) {
	if sreg, err := c.storage.LoadRegistration(name); nil != err || nil == sreg {
		return nil, err
	} else if nil != sreg {
		return &registration{
			dir:  &directory{sdir: sreg.StorageDirectory()},
			sreg: sreg,
		}, nil
	} else {
		return nil, nil
	}
}
