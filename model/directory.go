package model

import (
	"github.com/stbuehler/go-acme-client/requests"
	"github.com/stbuehler/go-acme-client/storage_interface"
	"github.com/stbuehler/go-acme-client/types"
)

type DirectoryModel interface {
	Refresh() error

	Directory() types.Directory

	NewRegistration(name string, signingKey types.SigningKey, contact []string) (RegistrationModel, error)
}

type directory struct {
	sdir storage_interface.StorageDirectory
}

func (dir *directory) Directory() types.Directory {
	return *dir.sdir.Directory()
}

func (dir *directory) Refresh() error {
	if dirData, err := requests.FetchDirectory(dir.Directory().RootURL); nil != err {
		return err
	} else {
		return dir.sdir.SetDirectory(*dirData)
	}
}

func (c *controller) getDirectory(rootURL string, refresh bool) (*directory, error) {
	if dir, err := c.storage.LoadDirectory(rootURL); nil != err {
		return nil, err
	} else if nil != dir {
		dirM := &directory{sdir: dir}
		if refresh {
			if err := dirM.Refresh(); nil != err {
				return nil, err
			}
		}
		return dirM, nil
	} else {
		if dirData, err := requests.FetchDirectory(rootURL); nil != err {
			return nil, err
		} else if dir, err := c.storage.NewDirectory(*dirData); nil != err {
			return nil, err
		} else {
			return &directory{sdir: dir}, nil
		}
	}
}

func (c *controller) GetDirectory(rootURL string, refresh bool) (DirectoryModel, error) {
	return c.getDirectory(rootURL, refresh)
}
