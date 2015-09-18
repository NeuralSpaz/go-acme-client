package model

import (
	"fmt"
	"github.com/stbuehler/go-acme-client/requests"
	"github.com/stbuehler/go-acme-client/storage_interface"
	"github.com/stbuehler/go-acme-client/types"
)

type AuthorizationModel interface {
	Refresh() error

	Authorization() types.Authorization

	UpdateChallenge(challengeResponse types.ChallengeResponding) error
	SaveChallengeData(challengeResponse types.ChallengeResponding) error
}

type authorization struct {
	reg   *registration
	sauth storage_interface.StorageAuthorization
}

func (auth *authorization) Refresh() error {
	if newAuth, err := requests.FetchAuthorization(auth.Authorization().Location); nil != err {
		return err
	} else {
		authData := *auth.sauth.Authorization()
		authData.Resource = *newAuth
		return auth.sauth.SetAuthorization(authData)
	}
}

func (auth *authorization) Authorization() types.Authorization {
	return *auth.sauth.Authorization()
}

func (auth *authorization) UpdateChallenge(challengeResponse types.ChallengeResponding) error {
	if err := auth.SaveChallengeData(challengeResponse); nil != err {
		return err
	} else if err := requests.UpdateChallenge(challengeResponse); nil != err {
		return err
	} else {
		return auth.Refresh()
	}
}

func (auth *authorization) SaveChallengeData(challengeResponse types.ChallengeResponding) error {
	challenge := challengeResponse.Challenge()

	uri := challenge.GetURI()
	if 0 == len(uri) {
		return fmt.Errorf("A challenge without URI cannot be updated")
	}

	authData := auth.sauth.Authorization()
	challengeNdx := -1
	for ndx, ch := range authData.Resource.Challenges {
		if uri == ch.GetURI() {
			challengeNdx = ndx
			break
		}
	}
	if -1 == challengeNdx {
		return fmt.Errorf("Challenge %v doesn't belong to authorization %v", uri, authData.Location)
	}

	if nil == authData.ChallengesData {
		authData.ChallengesData = make(map[string]types.ChallengeData)
	}
	authData.ChallengesData[uri] = challengeResponse.ChallengeData()
	if err := auth.sauth.SetAuthorization(*authData); nil != err {
		return err
	}
	return nil
}

func (reg *registration) importAuthorization(authURL string, refresh bool) (*authorization, error) {
	if auth, err := reg.sreg.LoadAuthorizationByURL(authURL); nil != err {
		return nil, err
	} else if nil != auth {
		authM := &authorization{reg: reg, sauth: auth}
		if refresh {
			if err := authM.Refresh(); nil != err {
				return nil, err
			}
		}
		return authM, nil
	} else {
		if newAuth, err := requests.FetchAuthorization(authURL); nil != err {
			return nil, err
		} else if auth, err := reg.sreg.NewAuthorization(
			types.Authorization{
				Resource: *newAuth,
				Location: authURL,
			}); nil != err {
			return nil, err
		} else {
			return &authorization{reg: reg, sauth: auth}, nil
		}
	}
}

func (reg *registration) AuthorizationInfos() (storage_interface.AuthorizationInfos, error) {
	return reg.sreg.AuthorizationInfos()
}

func (reg *registration) AuthorizationInfosWithStatus(status types.AuthorizationStatus) (storage_interface.AuthorizationInfos, error) {
	return reg.sreg.AuthorizationInfosWithStatus(status)
}

func (reg *registration) Authorizations() ([]AuthorizationModel, error) {
	if sauths, err := reg.sreg.Authorizations(); nil != err {
		return nil, err
	} else {
		auths := make([]AuthorizationModel, len(sauths))
		for ndx, sauth := range sauths {
			auths[ndx] = &authorization{
				reg:   reg,
				sauth: sauth,
			}
		}
		return auths, nil
	}
}

func (reg *registration) LoadAuthorizationByURL(authURL string) (AuthorizationModel, error) {
	if auth, err := reg.sreg.LoadAuthorizationByURL(authURL); nil != err {
		return nil, err
	} else if nil != auth {
		return &authorization{reg: reg, sauth: auth}, nil
	} else {
		return nil, nil
	}
}

func (reg *registration) FetchAllAuthorizations(updateAll bool) error {
	authUrls, err := requests.FetchAuthorizations(reg.sreg.Registration().Resource.AuthorizationsURL)
	if nil != err {
		return err
	}

	for _, authURL := range authUrls {
		if _, err := reg.ImportAuthorizationByURL(authURL, updateAll); nil != err {
			return err
		}
	}
	return nil
}

func (reg *registration) ImportAuthorizationByURL(authURL string, refresh bool) (AuthorizationModel, error) {
	if authM, err := reg.importAuthorization(authURL, refresh); nil != err || nil == authM {
		// make sure to create a nil interface from the nil pointer!
		return nil, err
	} else {
		return authM, nil
	}
}

func (reg *registration) GetAuthorizationByDNS(dnsIdentifier string, refresh bool) (AuthorizationModel, error) {
	if refresh {
		// make sure we know about all authorizations, but don't update all of them - the identifier doesn't change
		if err := reg.FetchAllAuthorizations(false); nil != err {
			return nil, err
		}
	}
	if auth, err := reg.sreg.LoadAuthorizationByDNS(dnsIdentifier); nil != err {
		return nil, err
	} else if nil != auth {
		authM := &authorization{reg: reg, sauth: auth}
		if refresh {
			if err := authM.Refresh(); nil != err {
				return nil, err
			}
		}
		return authM, nil
	} else {
		return nil, nil
	}
}

func (reg *registration) NewAuthorization(dnsIdentifier string) (AuthorizationModel, error) {
	if authData, err := requests.NewDNSAuthorization(reg.sreg.Directory(), reg.sreg.Registration().SigningKey, dnsIdentifier); nil != err {
		return nil, err
	} else if auth, err := reg.sreg.NewAuthorization(*authData); nil != err {
		return nil, err
	} else {
		return &authorization{reg: reg, sauth: auth}, nil
	}
}

func (reg *registration) AuthorizeDNS(dnsIdentifier string) (AuthorizationModel, error) {
	if auth, err := reg.GetAuthorizationByDNS(dnsIdentifier, true /* refresh */); nil != err {
		return nil, err
	} else if nil != auth {
		return auth, nil
	} else {
		return reg.NewAuthorization(dnsIdentifier)
	}
}
