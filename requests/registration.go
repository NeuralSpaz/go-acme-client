package requests

import (
	"encoding/json"
	"fmt"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/utils"
)

type rawRegistration struct {
	Contact       []string `json:"contact,omitempty"`
	Agreement     string   `json:"agreement,omitempty"`
	RecoveryToken string   `json:"recoveryToken,omitempty"`
}

func sendRegistration(url string, signingKey types.SigningKey, payload interface{}, old *types.Registration) (*types.Registration, error) {
	payloadJson, err := json.Marshal(payload)
	if nil != err {
		return nil, err
	}

	req := utils.HttpRequest{
		Method: "POST",
		URL:    url,
		Headers: utils.HttpRequestHeader{
			ContentType: "application/json",
		},
	}

	resp, err := RunSignedRequest(signingKey, &req, payloadJson)
	if nil != err {
		return nil, fmt.Errorf("POSTing registration %s to %s failed: %s", string(payloadJson), url, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("POST %s to %s failed: %s", string(payloadJson), url, resp.Status)
	}

	var registration types.Registration
	err = json.Unmarshal(resp.Body, &registration.Resource)
	if nil != err {
		return nil, fmt.Errorf("Failed decoding response from POST %s to %s: %s", string(payloadJson), url, err)
	}

	registration.SigningKey = signingKey
	if 0 == len(resp.Location) || old.Location == url {
		registration.Location = old.Location
	} else {
		registration.Location = resp.Location
	}
	if 0 == len(registration.Location) {
		return nil, fmt.Errorf("Invalid registration location")
	}
	registration.LinkTermsOfService = resp.Links["terms-of-service"].URL
	// TODO: handle RecoveryToken updates
	registration.RecoveryToken = old.RecoveryToken
	registration.Name = old.Name

	return &registration, nil
}

// should use a unique signing key for each registration!
type newRegistration struct {
	Resource types.ResourceNewRegistrationTag `json:"resource"`
	Contact  []string                         `json:"contact,omitempty"`
}

func NewRegistration(directory *types.Directory, signingKey types.SigningKey, contact []string) (*types.Registration, error) {
	old := types.Registration{} // empty Name
	reg, err := sendRegistration(directory.Resource.NewRegistration, signingKey, newRegistration{
		Contact: contact,
	}, &old)
	if nil != err {
		return nil, err
	}
	return reg, nil
}

func UpdateRegistration(registration *types.Registration) (*types.Registration, error) {
	reg, err := sendRegistration(registration.Location, registration.SigningKey, types.RegistrationResource{
		Contact:      registration.Resource.Contact,
		AgreementURL: registration.Resource.AgreementURL,
	}, registration)
	if nil != err {
		return nil, err
	}
	return reg, nil
}

func FetchRegistration(registration *types.Registration) (*types.Registration, error) {
	reg, err := sendRegistration(registration.Location, registration.SigningKey, types.RegistrationResource{}, registration)
	if nil != err {
		return nil, err
	}
	return reg, nil
}
