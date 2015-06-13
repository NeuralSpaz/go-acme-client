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
	err = json.Unmarshal(resp.Body, &registration)
	if nil != err {
		return nil, fmt.Errorf("Failed decoding response from POST %s to %s: %s", string(payloadJson), url, err)
	}

	registration.Location = resp.Location

	registration.LinkAuth = resp.Links["next"].URL
	registration.LinkTermsOfService = resp.Links["terms-of-service"].URL

	if nil == old {
		if 0 == len(registration.Location) {
			return nil, fmt.Errorf("Missing Location header in registration response")
		}
		if 0 == len(registration.LinkAuth) {
			return nil, fmt.Errorf("Missing Link rel=\"next\" header in registration response")
		}
	} else {
		if 0 == len(registration.Location) {
			registration.Location = old.Location
		}
		if 0 == len(registration.LinkAuth) {
			registration.LinkAuth = old.LinkAuth
		}
		if 0 == len(registration.LinkTermsOfService) {
			registration.LinkTermsOfService = old.LinkTermsOfService
		}
	}

	return &registration, nil
}

// should use a unique signing key for each registration!
func NewRegistration(url string, signingKey types.SigningKey, contact []string) (*types.Registration, error) {
	reg, err := sendRegistration(url, signingKey, rawRegistration{
		Contact: contact,
	}, nil)
	if nil != err {
		return nil, err
	}
	return reg, nil
}

func UpdateRegistration(signingKey types.SigningKey, registration *types.Registration) (*types.Registration, error) {
	reg, err := sendRegistration(registration.Location, signingKey, rawRegistration{
		Contact:   registration.Contact,
		Agreement: registration.Agreement,
	}, registration)
	if nil != err {
		return nil, err
	}
	return reg, nil
}

func FetchRegistration(signingKey types.SigningKey, registration *types.Registration) (*types.Registration, error) {
	reg, err := sendRegistration(registration.Location, signingKey, rawRegistration{}, registration)
	if nil != err {
		return nil, err
	}
	return reg, nil
}
