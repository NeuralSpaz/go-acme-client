package requests

import (
	"encoding/json"
	"fmt"
	jose "github.com/square/go-jose"
	"github.com/stbuehler/go-acme-client/utils"
)

type rawRegistrationResponse struct {
	// some "id" ? ignore
	Key           *jose.JsonWebKey `json:"key,omitempty"`
	RecoveryToken string           `json:"recoveryToken,omitempty"`
	Contact       []string         `json:"contact,omitempty"`
	Agreement     string           `json:"agreement,omitempty"`
}

func sendRegistration(url string, signingKey utils.SigningKey, payload interface{}, old *Registration) (*Registration, error) {
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

	var r Registration
	r.UrlSelf = resp.Location

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("POST %s to %s failed: %s", string(payloadJson), url, resp.Status)
	}

	var responseReg rawRegistrationResponse
	err = json.Unmarshal(resp.Body, &responseReg)
	if nil != err {
		return nil, fmt.Errorf("Failed decoding response from POST %s to %s: %s", string(payloadJson), url, err)
	}

	r.PublicKey = responseReg.Key
	r.RecoveryToken = responseReg.RecoveryToken
	r.Contact = responseReg.Contact
	r.Agreement = responseReg.Agreement

	if !utils.EqualJsonWebKey(*r.PublicKey, *signingKey.GetPublicKey()) {
		return nil, fmt.Errorf("Returned public key doesn't match the key used to sign the request")
	}

	r.UrlAuth = resp.Links["next"].URL
	r.UrlTermsOfService = resp.Links["terms-of-service"].URL

	if nil == old {
		if 0 == len(r.UrlSelf) {
			return nil, fmt.Errorf("Missing Location header in registration response")
		}
		if 0 == len(r.UrlAuth) {
			return nil, fmt.Errorf("Missing Link rel=\"next\" header in registration response")
		}
	} else {
		if 0 == len(r.UrlSelf) {
			r.UrlSelf = old.UrlSelf
		}
		if 0 == len(r.UrlAuth) {
			r.UrlAuth = old.UrlAuth
		}
		if 0 == len(r.UrlTermsOfService) {
			r.UrlTermsOfService = old.UrlTermsOfService
		}
	}

	return &r, nil
}

type rawNewRegistration struct {
	Contact []string `json:"contact,omitempty"`
}

// should use a unique signing key for each registration!
func NewRegistration(url string, signingKey utils.SigningKey, contact []string) (*Registration, error) {
	reg, err := sendRegistration(url, signingKey, rawNewRegistration{
		Contact: contact,
	}, nil)
	if nil != err {
		return nil, err
	}
	return reg, nil
}

type rawUpdateRegistration struct {
	Contact   []string `json:"contact,omitempty"`
	Agreement string   `json:"agreement,omitempty"`
}

func UpdateRegistration(signingKey utils.SigningKey, registration *Registration) (*Registration, error) {
	reg, err := sendRegistration(registration.UrlSelf, signingKey, rawUpdateRegistration{
		Contact:   registration.Contact,
		Agreement: registration.Agreement,
	}, registration)
	if nil != err {
		return nil, err
	}
	return reg, nil
}

func FetchRegistration(signingKey utils.SigningKey, registration *Registration) (*Registration, error) {
	reg, err := sendRegistration(registration.UrlSelf, signingKey, rawUpdateRegistration{}, registration)
	if nil != err {
		return nil, err
	}
	return reg, nil
}
