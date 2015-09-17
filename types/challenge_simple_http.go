package types

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/stbuehler/go-acme-client/ui"
	"io/ioutil"
	"net/http"
	"strings"
)

const simpleHttpIdentifier string = "simpleHttp"

type challengeSimpleHttp struct {
	Resource ResourceChallengeTag `json:"resource"`
	rawChallengeBasic
	Token string `json:"token,omitempty"` // ASCII only
}

func (simpleHttps *challengeSimpleHttp) GetType() string {
	return simpleHttps.Type
}

func (simpleHttps *challengeSimpleHttp) GetStatus() string {
	return simpleHttps.Status
}

func (simpleHttps *challengeSimpleHttp) GetValidated() string {
	return simpleHttps.Validated
}

func (simpleHttps *challengeSimpleHttp) GetURI() string {
	return simpleHttps.URI
}

type challengeSimpleHttpData struct {
	Resource ResourceChallengeTag `json:"resource"`
	Type     string               `json:"type"`
	TLS      bool                 `json:"tls"`
}

type challengeSimpleHttpFileData struct {
	Type  string `json:"type"`
	TLS   bool   `json:"tls"`
	Token string `json:"token"`
}

func (simpleHttpData *challengeSimpleHttpData) GetType() string {
	return simpleHttpData.Type
}

func (simpleHttps *challengeSimpleHttp) initializeResponse(registration *Registration, authorization *Authorization) (ChallengeResponding, error) {
	responding := challengeSimpleHttpResponding{
		registration:  registration,
		dnsIdentifier: string(authorization.Resource.DNSIdentifier),
		challenge:     *simpleHttps,
		data: challengeSimpleHttpData{
			Type: simpleHttpIdentifier,
			TLS:  true,
		},
	}

	if oldData := authorization.ChallengesData[simpleHttps.GetURI()].chDataImpl; nil != oldData {
		if oldData := oldData.(*challengeSimpleHttpData); nil != oldData {
			responding.data = *oldData
		}
	}
	return &responding, nil
}

type challengeSimpleHttpResponding struct {
	registration  *Registration
	dnsIdentifier string
	challenge     challengeSimpleHttp
	data          challengeSimpleHttpData
}

func (responding *challengeSimpleHttpResponding) WellKnownURL() string {
	var proto string
	if responding.data.TLS {
		proto = "https"
	} else {
		proto = "http"
	}
	return fmt.Sprintf(
		"%s://%s/.well-known/acme-challenge/%s",
		proto,
		responding.dnsIdentifier,
		responding.challenge.Token)
}

var simpleHttpsClient *http.Client

func getSimpleHttpsClient() *http.Client {
	if nil == simpleHttpsClient {
		simpleHttpsClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	}
	return simpleHttpsClient
}

func (responding *challengeSimpleHttpResponding) ResetResponse() error {
	responding.data.TLS = true
	return nil
}

func (responding *challengeSimpleHttpResponding) InitializeResponse(UI ui.UserInterface) error {
	tls, err := UI.YesNoDialog("", "", "Use TLS for simple http(s) domain name verification?", true)
	if nil != err {
		return err
	}
	responding.data.TLS = tls
	return nil
}

func (responding *challengeSimpleHttpResponding) createVerificationFileData() challengeSimpleHttpFileData {
	return challengeSimpleHttpFileData{
		Type:  simpleHttpIdentifier,
		TLS:   responding.data.TLS,
		Token: responding.challenge.Token,
	}
}

func (responding *challengeSimpleHttpResponding) createVerificationFile() (string, error) {
	if payload, err := json.Marshal(responding.createVerificationFileData()); nil != err {
		return "", err
	} else if sig, err := responding.Registration().SigningKey.Sign(payload, ""); nil != err {
		return "", err
	} else {
		return sig.FullSerialize(), nil
	}
}

func (responding *challengeSimpleHttpResponding) ShowInstructions(UI ui.UserInterface) error {
	if file, err := responding.createVerificationFile(); nil != err {
		return err
	} else if _, err := UI.Prompt(fmt.Sprintf(
		"Make the text on the next line available (without quotes) as %s\n%v\nPress enter when done",
		responding.WellKnownURL(), file)); nil != err {
		return err
	}
	return nil
}

func (responding *challengeSimpleHttpResponding) Verify() error {
	var httpClient *http.Client
	if responding.data.TLS {
		httpClient = getSimpleHttpsClient()
	} else {
		httpClient = &http.Client{}
	}

	url := responding.WellKnownURL()
	resp, err := httpClient.Get(url)
	if nil != err {
		return err
	}
	defer resp.Body.Close()
	if 200 != resp.StatusCode {
		return fmt.Errorf("GET %s failed: %s", url, resp.Status)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if nil != err {
		return err
	}
	contentType := resp.Header.Get("Content-Type")
	contentType = strings.Split(contentType, ";")[0]
	contentType = strings.TrimSpace(contentType)
	if 0 != len(contentType) && "application/jose+json" != contentType {
		return fmt.Errorf("document at %s has wrong content-type %#v, expected none or application/jose+json", url, contentType)
	}

	var payload []byte
	var verifyData challengeSimpleHttpFileData
	expectedData := responding.createVerificationFileData()
	if err := responding.Registration().SigningKey.Verify(string(body), &payload, nil); nil != err {
		return fmt.Errorf("couldn't parse / verify signature of document at %s: %v", url, err)
	} else if err := json.Unmarshal(payload, &verifyData); nil != err {
		return fmt.Errorf("couldn't parse payload of signature of document at %s: %v", url, err)
	} else if verifyData != expectedData {
		return fmt.Errorf("payload of signature of document at %s is not valid (expected %#v, not %#v)", url, expectedData, verifyData)
	}

	return nil
}

func (responding *challengeSimpleHttpResponding) SendPayload() (interface{}, error) {
	return responding.data, nil
}

func (responding *challengeSimpleHttpResponding) ChallengeData() ChallengeData {
	return ChallengeData{chDataImpl: &responding.data}
}

func (responding *challengeSimpleHttpResponding) Challenge() Challenge {
	return Challenge{chImpl: &responding.challenge}
}

func (responding *challengeSimpleHttpResponding) Registration() *Registration {
	return responding.registration
}
