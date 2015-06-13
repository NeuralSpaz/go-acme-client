package types

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/stbuehler/go-acme-client/ui"
	"io/ioutil"
	"net/http"
	"strings"
)

const acmeWellKnownFormatString = "https://%s/.well-known/acme-challenge/%s"

type SimpleHttps struct {
	Token string // ASCII only
	Path  string
}

type rawSimpleHttps struct {
	Type      string `json:"type,omitempty"`
	Status    string `json:"status,omitempty"`
	Validated string `json:"validated,omitempty"`
	URI       string `json:"uri,omitempty"`
	Token     string `json:"token,omitempty"`
	Path      string `json:"path,omitempty"`
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

func (simpleHttps *SimpleHttps) merge(data json.RawMessage) error {
	var raw rawSimpleHttps
	err := json.Unmarshal(data, &raw)
	if nil != err {
		return err
	}
	simpleHttps.Token = raw.Token
	if 0 != len(raw.Path) {
		simpleHttps.Path = raw.Path
	}
	return nil
}

func (simpleHttps *SimpleHttps) marshalJSON(challenge *Challenge) ([]byte, error) {
	return json.Marshal(rawSimpleHttps{
		Type:      challenge.Type,
		Status:    challenge.Status,
		Validated: challenge.Validated,
		URI:       challenge.URI,
		Token:     simpleHttps.Token,
		Path:      simpleHttps.Path,
	})
}

func (simpleHttps *SimpleHttps) WellKnownURL(authorization *Authorization) string {
	return fmt.Sprintf(acmeWellKnownFormatString, authorization.DNSIdentifier, simpleHttps.Path)
}

func (simpleHttps *SimpleHttps) resetResponse() {
	simpleHttps.Path = ""
}

func (simpleHttps *SimpleHttps) initializeResponse(authorization *Authorization, challenge *Challenge, UI ui.UserInterface) error {
	if 0 == len(simpleHttps.Path) {
		simpleHttps.Path = authorization.DNSIdentifier + ".txt"
	}
	path, err := UI.Prompt(fmt.Sprintf("Enter path for the file on your webserver to put the token into\n"+
		"It gets prefixed with "+acmeWellKnownFormatString+"\n"+
		"Default %#v\n"+
		"Path", authorization.DNSIdentifier, "", simpleHttps.Path))
	if nil != err {
		return err
	}
	if 0 != len(path) {
		simpleHttps.Path = path
	}
	return nil
}

func (simpleHttps *SimpleHttps) showInstructions(authorization *Authorization, challenge *Challenge, UI ui.UserInterface) error {
	_, err := UI.Prompt(fmt.Sprintf(
		"Make the quoted token on the next line available (without quotes) as %s\n%#v\nPress enter when done",
		simpleHttps.WellKnownURL(authorization), simpleHttps.Token))
	if nil != err {
		return err
	}
	return nil
}

func (simpleHttps *SimpleHttps) verify(authorization *Authorization, challenge *Challenge) error {
	url := simpleHttps.WellKnownURL(authorization)
	resp, err := getSimpleHttpsClient().Get(url)
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
	if !bytes.Equal(body, []byte(simpleHttps.Token)) {
		return fmt.Errorf("document at %s didn't contain the expected token %#v, got %#v", url, simpleHttps.Token, string(body))
	}
	contentType := resp.Header.Get("Content-Type")
	contentType = strings.Split(contentType, ";")[0]
	contentType = strings.TrimSpace(contentType)
	if 0 != len(contentType) && "text/plain" != contentType {
		return fmt.Errorf("document at %s has wrong content-type %#v, expected none or text/plain", contentType)
	}
	return nil
}

func (simpleHttps *SimpleHttps) sendPayload(authorization *Authorization, challenge *Challenge) (interface{}, error) {
	if 0 == len(simpleHttps.Path) {
		return nil, fmt.Errorf("cannot send payload for simpleHttps as no path is set")
	}

	return rawSimpleHttps{
		Path: simpleHttps.Path,
	}, nil
}
