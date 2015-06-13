package requests

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

type rawSimpleHttps struct {
	Type  string `json:"type,omitempty"` // only for sending
	Token string `json:"token,omitempty"`
	Path  string `json:"path,omitempty"`
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

func (simple *SimpleHttps) Merge(m json.RawMessage) error {
	var raw *rawSimpleHttps
	err := json.Unmarshal(m, &raw)
	if nil != err {
		return err
	}

	simple.Token = raw.Token
	if 0 != len(raw.Path) {
		simple.Path = raw.Path
	}

	return nil
}

func (simple *SimpleHttps) MarshalJSONPartial() (map[string]interface{}, error) {
	return map[string]interface{}{
		"path":  simple.Path,
		"token": simple.Token,
	}, nil
}

func (simple *SimpleHttps) ResetResponse() {
	simple.Path = ""
}

func (simple *SimpleHttps) WellKnownURL(auth *Authorization) string {
	return fmt.Sprintf("https://%s/.well-known/acme-challenge/%s", auth.DNSIdentifier, simple.Path)
}

func (simple *SimpleHttps) InitializeResponse(auth *Authorization, UI ui.UserInterface) error {
	if 0 == len(simple.Path) {
		simple.Path = auth.DNSIdentifier + ".txt"
	}
	path, err := UI.Prompt(fmt.Sprintf("Enter path for the file on your webserver to put the token into\n"+
		"It gets prefixed with https://%s/.well-known/acme-challenge/\n"+
		"Default %#v\n"+
		"Path", auth.DNSIdentifier, simple.Path))
	if nil != err {
		return err
	}
	if 0 != len(path) {
		simple.Path = path
	}
	return nil
}

func (simple *SimpleHttps) ShowInstructions(auth *Authorization, UI ui.UserInterface) error {
	_, err := UI.Prompt(fmt.Sprintf(
		"Make the quoted token on the next line available (without quotes) as %s\n%#v\nPress enter when done",
		simple.WellKnownURL(auth), simple.Token))
	if nil != err {
		return err
	}
	return nil
}

func (simple *SimpleHttps) Verify(auth *Authorization) error {
	return nil // shortcut verify for now

	url := simple.WellKnownURL(auth)
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
	if !bytes.Equal(body, []byte(simple.Token)) {
		return fmt.Errorf("document at %s didn't contain the expected token %#v, got %#v", url, simple.Token, string(body))
	}
	contentType := resp.Header.Get("Content-Type")
	contentType = strings.Split(contentType, ";")[0]
	contentType = strings.TrimSpace(contentType)
	if 0 != len(contentType) && "text/plain" != contentType {
		return fmt.Errorf("document at %s has wrong content-type %#v, expected none or text/plain", contentType)
	}
	return nil
}

func (simple *SimpleHttps) SendPayload() (interface{}, error) {
	if 0 == len(simple.Path) {
		return nil, fmt.Errorf("cannot send payload for simpleHttps as no path is set")
	}

	return rawSimpleHttps{
		Type: "simpleHttps",
		Path: simple.Path,
	}, nil
}
