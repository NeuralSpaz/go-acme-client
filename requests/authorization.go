package requests

import (
	"encoding/json"
	"fmt"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/utils"
)

type newAuthorization struct {
	Resource      types.ResourceNewAuthorizationTag `json:"resource"`
	DNSIdentifier types.DNSIdentifier               `json:"identifier,omitempty"`
}

func NewDNSAuthorization(directory *types.Directory, signingKey types.SigningKey, domain string) (*types.Authorization, error) {
	payload := newAuthorization{
		DNSIdentifier: types.DNSIdentifier(domain),
	}

	payloadJson, err := json.Marshal(payload)
	if nil != err {
		return nil, err
	}

	url := directory.Resource.NewAuthorization
	req := utils.HttpRequest{
		Method: "POST",
		URL:    url,
		Headers: utils.HttpRequestHeader{
			ContentType: "application/json",
		},
	}

	resp, err := RunSignedRequest(signingKey, &req, payloadJson)
	if nil != err {
		return nil, fmt.Errorf("POST authorization %s to %s failed: %s", string(payloadJson), url, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		utils.DebugLogHttpResponse(resp)
		return nil, fmt.Errorf("POST %s to %s failed: %s", string(payloadJson), url, resp.Status)
	}

	if 0 == len(resp.Location) {
		return nil, fmt.Errorf("Creating authorization failed: missing Location")
	}

	var response types.Authorization
	err = json.Unmarshal(resp.Body, &response.Resource)
	if nil != err {
		return nil, fmt.Errorf("Failed decoding response from POST %s to %s: %s", string(payloadJson), url, err)
	}
	response.Location = resp.Location

	return &response, nil
}

func FetchAuthorization(authURL string) (*types.AuthorizationResource, error) {
	req := utils.HttpRequest{
		Method: "GET",
		URL:    authURL,
	}

	resp, err := req.Run()
	if nil != err {
		return nil, fmt.Errorf("Refreshing authorization %s failed: %s", authURL, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s failed: %s", authURL, resp.Status)
	}

	var response types.AuthorizationResource
	err = json.Unmarshal(resp.Body, &response)
	if nil != err {
		return nil, fmt.Errorf("Failed decoding response from GET %s: %s", authURL, err)
	}

	return &response, nil
}
