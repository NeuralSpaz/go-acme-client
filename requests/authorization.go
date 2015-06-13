package requests

import (
	"encoding/json"
	"fmt"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/utils"
)

func NewDNSAuthorization(url string, signingKey types.SigningKey, domain string) (*types.Authorization, error) {
	payload := map[string]interface{}{
		"identifier": map[string]interface{}{
			"type":  "dns",
			"value": domain,
		},
	}

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
	err = json.Unmarshal(resp.Body, &response)
	if nil != err {
		return nil, fmt.Errorf("Failed decoding response from POST %s to %s: %s", string(payloadJson), url, err)
	}

	response.Location = resp.Location
	response.LinkCert = resp.Links["next"].URL
	if 0 == len(response.LinkCert) {
		return nil, fmt.Errorf("Missing \"next\" link to request new certificates\n")
	}

	return &response, nil
}

func RefreshAuthorization(auth *types.Authorization) error {
	req := utils.HttpRequest{
		Method: "GET",
		URL:    auth.Location,
	}

	resp, err := req.Run()
	if nil != err {
		return fmt.Errorf("Refreshing authorization %s failed: %s", auth.Location, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s failed: %s", auth.Location, resp.Status)
	}

	var response types.Authorization
	err = json.Unmarshal(resp.Body, &response)
	if nil != err {
		return fmt.Errorf("Failed decoding response from GET %s: %s", auth.Location, err)
	}
	response.Location = auth.Location // use old location value
	response.LinkCert = resp.Links["next"].URL
	if 0 == len(response.LinkCert) {
		return fmt.Errorf("Missing \"next\" link to request new certificates\n")
	}
	*auth = response

	return nil
}
