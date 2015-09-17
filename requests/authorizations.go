package requests

import (
	"encoding/json"
	"fmt"
	"github.com/stbuehler/go-acme-client/utils"
)

type authorizationsJSON struct {
	authorizations []string
}

func FetchAuthorizations(authorizationsURL string) ([]string, error) {
	if 0 == len(authorizationsURL) {
		return []string{}, nil
	}

	req := utils.HttpRequest{
		Method: "GET",
		URL:    authorizationsURL,
	}

	resp, err := req.Run()
	if nil != err {
		return nil, fmt.Errorf("Retrieving authorizations list from %s failed: %s", authorizationsURL, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s failed: %s", authorizationsURL, resp.Status)
	}

	response := authorizationsJSON{
		authorizations: []string{},
	}
	err = json.Unmarshal(resp.Body, &response)
	if nil != err {
		return nil, fmt.Errorf("Failed decoding response from GET %s: %s", authorizationsURL, err)
	}

	return response.authorizations, nil
}
