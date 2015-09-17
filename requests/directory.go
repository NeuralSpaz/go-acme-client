package requests

import (
	"encoding/json"
	"fmt"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/utils"
)

func FetchDirectory(rootURL string) (*types.Directory, error) {
	req := utils.HttpRequest{
		Method: "GET",
		URL:    rootURL,
	}

	resp, err := req.Run()
	if nil != err {
		return nil, fmt.Errorf("Retrieving directory %s failed: %s", rootURL, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s failed: %s", rootURL, resp.Status)
	}

	var response types.Directory
	err = json.Unmarshal(resp.Body, &response.Resource)
	if nil != err {
		return nil, fmt.Errorf("Failed decoding response from GET %s: %s", rootURL, err)
	}
	response.RootURL = rootURL
	return &response, nil
}
