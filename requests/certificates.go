package requests

import (
	"encoding/json"
	"fmt"
	"github.com/stbuehler/go-acme-client/utils"
)

type certificatesJSON struct {
	Certificates []string `json:"certificates"`
}

func FetchCertificates(certificatesURL string) ([]string, error) {
	if 0 == len(certificatesURL) {
		return []string{}, nil
	}

	req := utils.HttpRequest{
		Method: "GET",
		URL:    certificatesURL,
	}

	resp, err := req.Run()
	if nil != err {
		return nil, fmt.Errorf("Retrieving certificates list from %s failed: %s", certificatesURL, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s failed: %s", certificatesURL, resp.Status)
	}

	response := certificatesJSON{
		Certificates: []string{},
	}
	err = json.Unmarshal(resp.Body, &response)
	if nil != err {
		return nil, fmt.Errorf("Failed decoding response from GET %s: %s", certificatesURL, err)
	}

	return response.Certificates, nil
}
