package requests

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/utils"
)

type newCertificate struct {
	Resource types.ResourceNewCertificateTag `json:"resource"`
	CSR      string                          `json:"csr"`
}

func NewCertificate(directory *types.Directory, signingKey types.SigningKey, csr pem.Block) (*types.Certificate, error) {
	payload := newCertificate{
		CSR: utils.Base64UrlEncode(csr.Bytes),
	}

	payloadJson, err := json.Marshal(payload)
	if nil != err {
		return nil, err
	}

	url := directory.Resource.NewCertificate
	req := utils.HttpRequest{
		Method: "POST",
		URL:    url,
		Headers: utils.HttpRequestHeader{
			ContentType: "application/json",
			Accept:      "application/pkix-cert",
		},
	}
	resp, err := RunSignedRequest(signingKey, &req, payloadJson)
	if nil != err {
		return nil, fmt.Errorf("POST certificate request %s to %s failed: %s", string(payloadJson), url, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("POST certificate request %s to %s failed: %s", string(payloadJson), url, resp.Status)
	}

	if 0 == len(resp.Location) {
		return nil, fmt.Errorf("Requesting certificate failed: missing Location")
	}

	if "application/pkix-cert" != resp.ContentType {
		return nil, fmt.Errorf("Unexpected response Content-Type: %s, expected application/pkix-cert", resp.ContentType)
	}

	return &types.Certificate{
		Location:   resp.Location,
		LinkIssuer: resp.Links["up"].URL,
		Certificate: &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: resp.Body,
		},
	}, nil
}

func FetchCertificate(certURL string) (*types.Certificate, error) {
	req := utils.HttpRequest{
		Method: "GET",
		URL:    certURL,
		Headers: utils.HttpRequestHeader{
			Accept: "application/pkix-cert",
		},
	}

	resp, err := req.Run()
	if nil != err {
		return nil, fmt.Errorf("Fetching certificate %s failed: %s", certURL, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s failed: %s", certURL, resp.Status)
	}

	if "application/pkix-cert" != resp.ContentType {
		return nil, fmt.Errorf("Unexpected response Content-Type: %s, expected application/pkix-cert", resp.ContentType)
	}

	var response types.Certificate
	err = json.Unmarshal(resp.Body, &response)
	if nil != err {
		return nil, fmt.Errorf("Failed decoding response from GET %s: %s", certURL, err)
	}

	return &types.Certificate{
		Location:   certURL,
		LinkIssuer: resp.Links["up"].URL,
		Certificate: &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: resp.Body,
		},
	}, nil
}
