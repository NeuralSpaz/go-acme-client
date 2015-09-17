package requests

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/utils"
)

func RequestCertificate(directory *types.Directory, signingKey types.SigningKey, csr pem.Block, authorizations []string) (*types.Certificate, error) {
	payload := map[string]interface{}{
		"csr":            utils.Base64UrlEncode(csr.Bytes),
		"authorizations": authorizations,
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

	var cert types.Certificate
	cert.Location = resp.Location
	cert.LinkIssuer = resp.Links["up"].URL

	if 0 == len(cert.Location) {
		return nil, fmt.Errorf("Requesting certificate failed: missing Location")
	}

	if "application/pkix-cert" != resp.ContentType {
		return nil, fmt.Errorf("Unexpected response Content-Type: %s, expected application/pkix-cert", resp.ContentType)
	}

	cert.Certificate = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: resp.Body,
	}

	return &cert, nil
}
