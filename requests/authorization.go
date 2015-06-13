package requests

import (
	"encoding/json"
	"fmt"
	jose "github.com/square/go-jose"
	"github.com/stbuehler/go-acme-client/utils"
	"time"
)

func (status *AuthorizationStatus) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); nil != err {
		return err
	}
	switch str {
	case "pending":
		// normalize: unset or empty string means pending; go doesn't have
		// "default" values, so always use empty string to represent "pending"
		*status = AuthorizationStatus("")
	case "unknown", "processing", "valid", "invalid", "revoked":
		*status = AuthorizationStatus(str)
	default:
		return fmt.Errorf("Uknown authorization status %v", str)
	}
	return nil
}

func (status AuthorizationStatus) MarshalJSON() (data []byte, err error) {
	return json.Marshal(string(status))
}

func (status AuthorizationStatus) String() string {
	str := string(status)
	switch str {
	case "":
		return "pending"
	default:
		return str
	}
}

type rawAuthorizationResponse struct {
	Identifier struct {
		Type  string `json:"type,omitempty"`
		Value string `json:"value,omitempty"`
	} `json:"identifier,omitempty"`
	Key          *jose.JsonWebKey    `json:"key,omitempty"`
	Status       AuthorizationStatus `json:"status,omitempty"`
	Challenges   []json.RawMessage   `json:"challenges,omitempty"`
	Combinations [][]int             `json:"combinations,omitempty"`
	Expires      *time.Time          `json:"expires,omitempty"`
}

func NewDNSAuthorization(url string, signingKey utils.SigningKey, domain string) (*Authorization, error) {
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

	var rawResponse rawAuthorizationResponse
	err = json.Unmarshal(resp.Body, &rawResponse)
	if nil != err {
		return nil, fmt.Errorf("Failed decoding response from POST %s to %s: %s", string(payloadJson), url, err)
	}
	if rawResponse.Identifier.Type != "dns" {
		return nil, fmt.Errorf("Not a DNS authorization, identifier is %v of type %v", rawResponse.Identifier.Value, rawResponse.Identifier.Type)
	}
	response := Authorization{
		UrlSelf:       resp.Location,
		DNSIdentifier: rawResponse.Identifier.Value,
		PublicKey:     rawResponse.Key,
		Status:        rawResponse.Status,
		Challenges:    make([]Challenge, len(rawResponse.Challenges)),
		Combinations:  rawResponse.Combinations,
		Expires:       rawResponse.Expires,
	}

	for ndx, rawCh := range rawResponse.Challenges {
		err := json.Unmarshal(rawCh, &response.Challenges[ndx])
		if nil != err {
			return nil, fmt.Errorf("Failed decoding challenge %d in response from POST %s to %s: %s", ndx, string(payloadJson), url, err)
		}
	}

	response.UrlCert = resp.Links["next"].URL
	if 0 == len(response.UrlCert) {
		return nil, fmt.Errorf("Missing \"next\" link to request new certificates\n")
	}

	return &response, nil
}

func (auth *Authorization) Refresh() error {
	req := utils.HttpRequest{
		Method: "GET",
		URL:    auth.UrlSelf,
	}

	resp, err := req.Run()
	if nil != err {
		return fmt.Errorf("Refreshing authorization %s failed: %s", auth.UrlSelf, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s failed: %s", auth.UrlSelf, resp.Status)
	}

	var rawResponse rawAuthorizationResponse
	err = json.Unmarshal(resp.Body, &rawResponse)
	if nil != err {
		return fmt.Errorf("Failed decoding response from GET %s: %s", auth.UrlSelf, err)
	}
	if rawResponse.Identifier.Type != "dns" {
		return fmt.Errorf("Not a DNS authorization, identifier is %v of type %v", rawResponse.Identifier.Value, rawResponse.Identifier.Type)
	}
	response := Authorization{
		UrlSelf:       auth.UrlSelf,
		DNSIdentifier: rawResponse.Identifier.Value,
		PublicKey:     rawResponse.Key,
		Status:        rawResponse.Status,
		Challenges:    make([]Challenge, len(rawResponse.Challenges)),
		Combinations:  rawResponse.Combinations,
		Expires:       rawResponse.Expires,
	}
	if nil == response.PublicKey {
		response.PublicKey = auth.PublicKey
	}

	haveChallenges := make(map[string]Challenge)
	for _, haveCh := range auth.Challenges {
		if 0 == len(haveCh.URI) {
			continue
		}
		haveChallenges[haveCh.URI] = haveCh
	}

	for ndx, rawCh := range rawResponse.Challenges {
		var newCh Challenge
		err = json.Unmarshal(rawCh, &newCh)
		if nil != err {
			return fmt.Errorf("Failed decoding challenge %d in response from GET %s: %s", ndx, auth.UrlSelf, err)
		}
		if oldCh, haveOldCh := haveChallenges[newCh.URI]; haveOldCh {
			// if we know challenge, merge new data into old data into new challenge struct
			if err = oldCh.Data.Merge(rawCh); nil != err {
				return err
			}
			newCh.Data = oldCh.Data
		}
		response.Challenges[ndx] = newCh
	}

	response.UrlCert = resp.Links["next"].URL
	if 0 == len(response.UrlCert) {
		return fmt.Errorf("Missing \"next\" link to request new certificates\n")
	}
	*auth = response

	return nil
}
