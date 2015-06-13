package requests

import (
	"encoding/json"
	"fmt"
	"github.com/stbuehler/go-acme-client/utils"
)

type rawChallengeBasic struct {
	Type      string `json:"type,omitempty"`
	Status    string `json:"status,omitempty"`
	Validated string `json:"validated,omitempty"`
	URI       string `json:"uri,omitempty"`
}

func (challenge *Challenge) UnmarshalJSON(data []byte) error {
	var base rawChallengeBasic
	if err := json.Unmarshal(data, &base); nil != err {
		return err
	}

	challenge.Type = base.Type
	challenge.Status = base.Status
	challenge.Validated = base.Validated
	challenge.URI = base.URI
	if 0 != len(challenge.URI) {
		switch base.Type {
		case "simpleHttps":
			challenge.Data = &SimpleHttps{}
		case "dvsni":
			challenge.Data = &DVSNI{}
		}
	}

	if nil == challenge.Data {
		challenge.Data = &FixedChallenge{}
	}
	return challenge.Data.Merge(json.RawMessage(data))
}

func (challenge *Challenge) MarshalJSON() (data []byte, err error) {
	var msg map[string]interface{}
	if nil != challenge.Data {
		if msg, err = challenge.Data.MarshalJSONPartial(); nil != err {
			return
		}
	}
	if nil == msg {
		msg = make(map[string]interface{})
	}
	set := func(k, v string) {
		if 0 == len(v) {
			delete(msg, k)
		} else {
			msg[k] = v
		}
	}
	set("type", challenge.Type)
	set("status", challenge.Status)
	set("validated", challenge.Validated)
	set("uri", challenge.URI)
	return json.Marshal(msg)
}

func mergeChallenge(responseData json.RawMessage, dest *Challenge) error {
	var base rawChallengeBasic
	if err := json.Unmarshal(responseData, &base); nil != err {
		return err
	}
	if base.Type != dest.Type {
		return fmt.Errorf("Updated challenge %v has wrong type %v", dest.Type, base.Type)
	}
	dest.Status = base.Status
	dest.Validated = base.Validated
	return dest.Data.Merge(responseData)
}

func (challenge *Challenge) Update(signingKey utils.SigningKey) error {
	chResp := challenge.Data.(ChallengeResponding)
	if nil == chResp {
		return fmt.Errorf("Challenge doesn't support responding")
	}

	payload, err := chResp.SendPayload()
	if nil != err {
		return err
	}

	payloadJson, err := json.Marshal(payload)
	if nil != err {
		return err
	}

	req := utils.HttpRequest{
		Method: "POST",
		URL:    challenge.URI,
		Headers: utils.HttpRequestHeader{
			ContentType: "application/json",
		},
	}

	resp, err := RunSignedRequest(signingKey, &req, payloadJson)
	if nil != err {
		return fmt.Errorf("POST %s to %s failed: %s", string(payloadJson), challenge.URI, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("POST %s to %s failed: %s", string(payloadJson), challenge.URI, resp.Status)
	}

	return mergeChallenge(json.RawMessage(resp.Body), challenge)
}
