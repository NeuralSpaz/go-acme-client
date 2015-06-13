package requests

import (
	"encoding/json"
	"fmt"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/utils"
)

func UpdateChallenge(challengeResponse *types.ChallengeResponding, signingKey types.SigningKey) error {
	challenge := challengeResponse.Challenge()
	payload, err := challengeResponse.SendPayload()
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

	return challenge.Merge(json.RawMessage(resp.Body))
}
