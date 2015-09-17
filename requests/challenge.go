package requests

import (
	"encoding/json"
	"fmt"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/utils"
)

func UpdateChallenge(challengeResponse types.ChallengeResponding) error {
	challenge := challengeResponse.Challenge()
	payload, err := challengeResponse.SendPayload()
	if nil != err {
		return err
	}

	payloadJson, err := json.Marshal(payload)
	if nil != err {
		return err
	}

	uri := challenge.GetURI()
	req := utils.HttpRequest{
		Method: "POST",
		URL:    uri,
		Headers: utils.HttpRequestHeader{
			ContentType: "application/json",
		},
	}

	resp, err := RunSignedRequest(challengeResponse.Registration().SigningKey, &req, payloadJson)
	if nil != err {
		return fmt.Errorf("POST %s to %s failed: %s", string(payloadJson), uri, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("POST %s to %s failed: %s", string(payloadJson), uri, resp.Status)
	}

	return nil
}
