package types

import (
	"encoding/json"
	"fmt"
	"time"
)

type Authorization struct {
	Location      string              `json:"meta-location,omitempty"`
	LinkCert      string              `json:"link-cert,omitempty"`
	DNSIdentifier string              `json:"dns-identifier,omitempty"`
	Status        AuthorizationStatus `json:"status,omitempty"`
	Challenges    []Challenge         `json:"challenges,omitempty"`
	Combinations  [][]int             `json:"combinations,omitempty"`
	Expires       *time.Time          `json:"expires,omitempty"`
}

type rawAuthorizationIdentifier struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

type rawAuthorization struct {
	// meta data from http header
	Location string `json:"meta-location,omitempty"`
	LinkCert string `json:"link-cert,omitempty"`
	// real json content
	Identifier   rawAuthorizationIdentifier `json:"identifier,omitempty"`
	Status       AuthorizationStatus        `json:"status,omitempty"`
	Challenges   []Challenge                `json:"challenges,omitempty"`
	Combinations [][]int                    `json:"combinations,omitempty"`
	Expires      *time.Time                 `json:"expires,omitempty"`
}

func (auth *Authorization) UnmarshalJSON(data []byte) error {
	var raw rawAuthorization
	if err := json.Unmarshal(data, &raw); nil != err {
		return err
	}
	if raw.Identifier.Type != "dns" {
		return fmt.Errorf("Unknown identifier.type %s, expected \"dns\"", raw.Identifier.Type)
	}
	auth.Location = raw.Location
	auth.LinkCert = raw.LinkCert
	auth.DNSIdentifier = raw.Identifier.Value
	auth.Status = raw.Status
	auth.Challenges = raw.Challenges
	auth.Combinations = raw.Combinations
	auth.Expires = raw.Expires
	return nil
}

func (auth Authorization) MarshalJSON() (data []byte, err error) {
	return json.Marshal(rawAuthorization{
		Location: auth.Location,
		LinkCert: auth.LinkCert,
		Identifier: rawAuthorizationIdentifier{
			Type:  "dns",
			Value: auth.DNSIdentifier,
		},
		Status:       auth.Status,
		Challenges:   auth.Challenges,
		Combinations: auth.Combinations,
		Expires:      auth.Expires,
	})
}
