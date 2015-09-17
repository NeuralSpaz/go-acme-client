package types

import (
	"encoding/json"
	"fmt"
)

type DNSIdentifier string

type rawAuthorizationIdentifier struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

func (dnsId DNSIdentifier) MarshalJSON() (data []byte, err error) {
	return json.Marshal(rawAuthorizationIdentifier{
		Type:  "dns",
		Value: string(dnsId),
	})
}

func (dnsId *DNSIdentifier) UnmarshalJSON(data []byte) error {
	var rawId rawAuthorizationIdentifier
	if err := json.Unmarshal(data, &rawId); nil != err {
		return err
	}
	if rawId.Type != "dns" {
		return fmt.Errorf("Unknown identifier.type %s, expected \"dns\"", rawId.Type)
	}
	*dnsId = DNSIdentifier(rawId.Value)
	return nil
}
