package types

import (
	"encoding/json"
	"fmt"
)

type AuthorizationStatus string

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
