package types

import (
	"encoding/json"
	"fmt"
)

type ChallengeDataImplementation interface {
	GetType() string
}

type ChallengeData struct {
	chDataImpl ChallengeDataImplementation
}

type rawChallengeDataBasic struct {
	Type string `json:"type,omitempty"`
}

func (cdata *ChallengeData) UnmarshalJSON(data []byte) error {
	var jsonType struct {
		Type string `json:"type,omitempty"`
	}
	if err := json.Unmarshal(data, &jsonType); nil != err {
		return err
	}

	var newData ChallengeDataImplementation

	switch jsonType.Type {
	case "":
		cdata.chDataImpl = nil
		return nil
	case simpleHttpIdentifier:
		newData = &challengeSimpleHttpData{}
	case dvsniIdentifier:
		newData = &challengeDVSNIData{}
	}

	if nil == newData {
		return fmt.Errorf("Unknown challenge data type %#v", jsonType.Type)
	}

	if err := json.Unmarshal(data, newData); nil != err {
		return err
	}
	cdata.chDataImpl = newData
	return nil
}

func (cdata ChallengeData) MarshalJSON() ([]byte, error) {
	return json.Marshal(cdata.chDataImpl)
}

func (cdata ChallengeData) GetType() string {
	return cdata.chDataImpl.GetType()
}
