package requests

import (
	"encoding/json"
)

func (ch *FixedChallenge) Merge(m json.RawMessage) error {
	var data map[string]interface{}
	err := json.Unmarshal(m, &data)
	if nil == data {
		return err
	}
	delete(data, "type")
	delete(data, "status")
	delete(data, "validated")
	delete(data, "uri")
	*ch = FixedChallenge(data)
	return nil
}

func (ch *FixedChallenge) MarshalJSONPartial() (map[string]interface{}, error) {
	return map[string]interface{}(*ch), nil
}
