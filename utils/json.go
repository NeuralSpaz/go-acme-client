package utils

import (
	"encoding/json"
)

func MustEncodeJson(v interface{}) []byte {
	data, err := json.Marshal(v)
	if nil != err {
		panic(err)
	}
	return data
}

func MustPrettyEncodeJson(v interface{}) []byte {
	data, err := json.MarshalIndent(v, "", "  ")
	if nil != err {
		panic(err)
	}
	return data
}
