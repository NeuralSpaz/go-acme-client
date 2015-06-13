package utils

import (
	"encoding/hex"
)

func IsValidHex(s string) bool {
	_, err := hex.DecodeString(s)
	return nil == err
}

func MustHexDecode(s string) []byte {
	data, err := hex.DecodeString(s)
	if nil != err {
		panic(err)
	}
	return data
}
