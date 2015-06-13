package utils

import (
	"encoding/base64"
	"strings"
)

// also adds missing padding
func Base64UrlDecode(s string) ([]byte, error) {
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// also adds missing padding
func MustBase64UrlDecode(s string) []byte {
	data, err := Base64UrlDecode(s)
	if nil != err {
		panic(err)
	}
	return data
}

// also removes padding
func Base64UrlEncode(data []byte) string {
	/*	padlen := 0
		switch len(data) % 3 {
		case 1:
			padlen = 2
		case 2:
			padlen = 1
		}
		enc := base64.URLEncoding.EncodeToString(data)
		return enc[0 : len(enc)-padlen]
	*/
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}
