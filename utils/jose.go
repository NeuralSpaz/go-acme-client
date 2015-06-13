package utils

import (
	jose "github.com/square/go-jose"
	"reflect"
)

func EqualJsonWebKey(a, b jose.JsonWebKey) bool {
	return reflect.DeepEqual(a.Key, b.Key)
}
