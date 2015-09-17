package types

import (
	"encoding/pem"
)

type Certificate struct {
	Certificate *pem.Block
	PrivateKey  *pem.Block
	Location    string
	LinkIssuer  string
}
