package types

import (
	"encoding/pem"
)

type Certificate struct {
	PemCertificate *pem.Block
	PemPrivateKey  *pem.Block
	Location       string
	LinkIssuer     string
}
