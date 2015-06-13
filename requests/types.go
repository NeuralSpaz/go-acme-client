package requests

import (
	"encoding/json"
	"encoding/pem"
	jose "github.com/square/go-jose"
	"github.com/stbuehler/go-acme-client/ui"
	"time"
)

type Registration struct {
	UrlSelf           string           `json:"meta-location,omitempty"`
	UrlAuth           string           `json:"meta-auth-location,omitempty"`
	UrlTermsOfService string           `json:"meta-tos-location,omitempty"`
	PublicKey         *jose.JsonWebKey `json:"key,omitempty"`
	RecoveryToken     string           `json:"-,omitempty"` // don't store RecoveryToken by default
	Contact           []string         `json:"contact,omitempty"`
	Agreement         string           `json:"agreement,omitempty"`
}

type AuthorizationStatus string

type Authorization struct {
	UrlSelf       string              `json:"meta-location,omitempty"`
	UrlCert       string              `json:"meta-cert-location,omitempty"`
	DNSIdentifier string              `json:"dns-identifier,omitempty"`
	PublicKey     *jose.JsonWebKey    `json:"key,omitempty"`
	Status        AuthorizationStatus `json:"status,omitempty"`
	Challenges    []Challenge         `json:"challenges,omitempty"`
	Combinations  [][]int             `json:"combinations,omitempty"`
	Expires       *time.Time          `json:"expires,omitempty"`
}

type ChallengeData interface {
	Merge(json.RawMessage) error                         // merge json response from server
	MarshalJSONPartial() (map[string]interface{}, error) // export data for reimport with Merge
}

type ChallengeResponding interface {
	ChallengeData
	ResetResponse()                                            // clear fields set by the client
	InitializeResponse(*Authorization, ui.UserInterface) error // set some fields, maybe ask the client about them
	ShowInstructions(*Authorization, ui.UserInterface) error   // show instructions to provide response for challenge
	Verify(*Authorization) error                               // verify pending response
	SendPayload() (interface{}, error)                         // payload to update challenge
}

type Challenge struct {
	Type      string
	Status    string
	Validated string
	URI       string
	Data      ChallengeData
}

type DVSNI struct {
	R     []byte // 32 bytes
	S     []byte // empty or 32 bytes
	Nonce string // always 32-character hex string
}

type SimpleHttps struct {
	Token string // ASCII only
	Path  string
}

// unknown challenges / challenges which don't have a URI anymore
type FixedChallenge map[string]interface{}

type Certificate struct {
	File      *pem.Block
	UrlSelf   string
	UrlIssuer string
}
