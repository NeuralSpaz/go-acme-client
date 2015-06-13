package types

type Registration struct {
	Location           string   `json:"meta-location,omitempty"`
	LinkAuth           string   `json:"link-auth,omitempty"`
	LinkTermsOfService string   `json:"link-tos,omitempty"`
	Certificates       string   `json:"certificates,omitempty"`
	Authorizations     string   `json:"authorizations,omitempty"`
	RecoveryToken      string   `json:"recoveryToken,omitempty"`
	Contact            []string `json:"contact,omitempty"`
	Agreement          string   `json:"agreement,omitempty"`
}
