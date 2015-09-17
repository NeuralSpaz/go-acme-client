package types

type RegistrationResource struct {
	Resource          ResourceRegistrationTag `json:"resource"`
	Contact           []string                `json:"contact,omitempty"`
	AgreementURL      string                  `json:"agreement,omitempty"`
	AuthorizationsURL string                  `json:"authorizations,omitempty"`
	CertificatesURL   string                  `json:"certificates,omitempty"`
	// recovery not supported yet
}

type Registration struct {
	Resource           RegistrationResource
	SigningKey         SigningKey
	Location           string
	LinkTermsOfService string
	RecoveryToken      string
	Name               string
}
