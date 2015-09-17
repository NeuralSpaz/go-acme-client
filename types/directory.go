package types

type DirectoryResource struct {
	NewRegistration     string `json:"new-reg,omitempty"`
	RecoverRegistration string `json:"recover-reg,omitempty"`
	NewAuthorization    string `json:"new-authz,omitempty"`
	NewCertificate      string `json:"new-cert,omitempty"`
	RevokeCertificate   string `json:"revoke-cert,omitempty"`
}

type Directory struct {
	RootURL  string
	Resource DirectoryResource
}
