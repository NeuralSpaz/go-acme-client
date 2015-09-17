package types

import (
	"encoding/json"
	"fmt"
)

type Resource int

const (
	// action resources to create new resources
	Resource_NewRegistration Resource = iota
	Resource_RecoverRegistration
	Resource_NewAuthorization
	Resource_NewCertificate
	Resource_RevokeCertificate
	// existing resources with an actual value
	Resource_Registration
	Resource_Authorization
	Resource_Challenge
	Resource_Certificate
)

func (r Resource) String() string {
	switch r {
	case Resource_NewRegistration:
		return "new-reg"
	case Resource_RecoverRegistration:
		return "recover-reg"
	case Resource_NewAuthorization:
		return "new-authz"
	case Resource_NewCertificate:
		return "new-cert"
	case Resource_RevokeCertificate:
		return "revoke-cert"
	case Resource_Registration:
		return "reg"
	case Resource_Authorization:
		return "authz"
	case Resource_Challenge:
		return "challenge"
	case Resource_Certificate:
		return "cert"
	}
	panic("Invalid resource")
}

func (r Resource) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

func (r Resource) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); nil != err {
		return err
	}
	if r.String() != s {
		return fmt.Errorf("Expected resource %s, got %v", r, s)
	}
	return nil
}

type ResourceNewRegistrationTag struct{}
type ResourceRecoverRegistrationTag struct{}
type ResourceNewAuthorizationTag struct{}
type ResourceNewCertificateTag struct{}
type ResourceRevokeCertificateTag struct{}
type ResourceRegistrationTag struct{}
type ResourceAuthorizationTag struct{}
type ResourceChallengeTag struct{}
type ResourceCertificateTag struct{}

func (ResourceNewRegistrationTag) MarshalJSON() ([]byte, error) {
	return Resource_NewRegistration.MarshalJSON()
}
func (ResourceRecoverRegistrationTag) MarshalJSON() ([]byte, error) {
	return Resource_RecoverRegistration.MarshalJSON()
}
func (ResourceNewAuthorizationTag) MarshalJSON() ([]byte, error) {
	return Resource_NewAuthorization.MarshalJSON()
}
func (ResourceNewCertificateTag) MarshalJSON() ([]byte, error) {
	return Resource_NewCertificate.MarshalJSON()
}
func (ResourceRevokeCertificateTag) MarshalJSON() ([]byte, error) {
	return Resource_RevokeCertificate.MarshalJSON()
}
func (ResourceRegistrationTag) MarshalJSON() ([]byte, error) {
	return Resource_Registration.MarshalJSON()
}
func (ResourceAuthorizationTag) MarshalJSON() ([]byte, error) {
	return Resource_Authorization.MarshalJSON()
}
func (ResourceChallengeTag) MarshalJSON() ([]byte, error) {
	return Resource_Challenge.MarshalJSON()
}
func (ResourceCertificateTag) MarshalJSON() ([]byte, error) {
	return Resource_Certificate.MarshalJSON()
}

func (ResourceNewRegistrationTag) UnmarshalJSON(data []byte) error {
	return Resource_NewRegistration.UnmarshalJSON(data)
}
func (ResourceRecoverRegistrationTag) UnmarshalJSON(data []byte) error {
	return Resource_RecoverRegistration.UnmarshalJSON(data)
}
func (ResourceNewAuthorizationTag) UnmarshalJSON(data []byte) error {
	return Resource_NewAuthorization.UnmarshalJSON(data)
}
func (ResourceNewCertificateTag) UnmarshalJSON(data []byte) error {
	return Resource_NewCertificate.UnmarshalJSON(data)
}
func (ResourceRevokeCertificateTag) UnmarshalJSON(data []byte) error {
	return Resource_RevokeCertificate.UnmarshalJSON(data)
}
func (ResourceRegistrationTag) UnmarshalJSON(data []byte) error {
	return Resource_Registration.UnmarshalJSON(data)
}
func (ResourceAuthorizationTag) UnmarshalJSON(data []byte) error {
	return Resource_Authorization.UnmarshalJSON(data)
}
func (ResourceChallengeTag) UnmarshalJSON(data []byte) error {
	return Resource_Challenge.UnmarshalJSON(data)
}
func (ResourceCertificateTag) UnmarshalJSON(data []byte) error {
	return Resource_Certificate.UnmarshalJSON(data)
}
