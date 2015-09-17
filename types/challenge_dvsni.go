package types

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
	"strings"
)

const dvsniIdentifier string = "dvsni"

type challengeDVSNI struct {
	Resource ResourceChallengeTag `json:"resource"`
	rawChallengeBasic
	Token string `json:"token,omitempty"` // ASCII only
}

func (dvsni *challengeDVSNI) GetType() string {
	return dvsni.Type
}

func (dvsni *challengeDVSNI) GetStatus() string {
	return dvsni.Status
}

func (dvsni *challengeDVSNI) GetValidated() string {
	return dvsni.Validated
}

func (dvsni *challengeDVSNI) GetURI() string {
	return dvsni.URI
}

type challengeDVSNIData struct {
	Resource   ResourceChallengeTag `json:"resource"`
	Type       string               `json:"type"`
	Validation JSONSignature
}

func (dvsniData *challengeDVSNIData) GetType() string {
	return dvsniData.Type
}

func (dvsni *challengeDVSNI) initializeResponse(registration *Registration, authorization *Authorization) (ChallengeResponding, error) {
	responding := challengeDVSNIResponding{
		registration:  registration,
		dnsIdentifier: string(authorization.Resource.DNSIdentifier),
		challenge:     *dvsni,
		data: challengeDVSNIData{
			Type: dvsniIdentifier,
		},
	}

	if oldData := authorization.ChallengesData[dvsni.GetURI()].chDataImpl; nil != oldData {
		if oldDVSNIData := oldData.(*challengeDVSNIData); nil != oldDVSNIData {
			responding.data = *oldDVSNIData
		} else {
			return nil, fmt.Errorf("Mismatching challenge data %#v", oldData)
		}
	} else {
	}
	if nil == responding.data.Validation.Signature {
		responding.ResetResponse()
	}
	return &responding, nil
}

type challengeDVSNIResponding struct {
	registration  *Registration
	dnsIdentifier string
	challenge     challengeDVSNI
	data          challengeDVSNIData
}

type challengeDVSNIFileData struct {
	Type  string `json:"type"`
	Token string `json:"token"`
}

func (responding *challengeDVSNIResponding) ResetResponse() error {
	if payload, err := json.Marshal(
		challengeDVSNIFileData{
			Type:  dvsniIdentifier,
			Token: responding.challenge.Token,
		}); nil != err {
		return err
	} else if sig, err := responding.registration.SigningKey.Sign(payload, ""); nil != err {
		return err
	} else {
		responding.data.Validation.Signature = sig
		return nil
	}
}

func (responding *challengeDVSNIResponding) InitializeResponse(UI ui.UserInterface) error {
	return nil
}

func (responding *challengeDVSNIResponding) ShowInstructions(UI ui.UserInterface) error {
	text := fmt.Sprintf("%s:443 needs to present a (self-signed) certificate for SNI name (\"vhost\") %s\n", responding.dnsIdentifier, responding.subjectAltName())
	if cert, err := responding.makeCertificate(); nil != err {
		text += fmt.Sprintf("Couldn't generate example certificate (build your own instead): %s\n", err)
	} else {
		text += fmt.Sprintf("You can use the following 2048-bit RSA certificate:\n%s", cert)
	}
	text += "Press enter when done"
	_, err := UI.Prompt(text)
	return err
}

func (responding *challengeDVSNIResponding) Verify() error {
	sniName := responding.subjectAltName()
	if conn, err := tls.Dial("tcp", responding.dnsIdentifier+":443", &tls.Config{
		RootCAs:            x509.NewCertPool(),
		ServerName:         sniName,
		InsecureSkipVerify: true,
	}); nil != err {
		return fmt.Errorf("Failed to establish connection with %s:443: %v", responding.dnsIdentifier, err)
	} else if err := conn.Handshake(); nil != err {
		return fmt.Errorf("Failed TLS handshake with %s:443: %v", responding.dnsIdentifier, err)
	} else {
		cState := conn.ConnectionState()
		if 0 == len(cState.PeerCertificates) {
			return fmt.Errorf("Server %s:443 returned no certificates", responding.dnsIdentifier)
		}
		cert := cState.PeerCertificates[0]
		for _, name := range cert.DNSNames {
			if name == sniName {
				// found name, verifiation successful
				return nil
			}
		}
		return fmt.Errorf(
			"Certificate on %s:443 for SNI name %s didn't contain the SNI name in SubjectAltName: CommonName=%s, DNSNames=%v",
			responding.dnsIdentifier, sniName, cert.Subject.CommonName, cert.DNSNames)
	}
}

func (responding *challengeDVSNIResponding) SendPayload() (interface{}, error) {
	return responding.data, nil
}

func (responding *challengeDVSNIResponding) ChallengeData() ChallengeData {
	return ChallengeData{chDataImpl: &responding.data}
}

func (responding *challengeDVSNIResponding) Challenge() Challenge {
	return Challenge{chImpl: &responding.challenge}
}

func (responding *challengeDVSNIResponding) Registration() *Registration {
	return responding.registration
}

func (responding *challengeDVSNIResponding) makeCertificate() (string, error) {
	var out bytes.Buffer

	if privKey, err := utils.CreateRsaPrivateKey(2048); nil != err {
		return "", err
	} else if block_cert, err := utils.MakeCertificate(
		utils.CertificateParameters{
			SigningKey: privKey,
			DNSNames:   []string{responding.subjectAltName()},
		}); nil != err {
		return "", err
	} else if block_pkey, err := utils.EncodePrivateKey(privKey); nil != err {
		return "", err
	} else if err := pem.Encode(&out, block_cert); nil != err {
		return "", err
	} else if err := pem.Encode(&out, block_pkey); nil != err {
		return "", err
	} else {
		return out.String(), nil
	}
}

func (responding *challengeDVSNIResponding) subjectAltName() string {
	const dvsni_base_servername = ".acme.invalid"

	hash := sha256.New()
	if compSig, err := responding.data.Validation.Signature.CompactSerialize(); nil != err {
		panic("Invalid validation signature, CompactSerialize() failed")
	} else {
		hash.Write([]byte(strings.Split(compSig, ".")[2]))
	}
	Z := hex.EncodeToString(hash.Sum(nil))

	return Z[0:32] + "." + Z[32:64] + dvsni_base_servername
}
