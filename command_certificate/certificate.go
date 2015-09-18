package command_certificate

import (
	"encoding/pem"
	"flag"
	"github.com/stbuehler/go-acme-client/command_base"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
	"os"
)

var register_flags = flag.NewFlagSet("register", flag.ExitOnError)

var rsabits int = 2048
var curve utils.Curve = utils.CurveP521
var keyType utils.KeyType = utils.KeyRSA

func init() {
	register_flags.IntVar(&rsabits, "rsa-bits", 2048, "Number of bits to generate the RSA key with (if selected)")
	register_flags.Var(&curve, "curve", "Elliptic curve to generate ECDSA key with (if selected), one of P-256, P-384, P-521")
	register_flags.Var(&keyType, "key-type", "Key type to generate, RSA or ECDSA")
	command_base.AddStorageFlags(register_flags)
	utils.AddLogFlags(register_flags)
}

func Run(UI ui.UserInterface, args []string) {
	register_flags.Parse(args)

	_, _, reg := command_base.OpenStorageFromFlags(UI)
	if nil == reg {
		utils.Fatalf("You need to register first")
	}

	listValidAuths, err := reg.AuthorizationInfosWithStatus(types.AuthorizationStatus("valid"))
	if nil != err {
		utils.Fatalf("Couldn't list valid authorizations: %s", err)
	}

	validAuths := make(map[string]bool)
	var validDomains []string

	for dnsName, _ := range listValidAuths {
		validAuths[dnsName] = true
		validDomains = append(validDomains, dnsName)
	}

	if 0 == len(validDomains) {
		utils.Fatalf("You don't have any valid authorizations.")
	}

	var pkey interface{}
	privateKeyGenerated := false
	if 0 != len(register_flags.Args()) {
		pkeyPrompt, _ := UI.PasswordPromptOnce("Enter private key password")
		if pkeyFile, err := os.Open(register_flags.Arg(0)); nil != err {
			utils.Fatalf("%s", err)
		} else if pkey, err = utils.LoadFirstPrivateKey(pkeyFile, pkeyPrompt); nil != err {
			utils.Fatalf("%s", err)
		}
	} else {
		UI.Message("Generating private key for certificate")
		privateKeyGenerated = true
		var err error
		if pkey, err = utils.CreatePrivateKey(keyType, curve, &rsabits); nil != err {
			utils.Fatalf("Couldn't create private key for certificate: %s", err)
		}
	}

	UI.Messagef("Available domains: %v", validDomains)

	markSelectedDomains := make(map[string]bool)
	var selectedDomains []string
	for {
		domain, err := UI.Prompt("Enter domain to add to certificate (empty to end list)")
		if err != nil {
			utils.Fatalf("Couldn't read domain: %s", err)
		}
		if 0 == len(domain) {
			break
		}
		if markSelectedDomains[domain] {
			UI.Messagef("Already selected %#v", domain)
			continue
		}
		markSelectedDomains[domain] = true
		if !validAuths[domain] {
			UI.Messagef("Unknown domain %#v, not adding - try again", domain)
			continue
		}
		selectedDomains = append(selectedDomains, domain)
	}

	if 0 == len(selectedDomains) {
		UI.Message("No domains entered, aborting")
		return
	}

	csr, err := utils.MakeCertificateRequest(utils.CertificateRequestParameters{
		PrivateKey: pkey,
		DNSNames:   selectedDomains,
	})
	if nil != err {
		utils.Fatalf("Couldn't create certificate request: %s", err)
	}

	utils.Debugf("CSR:\n%s", pem.EncodeToMemory(csr))

	cert, err := reg.NewCertificate(*csr)
	if nil != err {
		utils.Fatalf("Certificate request failed: %s", err)
	}

	if privateKeyGenerated {
		if err := cert.SetPrivateKey(pkey); nil != err {
			utils.Errorf("Couldn't store private key: %s", err)
		}
	}
	certData := cert.Certificate()

	UI.Messagef("New certificate is available under: %s (DER encoded)", certData.Location)
	if 0 != len(certData.LinkIssuer) {
		UI.Messagef("Issueing certificate available at: %s", certData.LinkIssuer)
	}
	UI.Messagef("%s", pem.EncodeToMemory(certData.Certificate))
	if nil != certData.PrivateKey {
		UI.Messagef("%s", pem.EncodeToMemory(certData.PrivateKey))
	}
}
