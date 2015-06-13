package command_certificate

import (
	"encoding/pem"
	"flag"
	"github.com/stbuehler/go-acme-client/requests"
	"github.com/stbuehler/go-acme-client/storage"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
	"os"
)

var register_flags = flag.NewFlagSet("register", flag.ExitOnError)

var storagePath string

func init() {
	register_flags.StringVar(&storagePath, "storage", "storage.pem", "Storagefile")
	utils.AddLogFlags(register_flags)
}

func Run(UI ui.UserInterface, args []string) {
	register_flags.Parse(args)

	if 0 == len(register_flags.Args()) {
		utils.Fatalf("Give a private key as argument")
	}
	var pkey interface{}
	if pkeyFile, err := os.Open(register_flags.Arg(0)); nil != err {
		utils.Fatalf("%s", err)
	} else if pkey, err = utils.LoadFirstPrivateKey(pkeyFile, UI.PasswordPromptOnce("Enter password")); nil != err {
		utils.Fatalf("%s", err)
	}

	st, err := storage.LoadStorageFile(storagePath, UI.PasswordPromptOnce("Enter password: "))
	if nil != err {
		utils.Fatalf("Couldn't load the registration: %s", err)
	}

	if nil == st.RegistrationData {
		utils.Fatalf("You need to register first")
	}

	validAuths := make(map[string]*requests.Authorization)
	var validDomains []string

	for authNdx, auth := range st.Authorizations {
		if auth.Status == "valid" {
			validAuths[auth.DNSIdentifier] = &st.Authorizations[authNdx]
			validDomains = append(validDomains, auth.DNSIdentifier)
		}
	}
	UI.Messagef("Available domains: %v", validDomains)

	markSelectedDomains := make(map[string]bool)
	var selectedAuthUrls []string
	var selectedDomains []string
	var newCertUrl string
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
		auth := validAuths[domain]
		if nil == auth {
			UI.Messagef("Unknown domain %#v, not adding - try again", domain)
			continue
		}
		if 0 == len(newCertUrl) {
			newCertUrl = auth.UrlCert
		} else if newCertUrl != auth.UrlCert {
			UI.Messagef("Authentication for %v wants a different certificate URL than the previous domains - adding anyway", domain)
		}
		selectedDomains = append(selectedDomains, domain)
		selectedAuthUrls = append(selectedAuthUrls, auth.UrlSelf)
	}

	if 0 == len(selectedDomains) {
		UI.Message("No domains entered, aborting")
		return
	}

	if err = storage.SaveStorageFile(storagePath, st); nil != err {
		utils.Fatalf("Couldn't save the new authorization: %s", err)
	}

	csr, err := utils.MakeCertificateRequest(utils.CertificateRequestParameters{
		PrivateKey: pkey,
		DNSNames:   selectedDomains,
	})
	if nil != err {
		utils.Fatalf("Couldn't create certificate request: %s", err)
	}

	utils.Debugf("CSR:\n%s", pem.EncodeToMemory(csr))

	cert, err := requests.RequestCertificate(st.RegistrationKey, newCertUrl, *csr, selectedAuthUrls)
	if nil != err {
		utils.Fatalf("Certificate request failed: %s", err)
	}

	UI.Messagef("New certificate is available under: %s (DER encoded)", cert.UrlSelf)
	if 0 != len(cert.UrlIssuer) {
		UI.Messagef("Issueing certificate available at: %s", cert.UrlIssuer)
	}
	UI.Messagef("Certificate:\n%s", pem.EncodeToMemory(cert.File))
}
