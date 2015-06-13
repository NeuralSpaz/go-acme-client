package command_certificate_show

import (
	"encoding/pem"
	"flag"
	"github.com/stbuehler/go-acme-client/storage"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
)

var register_flags = flag.NewFlagSet("register", flag.ExitOnError)

func init() {
	storage.AddStorageFlags(register_flags)
	utils.AddLogFlags(register_flags)
}

func Run(UI ui.UserInterface, args []string) {
	register_flags.Parse(args)

	_, reg := storage.OpenStorageFromFlags(UI)
	if nil == reg {
		utils.Fatalf("You need to register first")
	}

	if 0 == len(register_flags.Args()) {
		certs, err := reg.CertificateList()
		if nil != err {
			utils.Fatalf("Couldn't load certificate list: %s", err)
		}
		UI.Message("Certificate list")
		for _, certInfo := range certs {
			UI.Messagef("\t%s", certInfo.Location)
		}
	} else {
		location := register_flags.Arg(0)
		cert, err := reg.LoadCertificate(location)
		if nil != err {
			utils.Fatalf("Couldn't load certificate: %s", err)
		}
		if nil == cert {
			utils.Fatalf("Couldn't find certificate")
		}

		UI.Messagef("Certificate from %s (DER encoded)", location)
		if 0 != len(cert.Certificate.LinkIssuer) {
			UI.Messagef("Issued by %s", cert.Certificate.LinkIssuer)
		}
		UI.Messagef("%s", pem.EncodeToMemory(cert.Certificate.PemCertificate))
		if nil != cert.Certificate.PemPrivateKey {
			UI.Messagef("%s", pem.EncodeToMemory(cert.Certificate.PemPrivateKey))
		}
	}
}
