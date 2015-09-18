package command_certificate_show

import (
	"encoding/pem"
	"flag"
	"github.com/stbuehler/go-acme-client/command_base"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
)

var register_flags = flag.NewFlagSet("register", flag.ExitOnError)

func init() {
	command_base.AddStorageFlags(register_flags)
	utils.AddLogFlags(register_flags)
}

func Run(UI ui.UserInterface, args []string) {
	register_flags.Parse(args)

	_, _, reg := command_base.OpenStorageFromFlags(UI)
	if nil == reg {
		utils.Fatalf("You need to register first")
	}

	if 0 == len(register_flags.Args()) {
		certs, err := reg.CertificateInfos()
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
		} else if nil == cert {
			utils.Fatalf("Couldn't find certificate")
		}
		certData := cert.Certificate()

		UI.Messagef("Certificate from %s (DER encoded)", location)
		if 0 != len(certData.LinkIssuer) {
			UI.Messagef("Issued by %s", certData.LinkIssuer)
		}
		UI.Messagef("%s", pem.EncodeToMemory(certData.Certificate))
		if nil != certData.PrivateKey {
			UI.Messagef("%s", pem.EncodeToMemory(certData.PrivateKey))
		}
	}
}
