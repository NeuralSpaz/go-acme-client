package challenges

import (
	"bytes"
	"encoding/pem"
	"errors"
	"github.com/stbuehler/go-acme-client/requests"
	"github.com/stbuehler/go-acme-client/utils"
)

var DVSNI_EmptyS = errors.New("DVSNI S value is empty")

func MakeCertificate(privKey interface{}, domain string, dvsni requests.DVSNI) (pemData string, err error) {
	if 0 == len(dvsni.S) {
		err = DVSNI_EmptyS
		return
	}
	if err = dvsni.Check(); nil != err {
		return
	}

	block_cert, err := utils.MakeCertificate(utils.CertificateParameters{
		SigningKey: privKey,
		DNSNames:   dvsni.DNSNames(domain),
	})

	block_pkey, err := utils.EncodePrivateKey(privKey)

	var out bytes.Buffer
	if err = pem.Encode(&out, block_cert); nil != err {
		return
	}
	if err = pem.Encode(&out, block_pkey); nil != err {
		return
	}

	pemData = out.String()

	return
}
