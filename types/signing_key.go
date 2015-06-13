package types

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	jose "github.com/square/go-jose"
	"github.com/stbuehler/go-acme-client/utils"
)

type SigningKey struct {
	privateKey interface{}
}

func (skey SigningKey) GetSignatureAlgorithm() jose.SignatureAlgorithm {
	switch pkey := skey.privateKey.(type) {
	case *ecdsa.PrivateKey:
		switch pkey.Curve {
		case elliptic.P224():
			return jose.ES256
		case elliptic.P256():
			return jose.ES256
		case elliptic.P384():
			return jose.ES384
		case elliptic.P521():
			return jose.ES512
		default:
			panic("Unknown elliptic curve")
		}
	case *rsa.PrivateKey:
		return jose.PS512
	default:
		panic("Unkown private key type")
	}
}

func (skey SigningKey) GetPublicKey() *jose.JsonWebKey {
	return &jose.JsonWebKey{
		Key:       utils.MustPublicKey(skey.privateKey),
		Algorithm: string(skey.GetSignatureAlgorithm()),
	}
}
func (skey SigningKey) EncryptPrivateKey(password string, alg x509.PEMCipher) (*pem.Block, error) {
	return utils.EncryptPrivateKey(skey.privateKey, password, alg)
}

func (skey SigningKey) Sign(payload []byte, nonce string) (*jose.JsonWebSignature, error) {
	signer, err := jose.NewSigner(skey.GetSignatureAlgorithm(), skey.privateKey)
	if nil != err {
		return nil, err
	}
	return signer.Sign(payload, nonce)
}

func CreateSigningKey(keyType utils.KeyType, curve utils.Curve, rsaBits *int) (SigningKey, error) {
	pkey, err := utils.CreatePrivateKey(keyType, curve, rsaBits)
	if nil != err {
		return SigningKey{}, err
	}
	return SigningKey{privateKey: pkey}, nil
}

func LoadSigningKey(block pem.Block) (SigningKey, error) {
	privateKey, err := utils.DecodePrivateKey(block)
	if nil != err {
		return SigningKey{}, err
	}
	return SigningKey{privateKey: privateKey}, nil
}
