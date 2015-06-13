package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	jose "github.com/square/go-jose"
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
		Key:       MustPublicKey(skey.privateKey),
		Algorithm: string(skey.GetSignatureAlgorithm()),
	}
}
func (skey SigningKey) EncryptPrivateKey(password string, alg x509.PEMCipher) (*pem.Block, error) {
	return EncryptPrivateKey(skey.privateKey, password, alg)
}

func (skey SigningKey) Sign(payload []byte, nonce string) (*jose.JsonWebSignature, error) {
	signer, err := jose.NewSigner(skey.GetSignatureAlgorithm(), skey.privateKey)
	if nil != err {
		return nil, err
	}
	return signer.Sign(payload, nonce)
}

func CreateSigningKey(keyType KeyType, curve Curve, rsaBits *int) (SigningKey, error) {
	pkey, err := CreatePrivateKey(keyType, curve, rsaBits)
	if nil != err {
		return SigningKey{}, err
	}
	return SigningKey{privateKey: pkey}, nil
}

func LoadSigningKey(block pem.Block) (SigningKey, error) {
	privateKey, err := DecodePrivateKey(block)
	if nil != err {
		return SigningKey{}, err
	}
	return SigningKey{privateKey: privateKey}, nil
}
