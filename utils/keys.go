package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
)

type KeyType string

const (
	KeyEcdsa KeyType = "ECDSA"
	KeyRSA   KeyType = "RSA"
)

type Curve string

const (
	curveDefault Curve = ""
	CurveP256    Curve = "P-256"
	CurveP384    Curve = "P-384"
	CurveP521    Curve = "P-521"
)

var UnknownPrivateKey = errors.New("Unknown Private Key")
var UnknownKeyType = errors.New("Unknown Key Type")
var UnknownCurve = errors.New("Unknown Curve")
var InvalidRsaBits = errors.New("Invalid RSA bits (must be in range 2048..4096)")

const pemTypeEcPrivateKey = "EC PRIVATE KEY"
const pemTypeRsaPrivateKey = "RSA PRIVATE KEY"
const pemTypePublicKey = "PUBLIC KEY"

func CreateEcdsaPrivateKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(curve, rand.Reader)
}

func CreateRsaPrivateKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

func CreatePrivateKey(keyType KeyType, curve Curve, rsaBits *int) (interface{}, error) {
	switch keyType {
	case KeyEcdsa:
		switch curve {
		case curveDefault:
			return CreateEcdsaPrivateKey(elliptic.P521())
		case CurveP256:
			return CreateEcdsaPrivateKey(elliptic.P256())
		case CurveP384:
			return CreateEcdsaPrivateKey(elliptic.P384())
		case CurveP521:
			return CreateEcdsaPrivateKey(elliptic.P521())
		default:
			return nil, UnknownCurve
		}
	case KeyRSA:
		bits := 2048
		if nil != rsaBits {
			bits = *rsaBits
		}
		if bits < 2048 || bits > 4096 {
			return nil, InvalidRsaBits
		}
		return CreateRsaPrivateKey(bits)
	default:
		return nil, UnknownKeyType
	}
}

func PublicKey(privateKey interface{}) (pubKey interface{}, err error) {
	if nil == privateKey {
		return
	}
	switch pkey := privateKey.(type) {
	case *ecdsa.PublicKey:
		pubKey = pkey
	case *ecdsa.PrivateKey:
		pubKey = &pkey.PublicKey
	case *rsa.PublicKey:
		pubKey = pkey
	case *rsa.PrivateKey:
		pubKey = &pkey.PublicKey
	default:
		err = UnknownPrivateKey
	}
	return
}

func MustPublicKey(privateKey interface{}) interface{} {
	pubKey, err := PublicKey(privateKey)
	if nil != err {
		panic(err)
	}
	return pubKey
}

func PickSignatureAlgorithm(privateKey interface{}, defaultAlg x509.SignatureAlgorithm) x509.SignatureAlgorithm {
	switch pkey := privateKey.(type) {
	case *ecdsa.PrivateKey:
		switch pkey.Curve {
		case elliptic.P224():
			return x509.ECDSAWithSHA256
		case elliptic.P256():
			return x509.ECDSAWithSHA256
		case elliptic.P384():
			return x509.ECDSAWithSHA384
		case elliptic.P521():
			return x509.ECDSAWithSHA512
		}
	}
	return defaultAlg
}

func EncodePrivateKey(privateKey interface{}) (*pem.Block, error) {
	switch pkey := privateKey.(type) {
	case *ecdsa.PrivateKey:
		data, err := x509.MarshalECPrivateKey(pkey)
		if nil != err {
			return nil, err
		}
		return &pem.Block{
			Type:  pemTypeEcPrivateKey,
			Bytes: data,
		}, nil
	case *rsa.PrivateKey:
		return &pem.Block{
			Type:  pemTypeRsaPrivateKey,
			Bytes: x509.MarshalPKCS1PrivateKey(pkey),
		}, nil
	default:
		return nil, UnknownPrivateKey
	}
}

func DecodePrivateKey(block pem.Block) (interface{}, error) {
	switch block.Type {
	case pemTypeEcPrivateKey:
		return x509.ParseECPrivateKey(block.Bytes)
	case pemTypeRsaPrivateKey:
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, UnknownPrivateKey
	}
}

func EncryptPrivateKey(privateKey interface{}, password string, alg x509.PEMCipher) (*pem.Block, error) {
	if block, err := EncodePrivateKey(privateKey); nil != err {
		return nil, err
	} else if err := EncryptPemBlock(block, password, alg); nil != err {
		return nil, err
	} else {
		return block, nil
	}
}

func LoadFirstPrivateKey(r io.Reader, prompt func() (string, error)) (interface{}, error) {
	if block, err := FirstPemBlock(r, pemTypeEcPrivateKey, pemTypeRsaPrivateKey); nil != err {
		return nil, err
	} else if err := DecryptPemBlock(block, prompt); nil != err {
		return nil, err
	} else {
		return DecodePrivateKey(*block)
	}
}

func EncodePublicKey(publicKey interface{}) (*pem.Block, error) {
	publicKey, err := PublicKey(publicKey)
	if nil != err {
		return nil, err
	}
	data, err := x509.MarshalPKIXPublicKey(publicKey)
	if nil != err {
		return nil, err
	}
	return &pem.Block{
		Type:  pemTypePublicKey,
		Bytes: data,
	}, nil
}

func DecodePublicKey(block pem.Block) (interface{}, error) {
	switch block.Type {
	case pemTypePublicKey:
		return x509.ParsePKIXPublicKey(block.Bytes)
	default:
		return nil, errors.New("Not a public key block")
	}
}

func LoadFirstPublicKey(r io.Reader, prompt func() (string, error)) (interface{}, error) {
	if block, err := FirstPemBlock(r, pemTypePublicKey); nil != err {
		return nil, err
	} else if err := DecryptPemBlock(block, prompt); nil != err {
		return nil, err
	} else {
		return DecodePublicKey(*block)
	}
}

func (curve Curve) IsValid() bool {
	switch curve {
	case CurveP256:
		return true
	case CurveP384:
		return true
	case CurveP521:
		return true
	default:
		return false
	}
}

func (curve *Curve) String() string {
	return string(*curve)
}

func (curve *Curve) Set(v string) error {
	c := Curve(v)
	if c.IsValid() {
		*curve = c
		return nil
	} else {
		return UnknownCurve
	}
}

func (keyType KeyType) IsValid() bool {
	switch keyType {
	case KeyEcdsa:
		return true
	case KeyRSA:
		return true
	default:
		return false
	}
}

func (keyType *KeyType) String() string {
	return string(*keyType)
}

func (keyType *KeyType) Set(v string) error {
	kt := KeyType(v)
	if kt.IsValid() {
		*keyType = kt
		return nil
	} else {
		return UnknownKeyType
	}
}
