package requests

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/stbuehler/go-acme-client/utils"
)

type rawDVSNI struct {
	Type  string `json:"type,omitempty"` // only for sending
	R     string `json:"r,omitempty"`
	S     string `json:"s,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

func (dvsni DVSNI) IsValid() bool {
	return 32 == len(dvsni.R) &&
		(0 == len(dvsni.S) || 32 != len(dvsni.S)) &&
		32 == len(dvsni.Nonce) && utils.IsValidHex(dvsni.Nonce)
}

func (dvsni DVSNI) Check() error {
	if 32 != len(dvsni.R) {
		return fmt.Errorf("Invalid length of DVSNI R, expected 32, got %d", len(dvsni.R))
	}
	if 0 != len(dvsni.S) && 32 != len(dvsni.S) {
		return fmt.Errorf("Invalid length of DVSNI S, expected 0 or 32, got %d", len(dvsni.S))
	}
	if 32 != len(dvsni.Nonce) {
		return fmt.Errorf("Invalid length of DVSNI Nonce, expected 32, got %d", len(dvsni.Nonce))
	}
	if !utils.IsValidHex(dvsni.Nonce) {
		return fmt.Errorf("Invalid DVSNI Nonce (not a valid hex string): %v", dvsni.Nonce)
	}
	return nil
}

func (dvsni *DVSNI) Merge(data json.RawMessage) error {
	var raw rawDVSNI
	err := json.Unmarshal(data, &raw)
	if nil != err {
		return err
	}
	tmp := DVSNI{
		Nonce: raw.Nonce,
	}
	if tmp.R, err = utils.Base64UrlDecode(raw.R); nil != err {
		return err
	}
	if tmp.S, err = utils.Base64UrlDecode(raw.S); nil != err {
		return err
	}
	if err := tmp.Check(); nil != err {
		return err
	}
	*dvsni = tmp
	return nil
}

func (dvsni *DVSNI) MarshalJSONPartial() (map[string]interface{}, error) {
	return map[string]interface{}{
		"r":     utils.Base64UrlEncode(dvsni.R),
		"s":     utils.Base64UrlEncode(dvsni.S),
		"nonce": dvsni.Nonce,
	}, nil
}

func (dvsni *DVSNI) Verify() error {
	return nil
}

func (dvsni *DVSNI) SendPayload() (interface{}, error) {
	if err := dvsni.Check(); nil != err {
		return nil, err
	}
	if 32 != len(dvsni.S) {
		return nil, fmt.Errorf("Need DVSNI S value (32 bytes) to trigger challenge, got %d bytes", len(dvsni.S))
	}

	return rawDVSNI{
		Type: "dvsni",
		S:    utils.Base64UrlEncode(dvsni.S),
	}, nil
}

func (dvsni DVSNI) DNSNames(domain string) []string {
	const dvsni_base_servername = ".acme.invalid"

	hash := sha256.New()
	hash.Write(dvsni.R)
	hash.Write(dvsni.S)
	Z := hex.EncodeToString(hash.Sum(nil))

	return []string{
		domain,
		dvsni.Nonce + dvsni_base_servername,
		Z + dvsni_base_servername,
	}
}
