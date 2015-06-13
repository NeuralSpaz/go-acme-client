package utils

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
)

func EncryptPemBlock(block *pem.Block, password string, alg x509.PEMCipher) error {
	if 0 != len(password) {
		if x509.PEMCipher(0) == alg {
			alg = x509.PEMCipherAES256
		}
		newBlock, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(password), alg)
		if nil != err {
			return err
		}
		if nil == block.Headers {
			block.Headers = newBlock.Headers
		} else {
			for hdr, val := range newBlock.Headers {
				block.Headers[hdr] = val
			}
		}
		block.Bytes = newBlock.Bytes
	}
	return nil
}

func DecryptPemBlock(block *pem.Block, prompt func() (string, error)) (err error) {
	if x509.IsEncryptedPEMBlock(block) {
		if password, err := prompt(); nil != err {
			return err
		} else if data, err := x509.DecryptPEMBlock(block, []byte(password)); nil != err {
			return err
		} else {
			delete(block.Headers, "Proc-Type")
			delete(block.Headers, "DEK-Info")
			block.Bytes = data
		}
	}
	return nil
}

func LoadPemBlocks(r io.Reader, prompt func() (string, error)) ([]*pem.Block, error) {
	var blocks []*pem.Block

	data, err := ioutil.ReadAll(r)
	if nil != err {
		return nil, err
	}

	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if nil == block {
			break
		}

		if err := DecryptPemBlock(block, prompt); nil != err {
			return nil, err
		}

		blocks = append(blocks, block)
	}

	return blocks, nil
}

func FirstPemBlock(r io.Reader, types ...string) (*pem.Block, error) {
	data, err := ioutil.ReadAll(r)
	if nil != err {
		return nil, err
	}

	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if nil == block {
			break
		}

		for _, t := range types {
			if block.Type == t {
				return block, nil
			}
		}
	}

	return nil, fmt.Errorf("Couldn't find any of %v in file", types)
}
