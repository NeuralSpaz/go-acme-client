package requests

import (
	"fmt"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/utils"
	"net/http"
)

func RunSignedRequest(signingKey types.SigningKey, req *utils.HttpRequest, payloadJson []byte) (*utils.HttpResponse, error) {
	var nonce string
	{
		nonceResp, err := http.Head(req.URL)
		if nil != err {
			return nil, err
		}
		defer nonceResp.Body.Close()

		nonce = nonceResp.Header.Get("Replay-Nonce")
	}
	if 0 == len(nonce) {
		return nil, fmt.Errorf("Didn't get a Replay-Nonce header")
	}

	sig, err := signingKey.Sign(payloadJson, nonce)
	if nil != err {
		return nil, err
	}
	utils.Debugf("sending to %s signed payload: %s\n", req.URL, string(payloadJson))
	req.Body = []byte(sig.FullSerialize())

	return req.Run()
}
