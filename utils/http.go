package utils

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
)

type HttpRequestHeader struct {
	ContentType string
	Accept      string
}

type HttpRequest struct {
	Method  string
	URL     string
	Body    []byte
	Headers HttpRequestHeader
}

type HttpLink struct {
	URL        string
	Properties map[string]string
}

type HttpResponse struct {
	RawResponse *http.Response
	Body        []byte
	StatusCode  int
	Status      string
	Location    string
	ContentType string
	Links       map[string]HttpLink
}

var parseLinkHeader = regexp.MustCompile(`^\s*<([^>]*)>\s*(.*)$`)
var parseLinkHeaderProps = regexp.MustCompile(`\s*;([^=]+)\s*=\s*"([^"]*)"`)

func (req *HttpRequest) Run() (*HttpResponse, error) {
	var body io.Reader
	if nil != req.Body {
		body = bytes.NewReader(req.Body)
	}

	hReq, err := http.NewRequest(req.Method, req.URL, body)
	if nil != err {
		return nil, err
	}
	if 0 != len(req.Headers.ContentType) {
		hReq.Header.Add("Content-Type", req.Headers.ContentType)
	}
	if 0 != len(req.Headers.Accept) {
		hReq.Header.Add("Accept", req.Headers.Accept)
	}
	DebugLogHttpRequest(req, hReq)

	resp := HttpResponse{
		Links: make(map[string]HttpLink),
	}
	if resp.RawResponse, err = http.DefaultClient.Do(hReq); nil != err {
		return nil, err
	}
	defer resp.RawResponse.Body.Close()
	resp.StatusCode = resp.RawResponse.StatusCode
	resp.Status = resp.RawResponse.Status
	resp.Location = resp.RawResponse.Header.Get("Location")
	resp.ContentType = resp.RawResponse.Header.Get("Content-Type")

	for _, link := range resp.RawResponse.Header["Link"] {
		if matches := parseLinkHeader.FindStringSubmatch(link); nil != matches {
			link := HttpLink{
				URL:        matches[1],
				Properties: make(map[string]string),
			}
			for _, propMatches := range parseLinkHeaderProps.FindAllStringSubmatch(matches[2], -1) {
				link.Properties[propMatches[1]] = propMatches[2]
			}
			rel := link.Properties["rel"]
			if 0 != len(rel) {
				resp.Links[rel] = link
			}
		}
	}

	if resp.Body, err = ioutil.ReadAll(resp.RawResponse.Body); nil != err {
		resp.Body = []byte{}
		DebugLogHttpResponse(&resp)
		return nil, err
	}
	DebugLogHttpResponse(&resp)

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP error code: %s", resp.Status)
	}

	return &resp, nil
}
