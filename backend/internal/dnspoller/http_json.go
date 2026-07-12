package dnspoller

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

func newPollerHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		// DNS-source credentials must never follow an upstream redirect to a
		// different endpoint. Operators configure the final API base URL.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

const (
	pollerMaxResponseBytes = int64(16 << 20) // 16 MiB hard cap for upstream JSON.
	pollerMaxErrorBytes    = int64(8 << 10)  // Never echo an unbounded error body.
)

func readBoundedBody(r io.Reader, maxBytes int64) ([]byte, error) {
	limited := &io.LimitedReader{R: r, N: maxBytes + 1}
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("response exceeds %d-byte limit", maxBytes)
	}
	return body, nil
}

func readBoundedErrorBody(r io.Reader) string {
	body, err := readBoundedBody(r, pollerMaxErrorBytes)
	if err != nil {
		return "response body omitted"
	}
	return string(body)
}

// redactRequestError retains the useful transport cause without returning
// url.Error's full request URL. Pi-hole v5 necessarily carries its static token
// in the legacy auth query parameter; echoing the URL on an outage would put
// that token in Core's activity and container logs.
func redactRequestError(err error) error {
	var requestError *url.Error
	if errors.As(err, &requestError) {
		if requestError.Err != nil {
			return fmt.Errorf("%s request failed: %w", requestError.Op, requestError.Err)
		}
		return fmt.Errorf("%s request failed", requestError.Op)
	}
	return err
}
