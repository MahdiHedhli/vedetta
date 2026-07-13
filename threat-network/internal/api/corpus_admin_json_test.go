package api

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestRejectDuplicateJSONKeysNestingDepthBoundary(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantError bool
	}{
		{
			name: "array at limit",
			body: strings.Repeat("[", maxAdminJSONNestingDepth) + "0" +
				strings.Repeat("]", maxAdminJSONNestingDepth),
		},
		{
			name: "array over limit",
			body: strings.Repeat("[", maxAdminJSONNestingDepth+1) + "0" +
				strings.Repeat("]", maxAdminJSONNestingDepth+1),
			wantError: true,
		},
		{
			name: "object at limit",
			body: strings.Repeat(`{"next":`, maxAdminJSONNestingDepth) + "0" +
				strings.Repeat("}", maxAdminJSONNestingDepth),
		},
		{
			name: "object over limit",
			body: strings.Repeat(`{"next":`, maxAdminJSONNestingDepth+1) + "0" +
				strings.Repeat("}", maxAdminJSONNestingDepth+1),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rejectDuplicateJSONKeys([]byte(tt.body))
			if tt.wantError {
				if err == nil || err.Error() != "JSON nesting depth exceeds limit" {
					t.Fatalf("error = %v, want nesting-depth error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("boundary input rejected: %v", err)
			}
		})
	}
}

func TestCorpusAdminRejectsExcessiveJSONNestingWithoutEcho(t *testing.T) {
	_, _, admin := newCorpusAPIServers(t)
	const secret = "DEPTH-LIMIT-SECRET"
	body := strings.Repeat("[", maxAdminJSONNestingDepth+1) + fmt.Sprintf("%q", secret) +
		strings.Repeat("]", maxAdminJSONNestingDepth+1)

	resp := adminRequest(t, http.DefaultClient, http.MethodPost,
		admin.URL+"/api/v1/admin/device-corpus/profiles", body, "")
	responseBody := readResponse(t, resp)
	if resp.StatusCode != http.StatusUnprocessableEntity ||
		!bytes.Contains(responseBody, []byte(`"code":"STRICT_SCHEMA"`)) {
		t.Fatalf("status=%d body=%s", resp.StatusCode, responseBody)
	}
	if bytes.Contains(responseBody, []byte(secret)) {
		t.Fatalf("error reflected submitted content: %s", responseBody)
	}
}
