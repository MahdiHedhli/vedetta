package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/vedetta-network/vedetta/threat-network/internal/adminauth"
	"github.com/vedetta-network/vedetta/threat-network/internal/corpus"
	"github.com/vedetta-network/vedetta/threat-network/internal/store"
)

var testAdminToken = strings.Repeat("a", adminauth.MinTokenBytes)

func newCorpusAPIServers(t *testing.T) (*Server, *httptest.Server, *httptest.Server) {
	t.Helper()
	db, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	tokenPath := t.TempDir() + "/admin-token"
	if err = os.WriteFile(tokenPath, []byte(testAdminToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	authenticator, err := adminauth.LoadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(db, log.New(io.Discard, "", 0))
	public := httptest.NewServer(s.Handler())
	admin := httptest.NewServer(s.AdminHandler(authenticator))
	t.Cleanup(public.Close)
	t.Cleanup(admin.Close)
	return s, public, admin
}

func adminRequest(t *testing.T, client *http.Client, method, target, body, etag string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if etag != "" {
		req.Header.Set("If-Match", etag)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readResponse(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCorpusAdminAuthAndPublicSeparation(t *testing.T) {
	_, public, admin := newCorpusAPIServers(t)
	for _, authorization := range []string{"", "Bearer definitely-wrong"} {
		req, _ := http.NewRequest(http.MethodGet, admin.URL+"/api/v1/admin/device-corpus/profiles", nil)
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body := readResponse(t, resp)
		if resp.StatusCode != http.StatusUnauthorized ||
			string(body) != "{\"error\":{\"code\":\"UNAUTHORIZED\",\"message\":\"unauthorized\"}}\n" ||
			resp.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("auth rejection status=%d body=%q", resp.StatusCode, body)
		}
	}
	resp, err := http.Get(public.URL + "/api/v1/admin/device-corpus/profiles")
	if err != nil {
		t.Fatal(err)
	}
	readResponse(t, resp)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("public listener exposed admin route: %d", resp.StatusCode)
	}
}

func TestCorpusAdminEndToEndAndPublicETag(t *testing.T) {
	_, public, admin := newCorpusAPIServers(t)
	createBody := `{"labels":{"manufacturer":"Example Devices","model":"Camera Two","device_type":"camera","os_family":"embedded"},"reason_code":"new_profile"}`
	resp := adminRequest(t, http.DefaultClient, http.MethodPost, admin.URL+"/api/v1/admin/device-corpus/profiles", createBody, "")
	body := readResponse(t, resp)
	if resp.StatusCode != http.StatusCreated || resp.Header.Get("ETag") == "" {
		t.Fatalf("create status=%d headers=%v body=%s", resp.StatusCode, resp.Header, body)
	}
	var profile corpus.Profile
	if err := json.Unmarshal(body, &profile); err != nil {
		t.Fatal(err)
	}
	etag := resp.Header.Get("ETag")
	variantBody := `{
      "variant_key":"firmware-2","confidence_bp":9200,"reason_code":"new_variant",
      "shape":{"schema_version":1,"dhcp_option_55":[1,3,6,15,119],"oui_prefixes":["00:00:5e"],"mdns_services":["_rtsp._tcp"],"mdns_models":["Example Camera Two"],"tcp_ports":[80,443,554]},
      "sources":[{"source_ref":"vendor","kind":"vendor_doc","title":"Example Camera Support","public_url":"https://docs.example.com/camera-two"}],
      "version_facts":[{"attribute":"firmware_version","relation":"exact","value":"2.4.1","confidence_bp":9000,"source_ref":"vendor"}]
    }`
	resp = adminRequest(t, http.DefaultClient, http.MethodPost,
		admin.URL+"/api/v1/admin/device-corpus/profiles/"+profile.ProfileID+"/variants", variantBody, etag)
	body = readResponse(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("variant status=%d body=%s", resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, &profile); err != nil {
		t.Fatal(err)
	}
	variantETag := resp.Header.Get("ETag")

	// A missing/stale profile precondition cannot overwrite the newer draft.
	resp = adminRequest(t, http.DefaultClient, http.MethodPut,
		admin.URL+"/api/v1/admin/device-corpus/profiles/"+profile.ProfileID, createBody, "")
	readResponse(t, resp)
	if resp.StatusCode != http.StatusPreconditionRequired {
		t.Fatalf("missing If-Match status=%d", resp.StatusCode)
	}
	resp = adminRequest(t, http.DefaultClient, http.MethodPut,
		admin.URL+"/api/v1/admin/device-corpus/profiles/"+profile.ProfileID, createBody, etag)
	readResponse(t, resp)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("stale If-Match status=%d", resp.StatusCode)
	}

	resp = adminRequest(t, http.DefaultClient, http.MethodPost,
		admin.URL+"/api/v1/admin/device-corpus/profiles/"+profile.ProfileID+"/publish",
		`{"reason_code":"publish_reviewed","expected_corpus_revision":0}`, variantETag)
	body = readResponse(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("publish status=%d body=%s", resp.StatusCode, body)
	}

	resp, err := http.Get(public.URL + "/api/v1/device-corpus/snapshot")
	if err != nil {
		t.Fatal(err)
	}
	snapshotBytes := readResponse(t, resp)
	publicETag := resp.Header.Get("ETag")
	if resp.StatusCode != http.StatusOK || publicETag == "" || !bytes.Contains(snapshotBytes, []byte(`"Camera Two"`)) {
		t.Fatalf("snapshot status=%d etag=%q body=%s", resp.StatusCode, publicETag, snapshotBytes)
	}
	req, _ := http.NewRequest(http.MethodGet, public.URL+"/api/v1/device-corpus/snapshot", nil)
	req.Header.Set("If-None-Match", publicETag)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	readResponse(t, resp)
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("snapshot conditional GET status=%d", resp.StatusCode)
	}

	resp = adminRequest(t, http.DefaultClient, http.MethodGet,
		admin.URL+"/api/v1/admin/device-corpus/releases/1", "", "")
	historical := readResponse(t, resp)
	if resp.StatusCode != http.StatusOK || !bytes.Equal(historical, snapshotBytes) || resp.Header.Get("ETag") != publicETag {
		t.Fatalf("historical release status=%d etag=%q body=%s", resp.StatusCode, resp.Header.Get("ETag"), historical)
	}
}

func TestCorpusAdminStrictJSONAndPrivacyErrorsDoNotEcho(t *testing.T) {
	_, _, admin := newCorpusAPIServers(t)
	tests := []struct {
		name, body, secret string
	}{
		{"unknown nested key", `{"labels":{"manufacturer":"Example","model":"Cam","device_type":"camera","source_ip":"192.0.2.9"},"reason_code":"new_profile"}`, "192.0.2.9"},
		{"duplicate nested key", `{"labels":{"manufacturer":"Example","manufacturer":"SECRET-DUPLICATE","model":"Cam","device_type":"camera"},"reason_code":"new_profile"}`, "SECRET-DUPLICATE"},
		{"case-folded duplicate key", `{"labels":{"manufacturer":"Example","model":"Cam","device_type":"camera"},"Labels":{"manufacturer":"SECRET-CASEFOLD","model":"Other","device_type":"camera"},"reason_code":"new_profile"}`, "SECRET-CASEFOLD"},
		{"forbidden label value", `{"labels":{"manufacturer":"Example","model":"Camera 192.0.2.9","device_type":"camera"},"reason_code":"new_profile"}`, "192.0.2.9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := adminRequest(t, http.DefaultClient, http.MethodPost,
				admin.URL+"/api/v1/admin/device-corpus/profiles", tt.body, "")
			body := readResponse(t, resp)
			if resp.StatusCode != http.StatusUnprocessableEntity {
				t.Fatalf("status=%d body=%s", resp.StatusCode, body)
			}
			if bytes.Contains(body, []byte(tt.secret)) {
				t.Fatalf("error reflected submitted content: %s", body)
			}
		})
	}
}
