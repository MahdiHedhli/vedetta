package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

func TestCorpusAdminMethodNotAllowedAdvertisesAllowedMethods(t *testing.T) {
	_, _, admin := newCorpusAPIServers(t)
	tests := []struct {
		path   string
		method string
		allow  string
	}{
		{path: "/api/v1/admin/device-corpus/profiles", method: http.MethodDelete, allow: "GET, POST"},
		{path: "/api/v1/admin/device-corpus/profiles/profile_1", method: http.MethodPost, allow: "GET, PUT"},
		{path: "/api/v1/admin/device-corpus/profiles/profile_1/preview", method: http.MethodPost, allow: "GET"},
		{path: "/api/v1/admin/device-corpus/profiles/profile_1/variants", method: http.MethodGet, allow: "POST"},
		{path: "/api/v1/admin/device-corpus/variants/variant_1", method: http.MethodGet, allow: "PUT"},
		{path: "/api/v1/admin/device-corpus/variants/variant_1/withdraw", method: http.MethodGet, allow: "POST"},
		{path: "/api/v1/admin/device-corpus/audit", method: http.MethodPost, allow: "GET"},
		{path: "/api/v1/admin/device-corpus/releases", method: http.MethodPost, allow: "GET"},
		{path: "/api/v1/admin/device-corpus/releases/1", method: http.MethodPost, allow: "GET"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			resp := adminRequest(t, http.DefaultClient, tt.method, admin.URL+tt.path, "", "")
			readResponse(t, resp)
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want 405", resp.StatusCode)
			}
			if got := resp.Header.Get("Allow"); got != tt.allow {
				t.Fatalf("Allow = %q, want %q", got, tt.allow)
			}
		})
	}
}

func TestCorpusProfileReasonScopeRejectsMisleadingAPIRequests(t *testing.T) {
	s, _, admin := newCorpusAPIServers(t)
	badCreate := `{"labels":{"manufacturer":"Example Devices","model":"Misleading Camera","device_type":"camera"},"reason_code":"source_update"}`
	resp := adminRequest(t, http.DefaultClient, http.MethodPost,
		admin.URL+"/api/v1/admin/device-corpus/profiles", badCreate, "")
	body := readResponse(t, resp)
	if resp.StatusCode != http.StatusUnprocessableEntity ||
		!bytes.Contains(body, []byte(`"code":"VALIDATION_FAILED"`)) {
		t.Fatalf("misleading create reason status=%d body=%s", resp.StatusCode, body)
	}
	page, err := s.DB.PageCorpusProfiles(context.Background(), "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 0 {
		t.Fatalf("misleading create reason persisted a profile: %+v", page)
	}

	goodCreate := `{"labels":{"manufacturer":"Example Devices","model":"Scoped Camera","device_type":"camera"},"reason_code":"new_profile"}`
	resp = adminRequest(t, http.DefaultClient, http.MethodPost,
		admin.URL+"/api/v1/admin/device-corpus/profiles", goodCreate, "")
	body = readResponse(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("valid create status=%d body=%s", resp.StatusCode, body)
	}
	var profile corpus.Profile
	if err = json.Unmarshal(body, &profile); err != nil {
		t.Fatal(err)
	}
	etag := resp.Header.Get("ETag")
	badRevise := `{"labels":{"manufacturer":"Example Devices","model":"Wrong Audit Camera","device_type":"camera"},"reason_code":"publish_reviewed"}`
	resp = adminRequest(t, http.DefaultClient, http.MethodPut,
		admin.URL+"/api/v1/admin/device-corpus/profiles/"+profile.ProfileID, badRevise, etag)
	body = readResponse(t, resp)
	if resp.StatusCode != http.StatusUnprocessableEntity ||
		!bytes.Contains(body, []byte(`"code":"VALIDATION_FAILED"`)) {
		t.Fatalf("misleading revise reason status=%d body=%s", resp.StatusCode, body)
	}
	unchanged, err := s.DB.GetCorpusProfile(context.Background(), profile.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.ETag != profile.ETag || unchanged.Draft == nil || unchanged.Draft.Labels.Model != "Scoped Camera" ||
		len(unchanged.History) != 1 {
		t.Fatalf("misleading revise reason mutated profile: %+v", unchanged)
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
	reviseBody := `{"labels":{"manufacturer":"Example Devices","model":"Camera Two","device_type":"camera","os_family":"embedded"},"reason_code":"label_correction"}`
	resp = adminRequest(t, http.DefaultClient, http.MethodPut,
		admin.URL+"/api/v1/admin/device-corpus/profiles/"+profile.ProfileID, reviseBody, "")
	readResponse(t, resp)
	if resp.StatusCode != http.StatusPreconditionRequired {
		t.Fatalf("missing If-Match status=%d", resp.StatusCode)
	}
	resp = adminRequest(t, http.DefaultClient, http.MethodPut,
		admin.URL+"/api/v1/admin/device-corpus/profiles/"+profile.ProfileID, reviseBody, etag)
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
		name, body, secret, code string
	}{
		{"unknown nested key", `{"labels":{"manufacturer":"Example","model":"Cam","device_type":"camera","source_ip":"192.0.2.9"},"reason_code":"new_profile"}`, "192.0.2.9", "STRICT_SCHEMA"},
		{"duplicate nested key", `{"labels":{"manufacturer":"Example","manufacturer":"SECRET-DUPLICATE","model":"Cam","device_type":"camera"},"reason_code":"new_profile"}`, "SECRET-DUPLICATE", "STRICT_SCHEMA"},
		{"case-folded duplicate key", `{"labels":{"manufacturer":"Example","model":"Cam","device_type":"camera"},"Labels":{"manufacturer":"SECRET-CASEFOLD","model":"Other","device_type":"camera"},"reason_code":"new_profile"}`, "SECRET-CASEFOLD", "STRICT_SCHEMA"},
		{"forbidden label value", `{"labels":{"manufacturer":"Example","model":"Camera 192.0.2.9","device_type":"camera"},"reason_code":"new_profile"}`, "192.0.2.9", "FORBIDDEN_CONTENT"},
		{"compact date encoding an IPv4 value", `{"labels":{"manufacturer":"Example","model":"Camera 20260713","device_type":"camera"},"reason_code":"new_profile"}`, "20260713", "FORBIDDEN_CONTENT"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := adminRequest(t, http.DefaultClient, http.MethodPost,
				admin.URL+"/api/v1/admin/device-corpus/profiles", tt.body, "")
			body := readResponse(t, resp)
			if resp.StatusCode != http.StatusUnprocessableEntity ||
				!bytes.Contains(body, []byte(`"code":"`+tt.code+`"`)) {
				t.Fatalf("status=%d body=%s", resp.StatusCode, body)
			}
			if bytes.Contains(body, []byte(tt.secret)) {
				t.Fatalf("error reflected submitted content: %s", body)
			}
		})
	}
}

func TestCorpusAdminRequiresExplicitVariantConfidence(t *testing.T) {
	s, _, admin := newCorpusAPIServers(t)
	profile, err := s.DB.CreateCorpusProfile(context.Background(), corpus.CreateProfileRequest{
		Labels: corpus.ProfileLabels{
			Manufacturer: "Example Devices", Model: "Confidence Camera", DeviceType: "camera",
		},
		ReasonCode: "new_profile",
	}, store.CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}
	createTarget := admin.URL + "/api/v1/admin/device-corpus/profiles/" + profile.ProfileID + "/variants"
	validShape := `"shape":{"schema_version":1,"mdns_models":["Confidence Camera"]}`
	validSource := `"sources":[{"source_ref":"vendor","kind":"vendor_doc","title":"Confidence Camera Support","public_url":"https://docs.example.com/confidence-camera"}]`

	assertValidation := func(method, target, body, etag string) {
		t.Helper()
		resp := adminRequest(t, http.DefaultClient, method, target, body, etag)
		responseBody := readResponse(t, resp)
		if resp.StatusCode != http.StatusUnprocessableEntity ||
			!bytes.Contains(responseBody, []byte(`"code":"VALIDATION_FAILED"`)) {
			t.Fatalf("status=%d body=%s", resp.StatusCode, responseBody)
		}
	}

	for _, tt := range []struct {
		name string
		body string
	}{
		{
			name: "missing variant confidence",
			body: `{"variant_key":"missing-confidence",` + validShape + `,` + validSource + `,"reason_code":"new_variant"}`,
		},
		{
			name: "null variant confidence",
			body: `{"variant_key":"null-confidence","confidence_bp":null,` + validShape + `,` + validSource + `,"reason_code":"new_variant"}`,
		},
		{
			name: "missing version fact confidence",
			body: `{"variant_key":"missing-fact-confidence","confidence_bp":0,` + validShape + `,` + validSource + `,"version_facts":[{"attribute":"firmware_version","relation":"exact","value":"1.0","source_ref":"vendor"}],"reason_code":"new_variant"}`,
		},
		{
			name: "null version fact confidence",
			body: `{"variant_key":"null-fact-confidence","confidence_bp":0,` + validShape + `,` + validSource + `,"version_facts":[{"attribute":"firmware_version","relation":"exact","value":"1.0","confidence_bp":null,"source_ref":"vendor"}],"reason_code":"new_variant"}`,
		},
	} {
		t.Run("create "+tt.name, func(t *testing.T) {
			assertValidation(http.MethodPost, createTarget, tt.body, profile.ETag)
			current, getErr := s.DB.GetCorpusProfile(context.Background(), profile.ProfileID)
			if getErr != nil {
				t.Fatal(getErr)
			}
			if current.ETag != profile.ETag || len(current.Variants) != 0 {
				t.Fatalf("invalid create mutated profile: %+v", current)
			}
		})
	}

	explicitZero := `{"variant_key":"explicit-zero","confidence_bp":0,` + validShape + `,` + validSource + `,"reason_code":"new_variant"}`
	resp := adminRequest(t, http.DefaultClient, http.MethodPost, createTarget, explicitZero, profile.ETag)
	body := readResponse(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("explicit zero create status=%d body=%s", resp.StatusCode, body)
	}
	if err = json.Unmarshal(body, &profile); err != nil {
		t.Fatal(err)
	}
	if len(profile.Variants) != 1 || profile.Variants[0].Draft == nil || profile.Variants[0].Draft.ConfidenceBP != 0 {
		t.Fatalf("explicit zero confidence was not preserved: %+v", profile)
	}

	reviseTarget := admin.URL + "/api/v1/admin/device-corpus/variants/" + profile.Variants[0].VariantID
	for _, tt := range []struct {
		name string
		body string
	}{
		{
			name: "missing variant confidence",
			body: `{` + validShape + `,` + validSource + `,"reason_code":"signal_correction"}`,
		},
		{
			name: "missing version fact confidence",
			body: `{"confidence_bp":0,` + validShape + `,` + validSource + `,"version_facts":[{"attribute":"firmware_version","relation":"exact","value":"1.1","source_ref":"vendor"}],"reason_code":"signal_correction"}`,
		},
		{
			name: "null variant confidence",
			body: `{"confidence_bp":null,` + validShape + `,` + validSource + `,"reason_code":"signal_correction"}`,
		},
		{
			name: "null version fact confidence",
			body: `{"confidence_bp":0,` + validShape + `,` + validSource + `,"version_facts":[{"attribute":"firmware_version","relation":"exact","value":"1.1","confidence_bp":null,"source_ref":"vendor"}],"reason_code":"signal_correction"}`,
		},
	} {
		t.Run("revise "+tt.name, func(t *testing.T) {
			assertValidation(http.MethodPut, reviseTarget, tt.body, profile.ETag)
			current, getErr := s.DB.GetCorpusProfile(context.Background(), profile.ProfileID)
			if getErr != nil {
				t.Fatal(getErr)
			}
			if current.ETag != profile.ETag || len(current.Variants) != 1 || current.Variants[0].Draft.ConfidenceBP != 0 {
				t.Fatalf("invalid revision mutated profile: %+v", current)
			}
		})
	}

	explicitZeroRevision := `{"confidence_bp":0,` + validShape + `,` + validSource + `,"version_facts":[{"attribute":"firmware_version","relation":"exact","value":"1.1","confidence_bp":0,"source_ref":"vendor"}],"reason_code":"signal_correction"}`
	resp = adminRequest(t, http.DefaultClient, http.MethodPut, reviseTarget, explicitZeroRevision, profile.ETag)
	body = readResponse(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("explicit zero revision status=%d body=%s", resp.StatusCode, body)
	}
	if err = json.Unmarshal(body, &profile); err != nil {
		t.Fatal(err)
	}
	if profile.Variants[0].Draft == nil || profile.Variants[0].Draft.ConfidenceBP != 0 ||
		len(profile.Variants[0].Draft.VersionFacts) != 1 || profile.Variants[0].Draft.VersionFacts[0].ConfidenceBP != 0 {
		t.Fatalf("explicit zero revision confidence was not preserved: %+v", profile.Variants[0].Draft)
	}
}

func TestCorpusAdminRejectsVersionSuffixIdentifierWithoutEcho(t *testing.T) {
	_, _, admin := newCorpusAPIServers(t)
	createBody := `{"labels":{"manufacturer":"Example","model":"Suffix Test Camera","device_type":"camera","os_family":"embedded"},"reason_code":"new_profile"}`
	resp := adminRequest(t, http.DefaultClient, http.MethodPost,
		admin.URL+"/api/v1/admin/device-corpus/profiles", createBody, "")
	body := readResponse(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", resp.StatusCode, body)
	}
	var profile corpus.Profile
	if err := json.Unmarshal(body, &profile); err != nil {
		t.Fatal(err)
	}

	const marker = "192.168.1.1"
	variantBody := `{
      "variant_key":"suffix-test","confidence_bp":9000,"reason_code":"new_variant",
      "shape":{"schema_version":1,"oui_prefixes":["00:00:5e"]},
      "sources":[{"source_ref":"vendor","kind":"vendor_doc","public_url":"https://docs.example.com/camera"}],
      "version_facts":[{"attribute":"firmware_version","relation":"exact","value":"v1.2-192.168.1.1","confidence_bp":9000,"source_ref":"vendor"}]
    }`
	resp = adminRequest(t, http.DefaultClient, http.MethodPost,
		admin.URL+"/api/v1/admin/device-corpus/profiles/"+profile.ProfileID+"/variants",
		variantBody, resp.Header.Get("ETag"))
	body = readResponse(t, resp)
	if resp.StatusCode != http.StatusUnprocessableEntity ||
		!bytes.Contains(body, []byte(`"code":"FORBIDDEN_CONTENT"`)) ||
		bytes.Contains(body, []byte(marker)) {
		t.Fatalf("suffix privacy status=%d body=%s", resp.StatusCode, body)
	}
}

func TestCorpusAdminErrorClassificationUsesTypesNotMessageText(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code string
	}{
		{
			name: "privacy type",
			err:  &corpus.CorpusPrivacyError{Path: "profiles[0].labels", Rule: "network_identifier"},
			code: "FORBIDDEN_CONTENT",
		},
		{
			name: "validation sentinel through wrapping",
			err:  fmt.Errorf("different wording: %w", store.ErrCorpusValidation),
			code: "VALIDATION_FAILED",
		},
		{
			name: "internal error containing former marker words",
			err:  errors.New("database row contains prohibited value and must be repaired"),
			code: "INTERNAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			writeCorpusAdminError(recorder, tt.err)
			if recorder.Code == http.StatusOK ||
				!bytes.Contains(recorder.Body.Bytes(), []byte(`"code":"`+tt.code+`"`)) {
				t.Fatalf("status=%d body=%s, want code %s", recorder.Code, recorder.Body.Bytes(), tt.code)
			}
		})
	}
}
