package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/vedetta-network/vedetta/threat-network/internal/corpus"
	"github.com/vedetta-network/vedetta/threat-network/internal/store"
)

func TestCorpusAdminListPaginationAndQueryValidation(t *testing.T) {
	s, _, admin := newCorpusAPIServers(t)
	for _, model := range []string{"HTTP Paging Alpha", "HTTP Paging Beta"} {
		_, err := s.DB.CreateCorpusProfile(context.Background(), corpus.CreateProfileRequest{Labels: corpus.ProfileLabels{
			Manufacturer: "Example Devices", Model: model, ProductFamily: "Paging",
			DeviceType: "camera", OSFamily: "embedded",
		}, ReasonCode: "new_profile"}, store.CorpusMutation{})
		if err != nil {
			t.Fatal(err)
		}
	}

	resp := adminRequest(t, http.DefaultClient, http.MethodGet,
		admin.URL+"/api/v1/admin/device-corpus/profiles?search=HTTP+Paging&limit=1&offset=1", "", "")
	body := readResponse(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("profile page status=%d body=%s", resp.StatusCode, body)
	}
	var page struct {
		Items  []corpus.ProfileSummary `json:"items"`
		Total  int                     `json:"total"`
		Limit  int                     `json:"limit"`
		Offset int                     `json:"offset"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || page.Limit != 1 || page.Offset != 1 || len(page.Items) != 1 {
		t.Fatalf("unexpected profile page: %+v", page)
	}

	for _, query := range []string{
		"?limit=0", "?limit=101", "?offset=-1", "?limit=1&limit=2", "?unknown=1", "?limit=not-a-number",
	} {
		resp = adminRequest(t, http.DefaultClient, http.MethodGet,
			admin.URL+"/api/v1/admin/device-corpus/profiles"+query, "", "")
		body = readResponse(t, resp)
		if resp.StatusCode != http.StatusBadRequest || !bytes.Contains(body, []byte(`"code":"INVALID_QUERY"`)) {
			t.Fatalf("query %q status=%d body=%s", query, resp.StatusCode, body)
		}
	}
	resp = adminRequest(t, http.DefaultClient, http.MethodGet,
		admin.URL+"/api/v1/admin/device-corpus/audit?search=forbidden", "", "")
	readResponse(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("audit accepted profile-only search: %d", resp.StatusCode)
	}
	resp = adminRequest(t, http.DefaultClient, http.MethodGet,
		admin.URL+"/api/v1/admin/device-corpus/releases?limit=50&offset=0", "", "")
	body = readResponse(t, resp)
	if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"items":[]`)) || !bytes.Contains(body, []byte(`"total":0`)) {
		t.Fatalf("release page status=%d body=%s", resp.StatusCode, body)
	}
}

func TestCorpusAdminPreviewRequiresCurrentETag(t *testing.T) {
	s, _, admin := newCorpusAPIServers(t)
	profile, err := s.DB.CreateCorpusProfile(context.Background(), corpus.CreateProfileRequest{Labels: corpus.ProfileLabels{
		Manufacturer: "Example Devices", Model: "API Preview Camera", ProductFamily: "Preview",
		DeviceType: "camera", OSFamily: "embedded",
	}, ReasonCode: "new_profile"}, store.CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}
	profile, err = s.DB.CreateCorpusVariant(context.Background(), profile.ProfileID, corpus.CreateVariantRequest{
		VariantKey: "api-preview", ConfidenceBP: 9200,
		Shape: corpus.CanonicalShapeV1{MDNSModels: []string{"API Preview Camera"}},
		Sources: []corpus.Source{{SourceRef: "vendor", Kind: "vendor_doc",
			Title: "API Preview Support", PublicURL: "https://docs.example.com/api-preview"}},
		ReasonCode: "new_variant",
	}, store.CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	target := admin.URL + "/api/v1/admin/device-corpus/profiles/" + profile.ProfileID + "/preview"

	resp := adminRequest(t, http.DefaultClient, http.MethodGet, target, "", "")
	readResponse(t, resp)
	if resp.StatusCode != http.StatusPreconditionRequired {
		t.Fatalf("preview without If-Match status=%d", resp.StatusCode)
	}
	resp = adminRequest(t, http.DefaultClient, http.MethodGet, target, "", `"`+profile.ETag+`"`)
	body := readResponse(t, resp)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("ETag") != `"`+profile.ETag+`"` {
		t.Fatalf("preview status=%d etag=%q body=%s", resp.StatusCode, resp.Header.Get("ETag"), body)
	}
	var preview store.CorpusPreview
	if err = json.Unmarshal(body, &preview); err != nil {
		t.Fatal(err)
	}
	if preview.ETag != profile.ETag || preview.CurrentCorpusRevision != 0 || preview.ProposedCorpusRevision != 1 || len(preview.Snapshot.Profiles) != 1 {
		t.Fatalf("unexpected preview: %+v", preview)
	}
	resp = adminRequest(t, http.DefaultClient, http.MethodGet, target+"?unexpected=1", "", profile.ETag)
	readResponse(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("preview accepted query parameters: %d", resp.StatusCode)
	}
	publishTarget := admin.URL + "/api/v1/admin/device-corpus/profiles/" + profile.ProfileID + "/publish"
	resp = adminRequest(t, http.DefaultClient, http.MethodPost, publishTarget,
		`{"reason_code":"publish_reviewed"}`, profile.ETag)
	body = readResponse(t, resp)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("publish without corpus precondition status=%d body=%s", resp.StatusCode, body)
	}
	resp = adminRequest(t, http.DefaultClient, http.MethodPost, publishTarget,
		`{"reason_code":"new_variant","expected_corpus_revision":0}`, profile.ETag)
	body = readResponse(t, resp)
	if resp.StatusCode != http.StatusUnprocessableEntity ||
		!bytes.Contains(body, []byte(`"code":"VALIDATION_FAILED"`)) {
		t.Fatalf("publish with misleading reason status=%d body=%s", resp.StatusCode, body)
	}
	resp = adminRequest(t, http.DefaultClient, http.MethodPost, publishTarget,
		`{"reason_code":"publish_reviewed","expected_corpus_revision":1}`, profile.ETag)
	body = readResponse(t, resp)
	if resp.StatusCode != http.StatusConflict || !bytes.Contains(body, []byte(`"code":"CORPUS_ADVANCED"`)) {
		t.Fatalf("stale corpus revision status=%d body=%s", resp.StatusCode, body)
	}

	// Retire and full withdrawal can create complete public releases too, so
	// they require the same reviewed global revision as publish. Draft discard
	// remains a local edit and intentionally retains its original request body.
	variantID := profile.Variants[0].VariantID
	for _, tt := range []struct {
		name, target, body string
		status             int
		code               string
	}{
		{"retire missing revision", admin.URL + "/api/v1/admin/device-corpus/profiles/" + profile.ProfileID + "/retire", `{"reason_code":"obsolete_product"}`, http.StatusUnprocessableEntity, `"code":"VALIDATION_FAILED"`},
		{"retire negative revision", admin.URL + "/api/v1/admin/device-corpus/profiles/" + profile.ProfileID + "/retire", `{"reason_code":"obsolete_product","expected_corpus_revision":-1}`, http.StatusUnprocessableEntity, `"code":"VALIDATION_FAILED"`},
		{"retire stale revision", admin.URL + "/api/v1/admin/device-corpus/profiles/" + profile.ProfileID + "/retire", `{"reason_code":"obsolete_product","expected_corpus_revision":1}`, http.StatusConflict, `"code":"CORPUS_ADVANCED"`},
		{"retire unrelated reason", admin.URL + "/api/v1/admin/device-corpus/profiles/" + profile.ProfileID + "/retire", `{"reason_code":"source_update","expected_corpus_revision":0}`, http.StatusUnprocessableEntity, `"code":"VALIDATION_FAILED"`},
		{"withdraw missing revision", admin.URL + "/api/v1/admin/device-corpus/variants/" + variantID + "/withdraw", `{"reason_code":"privacy_withdrawal"}`, http.StatusUnprocessableEntity, `"code":"VALIDATION_FAILED"`},
		{"withdraw negative revision", admin.URL + "/api/v1/admin/device-corpus/variants/" + variantID + "/withdraw", `{"reason_code":"privacy_withdrawal","expected_corpus_revision":-1}`, http.StatusUnprocessableEntity, `"code":"VALIDATION_FAILED"`},
		{"withdraw stale revision", admin.URL + "/api/v1/admin/device-corpus/variants/" + variantID + "/withdraw", `{"reason_code":"privacy_withdrawal","expected_corpus_revision":1}`, http.StatusConflict, `"code":"CORPUS_ADVANCED"`},
		{"withdraw unrelated reason", admin.URL + "/api/v1/admin/device-corpus/variants/" + variantID + "/withdraw", `{"reason_code":"new_variant","expected_corpus_revision":0}`, http.StatusUnprocessableEntity, `"code":"VALIDATION_FAILED"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			response := adminRequest(t, http.DefaultClient, http.MethodPost, tt.target, tt.body, profile.ETag)
			responseBody := readResponse(t, response)
			if response.StatusCode != tt.status || !bytes.Contains(responseBody, []byte(tt.code)) {
				t.Fatalf("status=%d body=%s, want status=%d code=%s", response.StatusCode, responseBody, tt.status, tt.code)
			}
		})
	}

	discardTarget := admin.URL + "/api/v1/admin/device-corpus/variants/" + variantID + "/discard-draft"
	resp = adminRequest(t, http.DefaultClient, http.MethodPost, discardTarget,
		`{"reason_code":"new_profile"}`, profile.ETag)
	body = readResponse(t, resp)
	if resp.StatusCode != http.StatusUnprocessableEntity ||
		!bytes.Contains(body, []byte(`"code":"VALIDATION_FAILED"`)) {
		t.Fatalf("discard-draft misleading reason status=%d body=%s", resp.StatusCode, body)
	}
	unchanged, err := s.DB.GetCorpusProfile(context.Background(), profile.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.ETag != profile.ETag || unchanged.Variants[0].Draft == nil {
		t.Fatalf("discard-draft misleading reason mutated profile: %+v", unchanged)
	}
	resp = adminRequest(t, http.DefaultClient, http.MethodPost, discardTarget,
		`{"reason_code":"signal_correction"}`, profile.ETag)
	body = readResponse(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discard-draft old body status=%d body=%s", resp.StatusCode, body)
	}
}

func TestCorpusAdminContentTypeAndErrorsAreNonReflective(t *testing.T) {
	_, _, admin := newCorpusAPIServers(t)
	target := admin.URL + "/api/v1/admin/device-corpus/profiles"
	body := `{"labels":{"manufacturer":"Example","model":"Cam","device_type":"camera"},"reason_code":"new_profile"}`
	for _, contentType := range []string{"", "application/jsonp"} {
		req, err := http.NewRequest(http.MethodPost, target, bytes.NewBufferString(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+testAdminToken)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		responseBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusUnprocessableEntity || !bytes.Contains(responseBody, []byte(`"code":"STRICT_SCHEMA"`)) {
			t.Fatalf("content type %q status=%d body=%s", contentType, resp.StatusCode, responseBody)
		}
	}

	reflective := `{"labels":{"manufacturer":"Example","model":"Cam","device_type":"SECRET-UNSUPPORTED-TYPE"},"reason_code":"new_profile"}`
	resp := adminRequest(t, http.DefaultClient, http.MethodPost, target, reflective, "")
	responseBody := readResponse(t, resp)
	if resp.StatusCode != http.StatusUnprocessableEntity || bytes.Contains(responseBody, []byte("SECRET-UNSUPPORTED-TYPE")) {
		t.Fatalf("validation error reflected candidate status=%d body=%s", resp.StatusCode, responseBody)
	}
}
