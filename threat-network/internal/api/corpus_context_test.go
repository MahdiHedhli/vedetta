package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCanceledAdminCorpusRequestDoesNotMutate(t *testing.T) {
	s, _, _ := newCorpusAPIServers(t)
	body := `{"labels":{"manufacturer":"Example Devices","model":"Canceled Camera","product_family":"Vision","device_type":"camera","os_family":"embedded"},"reason_code":"new_profile"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/device-corpus/profiles", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(ctx)

	recorder := httptest.NewRecorder()
	s.handleAdminCorpusProfiles(recorder, req)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("canceled admin request status = %d, want %d", recorder.Code, http.StatusInternalServerError)
	}

	var profiles, audits int
	if err := s.DB.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM device_corpus_profiles`).Scan(&profiles); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM device_corpus_audit`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if profiles != 0 || audits != 0 {
		t.Fatalf("canceled request persisted profiles=%d audits=%d", profiles, audits)
	}
}
