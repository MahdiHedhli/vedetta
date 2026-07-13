package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/vedetta-network/vedetta/threat-network/internal/adminauth"
	"github.com/vedetta-network/vedetta/threat-network/internal/corpus"
	"github.com/vedetta-network/vedetta/threat-network/internal/store"
)

const maxAdminBodyBytes = 64 << 10

// AdminHandler constructs the management API. Callers must mount this handler
// on the dedicated management listener; Handler never exposes these routes.
func (s *Server) AdminHandler(authenticator *adminauth.Authenticator) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/device-corpus/profiles", s.handleAdminCorpusProfiles)
	mux.HandleFunc("/api/v1/admin/device-corpus/profiles/", s.handleAdminCorpusProfile)
	mux.HandleFunc("/api/v1/admin/device-corpus/variants/", s.handleAdminCorpusVariant)
	mux.HandleFunc("/api/v1/admin/device-corpus/audit", s.handleAdminCorpusAudit)
	mux.HandleFunc("/api/v1/admin/device-corpus/releases", s.handleAdminCorpusReleases)
	mux.HandleFunc("/api/v1/admin/device-corpus/releases/", s.handleAdminCorpusRelease)
	protected := authenticator.Middleware(mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		protected.ServeHTTP(w, r)
	})
}

func (s *Server) handleAdminCorpusProfiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		params, err := parseCorpusPageQuery(r.URL.RawQuery, true)
		if err != nil {
			writeCorpusQueryError(w)
			return
		}
		profiles, err := s.DB.PageCorpusProfiles(params.search, params.limit, params.offset)
		if err != nil {
			writeCorpusAdminError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, profiles)
	case http.MethodPost:
		var req corpus.CreateProfileRequest
		if err := decodeAdminJSON(r, &req); err != nil {
			writeCorpusStrictError(w, err)
			return
		}
		profile, err := s.DB.CreateCorpusProfile(req, corpusMeta(r))
		if err != nil {
			writeCorpusAdminError(w, err)
			return
		}
		writeCorpusProfile(w, http.StatusCreated, profile)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET or POST only")
	}
}

func (s *Server) handleAdminCorpusProfile(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/device-corpus/profiles/")
	parts := splitCorpusPath(path)
	if len(parts) == 0 || len(parts) > 2 {
		http.NotFound(w, r)
		return
	}
	profileID := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			profile, err := s.DB.GetCorpusProfile(profileID)
			if err != nil {
				writeCorpusAdminError(w, err)
				return
			}
			writeCorpusProfile(w, http.StatusOK, profile)
		case http.MethodPut:
			var req corpus.ReviseProfileRequest
			if err := decodeAdminJSON(r, &req); err != nil {
				writeCorpusStrictError(w, err)
				return
			}
			profile, err := s.DB.ReviseCorpusProfile(profileID, req, corpusMeta(r))
			if err != nil {
				writeCorpusAdminError(w, err)
				return
			}
			writeCorpusProfile(w, http.StatusOK, profile)
		default:
			writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET or PUT only")
		}
		return
	}
	if parts[1] == "preview" {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET only")
			return
		}
		if r.URL.RawQuery != "" {
			writeCorpusQueryError(w)
			return
		}
		preview, err := s.DB.PreviewCorpusProfile(profileID, corpusMeta(r))
		if err != nil {
			writeCorpusAdminError(w, err)
			return
		}
		w.Header().Set("ETag", `"`+preview.ETag+`"`)
		writeJSON(w, http.StatusOK, preview)
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST only")
		return
	}
	switch parts[1] {
	case "variants":
		var req corpus.CreateVariantRequest
		if err := decodeAdminJSON(r, &req); err != nil {
			writeCorpusStrictError(w, err)
			return
		}
		profile, err := s.DB.CreateCorpusVariant(profileID, req, corpusMeta(r))
		if err != nil {
			writeCorpusAdminError(w, err)
			return
		}
		writeCorpusProfile(w, http.StatusCreated, profile)
	case "publish":
		var req corpus.PublishRequest
		if err := decodeAdminJSON(r, &req); err != nil {
			writeCorpusStrictError(w, err)
			return
		}
		profile, err := s.DB.PublishCorpusProfile(profileID, req, corpusMeta(r))
		if err != nil {
			writeCorpusAdminError(w, err)
			return
		}
		writeCorpusProfile(w, http.StatusOK, profile)
	case "retire":
		var req corpus.LifecycleRequest
		if err := decodeAdminJSON(r, &req); err != nil {
			writeCorpusStrictError(w, err)
			return
		}
		profile, err := s.DB.RetireCorpusProfile(profileID, req, corpusMeta(r))
		if err != nil {
			writeCorpusAdminError(w, err)
			return
		}
		writeCorpusProfile(w, http.StatusOK, profile)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleAdminCorpusVariant(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/device-corpus/variants/")
	parts := splitCorpusPath(path)
	if len(parts) == 0 || len(parts) > 2 {
		http.NotFound(w, r)
		return
	}
	variantID := parts[0]
	if len(parts) == 1 {
		if r.Method != http.MethodPut {
			writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "PUT only")
			return
		}
		var req corpus.ReviseVariantRequest
		if err := decodeAdminJSON(r, &req); err != nil {
			writeCorpusStrictError(w, err)
			return
		}
		profile, err := s.DB.ReviseCorpusVariant(variantID, req, corpusMeta(r))
		if err != nil {
			writeCorpusAdminError(w, err)
			return
		}
		writeCorpusProfile(w, http.StatusOK, profile)
		return
	}
	if parts[1] != "withdraw" && parts[1] != "discard-draft" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST only")
		return
	}
	var req corpus.LifecycleRequest
	if err := decodeAdminJSON(r, &req); err != nil {
		writeCorpusStrictError(w, err)
		return
	}
	var profile *corpus.Profile
	var err error
	if parts[1] == "discard-draft" {
		profile, err = s.DB.DiscardCorpusVariantDraft(variantID, req, corpusMeta(r))
	} else {
		profile, err = s.DB.WithdrawCorpusVariant(variantID, req, corpusMeta(r))
	}
	if err != nil {
		writeCorpusAdminError(w, err)
		return
	}
	writeCorpusProfile(w, http.StatusOK, profile)
}

func (s *Server) handleAdminCorpusAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET only")
		return
	}
	params, err := parseCorpusPageQuery(r.URL.RawQuery, false)
	if err != nil {
		writeCorpusQueryError(w)
		return
	}
	entries, err := s.DB.PageCorpusAudit(params.limit, params.offset)
	if err != nil {
		writeCorpusAdminError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

func (s *Server) handleAdminCorpusReleases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET only")
		return
	}
	params, err := parseCorpusPageQuery(r.URL.RawQuery, false)
	if err != nil {
		writeCorpusQueryError(w)
		return
	}
	releases, err := s.DB.PageCorpusReleases(params.limit, params.offset)
	if err != nil {
		writeCorpusAdminError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, releases)
}

func (s *Server) handleAdminCorpusRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET only")
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/admin/device-corpus/releases/"), "/")
	if path == "" || strings.Contains(path, "/") {
		http.NotFound(w, r)
		return
	}
	revision, err := strconv.Atoi(path)
	if err != nil || revision < 1 {
		writeErr(w, http.StatusBadRequest, "INVALID_REVISION", "positive corpus revision required")
		return
	}
	data, release, err := s.DB.GetCorpusRelease(revision)
	if err != nil {
		writeCorpusAdminError(w, err)
		return
	}
	w.Header().Set("ETag", `"`+release.SnapshotSHA256+`"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func splitCorpusPath(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil
	}
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil
		}
	}
	return parts
}

func corpusMeta(r *http.Request) store.CorpusMutation {
	// Do not persist caller-supplied request/correlation identifiers: even on the
	// management plane they can encode a username, host, site, or ticket ID.
	return store.CorpusMutation{Actor: "admin", ExpectedETag: r.Header.Get("If-Match")}
}

func writeCorpusProfile(w http.ResponseWriter, status int, profile *corpus.Profile) {
	w.Header().Set("ETag", `"`+profile.ETag+`"`)
	writeJSON(w, status, profile)
}

type corpusPageQuery struct {
	limit  int
	offset int
	search string
}

func parseCorpusPageQuery(rawQuery string, allowSearch bool) (corpusPageQuery, error) {
	params := corpusPageQuery{limit: 50}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return params, err
	}
	for key, entries := range values {
		if (key != "limit" && key != "offset" && key != "search") || (key == "search" && !allowSearch) {
			return params, fmt.Errorf("unsupported query parameter")
		}
		if len(entries) != 1 {
			return params, fmt.Errorf("duplicate query parameter")
		}
	}
	if raw, ok := singleCorpusQueryValue(values, "limit"); ok {
		params.limit, err = strconv.Atoi(raw)
		if err != nil || params.limit < 1 || params.limit > 100 {
			return params, fmt.Errorf("invalid limit")
		}
	}
	if raw, ok := singleCorpusQueryValue(values, "offset"); ok {
		params.offset, err = strconv.Atoi(raw)
		if err != nil || params.offset < 0 {
			return params, fmt.Errorf("invalid offset")
		}
	}
	if raw, ok := singleCorpusQueryValue(values, "search"); ok {
		params.search = strings.TrimSpace(raw)
		if len(params.search) > 128 || strings.ContainsAny(params.search, "\r\n\x00") {
			return params, fmt.Errorf("invalid search")
		}
	}
	return params, nil
}

func singleCorpusQueryValue(values url.Values, key string) (string, bool) {
	entries, ok := values[key]
	if !ok || len(entries) != 1 {
		return "", false
	}
	return entries[0], true
}

func writeCorpusQueryError(w http.ResponseWriter) {
	writeErr(w, http.StatusBadRequest, "INVALID_QUERY", "invalid device corpus list query")
}

func decodeAdminJSON(r *http.Request, dst any) error {
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil || !strings.EqualFold(mediaType, "application/json") {
			return fmt.Errorf("Content-Type must be application/json")
		}
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxAdminBodyBytes+1))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if len(data) > maxAdminBodyBytes {
		return fmt.Errorf("body exceeds 64 KiB")
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return fmt.Errorf("JSON body required")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON schema: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("body must contain one JSON value")
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := walkJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("body must contain one JSON value")
		}
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := []string{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("invalid JSON: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("invalid JSON object key")
			}
			for _, prior := range seen {
				// encoding/json matches struct fields case-insensitively. Apply
				// the same semantic duplicate rule before decoding so `labels`
				// and `Labels` cannot become a last-value-wins bypass.
				if strings.EqualFold(prior, key) {
					return fmt.Errorf("duplicate JSON key")
				}
			}
			seen = append(seen, key)
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
			return fmt.Errorf("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		if token, err = decoder.Token(); err != nil || token != json.Delim(']') {
			return fmt.Errorf("invalid JSON array")
		}
	default:
		return fmt.Errorf("invalid JSON delimiter")
	}
	return nil
}

func writeCorpusStrictError(w http.ResponseWriter, _ error) {
	writeErr(w, http.StatusUnprocessableEntity, "STRICT_SCHEMA", "request does not match the device corpus schema")
}

func writeCorpusAdminError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrCorpusNotFound):
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "device corpus entity not found")
	case errors.Is(err, store.ErrCorpusPrecondition):
		writeErr(w, http.StatusPreconditionRequired, "IF_MATCH_REQUIRED", "current profile ETag is required")
	case errors.Is(err, store.ErrCorpusConflict):
		writeErr(w, http.StatusConflict, "EDIT_CONFLICT", "profile changed; reload and retry")
	case errors.Is(err, store.ErrCorpusRevisionConflict):
		writeErr(w, http.StatusConflict, "CORPUS_ADVANCED", "public corpus changed; generate a fresh preview")
	case errors.Is(err, store.ErrCorpusNoChanges):
		writeErr(w, http.StatusConflict, "NO_DRAFT_CHANGES", "no draft changes to publish")
	case errors.Is(err, store.ErrCorpusHasDependents):
		writeErr(w, http.StatusConflict, "ACTIVE_DESCENDANTS", "withdraw dependent variants first")
	case isCorpusPrivacyError(err):
		writeErr(w, http.StatusUnprocessableEntity, "FORBIDDEN_CONTENT", "content violates the device corpus privacy allowlist")
	default:
		if isCorpusValidationError(err) {
			writeErr(w, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "device corpus content failed validation")
			return
		}
		writeErr(w, http.StatusInternalServerError, "INTERNAL", "device corpus operation failed")
	}
}

func isCorpusPrivacyError(err error) bool {
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{"prohibited", "privacy", "ip address", "cidr", "public dns name", "url syntax"} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

func isCorpusValidationError(err error) bool {
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{"must ", "unsupported ", "requires ", "exceeds ", "contains ", "belongs to another"} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}
