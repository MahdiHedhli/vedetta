// Package corpus defines the privacy-reduced device corpus contract. It is a
// curated content plane and deliberately has no dependency on telemetry ingest.
package corpus

import "time"

const SchemaVersion = 1

// CanonicalShapeV1 is the complete allowlist for a centrally stored fingerprint.
// There is intentionally no extension map: adding a signal requires a schema change.
type CanonicalShapeV1 struct {
	SchemaVersion int `json:"schema_version"`
	// uint16 is intentional: encoding/json treats []uint8 as binary/base64,
	// while the wire contract requires a JSON array of DHCP option numbers.
	DHCPOption55      []uint16 `json:"dhcp_option_55,omitempty"`
	DHCPVendorClasses []string `json:"dhcp_vendor_classes,omitempty"`
	OUIPrefixes       []string `json:"oui_prefixes,omitempty"`
	HostnameTemplates []string `json:"hostname_templates,omitempty"`
	MDNSServices      []string `json:"mdns_services,omitempty"`
	MDNSModels        []string `json:"mdns_models,omitempty"`
	MDNSVendors       []string `json:"mdns_vendors,omitempty"`
	SSDPDeviceTypes   []string `json:"ssdp_device_types,omitempty"`
	SSDPServerTokens  []string `json:"ssdp_server_tokens,omitempty"`
	TCPPorts          []uint16 `json:"tcp_ports,omitempty"`
	UDPPorts          []uint16 `json:"udp_ports,omitempty"`
}

type ProfileLabels struct {
	Manufacturer  string `json:"manufacturer"`
	Model         string `json:"model"`
	ProductFamily string `json:"product_family,omitempty"`
	DeviceType    string `json:"device_type"`
	OSFamily      string `json:"os_family,omitempty"`
}

type Source struct {
	SourceID string `json:"source_id,omitempty"`
	// SourceRef is a request-local slug used to associate version facts with a
	// source before the server assigns immutable IDs. It is never persisted.
	SourceRef   string `json:"source_ref,omitempty"`
	Kind        string `json:"kind"`
	Title       string `json:"title,omitempty"`
	PublicURL   string `json:"public_url,omitempty"`
	RetrievedAt string `json:"retrieved_at,omitempty"`
	LicenseCode string `json:"license_code,omitempty"`
}

type VersionFact struct {
	FactID       string `json:"fact_id,omitempty"`
	Attribute    string `json:"attribute"`
	Relation     string `json:"relation"`
	Value        string `json:"value"`
	ValueEnd     string `json:"value_end,omitempty"`
	ConfidenceBP int    `json:"confidence_bp"`
	SourceID     string `json:"source_id,omitempty"`
	// SourceRef has the same request-local semantics as Source.SourceRef.
	SourceRef string `json:"source_ref,omitempty"`
}

type CreateProfileRequest struct {
	Labels     ProfileLabels `json:"labels"`
	ReasonCode string        `json:"reason_code"`
}

type ReviseProfileRequest struct {
	Labels     ProfileLabels `json:"labels"`
	ReasonCode string        `json:"reason_code"`
}

type CreateVariantRequest struct {
	VariantKey           string           `json:"variant_key"`
	PredecessorVariantID string           `json:"predecessor_variant_id,omitempty"`
	ConfidenceBP         int              `json:"confidence_bp"`
	Shape                CanonicalShapeV1 `json:"shape"`
	VersionFacts         []VersionFact    `json:"version_facts,omitempty"`
	Sources              []Source         `json:"sources,omitempty"`
	ReasonCode           string           `json:"reason_code"`
}

type ReviseVariantRequest struct {
	ConfidenceBP int              `json:"confidence_bp"`
	Shape        CanonicalShapeV1 `json:"shape"`
	VersionFacts []VersionFact    `json:"version_facts,omitempty"`
	Sources      []Source         `json:"sources,omitempty"`
	ReasonCode   string           `json:"reason_code"`
}

type LifecycleRequest struct {
	ReasonCode string `json:"reason_code"`
}

// PublishRequest binds an accepted profile draft to the public corpus revision
// the curator reviewed. A pointer distinguishes the valid bootstrap revision 0
// from an omitted precondition.
type PublishRequest struct {
	ReasonCode             string `json:"reason_code"`
	ExpectedCorpusRevision *int   `json:"expected_corpus_revision"`
}

type ProfileRevision struct {
	ProfileRevisionID string        `json:"profile_revision_id"`
	Revision          int           `json:"revision"`
	SupersedesID      string        `json:"supersedes_profile_revision_id,omitempty"`
	Labels            ProfileLabels `json:"labels"`
	Status            string        `json:"status"`
	CreatedAt         time.Time     `json:"created_at"`
	PublishedAt       *time.Time    `json:"published_at,omitempty"`
	RetiredAt         *time.Time    `json:"retired_at,omitempty"`
}

type VariantRevision struct {
	VariantRevisionID string           `json:"variant_revision_id"`
	Revision          int              `json:"revision"`
	SupersedesID      string           `json:"supersedes_revision_id,omitempty"`
	ShapeHash         string           `json:"shape_hash"`
	Shape             CanonicalShapeV1 `json:"shape"`
	ConfidenceBP      int              `json:"confidence_bp"`
	Status            string           `json:"status"`
	VersionFacts      []VersionFact    `json:"version_facts"`
	Sources           []Source         `json:"sources"`
	CreatedAt         time.Time        `json:"created_at"`
	PublishedAt       *time.Time       `json:"published_at,omitempty"`
	WithdrawnAt       *time.Time       `json:"withdrawn_at,omitempty"`
}

type Variant struct {
	VariantID            string            `json:"variant_id"`
	VariantKey           string            `json:"variant_key"`
	PredecessorVariantID string            `json:"predecessor_variant_id,omitempty"`
	CreatedAt            time.Time         `json:"created_at"`
	Draft                *VariantRevision  `json:"draft,omitempty"`
	Published            *VariantRevision  `json:"published,omitempty"`
	History              []VariantRevision `json:"history,omitempty"`
}

type Profile struct {
	ProfileID string            `json:"profile_id"`
	CreatedAt time.Time         `json:"created_at"`
	Draft     *ProfileRevision  `json:"draft,omitempty"`
	Published *ProfileRevision  `json:"published,omitempty"`
	History   []ProfileRevision `json:"history,omitempty"`
	Variants  []Variant         `json:"variants"`
	ETag      string            `json:"etag"`
}

type ProfileSummary struct {
	ProfileID         string        `json:"profile_id"`
	Labels            ProfileLabels `json:"labels"`
	Status            string        `json:"status"`
	PublishedVariants int           `json:"published_variants"`
	DraftVariants     int           `json:"draft_variants"`
	HasDraftChanges   bool          `json:"has_draft_changes"`
	UpdatedAt         time.Time     `json:"updated_at"`
	ETag              string        `json:"etag"`
}

type AuditEntry struct {
	AuditID        string    `json:"audit_id"`
	Actor          string    `json:"actor"`
	EntityType     string    `json:"entity_type"`
	EntityID       string    `json:"entity_id"`
	Action         string    `json:"action"`
	ReasonCode     string    `json:"reason_code"`
	BeforeHash     string    `json:"before_hash,omitempty"`
	AfterHash      string    `json:"after_hash,omitempty"`
	RequestID      string    `json:"request_id,omitempty"`
	CorpusRevision *int      `json:"corpus_revision,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// Public types are deliberately separate from management types so drafts,
// curator/audit material, and internal lifecycle metadata cannot serialize.
type PublicProfile struct {
	ProfileID string          `json:"profile_id"`
	Revision  int             `json:"revision"`
	Labels    ProfileLabels   `json:"labels"`
	Variants  []PublicVariant `json:"variants"`
}

type PublicVariant struct {
	VariantID            string           `json:"variant_id"`
	VariantKey           string           `json:"variant_key"`
	PredecessorVariantID string           `json:"predecessor_variant_id,omitempty"`
	Revision             int              `json:"revision"`
	ShapeHash            string           `json:"shape_hash"`
	Shape                CanonicalShapeV1 `json:"shape"`
	ConfidenceBP         int              `json:"confidence_bp"`
	VersionFacts         []VersionFact    `json:"version_facts"`
	Sources              []Source         `json:"sources"`
}

type PublicSnapshot struct {
	SchemaVersion  int             `json:"schema_version"`
	CorpusRevision int             `json:"corpus_revision"`
	GeneratedAt    time.Time       `json:"generated_at"`
	Profiles       []PublicProfile `json:"profiles"`
}

type Manifest struct {
	SchemaVersion  int       `json:"schema_version"`
	CorpusRevision int       `json:"corpus_revision"`
	SnapshotSHA256 string    `json:"snapshot_sha256"`
	ProfileCount   int       `json:"profile_count"`
	VariantCount   int       `json:"variant_count"`
	GeneratedAt    time.Time `json:"generated_at"`
	SnapshotPath   string    `json:"snapshot_path"`
}
