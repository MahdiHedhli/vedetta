package corpus

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	maxPublicProfiles           = 100_000
	maxPublicVariantsPerProfile = 1_024
	maxCanonicalShapeBytes      = 64 << 10
)

var (
	publicIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$`)
	dottedQuadPattern = regexp.MustCompile(`(?:^|[^0-9])((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?:$|[^0-9])`)
	ciscoMACPattern   = regexp.MustCompile(`(?i)(?:^|[^0-9a-f])(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}(?:$|[^0-9a-f])`)
	bareMACPattern    = regexp.MustCompile(`(?i)(?:^|[^0-9a-f])[0-9a-f]{12}(?:$|[^0-9a-f])`)
	// uuidAnyPattern intentionally covers every UUID version nibble. UUID-like
	// observed values remain identifying even when they are not RFC 4122 v1-v5.
	uuidAnyPattern           = regexp.MustCompile(`(?i)(?:^|[^0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:$|[^0-9a-f])`)
	dynamicIdentifierPattern = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(?:serial(?:[_ -]?number)?|client[_ -]?id|device[_ -]?id|sensor[_ -]?id|reporter[_ -]?id|install(?:ation)?[_ -]?id|account[_ -]?id|token|certificate[_ -]?id|cert[_ -]?id|uuid|usn|udn)\s*[:=]\s*[a-z0-9]`)
	unschemedURLPattern      = regexp.MustCompile(`(?i)(?:^|\s)[a-z0-9.-]+\.[a-z]{2,63}/[^\s]+`)
)

// CorpusPrivacyError identifies a publication privacy-gate failure without
// echoing the offending value. Callers may safely return Rule and Path in an
// operator response; they must not include the candidate content itself.
type CorpusPrivacyError struct {
	Path string
	Rule string
}

func (e *CorpusPrivacyError) Error() string {
	return fmt.Sprintf("device corpus privacy gate: %s at %s", e.Rule, e.Path)
}

func privacyFailure(path, rule string) error {
	return &CorpusPrivacyError{Path: path, Rule: rule}
}

// ValidatePublicSnapshot is the final publication-wide privacy and structural
// gate. It deliberately revalidates data loaded from SQLite instead of trusting
// request-time checks: corruption, an import, or a future code path must not be
// able to publish a value that the management API would have rejected.
//
// Shape hashes are checked only as content addresses. They provide no anonymity;
// privacy comes from the fixed public structs and value minimization enforced
// before a release is serialized.
func ValidatePublicSnapshot(snapshot PublicSnapshot) error {
	if err := validatePublicTypeAllowlist(); err != nil {
		return err
	}
	if snapshot.SchemaVersion != SchemaVersion {
		return fmt.Errorf("public snapshot has unsupported schema_version %d", snapshot.SchemaVersion)
	}
	if snapshot.CorpusRevision < 0 {
		return fmt.Errorf("public snapshot corpus_revision cannot be negative")
	}
	if snapshot.CorpusRevision == 0 && len(snapshot.Profiles) != 0 {
		return fmt.Errorf("bootstrap corpus_revision 0 must not contain profiles")
	}
	if snapshot.GeneratedAt.IsZero() {
		return fmt.Errorf("public snapshot generated_at is required")
	}
	if len(snapshot.Profiles) > maxPublicProfiles {
		return fmt.Errorf("public snapshot profile count exceeds publication bound")
	}

	profileIDs := make(map[string]bool, len(snapshot.Profiles))
	variantIDs := make(map[string]bool)
	variantProfiles := make(map[string]string)
	predecessors := make(map[string]string)
	for pi, profile := range snapshot.Profiles {
		profilePath := fmt.Sprintf("profiles[%d]", pi)
		if err := validatePublicID(profilePath+".profile_id", profile.ProfileID); err != nil {
			return err
		}
		if profileIDs[profile.ProfileID] {
			return fmt.Errorf("%s.profile_id is duplicated", profilePath)
		}
		profileIDs[profile.ProfileID] = true
		if profile.Revision < 1 {
			return fmt.Errorf("%s.revision must be positive", profilePath)
		}
		labels, err := ValidateLabels(profile.Labels)
		if err != nil {
			return privacyFailure(profilePath+".labels", "invalid_product_label")
		}
		if !reflect.DeepEqual(labels, profile.Labels) {
			return fmt.Errorf("%s.labels are not canonical", profilePath)
		}
		if err := scanLabels(profilePath+".labels", profile.Labels); err != nil {
			return err
		}
		if len(profile.Variants) > maxPublicVariantsPerProfile {
			return fmt.Errorf("%s variant count exceeds publication bound", profilePath)
		}

		for vi, variant := range profile.Variants {
			variantPath := fmt.Sprintf("%s.variants[%d]", profilePath, vi)
			if err := validatePublicVariant(variantPath, profile.ProfileID, variant,
				variantIDs, variantProfiles, predecessors); err != nil {
				return err
			}
		}
	}
	return validatePredecessorGraph(variantProfiles, predecessors)
}

func validatePublicVariant(path, profileID string, variant PublicVariant, allVariantIDs map[string]bool,
	variantProfiles, predecessors map[string]string) error {
	if err := validatePublicID(path+".variant_id", variant.VariantID); err != nil {
		return err
	}
	if allVariantIDs[variant.VariantID] {
		return fmt.Errorf("%s.variant_id is duplicated", path)
	}
	allVariantIDs[variant.VariantID] = true
	variantProfiles[variant.VariantID] = profileID
	if variant.PredecessorVariantID != "" {
		if err := validatePublicID(path+".predecessor_variant_id", variant.PredecessorVariantID); err != nil {
			return err
		}
		if variant.PredecessorVariantID == variant.VariantID {
			return fmt.Errorf("%s.predecessor_variant_id cannot reference itself", path)
		}
		predecessors[variant.VariantID] = variant.PredecessorVariantID
	}
	key, err := ValidateVariantKey(variant.VariantKey)
	if err != nil {
		return privacyFailure(path+".variant_key", "invalid_variant_key")
	}
	if key != variant.VariantKey {
		return fmt.Errorf("%s.variant_key is not canonical", path)
	}
	if err := scanPublicValue(path+".variant_key", variant.VariantKey); err != nil {
		return err
	}
	if variant.Revision < 1 {
		return fmt.Errorf("%s.revision must be positive", path)
	}
	if variant.ConfidenceBP < 0 || variant.ConfidenceBP > 10_000 {
		return fmt.Errorf("%s.confidence_bp must be 0..10000", path)
	}

	// Scan raw typed values before normalization or hash checks so a corrupt
	// stored row cannot turn a privacy violation into a generic mismatch.
	if err := scanShape(path+".shape", variant.Shape); err != nil {
		return err
	}
	shape, canonical, hash, _, err := CanonicalizeShape(variant.Shape)
	if err != nil {
		return privacyFailure(path+".shape", "invalid_canonical_shape")
	}
	if len(canonical) > maxCanonicalShapeBytes {
		return fmt.Errorf("%s.shape exceeds publication bound", path)
	}
	if !reflect.DeepEqual(shape, variant.Shape) {
		return fmt.Errorf("%s.shape is not canonical", path)
	}
	if variant.ShapeHash != hash {
		return fmt.Errorf("%s.shape_hash does not address the canonical shape", path)
	}
	if len(variant.Sources) > 16 {
		return fmt.Errorf("%s.sources exceeds publication bound", path)
	}
	if len(variant.VersionFacts) > 32 {
		return fmt.Errorf("%s.version_facts exceeds publication bound", path)
	}
	sourceIDs := make(map[string]bool, len(variant.Sources))
	sourceContent := make(map[string]bool, len(variant.Sources))
	for i, source := range variant.Sources {
		if err := validatePublicSource(fmt.Sprintf("%s.sources[%d]", path, i), source, sourceIDs); err != nil {
			return err
		}
		key := sourceDuplicateKey(source)
		if sourceContent[key] {
			return fmt.Errorf("%s.sources contains a duplicate citation", path)
		}
		sourceContent[key] = true
	}
	factIDs := make(map[string]bool, len(variant.VersionFacts))
	factContent := make(map[string]bool, len(variant.VersionFacts))
	for i, fact := range variant.VersionFacts {
		if err := validatePublicVersionFact(fmt.Sprintf("%s.version_facts[%d]", path, i), fact, sourceIDs, factIDs); err != nil {
			return err
		}
		key := versionFactDuplicateKey(fact)
		if factContent[key] {
			return fmt.Errorf("%s.version_facts contains a duplicate fact", path)
		}
		factContent[key] = true
	}
	return nil
}

func validatePredecessorGraph(variantProfiles map[string]string, predecessors map[string]string) error {
	variantOrder := make([]string, 0, len(variantProfiles))
	for variantID := range variantProfiles {
		variantOrder = append(variantOrder, variantID)
	}
	sort.Strings(variantOrder)
	for _, variantID := range variantOrder {
		predecessorID := predecessors[variantID]
		if predecessorID == "" {
			continue
		}
		predecessorProfile, exists := variantProfiles[predecessorID]
		if !exists {
			return fmt.Errorf("variant %s predecessor does not exist in this snapshot", variantID)
		}
		if predecessorProfile != variantProfiles[variantID] {
			return fmt.Errorf("variant %s predecessor belongs to another profile", variantID)
		}
	}

	// Every node has at most one predecessor, so a three-state walk is enough
	// to prove the directed lineage graph is acyclic independent of JSON order.
	state := make(map[string]uint8, len(variantProfiles))
	var visit func(string) error
	visit = func(variantID string) error {
		switch state[variantID] {
		case 1:
			return fmt.Errorf("device corpus predecessor graph contains a cycle")
		case 2:
			return nil
		}
		state[variantID] = 1
		if predecessorID := predecessors[variantID]; predecessorID != "" {
			if err := visit(predecessorID); err != nil {
				return err
			}
		}
		state[variantID] = 2
		return nil
	}
	for _, variantID := range variantOrder {
		if err := visit(variantID); err != nil {
			return err
		}
	}
	return nil
}

func validatePublicSource(path string, source Source, sourceIDs map[string]bool) error {
	if err := validatePublicID(path+".source_id", source.SourceID); err != nil {
		return err
	}
	if sourceIDs[source.SourceID] {
		return fmt.Errorf("%s.source_id is duplicated", path)
	}
	sourceIDs[source.SourceID] = true
	if source.SourceRef != "" {
		return privacyFailure(path+".source_ref", "request_only_field")
	}

	candidate := source
	candidate.SourceID = ""
	normalized, err := NormalizeSources([]Source{candidate})
	if err != nil {
		return privacyFailure(path, "invalid_public_citation")
	}
	if len(normalized) != 1 || !reflect.DeepEqual(normalized[0], candidate) {
		return fmt.Errorf("%s is not canonical", path)
	}
	for _, field := range []struct{ name, value string }{
		{"kind", source.Kind}, {"title", source.Title}, {"license_code", source.LicenseCode},
	} {
		name, value := field.name, field.value
		if value != "" {
			if err := scanPublicValue(path+"."+name, value); err != nil {
				return err
			}
		}
	}
	// public_url is the sole URL-bearing public field and has already been
	// constrained by NormalizeSources to a public HTTPS citation.
	return nil
}

func validatePublicVersionFact(path string, fact VersionFact, sourceIDs, factIDs map[string]bool) error {
	if err := validatePublicID(path+".fact_id", fact.FactID); err != nil {
		return err
	}
	if factIDs[fact.FactID] {
		return fmt.Errorf("%s.fact_id is duplicated", path)
	}
	factIDs[fact.FactID] = true
	if fact.SourceRef != "" {
		return privacyFailure(path+".source_ref", "request_only_field")
	}
	if fact.SourceID == "" {
		return privacyFailure(path+".source_id", "missing_provenance")
	}
	if !sourceIDs[fact.SourceID] {
		return fmt.Errorf("%s.source_id does not reference this revision", path)
	}

	candidate := fact
	candidate.FactID = ""
	candidate.SourceID = ""
	normalized, err := NormalizeVersionFacts([]VersionFact{candidate}, map[string]bool{})
	if err != nil {
		return privacyFailure(path, "invalid_version_fact")
	}
	if len(normalized) != 1 || !reflect.DeepEqual(normalized[0], candidate) {
		return fmt.Errorf("%s is not canonical", path)
	}
	for _, field := range []struct{ name, value string }{
		{"attribute", fact.Attribute}, {"relation", fact.Relation},
		{"value", fact.Value}, {"value_end", fact.ValueEnd},
	} {
		name, value := field.name, field.value
		if value != "" {
			if err := scanPublicValue(path+"."+name, value); err != nil {
				return err
			}
		}
	}
	return nil
}

func scanLabels(path string, labels ProfileLabels) error {
	for _, field := range []struct{ name, value string }{
		{"manufacturer", labels.Manufacturer}, {"model", labels.Model},
		{"product_family", labels.ProductFamily}, {"device_type", labels.DeviceType},
		{"os_family", labels.OSFamily},
	} {
		name, value := field.name, field.value
		if value != "" {
			if err := scanPublicValue(path+"."+name, value); err != nil {
				return err
			}
		}
	}
	return nil
}

func scanShape(path string, shape CanonicalShapeV1) error {
	stringFields := []struct {
		name   string
		values []string
	}{
		{"dhcp_vendor_classes", shape.DHCPVendorClasses},
		{"oui_prefixes", shape.OUIPrefixes},
		{"hostname_templates", shape.HostnameTemplates},
		{"mdns_services", shape.MDNSServices},
		{"mdns_models", shape.MDNSModels},
		{"mdns_vendors", shape.MDNSVendors},
		{"ssdp_device_types", shape.SSDPDeviceTypes},
		{"ssdp_server_tokens", shape.SSDPServerTokens},
	}
	for _, field := range stringFields {
		for i, value := range field.values {
			if err := scanPublicValue(fmt.Sprintf("%s.%s[%d]", path, field.name, i), value); err != nil {
				return err
			}
		}
	}
	return nil
}

func scanPublicValue(path, value string) error {
	if containsNetworkIdentifier(value) || containsDottedQuad(value) {
		return privacyFailure(path, "network_identifier")
	}
	if macPattern.MatchString(value) || ciscoMACPattern.MatchString(value) || bareMACPattern.MatchString(value) {
		return privacyFailure(path, "mac_address")
	}
	if uuidAnyPattern.MatchString(value) {
		return privacyFailure(path, "uuid")
	}
	if containsPrivateHostname(value) {
		return privacyFailure(path, "private_hostname")
	}
	if strings.Contains(value, "://") || unschemedURLPattern.MatchString(value) {
		return privacyFailure(path, "url")
	}
	if dynamicIdentifierPattern.MatchString(value) {
		return privacyFailure(path, "dynamic_identifier")
	}
	return nil
}

func containsDottedQuad(value string) bool {
	for _, match := range dottedQuadPattern.FindAllStringSubmatch(value, -1) {
		parts := strings.Split(match[1], ".")
		valid := len(parts) == 4
		for _, part := range parts {
			if len(part) == 0 || len(part) > 3 {
				valid = false
				break
			}
			value := 0
			for _, r := range part {
				value = value*10 + int(r-'0')
			}
			if value > 255 {
				valid = false
				break
			}
		}
		if valid {
			return true
		}
	}
	return false
}

func containsPrivateHostname(value string) bool {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' || r == '_')
	})
	for _, part := range parts {
		candidate := strings.Trim(part, ".")
		if strings.Contains(candidate, ".") && isPrivateName(candidate) {
			return true
		}
	}
	return false
}

func validatePublicID(path, value string) error {
	if !publicIDPattern.MatchString(value) {
		return fmt.Errorf("%s must be a bounded opaque server ID", path)
	}
	return nil
}

// validatePublicTypeAllowlist makes the privacy boundary fail closed if a
// future edit adds a public field without updating this gate. In particular,
// map/interface/raw-JSON extension points cannot silently become publishable.
func validatePublicTypeAllowlist() error {
	types := []struct {
		value  any
		fields []string
	}{
		{PublicSnapshot{}, []string{"schema_version", "corpus_revision", "generated_at", "profiles"}},
		{PublicProfile{}, []string{"profile_id", "revision", "labels", "variants"}},
		{PublicVariant{}, []string{"variant_id", "variant_key", "predecessor_variant_id", "revision", "shape_hash", "shape", "confidence_bp", "version_facts", "sources"}},
		{ProfileLabels{}, []string{"manufacturer", "model", "product_family", "device_type", "os_family"}},
		{CanonicalShapeV1{}, []string{"schema_version", "dhcp_option_55", "dhcp_vendor_classes", "oui_prefixes", "hostname_templates", "mdns_services", "mdns_models", "mdns_vendors", "ssdp_device_types", "ssdp_server_tokens", "tcp_ports", "udp_ports"}},
		{VersionFact{}, []string{"fact_id", "attribute", "relation", "value", "value_end", "confidence_bp", "source_id", "source_ref"}},
		{Source{}, []string{"source_id", "source_ref", "kind", "title", "public_url", "retrieved_at", "license_code"}},
	}
	for _, item := range types {
		if err := validateStructFields(reflect.TypeOf(item.value), item.fields); err != nil {
			return err
		}
	}
	return nil
}

func validateStructFields(t reflect.Type, allowed []string) error {
	want := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		want[name] = true
	}
	seen := make(map[string]bool, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" || !want[name] || seen[name] {
			return fmt.Errorf("public corpus type %s has unreviewed field %s", t.Name(), field.Name)
		}
		seen[name] = true
		if containsDynamicType(field.Type) {
			return fmt.Errorf("public corpus field %s.%s has a dynamic type", t.Name(), field.Name)
		}
	}
	if !reflect.DeepEqual(seen, want) {
		return fmt.Errorf("public corpus type %s does not match its privacy allowlist", t.Name())
	}
	return nil
}

func containsDynamicType(t reflect.Type) bool {
	if t == reflect.TypeOf(time.Time{}) {
		return false
	}
	marshaler := reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	if t.Implements(marshaler) || reflect.PointerTo(t).Implements(marshaler) {
		return true
	}
	switch t.Kind() {
	case reflect.Map, reflect.Interface, reflect.Pointer:
		return true
	case reflect.Slice:
		// []byte silently changes JSON shape to base64 and is also an
		// unbounded carrier for content outside the reviewed schema.
		if t.Elem().Kind() == reflect.Uint8 {
			return true
		}
		return containsDynamicType(t.Elem())
	case reflect.Array:
		return containsDynamicType(t.Elem())
	default:
		return t.PkgPath() == "encoding/json" && t.Name() == "RawMessage"
	}
}
