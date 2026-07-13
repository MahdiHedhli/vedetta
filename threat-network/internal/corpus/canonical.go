package corpus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const shapeDomain = "vedetta-device-shape\x00v1\x00"

var (
	macPattern      = regexp.MustCompile(`(?i)(?:^|[^0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?:$|[^0-9a-f])`)
	macCiscoPattern = regexp.MustCompile(`(?i)(?:^|[^0-9a-f])(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}(?:$|[^0-9a-f])`)
	macBarePattern  = regexp.MustCompile(`(?i)(?:^|[^0-9a-f])[0-9a-f]{12}(?:$|[^0-9a-f])`)
	dottedQuadRe    = regexp.MustCompile(`(?:^|[^0-9])([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})(?:$|[^0-9])`)
	// Version-agnostic: device identifiers often use non-RFC or newer UUID
	// versions, and none belong in a public product-class signature.
	uuidPattern      = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	ouiPattern       = regexp.MustCompile(`^[0-9A-F]{6}$`)
	mdnsServiceRe    = regexp.MustCompile(`^_[a-z0-9-]{1,63}\._(?:tcp|udp)$`)
	ssdpDeviceRe     = regexp.MustCompile(`^urn:[a-z0-9][a-z0-9.-]{0,63}:device:[a-z0-9][a-z0-9._-]{0,63}:[0-9]{1,5}$`)
	hostTemplateRe   = regexp.MustCompile(`^[a-z0-9_-]*(?:\{(?:hex|digits|random)\})[a-z0-9_-]*$`)
	variantKeyRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	sourceRefRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	safeLicenseRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	percentEscapeRe  = regexp.MustCompile(`(?i)%[0-9a-f]{2}`)
	dynamicIDLabelRe = regexp.MustCompile(`(?i)\b(?:serial(?:[ _-]?(?:number|no\.?))?|s\s*/\s*n|sn|account[ _-]?id|client[ _-]?id|device[ _-]?id|install[ _-]?id|reporter[ _-]?id|sensor[ _-]?id|token|uuid|usn|udn|hostname|cert(?:ificate)?[ _-]?(?:id|serial))\s*[:=]\s*\S+`)
	dynamicIDSpaceRe = regexp.MustCompile(`(?i)\b(?:serial(?:[ _-]?(?:number|no\.?))?|s\s*/\s*n|sn|account[ _-]?id|client[ _-]?id|device[ _-]?id|install[ _-]?id|reporter[ _-]?id|sensor[ _-]?id|token|uuid|usn|udn|hostname|cert(?:ificate)?[ _-]?(?:id|serial))\s+([a-z0-9][a-z0-9._/-]{3,127})\b`)
	dynamicURLPathRe = regexp.MustCompile(`(?i)(?:^|/)(?:serial(?:-(?:number|no))?|s-n|sn|account-id|client-id|device-id|install-id|installation-id|reporter-id|sensor-id|token|uuid|usn|udn|hostname|cert-id|certificate-id|cert-serial|certificate-serial)/[^/]+`)
	urlishPattern    = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,62})\.)+[a-z]{2,63}/[^\s]+`)
)

var dynamicURLSegmentLabels = []string{
	"certificate-serial", "certificate-id", "installation-id", "serial-number", "serial-no",
	"account-id", "client-id", "device-id", "install-id", "reporter-id", "sensor-id",
	"cert-serial", "cert-id", "hostname", "serial", "s-n", "sn", "token", "uuid", "usn", "udn",
}

var deviceTypes = stringSet(
	"access_point", "camera", "computer", "desktop", "doorbell", "firewall",
	"game_console", "gateway", "iot_generic", "laptop", "media_player", "nas",
	"phone", "printer", "router", "server", "smart_light", "smart_speaker",
	"smart_tv", "switch", "tablet", "thermostat", "wearable",
)

var osFamilies = stringSet(
	"", "android", "chromeos", "cisco_ios", "cisco_ios_xe", "embedded", "fireos",
	"ios", "ipados", "linux", "macos", "nx_os", "routeros", "tizen", "tvos",
	"unknown", "webos", "windows",
)

var sourceKinds = stringSet(
	"vendor_doc", "standards", "security_advisory", "lab_observation", "manual_curation", "import",
)

var factAttributes = stringSet(
	"firmware_version", "os_version", "hardware_revision", "model_number", "software_version",
)

var factRelations = stringSet("exact", "range", "family")

var reasonCodes = stringSet(
	"new_profile", "new_variant", "label_correction", "signal_correction",
	"firmware_evolution", "source_update", "publish_reviewed", "privacy_withdrawal",
	"obsolete_product", "restore_reviewed",
)

var privateSuffixes = []string{
	".local", ".lan", ".home", ".internal", ".corp", ".localhost",
	".invalid", ".test", ".onion", "home.arpa", ".arpa",
}

func stringSet(values ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(values))
	for _, v := range values {
		m[v] = struct{}{}
	}
	return m
}

// CanonicalizeShape validates, normalizes, and hashes a fixed shape. The hash
// is intentionally deterministic and enumerable: it is a content address, not
// an anonymity mechanism.
func CanonicalizeShape(in CanonicalShapeV1) (CanonicalShapeV1, []byte, string, int, error) {
	if in.SchemaVersion == 0 {
		in.SchemaVersion = SchemaVersion
	}
	if in.SchemaVersion != SchemaVersion {
		return CanonicalShapeV1{}, nil, "", 0, fmt.Errorf("unsupported shape schema_version %d", in.SchemaVersion)
	}
	if len(in.DHCPOption55) > 128 {
		return CanonicalShapeV1{}, nil, "", 0, fmt.Errorf("dhcp_option_55 exceeds 128 codes")
	}
	seenDHCP := map[uint16]bool{}
	for _, code := range in.DHCPOption55 {
		if code == 0 || code > 254 {
			return CanonicalShapeV1{}, nil, "", 0, fmt.Errorf("dhcp_option_55 code must be 1..254")
		}
		if seenDHCP[code] {
			return CanonicalShapeV1{}, nil, "", 0, fmt.Errorf("dhcp_option_55 contains duplicate code %d", code)
		}
		seenDHCP[code] = true
	}

	var out CanonicalShapeV1
	out.SchemaVersion = SchemaVersion
	out.DHCPOption55 = append([]uint16(nil), in.DHCPOption55...)
	var err error
	if out.DHCPVendorClasses, err = normalizeProductSet("dhcp_vendor_classes", in.DHCPVendorClasses, 64); err != nil {
		return out, nil, "", 0, err
	}
	if out.OUIPrefixes, err = normalizeOUIs(in.OUIPrefixes); err != nil {
		return out, nil, "", 0, err
	}
	if out.HostnameTemplates, err = normalizeHostnameTemplates(in.HostnameTemplates); err != nil {
		return out, nil, "", 0, err
	}
	if out.MDNSServices, err = normalizeMDNSServices(in.MDNSServices); err != nil {
		return out, nil, "", 0, err
	}
	if out.MDNSModels, err = normalizeProductSet("mdns_models", in.MDNSModels, 96); err != nil {
		return out, nil, "", 0, err
	}
	if out.MDNSVendors, err = normalizeProductSet("mdns_vendors", in.MDNSVendors, 64); err != nil {
		return out, nil, "", 0, err
	}
	if out.SSDPDeviceTypes, err = normalizeSSDPDeviceTypes(in.SSDPDeviceTypes); err != nil {
		return out, nil, "", 0, err
	}
	if out.SSDPServerTokens, err = normalizeProductSet("ssdp_server_tokens", in.SSDPServerTokens, 128); err != nil {
		return out, nil, "", 0, err
	}
	if out.TCPPorts, err = normalizePorts("tcp_ports", in.TCPPorts); err != nil {
		return out, nil, "", 0, err
	}
	if out.UDPPorts, err = normalizePorts("udp_ports", in.UDPPorts); err != nil {
		return out, nil, "", 0, err
	}

	// A family is an independent acquisition channel, not each field captured
	// by that channel. Counting option 55 and vendor class separately would let
	// one DHCP packet masquerade as corroboration from two sources.
	families := 0
	for _, present := range []bool{
		len(out.DHCPOption55) > 0 || len(out.DHCPVendorClasses) > 0,
		len(out.OUIPrefixes) > 0,
		len(out.HostnameTemplates) > 0,
		len(out.MDNSServices) > 0 || len(out.MDNSModels) > 0 || len(out.MDNSVendors) > 0,
		len(out.SSDPDeviceTypes) > 0 || len(out.SSDPServerTokens) > 0,
		len(out.TCPPorts) > 0 || len(out.UDPPorts) > 0,
	} {
		if present {
			families++
		}
	}
	if families == 0 {
		return out, nil, "", 0, fmt.Errorf("shape must contain at least one signal family")
	}
	canonical, err := json.Marshal(out)
	if err != nil {
		return out, nil, "", 0, err
	}
	digest := sha256.Sum256(append([]byte(shapeDomain), canonical...))
	return out, canonical, hex.EncodeToString(digest[:]), families, nil
}

func normalizeProductSet(field string, values []string, maxLen int) ([]string, error) {
	out := make([]string, 0, len(values))
	for _, raw := range values {
		if err := ensurePrintableASCII(field, raw); err != nil {
			return nil, err
		}
		v := strings.ToLower(strings.Join(strings.Fields(raw), " "))
		if err := validatePublicToken(field, v, maxLen); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return sortedUniqueStrings(out), nil
}

func normalizeOUIs(values []string) ([]string, error) {
	out := make([]string, 0, len(values))
	for _, raw := range values {
		v := strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "", " ", "").Replace(strings.TrimSpace(raw)))
		if !ouiPattern.MatchString(v) {
			return nil, fmt.Errorf("oui_prefixes must contain 24-bit prefixes only")
		}
		first, _ := strconv.ParseUint(v[:2], 16, 8)
		if first&0x03 != 0 {
			return nil, fmt.Errorf("oui_prefixes must be globally administered unicast prefixes")
		}
		out = append(out, v)
	}
	return sortedUniqueStrings(out), nil
}

func normalizeHostnameTemplates(values []string) ([]string, error) {
	out := make([]string, 0, len(values))
	for _, raw := range values {
		v := strings.ToLower(strings.TrimSpace(raw))
		if len(v) > 64 || !hostTemplateRe.MatchString(v) {
			return nil, fmt.Errorf("hostname_templates must use literals plus {hex}, {digits}, or {random}")
		}
		out = append(out, v)
	}
	return sortedUniqueStrings(out), nil
}

func normalizeMDNSServices(values []string) ([]string, error) {
	out := make([]string, 0, len(values))
	for _, raw := range values {
		v := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		v = strings.TrimSuffix(v, ".local")
		if !mdnsServiceRe.MatchString(v) {
			return nil, fmt.Errorf("mdns_services must be service types such as _rtsp._tcp")
		}
		out = append(out, v)
	}
	return sortedUniqueStrings(out), nil
}

func normalizeSSDPDeviceTypes(values []string) ([]string, error) {
	out := make([]string, 0, len(values))
	for _, raw := range values {
		v := strings.ToLower(strings.TrimSpace(raw))
		if len(v) > 160 || !ssdpDeviceRe.MatchString(v) {
			return nil, fmt.Errorf("ssdp_device_types must contain device URNs only")
		}
		out = append(out, v)
	}
	return sortedUniqueStrings(out), nil
}

func normalizePorts(field string, values []uint16) ([]uint16, error) {
	if len(values) == 0 {
		return nil, nil
	}
	seen := make(map[uint16]bool, len(values))
	out := make([]uint16, 0, len(values))
	for _, port := range values {
		if port == 0 {
			return nil, fmt.Errorf("%s contains port 0", field)
		}
		if !seen[port] {
			seen[port] = true
			out = append(out, port)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func sortedUniqueStrings(values []string) []string {
	sort.Strings(values)
	out := values[:0]
	for _, v := range values {
		if len(out) == 0 || out[len(out)-1] != v {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func ValidateLabels(in ProfileLabels) (ProfileLabels, error) {
	for _, field := range []struct{ name, value string }{
		{"manufacturer", in.Manufacturer}, {"model", in.Model},
		{"product_family", in.ProductFamily}, {"device_type", in.DeviceType},
		{"os_family", in.OSFamily},
	} {
		if err := ensurePrintableASCII(field.name, field.value); err != nil {
			return ProfileLabels{}, err
		}
	}
	out := ProfileLabels{
		Manufacturer:  strings.Join(strings.Fields(in.Manufacturer), " "),
		Model:         strings.Join(strings.Fields(in.Model), " "),
		ProductFamily: strings.Join(strings.Fields(in.ProductFamily), " "),
		DeviceType:    strings.ToLower(strings.TrimSpace(in.DeviceType)),
		OSFamily:      strings.ToLower(strings.TrimSpace(in.OSFamily)),
	}
	if err := validatePublicToken("manufacturer", out.Manufacturer, 64); err != nil {
		return out, err
	}
	if err := validatePublicToken("model", out.Model, 96); err != nil {
		return out, err
	}
	if out.ProductFamily != "" {
		if err := validatePublicToken("product_family", out.ProductFamily, 96); err != nil {
			return out, err
		}
	}
	if _, ok := deviceTypes[out.DeviceType]; !ok {
		return out, fmt.Errorf("unsupported device_type %q", out.DeviceType)
	}
	if _, ok := osFamilies[out.OSFamily]; !ok {
		return out, fmt.Errorf("unsupported os_family %q", out.OSFamily)
	}
	return out, nil
}

func ValidateVariantKey(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if !variantKeyRe.MatchString(v) {
		return "", fmt.Errorf("variant_key must be a 1..64 character lowercase slug")
	}
	return v, nil
}

func ValidateReasonCode(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if _, ok := reasonCodes[v]; !ok {
		return "", fmt.Errorf("unsupported reason_code")
	}
	return v, nil
}

func NormalizeSources(values []Source) ([]Source, error) {
	if len(values) > 16 {
		return nil, fmt.Errorf("sources exceeds 16 entries")
	}
	out := make([]Source, 0, len(values))
	seenIDs := make(map[string]bool, len(values))
	seenRefs := make(map[string]bool, len(values))
	seenContent := make(map[string]bool, len(values))
	for _, src := range values {
		if src.SourceID != "" {
			if err := validatePublicID("source.source_id", src.SourceID); err != nil {
				return nil, err
			}
			if seenIDs[src.SourceID] {
				return nil, fmt.Errorf("source.source_id must be unique within a revision")
			}
			seenIDs[src.SourceID] = true
		}
		src.SourceRef = strings.ToLower(strings.TrimSpace(src.SourceRef))
		if src.SourceRef != "" {
			if !sourceRefRe.MatchString(src.SourceRef) {
				return nil, fmt.Errorf("source.source_ref must be a 1..32 character lowercase slug")
			}
			if seenRefs[src.SourceRef] {
				return nil, fmt.Errorf("source.source_ref must be unique within a revision")
			}
			seenRefs[src.SourceRef] = true
		}
		if src.SourceID != "" && src.SourceRef != "" {
			return nil, fmt.Errorf("source cannot contain both source_id and source_ref")
		}
		src.Kind = strings.ToLower(strings.TrimSpace(src.Kind))
		if _, ok := sourceKinds[src.Kind]; !ok {
			return nil, fmt.Errorf("unsupported source kind")
		}
		for _, field := range []struct{ name, value string }{
			{"source.title", src.Title}, {"source.public_url", src.PublicURL},
			{"source.retrieved_at", src.RetrievedAt}, {"source.license_code", src.LicenseCode},
		} {
			if err := ensurePrintableASCII(field.name, field.value); err != nil {
				return nil, err
			}
		}
		src.Title = strings.Join(strings.Fields(src.Title), " ")
		src.PublicURL = strings.TrimSpace(src.PublicURL)
		src.RetrievedAt = strings.TrimSpace(src.RetrievedAt)
		src.LicenseCode = strings.TrimSpace(src.LicenseCode)

		localOnly := src.Kind == "lab_observation" || src.Kind == "manual_curation"
		if localOnly {
			if src.Title != "" || src.PublicURL != "" || src.RetrievedAt != "" || src.LicenseCode != "" {
				return nil, fmt.Errorf("%s sources contain kind only", src.Kind)
			}
		} else if src.PublicURL == "" {
			return nil, fmt.Errorf("%s sources require a public HTTPS citation", src.Kind)
		}
		if src.Title != "" {
			if err := validatePublicToken("source.title", src.Title, 120); err != nil {
				return nil, err
			}
		}
		if src.PublicURL != "" {
			var err error
			if src.PublicURL, err = normalizeCitationURL(src.PublicURL); err != nil {
				return nil, err
			}
		}
		if src.RetrievedAt != "" {
			t, err := time.Parse(time.RFC3339, src.RetrievedAt)
			if err != nil {
				return nil, fmt.Errorf("source.retrieved_at must be RFC3339")
			}
			src.RetrievedAt = t.UTC().Format(time.RFC3339)
		}
		if src.Kind == "import" && src.LicenseCode == "" {
			return nil, fmt.Errorf("import sources require an explicit license_code")
		}
		if src.LicenseCode != "" && !safeLicenseRe.MatchString(src.LicenseCode) {
			return nil, fmt.Errorf("source.license_code has invalid syntax")
		}
		contentKey := sourceDuplicateKey(src)
		if seenContent[contentKey] {
			return nil, fmt.Errorf("sources contains a duplicate citation")
		}
		seenContent[contentKey] = true
		out = append(out, src)
	}
	sort.SliceStable(out, func(i, j int) bool { return sourceSortKey(out[i]) < sourceSortKey(out[j]) })
	return out, nil
}

func NormalizeVersionFacts(values []VersionFact, knownSourceRefs map[string]bool) ([]VersionFact, error) {
	if len(values) > 32 {
		return nil, fmt.Errorf("version_facts exceeds 32 entries")
	}
	out := make([]VersionFact, 0, len(values))
	seenIDs := make(map[string]bool, len(values))
	seenFacts := make(map[string]bool, len(values))
	for _, fact := range values {
		if fact.FactID != "" {
			if err := validatePublicID("version_fact.fact_id", fact.FactID); err != nil {
				return nil, err
			}
			if seenIDs[fact.FactID] {
				return nil, fmt.Errorf("version_fact.fact_id must be unique within a revision")
			}
			seenIDs[fact.FactID] = true
		}
		if fact.SourceID != "" {
			if err := validatePublicID("version_fact.source_id", fact.SourceID); err != nil {
				return nil, err
			}
		}
		fact.SourceRef = strings.ToLower(strings.TrimSpace(fact.SourceRef))
		if fact.SourceID != "" && fact.SourceRef != "" {
			return nil, fmt.Errorf("version_fact cannot contain both source_id and source_ref")
		}
		for _, field := range []struct{ name, value string }{
			{"version_fact.attribute", fact.Attribute}, {"version_fact.relation", fact.Relation},
			{"version_fact.value", fact.Value}, {"version_fact.value_end", fact.ValueEnd},
		} {
			if err := ensurePrintableASCII(field.name, field.value); err != nil {
				return nil, err
			}
		}
		fact.Attribute = strings.ToLower(strings.TrimSpace(fact.Attribute))
		fact.Relation = strings.ToLower(strings.TrimSpace(fact.Relation))
		fact.Value = strings.Join(strings.Fields(fact.Value), " ")
		fact.ValueEnd = strings.Join(strings.Fields(fact.ValueEnd), " ")
		if _, ok := factAttributes[fact.Attribute]; !ok {
			return nil, fmt.Errorf("unsupported version fact attribute")
		}
		if _, ok := factRelations[fact.Relation]; !ok {
			return nil, fmt.Errorf("unsupported version fact relation")
		}
		if err := validateVersionValue("version_fact.value", fact.Value); err != nil {
			return nil, err
		}
		if fact.Relation == "range" {
			if err := validateVersionValue("version_fact.value_end", fact.ValueEnd); err != nil {
				return nil, err
			}
		} else if fact.ValueEnd != "" {
			return nil, fmt.Errorf("version_fact.value_end is only valid for range")
		}
		if fact.ConfidenceBP < 0 || fact.ConfidenceBP > 10000 {
			return nil, fmt.Errorf("version_fact.confidence_bp must be 0..10000")
		}
		if fact.SourceRef != "" && !knownSourceRefs[fact.SourceRef] {
			return nil, fmt.Errorf("version_fact.source_ref does not reference this revision")
		}
		factKey := versionFactDuplicateKey(fact)
		if seenFacts[factKey] {
			return nil, fmt.Errorf("version_facts contains a duplicate fact")
		}
		seenFacts[factKey] = true
		out = append(out, fact)
	}
	sort.SliceStable(out, func(i, j int) bool { return versionFactSortKey(out[i]) < versionFactSortKey(out[j]) })
	return out, nil
}

func validateVersionValue(field, value string) error {
	if value == "" || len(value) > 96 {
		return fmt.Errorf("%s must contain 1..96 characters", field)
	}
	if err := ensurePrintableASCII(field, value); err != nil {
		return err
	}
	if percentEscapeRe.MatchString(value) {
		return fmt.Errorf("%s contains percent-encoded material", field)
	}
	if containsNetworkIdentifier(value) || containsMAC(value) || uuidPattern.MatchString(value) || containsPrivateName(value) || containsDynamicIdentifier(value) || urlishPattern.MatchString(value) {
		return fmt.Errorf("%s contains a prohibited identifier", field)
	}
	for _, r := range value {
		if unicode.IsControl(r) || strings.ContainsRune("<>@?#\\", r) {
			return fmt.Errorf("%s contains prohibited syntax", field)
		}
	}
	return nil
}

// validatePublicToken enforces a deliberately narrow publication alphabet and
// rejects recognizable identifier syntax. It is not a general secret detector:
// arbitrary printable ASCII can encode data in ways no local classifier can
// identify reliably, so publication still requires curator review.
func validatePublicToken(field, value string, maxLen int) error {
	if value == "" || len(value) > maxLen {
		return fmt.Errorf("%s must contain 1..%d characters", field, maxLen)
	}
	if err := ensurePrintableASCII(field, value); err != nil {
		return err
	}
	if percentEscapeRe.MatchString(value) {
		return fmt.Errorf("%s contains percent-encoded material", field)
	}
	if containsNetworkIdentifier(value) {
		return fmt.Errorf("%s contains an IP address or CIDR", field)
	}
	if containsMAC(value) || uuidPattern.MatchString(value) || containsPrivateName(value) || containsDynamicIdentifier(value) || urlishPattern.MatchString(value) {
		return fmt.Errorf("%s contains a prohibited identifier", field)
	}
	if strings.Contains(value, "://") {
		return fmt.Errorf("%s contains URL syntax", field)
	}
	for _, r := range value {
		if unicode.IsControl(r) || strings.ContainsRune("<>@?#\\", r) {
			return fmt.Errorf("%s contains prohibited syntax", field)
		}
	}
	return nil
}

func ensurePrintableASCII(field, value string) error {
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return fmt.Errorf("%s must contain printable ASCII only", field)
		}
	}
	return nil
}

func normalizeCitationURL(raw string) (string, error) {
	if len(raw) > 2_048 {
		return "", fmt.Errorf("source.public_url exceeds 2048 characters")
	}
	u, err := url.Parse(raw)
	if err != nil || strings.ToLower(u.Scheme) != "https" || u.Opaque != "" ||
		u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.ForceQuery || strings.ContainsAny(raw, "?#") {
		return "", fmt.Errorf("source.public_url must be a public HTTPS URL without userinfo, query, or fragment")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if !isPublicDNSName(host) || net.ParseIP(host) != nil || isPrivateName(host) ||
		containsNetworkIdentifier(host) || containsMAC(host) || uuidPattern.MatchString(host) {
		return "", fmt.Errorf("source.public_url host must be a public DNS name")
	}
	port := u.Port()
	if strings.Contains(u.Host, ":") && port == "" {
		return "", fmt.Errorf("source.public_url has an invalid port")
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65_535 {
			return "", fmt.Errorf("source.public_url has an invalid port")
		}
	}
	decodedPath, err := decodeURLPath(u.EscapedPath())
	if err != nil {
		return "", err
	}
	if err = ensurePrintableASCII("source.public_url path", decodedPath); err != nil {
		return "", err
	}
	if containsNetworkIdentifier(decodedPath) || containsMAC(decodedPath) ||
		uuidPattern.MatchString(decodedPath) || containsPrivateName(decodedPath) ||
		containsDynamicIdentifier(decodedPath) ||
		containsDynamicURLPathIdentifier(decodedPath) {
		return "", fmt.Errorf("source.public_url path contains a prohibited identifier")
	}
	u.Scheme = "https"
	u.Host = host
	if port != "" && port != "443" {
		u.Host = net.JoinHostPort(host, port)
	}
	u.Path = decodedPath
	u.RawPath = ""
	u.ForceQuery = false
	return u.String(), nil
}

func decodeURLPath(raw string) (string, error) {
	current := raw
	for i := 0; i < 8; i++ {
		next, err := url.PathUnescape(current)
		if err != nil {
			return "", fmt.Errorf("source.public_url path contains invalid escaping")
		}
		if next == current {
			return current, nil
		}
		current = next
	}
	if percentEscapeRe.MatchString(current) {
		return "", fmt.Errorf("source.public_url path contains excessive escaping")
	}
	return current, nil
}

func isPublicDNSName(host string) bool {
	if len(host) == 0 || len(host) > 253 || !strings.Contains(host, ".") || host == "localhost" {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 || !strings.ContainsAny(tld, "abcdefghijklmnopqrstuvwxyz") {
		return false
	}
	return true
}

func sourceDuplicateKey(src Source) string {
	if src.PublicURL != "" {
		return "url\x00" + src.PublicURL
	}
	return "kind\x00" + src.Kind
}

func sourceContentKey(src Source) string {
	return strings.Join([]string{src.Kind, src.Title, src.PublicURL, src.RetrievedAt, src.LicenseCode}, "\x00")
}

func sourceSortKey(src Source) string {
	return strings.Join([]string{sourceContentKey(src), src.SourceRef, src.SourceID}, "\x00")
}

func versionFactContentKey(fact VersionFact) string {
	return strings.Join([]string{fact.Attribute, fact.Relation, fact.Value, fact.ValueEnd,
		strconv.Itoa(fact.ConfidenceBP), fact.SourceRef, fact.SourceID}, "\x00")
}

func versionFactDuplicateKey(fact VersionFact) string {
	return strings.Join([]string{fact.Attribute, fact.Relation, fact.Value, fact.ValueEnd,
		fact.SourceRef, fact.SourceID}, "\x00")
}

func versionFactSortKey(fact VersionFact) string {
	return strings.Join([]string{versionFactContentKey(fact), fact.FactID}, "\x00")
}

// containsNetworkIdentifier rejects address material even when it is embedded
// in an otherwise plausible product string (for example "camera 192.0.2.1").
// Hashing such a value would not make it anonymous, so it never enters storage.
func containsNetworkIdentifier(value string) bool {
	if matches := dottedQuadRe.FindAllStringSubmatch(value, -1); len(matches) > 0 {
		for _, match := range matches {
			valid := true
			for i := 1; i <= 4; i++ {
				n, err := strconv.Atoi(match[i])
				if err != nil || n > 255 {
					valid = false
					break
				}
			}
			if valid {
				return true
			}
		}
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return !(unicode.IsDigit(r) || unicode.IsLetter(r) || r == '.' || r == ':' || r == '%')
	})
	for _, raw := range parts {
		candidate := strings.Trim(raw, ".:")
		if candidate == "" {
			continue
		}
		if i := strings.LastIndexByte(candidate, '%'); i >= 0 {
			candidate = candidate[:i]
		}
		if net.ParseIP(candidate) != nil {
			return true
		}
		if host, _, err := net.SplitHostPort(candidate); err == nil && net.ParseIP(strings.Trim(host, "[]")) != nil {
			return true
		}
		if _, _, err := net.ParseCIDR(candidate); err == nil {
			return true
		}
	}
	return false
}

func containsMAC(value string) bool {
	return macPattern.MatchString(value) || macCiscoPattern.MatchString(value) || macBarePattern.MatchString(value)
}

func containsDynamicIdentifier(value string) bool {
	if dynamicIDLabelRe.MatchString(value) {
		return true
	}
	for _, match := range dynamicIDSpaceRe.FindAllStringSubmatch(value, -1) {
		if len(match) > 1 && looksLikeDynamicIdentifier(match[1]) {
			return true
		}
	}
	return false
}

// looksLikeDynamicIdentifier deliberately requires more than a label followed
// by an ordinary word. This catches common compact serial forms while allowing
// public prose such as "serial number guide" or "device id documentation".
func looksLikeDynamicIdentifier(value string) bool {
	v := strings.Trim(strings.ToLower(value), "._/-")
	if len(v) < 4 {
		return false
	}
	digits := 0
	for i := 0; i < len(v); i++ {
		if v[i] >= '0' && v[i] <= '9' {
			digits++
		}
	}
	return digits >= 5 || (strings.HasPrefix(v, "sn") && digits >= 3)
}

func containsDynamicURLPathIdentifier(path string) bool {
	if dynamicURLPathRe.MatchString(path) {
		return true
	}
	for _, segment := range strings.Split(path, "/") {
		lower := strings.ToLower(segment)
		for _, label := range dynamicURLSegmentLabels {
			for _, separator := range []byte{'-', '_', '='} {
				prefix := label + string(separator)
				if strings.HasPrefix(lower, prefix) && looksLikeDynamicIdentifier(segment[len(prefix):]) {
					return true
				}
			}
		}
	}
	return false
}

func containsPrivateName(value string) bool {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return !(unicode.IsDigit(r) || unicode.IsLetter(r) || r == '.' || r == '-' || r == '_')
	})
	for _, part := range parts {
		// A bare product word such as "Local" or "Home" is not a hostname.
		if strings.Contains(part, ".") && isPrivateName(part) {
			return true
		}
	}
	return false
}

func isPrivateName(value string) bool {
	v := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	for _, suffix := range privateSuffixes {
		plain := strings.TrimPrefix(suffix, ".")
		if v == plain || strings.HasSuffix(v, suffix) || strings.HasSuffix(v, "."+plain) {
			return true
		}
	}
	return false
}
