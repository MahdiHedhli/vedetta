package dnsintel

import (
	"regexp"
	"strings"
)

// TunnelResult holds the output of the DNS tunnel detection algorithm.
type TunnelResult struct {
	Score        float64 // 0.0 (normal) to 1.0 (highly suspicious)
	IsTunnel     bool    // True if score exceeds threshold
	Signals      []string // Which signals were triggered
}

// TunnelThreshold is the composite score above which a domain is flagged.
const TunnelThreshold = 0.6

// Regex patterns for encoded data in subdomains
var (
	hexPattern    = regexp.MustCompile(`^[0-9a-f]{16,}$`)
	base64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/=]{16,}$`)
	base32Pattern = regexp.MustCompile(`^[A-Z2-7=]{16,}$`)
)

// ScoreTunnel evaluates whether a DNS query looks like DNS tunneling.
// DNS tunneling encodes data in subdomain labels, producing queries like:
//   aGVsbG8gd29ybGQ.data.evil.com
//   4e6f7468696e672.tunnel.bad.xyz
//
// Detection signals:
// 1. Subdomain labels longer than 30 characters
// 2. Base64/hex encoding patterns in labels
// 3. High subdomain depth (many labels)
// 4. High total query length
func ScoreTunnel(domain string) TunnelResult {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")

	parts := strings.Split(domain, ".")
	if len(parts) < 3 {
		return TunnelResult{}
	}

	// Exclude the registered domain (last 2 parts, or last 3 for multi-part TLDs)
	tldParts := 2
	if len(parts) >= 4 {
		possibleTLD := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if isMultiPartTLD(possibleTLD) {
			tldParts = 3
		}
	}

	subdomainLabels := parts[:len(parts)-tldParts]
	if len(subdomainLabels) == 0 {
		return TunnelResult{}
	}

	var signals []string
	score := 0.0

	// Signal 1: Long subdomain labels
	maxLabelLen := 0
	totalSubLen := 0
	for _, label := range subdomainLabels {
		if len(label) > maxLabelLen {
			maxLabelLen = len(label)
		}
		totalSubLen += len(label)
	}

	if maxLabelLen > 50 {
		score += 0.4
		signals = append(signals, "very_long_label")
	} else if maxLabelLen > 30 {
		score += 0.25
		signals = append(signals, "long_label")
	}

	// Signal 2: Encoding patterns (hex, base64, base32)
	for _, label := range subdomainLabels {
		if len(label) < 16 {
			continue
		}
		if hexPattern.MatchString(label) {
			score += 0.35
			signals = append(signals, "hex_encoded")
			break
		}
		if base64Pattern.MatchString(label) {
			score += 0.3
			signals = append(signals, "base64_encoded")
			break
		}
		if base32Pattern.MatchString(label) {
			score += 0.3
			signals = append(signals, "base32_encoded")
			break
		}
	}

	// Signal 3: High subdomain depth (> 4 labels before the registered domain)
	if len(subdomainLabels) > 4 {
		score += 0.2
		signals = append(signals, "deep_subdomain")
	}

	// Signal 4: High total subdomain character count (data exfiltration)
	if totalSubLen > 100 {
		score += 0.25
		signals = append(signals, "high_total_length")
	} else if totalSubLen > 60 {
		score += 0.1
		signals = append(signals, "moderate_total_length")
	}

	// Signal 5: High entropy in the longest subdomain label
	if maxLabelLen >= 8 {
		longestLabel := ""
		for _, label := range subdomainLabels {
			if len(label) > len(longestLabel) {
				longestLabel = label
			}
		}
		entropy := shannonEntropy(longestLabel)
		if entropy > 3.8 {
			score += 0.15
			signals = append(signals, "high_entropy_subdomain")
		}
	}

	score = clamp(score)

	return TunnelResult{
		Score:    score,
		IsTunnel: score >= TunnelThreshold,
		Signals:  signals,
	}
}

// ScoreTXTQueryVolume is a supplementary check: if a source is making many
// TXT queries to a single domain, that's a strong tunnel indicator.
// This is a stateless per-event hint; the caller tracks state.
func IsTXTTunnelCandidate(queryType string) bool {
	return strings.EqualFold(queryType, "TXT") || strings.EqualFold(queryType, "NULL")
}
