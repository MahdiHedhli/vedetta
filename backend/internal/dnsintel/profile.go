package dnsintel

// AdvancedDNSHuntingProfile controls optional behavioural DNS detectors.
//
// These signals are useful on managed small-business networks, but can be
// noisy on consumer and IoT-heavy networks. They are therefore disabled by
// default and are deliberately separate from threat-intelligence matching:
// a known malicious indicator must remain visible regardless of this profile.
//
// Individual detector choices are retained while Enabled is false, so an
// operator can prepare a profile before activating it.
type AdvancedDNSHuntingProfile struct {
	Enabled        bool `json:"enabled"`
	Tunneling      bool `json:"tunneling"`
	Beaconing      bool `json:"beaconing"`
	DGANXDomain    bool `json:"dga_nxdomain"`
	AnswerChurn    bool `json:"answer_churn"`
	ResolverBypass bool `json:"resolver_bypass"`
	Rebinding      bool `json:"rebinding"`
	InternalRecon  bool `json:"internal_recon"`
}

// DefaultAdvancedDNSHuntingProfile is intentionally quiet. Collection health
// and exact threat-intelligence matches are not represented here because they
// remain active independently of behavioural hunting.
func DefaultAdvancedDNSHuntingProfile() AdvancedDNSHuntingProfile {
	return AdvancedDNSHuntingProfile{}
}

// DetectorEnabled makes the master switch authoritative while preserving
// per-detector selections for later reactivation.
func (p AdvancedDNSHuntingProfile) DetectorEnabled(detector string) bool {
	if !p.Enabled {
		return false
	}
	switch detector {
	case "tunneling":
		return p.Tunneling
	case "beaconing":
		return p.Beaconing
	case "dga_nxdomain":
		return p.DGANXDomain
	case "answer_churn":
		return p.AnswerChurn
	case "resolver_bypass":
		return p.ResolverBypass
	case "rebinding":
		return p.Rebinding
	case "internal_recon":
		return p.InternalRecon
	default:
		return false
	}
}
