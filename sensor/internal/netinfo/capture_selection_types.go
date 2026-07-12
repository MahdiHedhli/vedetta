package netinfo

// Capture-interface selection types are platform-neutral so main.go's
// --print-capture-plan path compiles everywhere. The pcap-backed implementation is
// Unix-only (capture_selection.go); Windows gets a stub (capture_selection_windows.go)
// because the base Windows sensor captures DNS via ETW (host-scoped, no NIC binding)
// and never selects a pcap capture interface.

// CaptureSelectionOptions controls automatic capture-interface selection.
type CaptureSelectionOptions struct {
	Preferred string
	CoreURL   string
	ScanCIDR  string
	Purpose   string
}

// CaptureSelection is the result of choosing a capture interface.
type CaptureSelection struct {
	Name         string
	Reason       string
	RouteSource  string
	ScanCIDR     string
	Candidates   []CaptureCandidate
	WasPreferred bool
}

// CaptureCandidate summarizes one ranked capture-interface candidate.
type CaptureCandidate struct {
	Name    string
	Score   int
	IPs     []string
	Reasons []string
}
