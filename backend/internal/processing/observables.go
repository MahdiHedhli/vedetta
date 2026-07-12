package processing

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

const (
	ObservableDomain          = "domain"
	ObservableDestinationIP   = "destination_ip"
	ObservableCNAME           = "cname"
	ObservableURL             = "url"
	ObservableDestinationPort = "destination_port"
	ObservableProtocol        = "protocol"
)

// ExtractObservables returns every observable actually present in the event,
// including every DNS answer rather than only Event.ResolvedIP.
func ExtractObservables(event models.Event) []models.Observable {
	meta := decodeObject(event.Metadata)
	values := make([]models.Observable, 0, 8)
	add := func(kind, value string) {
		value = normalizeObservable(kind, value)
		if value != "" {
			values = append(values, models.Observable{Type: kind, Value: value})
		}
	}

	add(ObservableDomain, event.Domain)
	addAnswer := func(value string) {
		if net.ParseIP(strings.TrimSpace(value)) != nil {
			add(ObservableDestinationIP, value)
		} else {
			add(ObservableCNAME, value)
		}
	}
	if event.ResolvedIP != "" {
		addAnswer(event.ResolvedIP)
	}
	for _, value := range stringValues(meta["dns_answers"]) {
		addAnswer(value)
	}
	for _, key := range []string{"dst_ip", "destination_ip"} {
		if value, ok := meta[key].(string); ok {
			add(ObservableDestinationIP, value)
		}
	}
	for _, key := range []string{"url", "request_url"} {
		if value, ok := meta[key].(string); ok {
			add(ObservableURL, value)
		}
	}
	for _, key := range []string{"dst_port", "destination_port"} {
		if value := scalarString(meta[key]); value != "" {
			add(ObservableDestinationPort, value)
		}
	}
	if value, ok := meta["protocol"].(string); ok {
		add(ObservableProtocol, value)
	}

	seen := make(map[string]struct{}, len(values))
	out := make([]models.Observable, 0, len(values))
	for _, observable := range values {
		key := observable.Type + "\x00" + observable.Value
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, observable)
	}
	return out
}

func normalizeObservable(kind, value string) string {
	value = strings.TrimSpace(value)
	switch kind {
	case ObservableDomain, ObservableCNAME:
		return strings.TrimSuffix(strings.ToLower(value), ".")
	case ObservableDestinationIP:
		if ip := net.ParseIP(value); ip != nil {
			return ip.String()
		}
		return ""
	case ObservableProtocol:
		return strings.ToLower(value)
	case ObservableDestinationPort:
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			return ""
		}
		return strconv.Itoa(port)
	case ObservableURL:
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return ""
		}
		parsed.Scheme = strings.ToLower(parsed.Scheme)
		parsed.Host = strings.ToLower(parsed.Host)
		return parsed.String()
	default:
		return value
	}
}

func stringValues(value any) []string {
	switch values := value.(type) {
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			if str, ok := value.(string); ok {
				out = append(out, str)
			}
		}
		return out
	case []string:
		return append([]string(nil), values...)
	case string:
		return []string{values}
	default:
		return nil
	}
}

func scalarString(value any) string {
	switch value := value.(type) {
	case string:
		return value
	case json.Number:
		return value.String()
	case float64:
		if value == float64(int(value)) {
			return strconv.Itoa(int(value))
		}
	case int:
		return strconv.Itoa(value)
	}
	return ""
}

func decodeObject(raw string) map[string]any {
	if strings.TrimSpace(raw) == "" {
		return map[string]any{}
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil || object == nil {
		return map[string]any{"unparsed_metadata": raw}
	}
	return object
}

func cloneObject(value map[string]any) map[string]any {
	b, _ := json.Marshal(value)
	var cloned map[string]any
	_ = json.Unmarshal(b, &cloned)
	if cloned == nil {
		cloned = map[string]any{}
	}
	return cloned
}

func marshalStableObject(object map[string]any) string {
	// encoding/json sorts string map keys, making metadata deterministic for
	// tests and forensic comparisons.
	b, err := json.Marshal(object)
	if err != nil {
		return fmt.Sprintf(`{"metadata_error":%q}`, err.Error())
	}
	return string(b)
}

func sortedObservableCopy(values []models.Observable) []models.Observable {
	out := append([]models.Observable(nil), values...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Type == out[j].Type {
			return out[i].Value < out[j].Value
		}
		return out[i].Type < out[j].Type
	})
	return out
}
