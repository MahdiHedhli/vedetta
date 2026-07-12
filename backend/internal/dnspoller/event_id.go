package dnspoller

import (
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/eventid"
)

func piHoleEventID(query PiHoleQuery) string {
	if query.QueryID != 0 {
		// Pi-hole v6 exposes the database query ID. Status/reply fields can move
		// from IN_PROGRESS to their final value between overlapping polls, so they
		// must not turn one upstream query into two Vedetta events.
		return eventid.Deterministic(
			"pihole",
			"pihole|"+normalizePollerAddress(query.ClientIP),
			piHoleQueryTime(query),
			struct {
				QueryID int64 `json:"query_id"`
			}{QueryID: query.QueryID},
		)
	}
	material := struct {
		QueryType   string  `json:"query_type"`
		Domain      string  `json:"domain"`
		ClientIP    string  `json:"client_ip"`
		Status      int     `json:"status"`
		StatusName  string  `json:"status_name"`
		DNSSEC      int     `json:"dnssec"`
		DNSSECName  string  `json:"dnssec_name"`
		ReplyType   int     `json:"reply_type"`
		ReplyName   string  `json:"reply_name"`
		ReplyTime   float64 `json:"reply_time"`
		CNAMETarget string  `json:"cname_target"`
		RegexID     string  `json:"regex_id"`
		Occurrence  int     `json:"occurrence"`
	}{
		QueryType: strings.ToUpper(strings.TrimSpace(query.QueryType)),
		Domain:    normalizePollerName(query.Domain), ClientIP: normalizePollerAddress(query.ClientIP),
		Status: query.Status, StatusName: strings.ToUpper(strings.TrimSpace(query.StatusName)),
		DNSSEC: query.DNSSEC, DNSSECName: strings.ToUpper(strings.TrimSpace(query.DNSSECName)),
		ReplyType: query.ReplyType, ReplyName: strings.ToUpper(strings.TrimSpace(query.ReplyName)), ReplyTime: query.ReplyTime,
		CNAMETarget: normalizePollerObservable(query.CNAMETarget), RegexID: strings.TrimSpace(query.RegexID),
		Occurrence: query.Occurrence,
	}
	return eventid.Deterministic(
		"pihole",
		"pihole|"+normalizePollerAddress(query.ClientIP),
		piHoleQueryTime(query),
		material,
	)
}

func piHoleQueryTime(query PiHoleQuery) time.Time {
	seconds, fraction := math.Modf(query.Timestamp)
	return time.Unix(int64(seconds), int64(fraction*float64(time.Second))).UTC()
}

func adGuardEventID(query AdGuardQuery) string {
	answers := canonicalAdGuardAnswers(query.Answer)
	originalAnswers := canonicalAdGuardAnswers(query.OriginalAnswer)
	rules := canonicalAdGuardRules(query.Rules)
	material := struct {
		Answers         []string `json:"answers"`
		OriginalAnswers []string `json:"original_answers"`
		Upstream        string   `json:"upstream"`
		ElapsedMS       string   `json:"elapsed_ms"`
		Client          string   `json:"client"`
		ClientID        string   `json:"client_id"`
		ClientName      string   `json:"client_name"`
		Rules           []string `json:"rules"`
		Rule            string   `json:"rule"`
		Reason          string   `json:"reason"`
		FilterID        int      `json:"filter_id"`
		QuestionName    string   `json:"question_name"`
		QuestionType    string   `json:"question_type"`
		QuestionClass   string   `json:"question_class"`
		Occurrence      int      `json:"occurrence"`
	}{
		Answers: answers, OriginalAnswers: originalAnswers,
		Upstream: strings.TrimSpace(strings.ToLower(query.Upstream)), ElapsedMS: strings.TrimSpace(query.ElapsedMs),
		Client: normalizePollerAddress(query.Client), ClientID: strings.TrimSpace(query.ClientID),
		ClientName: strings.TrimSpace(strings.ToLower(query.ClientInfo.Name)), Rules: rules,
		Rule:   strings.TrimSpace(query.Rule),
		Reason: strings.TrimSpace(query.Reason), FilterID: query.FilterID,
		QuestionName:  normalizePollerName(query.Question.Name),
		QuestionType:  strings.ToUpper(strings.TrimSpace(query.Question.Type)),
		QuestionClass: strings.ToUpper(strings.TrimSpace(query.Question.Class)),
		Occurrence:    query.Occurrence,
	}
	return eventid.Deterministic(
		"adguard",
		"adguard|"+normalizePollerAddress(query.Client)+"|"+strings.TrimSpace(query.ClientID),
		query.Time.UTC(),
		material,
	)
}

func canonicalAdGuardRules(rules []AdGuardRule) []string {
	canonical := make([]string, 0, len(rules))
	for _, rule := range rules {
		canonical = append(canonical,
			strconv.FormatInt(rule.FilterListID, 10)+"|"+strings.TrimSpace(rule.Text))
	}
	sort.Strings(canonical)
	return canonical
}

func canonicalAdGuardAnswers(answers []AdGuardAnswer) []string {
	canonical := make([]string, 0, len(answers))
	for _, answer := range answers {
		canonical = append(canonical,
			strings.ToUpper(strings.TrimSpace(answer.Type))+"|"+
				normalizePollerObservable(answer.Value)+"|"+
				strconv.Itoa(answer.TTL))
	}
	sort.Strings(canonical)
	return canonical
}

func normalizePollerName(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func normalizePollerAddress(value string) string {
	value = strings.TrimSpace(value)
	if parsed := net.ParseIP(value); parsed != nil {
		return parsed.String()
	}
	return strings.ToLower(value)
}

func normalizePollerObservable(value string) string {
	if parsed := net.ParseIP(strings.TrimSpace(value)); parsed != nil {
		return parsed.String()
	}
	return normalizePollerName(value)
}
