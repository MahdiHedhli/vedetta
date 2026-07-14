package store

import (
	"strings"
	"testing"

	"github.com/vedetta-network/vedetta/threat-network/internal/corpus"
)

func validCorpusWriteSource() []corpus.Source {
	return []corpus.Source{{
		SourceRef: "vendor",
		Kind:      "vendor_doc",
		Title:     "Example Device Support",
		PublicURL: "https://docs.example.com/device",
	}}
}

func validVersionFactForRelation(relation string) corpus.VersionFact {
	fact := corpus.VersionFact{
		Attribute:    "firmware_version",
		Relation:     relation,
		Value:        "2.4.1",
		ConfidenceBP: 9000,
		SourceRef:    "vendor",
	}
	if relation == "range" {
		fact.ValueEnd = "2.9.9"
	}
	if relation == "family" {
		fact.Value = "2.x"
	}
	return fact
}

func TestNormalizeVariantRequiresRequestLocalProvenanceForEveryFact(t *testing.T) {
	shape := corpusVariantRequest("ignored").Shape
	facts := []corpus.VersionFact{
		validVersionFactForRelation("exact"),
		validVersionFactForRelation("range"),
		validVersionFactForRelation("family"),
	}

	normalized, err := normalizeVariant(shape, 9000, validCorpusWriteSource(), facts)
	if err != nil {
		t.Fatalf("valid exact, range, and family facts rejected: %v", err)
	}
	if len(normalized.facts) != len(facts) {
		t.Fatalf("normalized %d facts, want %d", len(normalized.facts), len(facts))
	}
	for _, fact := range normalized.facts {
		if fact.SourceRef != "vendor" || fact.SourceID != "" || fact.FactID != "" {
			t.Fatalf("unexpected normalized write fact: %#v", fact)
		}
	}

	for _, relation := range []string{"exact", "range", "family"} {
		t.Run(relation+"_missing_source_ref", func(t *testing.T) {
			fact := validVersionFactForRelation(relation)
			fact.SourceRef = "  "
			if _, err := normalizeVariant(shape, 9000, validCorpusWriteSource(), []corpus.VersionFact{fact}); err == nil {
				t.Fatal("unprovenanced version fact unexpectedly accepted")
			}
		})

		t.Run(relation+"_foreign_source_ref", func(t *testing.T) {
			fact := validVersionFactForRelation(relation)
			fact.SourceRef = "other-request"
			if _, err := normalizeVariant(shape, 9000, validCorpusWriteSource(), []corpus.VersionFact{fact}); err == nil {
				t.Fatal("version fact referencing another request unexpectedly accepted")
			}
		})
	}
}

func TestNormalizeVariantRejectsClientSuppliedOutputIDsWithoutReflection(t *testing.T) {
	shape := corpusVariantRequest("ignored").Shape
	const marker = "customer-secret-SN123456789"
	tests := []struct {
		name    string
		sources []corpus.Source
		facts   []corpus.VersionFact
	}{
		{
			name: "source id",
			sources: []corpus.Source{{
				SourceID: marker, SourceRef: "vendor", Kind: "vendor_doc",
				PublicURL: "https://docs.example.com/device",
			}},
		},
		{
			name:    "fact id",
			sources: validCorpusWriteSource(),
			facts: func() []corpus.VersionFact {
				fact := validVersionFactForRelation("exact")
				fact.FactID = marker
				return []corpus.VersionFact{fact}
			}(),
		},
		{
			name:    "fact source id",
			sources: validCorpusWriteSource(),
			facts: func() []corpus.VersionFact {
				fact := validVersionFactForRelation("range")
				fact.SourceID = marker
				return []corpus.VersionFact{fact}
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := normalizeVariant(shape, 9000, tt.sources, tt.facts)
			if err == nil {
				t.Fatal("client-supplied output identifier unexpectedly accepted")
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("validation error reflected supplied identifier: %v", err)
			}
		})
	}
}

func TestCorpusVersionFactSourceIsDatabaseRequired(t *testing.T) {
	db := newTestDB(t)
	rows, err := db.Query(`PRAGMA table_info(device_corpus_version_facts)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err = rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		if name == "source_id" {
			found = true
			if notNull != 1 {
				t.Fatal("device_corpus_version_facts.source_id must be NOT NULL")
			}
		}
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("device_corpus_version_facts.source_id column missing")
	}
}
