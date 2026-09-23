// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package main

import (
	"os"
	"strings"
	"testing"
)

// repoFile reads a file relative to the repo root (two levels up from cmd/beacon).
func repoFile(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile("../../" + rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

// TestVersionFile proves the VERSION file carries 00.01.00 (C28).
func TestVersionFile(t *testing.T) {
	if got := strings.TrimSpace(repoFile(t, "VERSION")); got != "00.01.00" {
		t.Fatalf("VERSION = %q, want 00.01.00", got)
	}
}

// TestTestingDocCitesNewTests proves docs/TESTING.md exists and cites the new
// test files, per the Testing Standard's honesty convention (C28).
func TestTestingDocCitesNewTests(t *testing.T) {
	doc := repoFile(t, "docs/TESTING.md")
	for _, cite := range []string{
		"TestRunFanOutSpoolsOnlyFailedLeaf",
		"TestGatusGoldenVectors",
		"TestPerAdapterAuthMatrix",
		"internal/routing/tools/tools_test.go",
	} {
		if !strings.Contains(doc, cite) {
			t.Errorf("docs/TESTING.md should cite %q", cite)
		}
	}
}

// TestIngestContractDocExists proves the ingest contract is documented (C25).
func TestIngestContractDocExists(t *testing.T) {
	doc := repoFile(t, "docs/INGEST.md")
	if !strings.Contains(doc, "POST /alert/") {
		t.Error("docs/INGEST.md should document the POST /alert/<source> endpoint")
	}
	if !strings.Contains(doc, "vikunja") {
		t.Error("docs/INGEST.md should document the vikunja adapter")
	}
}

// TestLabelsDocSeverity proves docs/LABELS.md documents beacon.severity and the
// raw-container-label match note (C16).
func TestLabelsDocSeverity(t *testing.T) {
	doc := repoFile(t, "docs/LABELS.md")
	if !strings.Contains(doc, "beacon.severity") {
		t.Error("docs/LABELS.md should document beacon.severity")
	}
	if !strings.Contains(doc, "routing match inputs") && !strings.Contains(doc, "match on a container") {
		t.Error("docs/LABELS.md should note that raw container labels are match inputs")
	}
}
