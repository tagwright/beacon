// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package history

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tagwright/beacon/internal/clock"
)

func sampleRecord(event string) Record {
	return Record{
		Source:   "watch",
		Event:    event,
		Severity: "critical",
		Labels:   map[string]string{"env": "prod"},
		State:    "firing",
		Channel:  "fleet",
		DedupKey: "c1|" + event,
		Title:    event + ": c1",
		Level:    "error",
		Leaves:   []string{"signal-ops"},
	}
}

// TestRecordRoundTrip proves an event is recorded and read back with its match
// inputs intact, so replay can re-match (C18).
func TestRecordRoundTrip(t *testing.T) {
	store, err := New(t.TempDir(), 0, 0, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	rec := sampleRecord("oom")
	if err := store.Record(rec); err != nil {
		t.Fatal(err)
	}
	all, err := store.All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("read back %d records, want 1", len(all))
	}
	got := all[0]
	if got.Event != "oom" || got.Severity != "critical" || got.Labels["env"] != "prod" || got.State != "firing" {
		t.Errorf("round-trip lost fields: %+v", got)
	}
	if len(got.Leaves) != 1 || got.Leaves[0] != "signal-ops" {
		t.Errorf("round-trip lost routing decision: %+v", got.Leaves)
	}
}

// TestEmptyStoreErrors proves replay gets a clear error rather than silently
// routing nothing (C19).
func TestEmptyStoreErrors(t *testing.T) {
	store, err := New(t.TempDir(), 0, 0, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.All(); err == nil {
		t.Fatal("an empty store must error on All, not return an empty slice silently")
	}
}

// TestCorruptEntrySkipped proves a corrupt entry is skipped, not fatal (C18).
func TestCorruptEntrySkipped(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir, 0, 0, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Record(sampleRecord("die")); err != nil {
		t.Fatal(err)
	}
	// Plant a corrupt file alongside the valid record.
	corrupt := filepath.Join(dir, "00000000000000000001-000001.json")
	if err := os.WriteFile(corrupt, []byte("{not json"), 0o640); err != nil {
		t.Fatal(err)
	}
	all, err := store.All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("corrupt entry should be skipped, got %d records", len(all))
	}
	if _, err := os.Stat(corrupt); !os.IsNotExist(err) {
		t.Error("a corrupt entry should be removed so it never wedges a future read")
	}
}

// TestMaxCountEviction proves the count bound is enforced by eviction, oldest
// first (C19). Level-1 retention arithmetic over the input space.
func TestMaxCountEviction(t *testing.T) {
	store, err := New(t.TempDir(), 0, 3, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if err := store.Record(sampleRecord("e")); err != nil {
			t.Fatal(err)
		}
	}
	n, err := store.Len()
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("max_count=3 should bound the store at 3, got %d", n)
	}
}

// TestMaxAgeEviction proves the age bound evicts records older than max_age
// (C19), using the injected clock.
func TestMaxAgeEviction(t *testing.T) {
	clk := clock.NewFake(time.Unix(1_700_000_000, 0))
	store, err := New(t.TempDir(), time.Hour, 0, clk)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Record(sampleRecord("old")); err != nil {
		t.Fatal(err)
	}
	clk.Advance(2 * time.Hour)
	// This write triggers eviction; the first record is now older than max_age.
	if err := store.Record(sampleRecord("new")); err != nil {
		t.Fatal(err)
	}
	all, err := store.All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].Event != "new" {
		t.Fatalf("the aged-out record should be evicted, got %+v", all)
	}
}
