// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package history is beacon's bounded event-history store. beacon records every
// processed event here, after routing and before the suppression gates, so
// `beacon replay` can run a candidate ruleset against real recent history and
// see events the live ruleset would have suppressed. It is distinct from the
// spool: the spool holds only undelivered alerts and drains on delivery, while
// history is a durable, bounded record of everything that flowed through.
//
// The on-disk shape mirrors the spool: one JSON file per event, written
// atomically (temp file plus rename) so a crash mid-write never leaves a
// half-file. The store is bounded by a max age and a max count, enforced by
// eviction on write so it never grows without limit, and a corrupt entry is
// skipped on read rather than being fatal.
package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tagwright/beacon/internal/clock"
)

// Record is one processed event: the normalized alert's match inputs, its
// identity, and the routing decision captured at record time. It carries
// everything replay needs to re-match against a candidate ruleset.
type Record struct {
	Time     time.Time         `json:"time"`
	Source   string            `json:"source"`
	Event    string            `json:"event"`
	Severity string            `json:"severity,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	State    string            `json:"state"`
	Channel  string            `json:"channel,omitempty"`
	DedupKey string            `json:"dedup_key,omitempty"`
	Title    string            `json:"title,omitempty"`
	Level    string            `json:"level,omitempty"`
	// Leaves is the leaf set the live ruleset resolved to when the event was
	// recorded, for comparison against a replayed candidate.
	Leaves []string `json:"leaves,omitempty"`
}

// Recorder is the write surface the pipeline drives. It is an interface so the
// pipeline can take a nil store (recording disabled) and a fake in tests.
type Recorder interface {
	// Record persists one processed event. It is called unconditionally after
	// routing, never gated on the suppression outcome.
	Record(r Record) error
}

const historyExt = ".json"

// Store is the production Recorder, a bounded per-event disk store.
type Store struct {
	dir      string
	maxAge   time.Duration
	maxCount int
	clock    clock.Clock
	seq      atomic.Uint64
	mu       sync.Mutex
}

// New constructs a Store over dir, creating it if needed. maxAge and maxCount
// bound retention; zero disables that bound.
func New(dir string, maxAge time.Duration, maxCount int, clk clock.Clock) (*Store, error) {
	if clk == nil {
		clk = clock.Real{}
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("beacon: history dir %q: %w", dir, err)
	}
	return &Store{dir: dir, maxAge: maxAge, maxCount: maxCount, clock: clk}, nil
}

// Record writes one event atomically, then evicts to keep the store bounded.
func (s *Store) Record(r Record) error {
	if r.Time.IsZero() {
		r.Time = s.clock.Now()
	}
	data, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("beacon: history marshal: %w", err)
	}
	name := fmt.Sprintf("%020d-%06d%s", s.clock.Now().UnixNano(), s.seq.Add(1), historyExt)
	final := filepath.Join(s.dir, name)
	tmp := final + ".tmp"

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return fmt.Errorf("beacon: history write: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("beacon: history commit: %w", err)
	}
	s.evictLocked()
	return nil
}

// All returns every recorded event in chronological order, skipping any corrupt
// entry (removing it so it never wedges a future read). It errors clearly when
// the store is empty so replay does not route stale or absent data silently.
func (s *Store) All() ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := s.listLocked()
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("beacon: history store %q is empty, nothing to replay", s.dir)
	}
	out := make([]Record, 0, len(files))
	for _, f := range files {
		path := filepath.Join(s.dir, f)
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			continue
		}
		var r Record
		if uerr := json.Unmarshal(data, &r); uerr != nil {
			_ = os.Remove(path) // corrupt: skip and remove, never fatal
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// Len reports how many event files are currently stored.
func (s *Store) Len() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := s.listLocked()
	return len(files), err
}

// evictLocked drops files beyond the count bound (oldest first) and files older
// than the age bound. It reads the timestamp off the filename, so age eviction
// costs no file read.
func (s *Store) evictLocked() {
	files, err := s.listLocked()
	if err != nil {
		return
	}
	// Age bound: filename leads with the write UnixNano.
	if s.maxAge > 0 {
		cutoff := s.clock.Now().Add(-s.maxAge)
		kept := files[:0:0]
		for _, f := range files {
			if ts, ok := fileNanos(f); ok && time.Unix(0, ts).Before(cutoff) {
				_ = os.Remove(filepath.Join(s.dir, f))
				continue
			}
			kept = append(kept, f)
		}
		files = kept
	}
	// Count bound: remove the oldest surplus.
	if s.maxCount > 0 && len(files) > s.maxCount {
		surplus := len(files) - s.maxCount
		for _, f := range files[:surplus] {
			_ = os.Remove(filepath.Join(s.dir, f))
		}
	}
}

func (s *Store) listLocked() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("beacon: history list: %w", err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != historyExt {
			continue
		}
		files = append(files, e.Name())
	}
	sort.Strings(files) // lexical order is chronological (zero-padded nanos)
	return files, nil
}

// fileNanos parses the leading UnixNano from a store filename.
func fileNanos(name string) (int64, bool) {
	base := strings.TrimSuffix(name, historyExt)
	dash := strings.IndexByte(base, '-')
	if dash <= 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(base[:dash], 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}
