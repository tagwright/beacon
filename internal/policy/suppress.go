// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package policy

import (
	"sort"
	"sync"
	"time"

	"github.com/tagwright/beacon/internal/clock"
)

// maxSuppressEntries bounds the in-memory window state, evicted FIFO at the
// cap, matching airlock's model (no time-based expiry of an idle entry).
const maxSuppressEntries = 20000

// suppressEntry is the per-key window bookkeeping, following airlock's grammar:
// the window is anchored on the last FIRE, not the last hit, so repeats within
// the window do not slide it. Two suppressed counters track the same
// underlying repeats for two independent readers with separate reset points:
// suppressedSinceAlert is reported as "N since last alert" on the next fire and
// reset then; suppressedSinceDigest is reported by the periodic digest and
// reset when the digest drains it.
type suppressEntry struct {
	order                int
	windowStart          time.Time
	suppressedSinceAlert int
	suppressedSinceDigest int
	channel              string
	title                string
}

// suppressor is beacon's windowed dedup/storm state. It is used twice in the
// pipeline: once keyed on the dedup key (fine, storm suppression) and once
// keyed on the correlation key (coarse, cross-source incident collapse).
//
// The fire decision is split into suppressedRecently (a read that counts a
// repeat) and recordFired (commit a fire), so two suppressors can be consulted
// in sequence without one resetting its window for an alert the other then
// suppresses.
type suppressor struct {
	mu            sync.Mutex
	clock         clock.Clock
	defaultWindow time.Duration
	seq           int
	entries       map[string]*suppressEntry
}

func newSuppressor(clk clock.Clock, defaultWindow time.Duration) *suppressor {
	if clk == nil {
		clk = clock.Real{}
	}
	return &suppressor{
		clock:         clk,
		defaultWindow: defaultWindow,
		entries:       make(map[string]*suppressEntry),
	}
}

// suppressedRecently reports whether key fired within its window, in which case
// this occurrence is a suppressed repeat and both counters are incremented. A
// first occurrence, or one after the window has elapsed, is not suppressed and
// does not mutate the window (recordFired commits that).
func (s *suppressor) suppressedRecently(key string, window time.Duration) bool {
	if window <= 0 {
		window = s.defaultWindow
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.entries[key]
	if !ok {
		return false
	}
	if s.clock.Now().Sub(st.windowStart) >= window {
		return false
	}
	st.suppressedSinceAlert++
	st.suppressedSinceDigest++
	return true
}

// recordFired commits a fire for key: it arms (or re-arms) the window at now
// and returns the count suppressed since the last fire (for the "N since last
// alert" line), resetting that counter. It creates the entry on a first
// occurrence, evicting the oldest at the cap.
func (s *suppressor) recordFired(key, channel, title string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.entries[key]
	if !ok {
		if len(s.entries) >= maxSuppressEntries {
			s.evictOldestLocked()
		}
		st = &suppressEntry{order: s.seq}
		s.seq++
		s.entries[key] = st
	}
	sinceLast := st.suppressedSinceAlert
	st.windowStart = s.clock.Now()
	st.suppressedSinceAlert = 0
	st.channel = channel
	st.title = title
	return sinceLast
}

// digestItem is one line of a suppression digest.
type digestItem struct {
	Channel string
	Title   string
	Count   int
}

// drainDigest returns and resets the suppressed-since-digest counts across all
// keys, for the periodic rollup.
func (s *suppressor) drainDigest() []digestItem {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []digestItem
	for _, st := range s.entries {
		if st.suppressedSinceDigest > 0 {
			out = append(out, digestItem{Channel: st.channel, Title: st.title, Count: st.suppressedSinceDigest})
			st.suppressedSinceDigest = 0
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Channel != out[j].Channel {
			return out[i].Channel < out[j].Channel
		}
		return out[i].Title < out[j].Title
	})
	return out
}

func (s *suppressor) evictOldestLocked() {
	var oldestKey string
	oldest := int(^uint(0) >> 1)
	for k, st := range s.entries {
		if st.order < oldest {
			oldest = st.order
			oldestKey = k
		}
	}
	if oldestKey != "" {
		delete(s.entries, oldestKey)
	}
}
