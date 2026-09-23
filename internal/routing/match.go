// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package routing

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Input is the set of alert attributes the matcher tests. It is a small value
// so the engine does not couple to the full alert type, and so replay and
// explain can synthesize one.
type Input struct {
	// Channel is the entry channel name (a container beacon.channel or an
	// ingest channel), or empty for the fleet default.
	Channel string
	// Event is the event type or ingest source name.
	Event string
	// Source is watch or ingest.
	Source string
	// Severity is the container beacon.severity, empty for an ingest alert.
	Severity string
	// Labels are the raw container labels, nil for an ingest alert.
	Labels map[string]string
	// State is firing or resolved.
	State string
	// Time is the alert wall-clock time. The matcher converts it to the
	// engine timezone; it never reads the real clock, so replay evaluates at
	// the recorded time.
	Time time.Time
}

// matches reports whether every present dimension of m matches in. An empty
// match matches everything.
func (e *Engine) matches(m Match, in Input) bool {
	if !matchStringOrList(m.Event, in.Event) {
		return false
	}
	if m.Source != "" && m.Source != in.Source {
		return false
	}
	if !matchStringOrList(m.Severity, in.Severity) {
		return false
	}
	if !matchLabels(m.Labels, in.Labels) {
		return false
	}
	if len(m.State) > 0 && !containsExact(m.State, in.State) {
		return false
	}
	if m.Time != "" {
		w, err := parseTimeWindow(m.Time)
		if err != nil {
			// A malformed window is caught at load; defensively it never matches.
			return false
		}
		if !w.contains(in.Time.In(e.loc)) {
			return false
		}
	}
	return true
}

// matchStringOrList reports whether an OR-list matches value. An empty list is
// a wildcard (true). An empty value with a non-empty list is a non-match.
func matchStringOrList(list StringOrList, value string) bool {
	if len(list) == 0 {
		return true
	}
	return containsExact(list, value)
}

func containsExact(list StringOrList, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}

// matchLabels reports whether every wanted label is present with the exact
// value. An absent key is a non-match; an empty-string wanted value matches a
// present key holding an empty value.
func matchLabels(want, have map[string]string) bool {
	for k, v := range want {
		got, ok := have[k]
		if !ok || got != v {
			return false
		}
	}
	return true
}

// timeWindow is a parsed HH:MM-HH:MM window in minutes-since-midnight, with a
// wrap flag for a window that spans midnight (start>end).
type timeWindow struct {
	startMin int
	endMin   int
	wrap     bool
}

// parseTimeWindow parses "HH:MM-HH:MM". start is inclusive, end exclusive.
// start>end wraps midnight. start==end is an error (an empty or full-day window
// is ambiguous and disallowed).
func parseTimeWindow(s string) (timeWindow, error) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return timeWindow{}, fmt.Errorf("beacon: time %q must be HH:MM-HH:MM", s)
	}
	start, err := parseHHMM(parts[0])
	if err != nil {
		return timeWindow{}, err
	}
	end, err := parseHHMM(parts[1])
	if err != nil {
		return timeWindow{}, err
	}
	if start == end {
		return timeWindow{}, fmt.Errorf("beacon: time %q has start==end, which matches nothing or everything", s)
	}
	return timeWindow{startMin: start, endMin: end, wrap: start > end}, nil
}

func parseHHMM(s string) (int, error) {
	s = strings.TrimSpace(s)
	hm := strings.Split(s, ":")
	if len(hm) != 2 {
		return 0, fmt.Errorf("beacon: time component %q must be HH:MM", s)
	}
	h, err := strconv.Atoi(hm[0])
	if err != nil || h < 0 || h > 23 {
		return 0, fmt.Errorf("beacon: hour in %q must be 00-23", s)
	}
	m, err := strconv.Atoi(hm[1])
	if err != nil || m < 0 || m > 59 {
		return 0, fmt.Errorf("beacon: minute in %q must be 00-59", s)
	}
	return h*60 + m, nil
}

// contains reports whether t (already in the engine timezone) falls in the
// window, start inclusive and end exclusive.
func (w timeWindow) contains(t time.Time) bool {
	min := t.Hour()*60 + t.Minute()
	if w.wrap {
		// e.g. 22:00-07:00: match >=start OR <end.
		return min >= w.startMin || min < w.endMin
	}
	return min >= w.startMin && min < w.endMin
}
