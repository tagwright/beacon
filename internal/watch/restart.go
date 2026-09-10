// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package watch

import (
	"sync"
	"time"

	"github.com/tagwright/beacon/internal/clock"
)

// restartDetector is beacon's own restart-loop policy. core reports a
// container's raw RestartCount on Inspect; beacon decides what a loop is. A
// container start counts as a restart only when its RestartCount is above zero
// (so a first, fresh start is never a loop), and a loop is declared when the
// restart cadence reaches the threshold within the sliding window. A cooldown
// of one window after a declared loop stops it re-firing on every subsequent
// start; the pipeline's dedup layer collapses any that slip through.
type restartDetector struct {
	mu        sync.Mutex
	clock     clock.Clock
	threshold int
	window    time.Duration
	seen      map[string]*restartState
}

type restartState struct {
	times         []time.Time
	cooldownUntil time.Time
}

func newRestartDetector(clk clock.Clock, threshold int, window time.Duration) *restartDetector {
	if clk == nil {
		clk = clock.Real{}
	}
	return &restartDetector{
		clock:     clk,
		threshold: threshold,
		window:    window,
		seen:      make(map[string]*restartState),
	}
}

// observe records a start for a container and reports whether it constitutes a
// restart loop. restartCount is the container's current RestartCount from
// Inspect.
func (d *restartDetector) observe(id string, restartCount int) bool {
	if d.threshold <= 0 || restartCount <= 0 {
		return false
	}
	now := d.clock.Now()
	cutoff := now.Add(-d.window)

	d.mu.Lock()
	defer d.mu.Unlock()

	st, ok := d.seen[id]
	if !ok {
		st = &restartState{}
		d.seen[id] = st
	}

	kept := st.times[:0]
	for _, t := range st.times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	st.times = kept

	if len(kept) >= d.threshold && now.After(st.cooldownUntil) {
		st.cooldownUntil = now.Add(d.window)
		return true
	}
	return false
}
