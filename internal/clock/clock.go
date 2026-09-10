// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package clock is beacon's time seam. The dedup, correlation, and spool
// layers all decide on elapsed time, so they take a Clock rather than calling
// time.Now directly, which lets a test drive a window to its edge without
// sleeping.
package clock

import (
	"sync"
	"time"
)

// Clock reports the current time.
type Clock interface {
	Now() time.Time
}

// Real is the production Clock.
type Real struct{}

// Now returns the wall-clock time.
func (Real) Now() time.Time { return time.Now() }

// Fake is a manually advanced Clock for tests. Its zero value starts at the
// Unix epoch; use NewFake to start elsewhere. It is safe for concurrent use.
type Fake struct {
	mu  sync.Mutex
	now time.Time
}

// NewFake returns a Fake started at t.
func NewFake(t time.Time) *Fake {
	return &Fake{now: t}
}

// Now returns the fake's current time.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Advance moves the fake clock forward by d.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}
