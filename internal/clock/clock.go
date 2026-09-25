// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package clock is beacon's time seam. The dedup, correlation, and spool
// layers all decide on elapsed time, so they take a Clock rather than calling
// time.Now directly, which lets a test drive a window to its edge without
// sleeping.
package clock

import (
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
