// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package policy

import (
	"sync"

	"github.com/tagwright/beacon/internal/alert"
	"github.com/tagwright/courier"
)

// stateEngine owns beacon's firing-to-resolved state. It runs before the router
// so a rule can match on state. A source reports the raw transition on the
// alert; the engine finalizes Alert.State, maintains an in-memory map of what is
// currently firing (v1 keeps this in memory only), and applies any up/down
// phrasing the source deferred to it.
//
// An orphan resolve (no prior firing seen, e.g. after a restart) still carries
// resolved and still notifies: the map only tracks prior firings, it never
// suppresses a resolve.
type stateEngine struct {
	mu     sync.Mutex
	firing map[string]bool
}

func newStateEngine() *stateEngine {
	return &stateEngine{firing: make(map[string]bool)}
}

// apply finalizes the alert's state and phrases it. It keys the firing map on
// the alert's correlation key (its incident identity), so it must run after
// normalize has filled that key.
func (e *stateEngine) apply(a *alert.Alert) {
	if a.State == "" {
		a.State = alert.StateFiring
	}
	id := a.CorrelationKey
	e.mu.Lock()
	if a.State == alert.StateResolved {
		delete(e.firing, id)
	} else {
		e.firing[id] = true
	}
	e.mu.Unlock()
	PhraseStatus(a)
}

// PhraseStatus applies the up/down phrasing the resolution engine owns for a
// source that reports only the raw transition. Today one style ships: "gatus",
// which prepends DOWN or RECOVERED, sets the level from the state, and records
// the status field, reproducing gatus.go's former self-phrased output at the
// delivery boundary. A source with no StatusStyle is left untouched.
func PhraseStatus(a *alert.Alert) {
	switch a.StatusStyle {
	case "gatus":
		status := "DOWN"
		level := courier.LevelError
		if a.State == alert.StateResolved {
			status = "RECOVERED"
			level = courier.LevelInfo
		}
		a.Notification.Title = status + " " + a.Notification.Title
		a.Notification.Level = level
		if a.Notification.Fields == nil {
			a.Notification.Fields = map[string]string{}
		}
		a.Notification.Fields["status"] = status
	}
}
