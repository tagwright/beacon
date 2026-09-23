// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// This file is the first-class Gatus adapter, absorbing what beacon-server did
// for Gatus. Gatus is a widely used public monitor with a generic custom-alert
// webhook shape, so it ships as a built-in adapter. It translates Gatus's flat
// event into beacon's native alert; the destination and channel are deployment
// config, never baked in.
package ingest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tagwright/beacon/internal/alert"
	"github.com/tagwright/courier"
)

// gatusEvent is Gatus's custom-alert webhook body, the shape beacon-server
// accepted: four flat string fields.
type gatusEvent struct {
	Endpoint    string `json:"endpoint"`
	Group       string `json:"group"`
	Status      string `json:"status"`
	Description string `json:"description"`
}

// GatusAdapter parses a Gatus custom-alert webhook into a native alert.
type GatusAdapter struct{}

// Adapt decodes the Gatus event, normalizes its status vocabulary, and maps it
// to a native alert. It reports the raw transition as Alert.State and defers the
// DOWN/RECOVERED phrasing (the leading status word, the level, and the status
// field) to the resolution engine, which owns firing-to-resolved. The
// consumer-visible output is unchanged at the delivery boundary; the resolution
// engine now decides notify-on-resolved and the fast-recovery fix. An unrecognized
// status word has no DOWN/RECOVERED transition to defer, so it is phrased here at
// error level exactly as before.
func (GatusAdapter) Adapt(body []byte, r *http.Request) ([]alert.Alert, error) {
	var ev gatusEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		return nil, fmt.Errorf("beacon: gatus payload: %w", err)
	}
	status := normalizeGatusStatus(ev.Status)
	target := ev.Group + "/" + ev.Endpoint
	a := alert.Alert{
		Channel:        "",
		DedupKey:       "gatus|" + target,
		CorrelationKey: target,
		Source:         alert.SourceIngest,
		Adapter:        "gatus",
		Container:      ev.Endpoint,
		Event:          "gatus",
		Time:           time.Now(),
		Notification: courier.Notification{
			Body: ev.Description,
			Fields: map[string]string{
				"source":   "gatus",
				"group":    ev.Group,
				"endpoint": ev.Endpoint,
			},
		},
	}
	switch status {
	case "DOWN", "RECOVERED":
		// The engine prepends the status word, sets the level from the state,
		// and records the status field. The base title is the bare subject.
		a.State = alert.StateFiring
		if status == "RECOVERED" {
			a.State = alert.StateResolved
		}
		a.StatusStyle = "gatus"
		a.Notification.Title = "Gatus " + target
	default:
		// Unknown status: no up/down transition, phrase it here at error level
		// exactly as beacon-server did.
		a.State = alert.StateFiring
		a.Notification.Title = fmt.Sprintf("%s Gatus %s", status, target)
		a.Notification.Level = courier.LevelError
		a.Notification.Fields["status"] = status
	}
	return []alert.Alert{a}, nil
}

// normalizeGatusStatus folds Gatus's status words into DOWN or RECOVERED, and
// passes an unknown status through unchanged so it still alerts.
func normalizeGatusStatus(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "TRIGGERED", "DOWN":
		return "DOWN"
	case "RESOLVED", "RECOVERED":
		return "RECOVERED"
	default:
		return strings.ToUpper(strings.TrimSpace(s))
	}
}
