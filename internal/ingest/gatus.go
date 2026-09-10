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
// to a native alert. A recovered status is informational; anything else alerts
// at error level, matching beacon-server's routing.
func (GatusAdapter) Adapt(body []byte, r *http.Request) (alert.Alert, error) {
	var ev gatusEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		return alert.Alert{}, fmt.Errorf("beacon: gatus payload: %w", err)
	}
	status := normalizeGatusStatus(ev.Status)
	level := courier.LevelError
	if status == "RECOVERED" {
		level = courier.LevelInfo
	}
	target := ev.Group + "/" + ev.Endpoint
	return alert.Alert{
		Channel:        "",
		DedupKey:       "gatus|" + target,
		CorrelationKey: target,
		Source:         alert.SourceIngest,
		Adapter:        "gatus",
		Container:      ev.Endpoint,
		Event:          "gatus",
		Time:           time.Now(),
		Notification: courier.Notification{
			Title: fmt.Sprintf("%s Gatus %s", status, target),
			Body:  ev.Description,
			Level: level,
			Fields: map[string]string{
				"source":   "gatus",
				"group":    ev.Group,
				"endpoint": ev.Endpoint,
				"status":   status,
			},
		},
	}, nil
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
