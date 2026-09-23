// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package policy

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/tagwright/beacon/internal/ingest"
	"github.com/tagwright/courier"
)

// The gatus golden vectors pin the consumer-visible DOWN and RECOVERED output
// (Title, Body, Level, Fields) at the delivery boundary. They are the exact
// output beacon-server / the pre-migration gatus.go produced, so the migration
// (gatus reports the raw transition, the resolution engine phrases it) is proven
// unchanged except for the deliberate fast-recovery suppression fix, which does
// not alter a delivered alert's bytes.
//
// The consumer-visible output is the gatus adapter's alert AFTER the resolution
// engine's PhraseStatus runs, which is what reaches courier.

type goldenVector struct {
	status string
	title  string
	body   string
	level  courier.Level
	fields map[string]string
}

var gatusGolden = map[string]goldenVector{
	"DOWN": {
		status: "DOWN",
		title:  "DOWN Gatus apps/web",
		body:   "connection refused",
		level:  courier.LevelError,
		fields: map[string]string{"source": "gatus", "group": "apps", "endpoint": "web", "status": "DOWN"},
	},
	"RECOVERED": {
		status: "RECOVERED",
		title:  "RECOVERED Gatus apps/web",
		body:   "back to normal",
		level:  courier.LevelInfo,
		fields: map[string]string{"source": "gatus", "group": "apps", "endpoint": "web", "status": "RECOVERED"},
	},
}

func TestGatusGoldenVectors(t *testing.T) {
	for name, want := range gatusGolden {
		t.Run(name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{
				"endpoint":    "web",
				"group":       "apps",
				"status":      want.status,
				"description": want.body,
			})
			alerts, err := ingest.GatusAdapter{}.Adapt(body, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(alerts) != 1 {
				t.Fatalf("gatus adapter should produce one alert, got %d", len(alerts))
			}
			a := alerts[0]
			// The resolution engine phrases the raw transition into the
			// consumer-visible output.
			PhraseStatus(&a)

			if a.Notification.Title != want.title {
				t.Errorf("Title = %q, want %q", a.Notification.Title, want.title)
			}
			if a.Notification.Body != want.body {
				t.Errorf("Body = %q, want %q", a.Notification.Body, want.body)
			}
			if a.Notification.Level != want.level {
				t.Errorf("Level = %v, want %v", a.Notification.Level, want.level)
			}
			if !reflect.DeepEqual(a.Notification.Fields, want.fields) {
				t.Errorf("Fields = %v, want %v", a.Notification.Fields, want.fields)
			}
		})
	}
}
