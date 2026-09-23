// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package ingest

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/tagwright/beacon/internal/alert"
	"github.com/tagwright/beacon/internal/clock"
	"github.com/tagwright/courier"
)

var (
	beaconKey  = []byte("beacon-shared-key")
	vikunjaKey = []byte("vikunja-shared-key")
)

// perAdapterServer builds a server where native verifies X-Beacon-Signature,
// gatus is unauthenticated, and vikunja verifies X-Vikunja-Signature with its
// own key, the arrangement C24 requires.
func perAdapterServer(cap *captured) *Server {
	return NewServer(Options{
		Authenticators: map[string]Authenticator{
			"native":  NewHMACAuth(beaconKey),
			"gatus":   NoAuth{},
			"vikunja": NewHMACAuthHeader(vikunjaKey, VikunjaSignatureHeader),
		},
		Emit:           cap.emit,
		DefaultChannel: "ops",
	})
}

func vikunjaBody(t *testing.T, eventName string, data any) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"event_name": eventName,
		"time":       time.Now().UTC().Format(time.RFC3339),
		"data":       data,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestPerAdapterAuthMatrix is the signature tamper matrix (C24): each adapter
// verifies its own header and key, a request signed for the wrong header or with
// the wrong key is rejected, and gatus stays unauthenticated while vikunja is
// hmac.
func TestPerAdapterAuthMatrix(t *testing.T) {
	body := vikunjaBody(t, "task.overdue", map[string]any{
		"task": map[string]any{"id": 7, "title": "ship it", "identifier": "PRJ-7"},
	})

	cases := []struct {
		name    string
		path    string
		body    []byte
		headers map[string]string
		code    int
	}{
		{
			name:    "vikunja correct header and key verifies",
			path:    "/alert/vikunja",
			body:    body,
			headers: map[string]string{VikunjaSignatureHeader: Sign(vikunjaKey, body)},
			code:    http.StatusOK,
		},
		{
			name:    "vikunja signed into the beacon header is rejected",
			path:    "/alert/vikunja",
			body:    body,
			headers: map[string]string{SignatureHeader: Sign(vikunjaKey, body)},
			code:    http.StatusUnauthorized,
		},
		{
			name:    "vikunja wrong key is rejected",
			path:    "/alert/vikunja",
			body:    body,
			headers: map[string]string{VikunjaSignatureHeader: Sign(beaconKey, body)},
			code:    http.StatusUnauthorized,
		},
		{
			name:    "native correct beacon signature verifies",
			path:    "/alert/native",
			body:    nativeBody(time.Now()),
			headers: nil, // filled below
			code:    http.StatusOK,
		},
		{
			name:    "native with the vikunja key is rejected",
			path:    "/alert/native",
			body:    nativeBody(time.Now()),
			headers: nil, // filled below
			code:    http.StatusUnauthorized,
		},
		{
			name:    "gatus stays unauthenticated",
			path:    "/alert/gatus",
			body:    []byte(`{"endpoint":"web","group":"apps","status":"DOWN"}`),
			headers: nil,
			code:    http.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cap := &captured{}
			srv := perAdapterServer(cap)
			headers := tc.headers
			switch tc.name {
			case "native correct beacon signature verifies":
				headers = map[string]string{SignatureHeader: Sign(beaconKey, tc.body)}
			case "native with the vikunja key is rejected":
				headers = map[string]string{SignatureHeader: Sign(vikunjaKey, tc.body)}
			}
			rec := post(t, srv.Handler(), tc.path, tc.body, headers)
			if rec.Code != tc.code {
				t.Fatalf("code = %d, want %d (body %s)", rec.Code, tc.code, rec.Body.String())
			}
		})
	}
}

// TestHMACNoKeyFailsClosed proves an hmac adapter with no key rejects every
// request rather than opening the listener (C24).
func TestHMACNoKeyFailsClosed(t *testing.T) {
	a := NewHMACAuth(nil)
	req, _ := http.NewRequest(http.MethodPost, "/alert/native", nil)
	req.Header.Set(SignatureHeader, "anything")
	if err := a.Verify(req, []byte("body")); err == nil {
		t.Fatal("an hmac authenticator with no key must fail closed")
	}
}

// TestContractServedForEachAdapter proves the endpoint routes native, gatus, and
// vikunja to their adapters and returns 404 for an unknown adapter (C25).
func TestContractServedForEachAdapter(t *testing.T) {
	cap := &captured{}
	srv := perAdapterServer(cap)

	// native
	nb := nativeBody(time.Now())
	if rec := post(t, srv.Handler(), "/alert/native", nb, map[string]string{SignatureHeader: Sign(beaconKey, nb)}); rec.Code != http.StatusOK {
		t.Fatalf("native route = %d", rec.Code)
	}
	// gatus
	if rec := post(t, srv.Handler(), "/alert/gatus", []byte(`{"endpoint":"web","group":"apps","status":"DOWN"}`), nil); rec.Code != http.StatusOK {
		t.Fatalf("gatus route = %d", rec.Code)
	}
	// vikunja
	vb := vikunjaBody(t, "task.overdue", map[string]any{"task": map[string]any{"id": 1, "title": "t"}})
	if rec := post(t, srv.Handler(), "/alert/vikunja", vb, map[string]string{VikunjaSignatureHeader: Sign(vikunjaKey, vb)}); rec.Code != http.StatusOK {
		t.Fatalf("vikunja route = %d", rec.Code)
	}
	// unknown
	if rec := post(t, srv.Handler(), "/alert/nope", []byte(`{}`), nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown adapter = %d, want 404", rec.Code)
	}
}

// --- C26: the vikunja adapter itself, driven directly -----------------------

func decodeVikunja(t *testing.T, eventName string, data any) []alert.Alert {
	t.Helper()
	body := vikunjaBody(t, eventName, data)
	alerts, err := VikunjaAdapter{}.Adapt(body, nil)
	if err != nil {
		t.Fatalf("vikunja adapt: %v", err)
	}
	return alerts
}

func TestVikunjaReminderFired(t *testing.T) {
	alerts := decodeVikunja(t, "task.reminder.fired", map[string]any{
		"task": map[string]any{"id": 42, "title": "water the plants", "identifier": "HOME-3", "due_date": "2026-10-01T09:00:00Z"},
	})
	if len(alerts) != 1 {
		t.Fatalf("reminder should be one alert, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Event != "vikunja" {
		t.Errorf("Event = %q, want vikunja", a.Event)
	}
	if a.Notification.Level != courier.LevelInfo {
		t.Errorf("reminder level = %v, want info", a.Notification.Level)
	}
	if a.Notification.Title != "Task reminder: HOME-3 water the plants" {
		t.Errorf("title = %q", a.Notification.Title)
	}
	if a.DedupKey != "vikunja|42" {
		t.Errorf("dedup key = %q, want vikunja|42", a.DedupKey)
	}
	if a.Notification.Fields["event_name"] != "task.reminder.fired" {
		t.Errorf("event_name field = %q", a.Notification.Fields["event_name"])
	}
	if a.Notification.Body == "" {
		t.Error("a present due date should populate the body")
	}
}

func TestVikunjaTaskOverdue(t *testing.T) {
	alerts := decodeVikunja(t, "task.overdue", map[string]any{
		"task": map[string]any{"id": 9, "title": "renew cert"}, // no identifier, no due_date
	})
	if len(alerts) != 1 {
		t.Fatalf("overdue should be one alert, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Notification.Level != courier.LevelWarning {
		t.Errorf("overdue level = %v, want warning", a.Notification.Level)
	}
	// Empty identifier: the trailing space is omitted.
	if a.Notification.Title != "Task overdue: renew cert" {
		t.Errorf("empty-identifier title = %q, want 'Task overdue: renew cert'", a.Notification.Title)
	}
	// Zero due date: body is empty.
	if a.Notification.Body != "" {
		t.Errorf("a zero due date should leave the body empty, got %q", a.Notification.Body)
	}
	if a.DedupKey != "vikunja|9" {
		t.Errorf("dedup key = %q, want vikunja|9", a.DedupKey)
	}
}

func TestVikunjaTasksOverdueList(t *testing.T) {
	alerts := decodeVikunja(t, "tasks.overdue", map[string]any{
		"tasks": []any{
			map[string]any{"id": 1, "title": "a", "identifier": "P-1"},
			map[string]any{"id": 2, "title": "b"},
			map[string]any{"id": 3, "title": "c", "due_date": "2026-01-02T03:04:05Z"},
		},
	})
	if len(alerts) != 3 {
		t.Fatalf("tasks.overdue must produce one alert per task, got %d", len(alerts))
	}
	for _, a := range alerts {
		if a.Notification.Level != courier.LevelWarning {
			t.Errorf("each tasks.overdue alert should be warning, got %v", a.Notification.Level)
		}
		if a.Event != "vikunja" || a.Notification.Fields["event_name"] != "tasks.overdue" {
			t.Errorf("event wiring wrong: %+v", a.Notification.Fields)
		}
	}
	if alerts[0].DedupKey != "vikunja|1" || alerts[2].DedupKey != "vikunja|3" {
		t.Errorf("per-task dedup keys wrong: %q .. %q", alerts[0].DedupKey, alerts[2].DedupKey)
	}
}

// TestReplayGuardReadsTopLevelTime proves a payload carrying only a top-level
// `time` field (the Vikunja envelope shape) is replay-guarded (C27).
func TestReplayGuardReadsTopLevelTime(t *testing.T) {
	cap := &captured{}
	clk := clock.NewFake(time.Unix(1_700_000_000, 0))
	srv := NewServer(Options{
		Auth:    NoAuth{},
		Emit:    cap.emit,
		MaxSkew: time.Minute,
		Clock:   clk,
	})
	// A vikunja-shaped body whose top-level time is well outside the skew.
	body, _ := json.Marshal(map[string]any{
		"event_name": "task.overdue",
		"time":       clk.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339),
		"data":       map[string]any{"task": map[string]any{"id": 1, "title": "t"}},
	})
	rec := post(t, srv.Handler(), "/alert/vikunja", body, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a stale top-level time must be replay-rejected, code = %d", rec.Code)
	}
	if len(cap.alerts) != 0 {
		t.Fatal("a replayed vikunja request must not emit")
	}
}
