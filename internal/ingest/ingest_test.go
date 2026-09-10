// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tagwright/beacon/internal/alert"
	"github.com/tagwright/beacon/internal/clock"
)

type captured struct {
	alerts []alert.Alert
}

func (c *captured) emit(ctx context.Context, a alert.Alert) error {
	c.alerts = append(c.alerts, a)
	return nil
}

func post(t *testing.T, h http.Handler, path string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var testKey = []byte("shared-secret-key")

func nativeBody(ts time.Time) []byte {
	b, _ := json.Marshal(map[string]any{
		"title":     "disk full",
		"level":     "error",
		"channel":   "ops",
		"timestamp": ts.UTC().Format(time.RFC3339),
	})
	return b
}

func TestHMACAcceptsValidSignature(t *testing.T) {
	cap := &captured{}
	srv := NewServer(Options{Auth: NewHMACAuth(testKey), Emit: cap.emit})
	body := nativeBody(time.Now())
	rec := post(t, srv.Handler(), "/alert/native", body, map[string]string{
		SignatureHeader: Sign(testKey, body),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if len(cap.alerts) != 1 || cap.alerts[0].Channel != "ops" {
		t.Fatalf("emitted %+v", cap.alerts)
	}
}

func TestHMACRejectsBadSignature(t *testing.T) {
	cap := &captured{}
	srv := NewServer(Options{Auth: NewHMACAuth(testKey), Emit: cap.emit})
	body := nativeBody(time.Now())
	rec := post(t, srv.Handler(), "/alert/native", body, map[string]string{
		SignatureHeader: "deadbeef",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
	if len(cap.alerts) != 0 {
		t.Fatalf("a rejected request must not emit an alert")
	}
}

func TestHMACRejectsMissingSignature(t *testing.T) {
	cap := &captured{}
	srv := NewServer(Options{Auth: NewHMACAuth(testKey), Emit: cap.emit})
	body := nativeBody(time.Now())
	rec := post(t, srv.Handler(), "/alert/native", body, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
}

func TestReplayRejectsStaleTimestamp(t *testing.T) {
	cap := &captured{}
	clk := clock.NewFake(time.Unix(1_700_000_000, 0))
	srv := NewServer(Options{
		Auth:    NewHMACAuth(testKey),
		Emit:    cap.emit,
		MaxSkew: time.Minute,
		Clock:   clk,
	})
	// A validly signed request whose timestamp is well outside the skew window.
	body := nativeBody(clk.Now().Add(-10 * time.Minute))
	rec := post(t, srv.Handler(), "/alert/native", body, map[string]string{
		SignatureHeader: Sign(testKey, body),
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("stale timestamp must be rejected, code = %d", rec.Code)
	}
	if len(cap.alerts) != 0 {
		t.Fatalf("a replayed request must not emit an alert")
	}
}

func TestReplayAcceptsFreshTimestamp(t *testing.T) {
	cap := &captured{}
	clk := clock.NewFake(time.Unix(1_700_000_000, 0))
	srv := NewServer(Options{
		Auth:    NewHMACAuth(testKey),
		Emit:    cap.emit,
		MaxSkew: time.Minute,
		Clock:   clk,
	})
	body := nativeBody(clk.Now())
	rec := post(t, srv.Handler(), "/alert/native", body, map[string]string{
		SignatureHeader: Sign(testKey, body),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("fresh timestamp should be accepted, code = %d body %s", rec.Code, rec.Body.String())
	}
	if len(cap.alerts) != 1 {
		t.Fatalf("emitted %+v", cap.alerts)
	}
}

func TestNoAuthAcceptsClosedNetwork(t *testing.T) {
	cap := &captured{}
	srv := NewServer(Options{Auth: NoAuth{}, Emit: cap.emit})
	body := nativeBody(time.Now())
	rec := post(t, srv.Handler(), "/alert/native", body, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("NoAuth should accept, code = %d", rec.Code)
	}
}

func TestGatusAdapter(t *testing.T) {
	cap := &captured{}
	srv := NewServer(Options{Auth: NoAuth{}, Emit: cap.emit, DefaultChannel: "ops"})
	body, _ := json.Marshal(map[string]string{
		"endpoint":    "web",
		"group":       "apps",
		"status":      "DOWN",
		"description": "connection refused",
	})
	rec := post(t, srv.Handler(), "/alert/gatus", body, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d body %s", rec.Code, rec.Body.String())
	}
	if len(cap.alerts) != 1 {
		t.Fatalf("emitted %+v", cap.alerts)
	}
	a := cap.alerts[0]
	if a.Adapter != "gatus" {
		t.Errorf("adapter = %q, want gatus", a.Adapter)
	}
	if a.Channel != "ops" {
		t.Errorf("channel should default to ops, got %q", a.Channel)
	}
	if a.CorrelationKey != "apps/web" {
		t.Errorf("correlation key = %q, want apps/web", a.CorrelationKey)
	}
	if fmt.Sprintf("%v", a.Notification.Level) == "info" {
		t.Errorf("a DOWN status should not be info level")
	}
}

func TestUnknownAdapter404(t *testing.T) {
	srv := NewServer(Options{Auth: NoAuth{}, Emit: (&captured{}).emit})
	rec := post(t, srv.Handler(), "/alert/nope", []byte(`{}`), nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", rec.Code)
	}
}
