// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package ingest is beacon's HTTP ingress path. Anything on the host can raise
// an alert through it, delivered by the same governed path as the watch path.
// This generalizes what beacon-server did for Gatus into a channel-agnostic
// gateway. Ingest is authenticated by default: a caller presents an HMAC
// signature over the exact request body, the same X-Beacon-Signature scheme
// courier's webhook channel emits and billet's signed webhooks use, so all
// three agree on one contract. An unauthenticated listener is an explicit
// opt-in, never the default.
//
// Stage 1 defines the handler, the adapter and authenticator seams, a
// compiling HMAC authenticator (the frozen wire contract) with stubbed secret
// injection, and the native and Gatus adapters. Real secret resolution,
// replay-window enforcement, and further adapters land in later stages.
package ingest

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/tagwright/beacon/internal/alert"
	"github.com/tagwright/courier"
)

// SignatureHeader is the HMAC-SHA256 signature header, shared verbatim with
// courier's webhook channel so one contract spans beacon, courier, and billet.
const SignatureHeader = "X-Beacon-Signature"

// ErrUnauthorized is returned when a request fails authentication.
var ErrUnauthorized = errors.New("beacon: ingest unauthorized")

// Authenticator verifies an inbound ingest request against the read body.
type Authenticator interface {
	Verify(r *http.Request, body []byte) error
}

// Adapter translates an incoming payload into beacon's native alert.
type Adapter interface {
	Adapt(body []byte, r *http.Request) (alert.Alert, error)
}

// Server is the ingest HTTP path. It authenticates a request, routes it to the
// adapter named in the URL, and emits the resulting native alert into the
// governed delivery path.
type Server struct {
	auth           Authenticator
	adapters       map[string]Adapter
	emit           func(context.Context, alert.Alert) error
	defaultChannel string
	logger         *slog.Logger
}

// Options configures a Server.
type Options struct {
	Auth           Authenticator
	Adapters       map[string]Adapter
	Emit           func(context.Context, alert.Alert) error
	DefaultChannel string
	Logger         *slog.Logger
}

// NewServer builds an ingest Server. When no adapters are supplied it
// registers the built-in native and Gatus adapters.
func NewServer(opts Options) *Server {
	adapters := opts.Adapters
	if adapters == nil {
		adapters = map[string]Adapter{
			"native": NativeAdapter{},
			"gatus":  GatusAdapter{},
		}
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		auth:           opts.Auth,
		adapters:       adapters,
		emit:           opts.Emit,
		defaultChannel: opts.DefaultChannel,
		logger:         logger,
	}
}

// Handler returns the ingest HTTP mux: POST /alert/{adapter} and GET /health.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/alert/", s.handleAlert)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	return mux
}

func (s *Server) handleAlert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adapterName := strings.TrimPrefix(r.URL.Path, "/alert/")
	adapter, ok := s.adapters[adapterName]
	if !ok {
		http.Error(w, fmt.Sprintf("unknown adapter %q", adapterName), http.StatusNotFound)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	if s.auth != nil {
		if err := s.auth.Verify(r, body); err != nil {
			s.logger.Warn("beacon: ingest auth failed", "adapter", adapterName, "error", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	a, err := adapter.Adapt(body, r)
	if err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	if a.Channel == "" {
		a.Channel = s.defaultChannel
	}

	if err := s.emit(r.Context(), a); err != nil {
		s.logger.Error("beacon: ingest delivery failed", "adapter", adapterName, "error", err)
		http.Error(w, "delivery failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// HMACAuth verifies the X-Beacon-Signature HMAC-SHA256 over the exact request
// body, the frozen shared contract. Stage 1 holds the key directly; a later
// stage resolves it by injection (courier's SecretResolver) and enforces the
// payload-timestamp replay window.
type HMACAuth struct {
	key     []byte
	maxSkew time.Duration
}

// NewHMACAuth builds an HMACAuth over a raw key.
func NewHMACAuth(key []byte, maxSkew time.Duration) *HMACAuth {
	return &HMACAuth{key: key, maxSkew: maxSkew}
}

// Verify checks the request's X-Beacon-Signature against HMAC-SHA256 of the
// body. This is the exact scheme courier's webhook channel produces: lowercase
// hex of the MAC over the raw JSON bytes, no prefix.
func (a *HMACAuth) Verify(r *http.Request, body []byte) error {
	got := r.Header.Get(SignatureHeader)
	if got == "" {
		return ErrUnauthorized
	}
	mac := hmac.New(sha256.New, a.key)
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(got), []byte(want)) {
		return ErrUnauthorized
	}
	return nil
}

// NoAuth accepts every request. It backs the explicit opt-in unauthenticated
// listener for a closed network.
type NoAuth struct{}

// Verify always succeeds.
func (NoAuth) Verify(r *http.Request, body []byte) error { return nil }

// ingestPayload is the native ingest wire contract: courier's webhook payload
// (title, body, level, tags, fields, timestamp) extended with the routing and
// identity fields beacon governs (channel, dedup_key, correlation_key). A
// caller that omits channel gets the deployment default; one that omits
// dedup_key gets a key derived downstream.
type ingestPayload struct {
	Title          string            `json:"title"`
	Body           string            `json:"body"`
	Level          string            `json:"level"`
	Tags           []string          `json:"tags,omitempty"`
	Fields         map[string]string `json:"fields,omitempty"`
	Timestamp      string            `json:"timestamp"`
	Channel        string            `json:"channel,omitempty"`
	DedupKey       string            `json:"dedup_key,omitempty"`
	CorrelationKey string            `json:"correlation_key,omitempty"`
}

// NativeAdapter parses beacon's native ingest payload.
type NativeAdapter struct{}

// Adapt decodes the native payload into an alert.
func (NativeAdapter) Adapt(body []byte, r *http.Request) (alert.Alert, error) {
	var p ingestPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return alert.Alert{}, fmt.Errorf("beacon: native payload: %w", err)
	}
	level, err := parseLevel(p.Level)
	if err != nil {
		return alert.Alert{}, err
	}
	return alert.Alert{
		Channel:        p.Channel,
		DedupKey:       p.DedupKey,
		CorrelationKey: p.CorrelationKey,
		Source:         alert.SourceIngest,
		Adapter:        "native",
		Event:          "native",
		Time:           time.Now(),
		Notification: courier.Notification{
			Title:  p.Title,
			Body:   p.Body,
			Level:  level,
			Tags:   p.Tags,
			Fields: p.Fields,
		},
	}, nil
}

func parseLevel(s string) (courier.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return courier.LevelInfo, nil
	case "warning", "warn":
		return courier.LevelWarning, nil
	case "error":
		return courier.LevelError, nil
	default:
		return 0, fmt.Errorf("beacon: unknown level %q", s)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
