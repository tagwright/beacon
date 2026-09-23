// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package ingest is beacon's HTTP ingress path. Anything on the host can raise
// an alert through it, delivered by the same governed path as the watch path.
// This generalizes what beacon-server did for Gatus into a channel-agnostic
// gateway. Ingest is authenticated by default: a caller presents an HMAC
// signature over the exact request body, the same X-Beacon-Signature scheme
// courier's webhook channel emits and billet's signed webhooks use, so all
// three agree on one contract. An unauthenticated listener is an explicit
// opt-in for a closed network, never the default.
//
// Replay is guarded over the contract's own timestamp field: a signed request
// whose payload timestamp is older than the configured skew is rejected. No
// new nonce header is introduced, so the one wire shape holds across beacon,
// courier, and billet.
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
	"github.com/tagwright/beacon/internal/clock"
	"github.com/tagwright/courier"
)

// SignatureHeader is the default HMAC-SHA256 signature header, shared verbatim
// with courier's webhook channel so one contract spans beacon, courier, and
// billet. native and gatus use it; an adapter may declare its own (vikunja uses
// X-Vikunja-Signature).
const SignatureHeader = "X-Beacon-Signature"

// VikunjaSignatureHeader is the header Vikunja signs its webhooks with. It is
// beacon's own HMAC-SHA256 scheme with a different header and key.
const VikunjaSignatureHeader = "X-Vikunja-Signature"

// maxBodyBytes bounds an ingest request body.
const maxBodyBytes = 1 << 20

// ErrUnauthorized is returned when a request fails authentication.
var ErrUnauthorized = errors.New("beacon: ingest unauthorized")

// Authenticator verifies an inbound ingest request against the read body.
type Authenticator interface {
	Verify(r *http.Request, body []byte) error
}

// Adapter translates an incoming payload into one or more beacon native alerts.
// Most adapters produce exactly one; the vikunja tasks.overdue event produces
// one alert per task, so the interface returns a slice.
type Adapter interface {
	Adapt(body []byte, r *http.Request) ([]alert.Alert, error)
}

// Server is the ingest HTTP path. It authenticates a request per adapter,
// enforces the replay window, routes it to the adapter named in the URL, and
// emits the resulting native alerts into the governed delivery path.
type Server struct {
	defaultAuth    Authenticator
	adapterAuth    map[string]Authenticator
	adapters       map[string]Adapter
	emit           func(context.Context, alert.Alert) error
	defaultChannel string
	maxSkew        time.Duration
	clock          clock.Clock
	logger         *slog.Logger
}

// Options configures a Server.
type Options struct {
	// Auth is the default authenticator applied to any adapter without its own
	// entry in Authenticators.
	Auth Authenticator
	// Authenticators carries per-adapter authenticators, keyed by adapter name,
	// so vikunja can verify X-Vikunja-Signature with its own key while gatus
	// stays unauthenticated.
	Authenticators map[string]Authenticator
	Adapters       map[string]Adapter
	Emit           func(context.Context, alert.Alert) error
	DefaultChannel string
	// MaxSkew rejects a signed request whose payload timestamp is older
	// than this. Zero disables the replay guard.
	MaxSkew time.Duration
	Clock   clock.Clock
	Logger  *slog.Logger
}

// NewServer builds an ingest Server. When no adapters are supplied it
// registers the built-in native, Gatus, and Vikunja adapters.
func NewServer(opts Options) *Server {
	adapters := opts.Adapters
	if adapters == nil {
		adapters = map[string]Adapter{
			"native":  NativeAdapter{},
			"gatus":   GatusAdapter{},
			"vikunja": VikunjaAdapter{},
		}
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	clk := opts.Clock
	if clk == nil {
		clk = clock.Real{}
	}
	return &Server{
		defaultAuth:    opts.Auth,
		adapterAuth:    opts.Authenticators,
		adapters:       adapters,
		emit:           opts.Emit,
		defaultChannel: opts.DefaultChannel,
		maxSkew:        opts.MaxSkew,
		clock:          clk,
		logger:         logger,
	}
}

// authFor returns the authenticator for an adapter: its own if configured, else
// the default.
func (s *Server) authFor(adapter string) Authenticator {
	if a, ok := s.adapterAuth[adapter]; ok {
		return a
	}
	return s.defaultAuth
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

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	if auth := s.authFor(adapterName); auth != nil {
		if err := auth.Verify(r, body); err != nil {
			s.logger.Warn("beacon: ingest auth failed", "adapter", adapterName, "error", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	if s.maxSkew > 0 {
		if ts, present := payloadTimestamp(body); present {
			if skew := absDuration(s.clock.Now().Sub(ts)); skew > s.maxSkew {
				s.logger.Warn("beacon: ingest replay rejected", "adapter", adapterName, "skew", skew)
				http.Error(w, "stale timestamp", http.StatusUnauthorized)
				return
			}
		}
	}

	alerts, err := adapter.Adapt(body, r)
	if err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	for i := range alerts {
		if alerts[i].Channel == "" {
			alerts[i].Channel = s.defaultChannel
		}
		if err := s.emit(r.Context(), alerts[i]); err != nil {
			s.logger.Error("beacon: ingest delivery failed", "adapter", adapterName, "error", err)
			http.Error(w, "delivery failed", http.StatusBadGateway)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// HMACAuth verifies an HMAC-SHA256 signature over the exact request body, the
// frozen shared contract courier's webhook channel produces: lowercase hex of
// the MAC over the raw JSON bytes, no prefix. The header it reads is
// configurable so each adapter can declare its own (native and gatus use
// X-Beacon-Signature, vikunja uses X-Vikunja-Signature), while the scheme is
// byte-for-byte identical.
type HMACAuth struct {
	key    []byte
	header string
}

// NewHMACAuth builds an HMACAuth over a raw key, reading the default
// X-Beacon-Signature header.
func NewHMACAuth(key []byte) *HMACAuth {
	return &HMACAuth{key: key, header: SignatureHeader}
}

// NewHMACAuthHeader builds an HMACAuth over a raw key that reads a named
// header. An empty header falls back to the default X-Beacon-Signature.
func NewHMACAuthHeader(key []byte, header string) *HMACAuth {
	if header == "" {
		header = SignatureHeader
	}
	return &HMACAuth{key: key, header: header}
}

// Verify checks the request's configured signature header against HMAC-SHA256
// of the body. A missing key fails closed. A signature in the wrong header (the
// configured one absent) is rejected.
func (a *HMACAuth) Verify(r *http.Request, body []byte) error {
	if len(a.key) == 0 {
		return fmt.Errorf("%w: no signing key configured", ErrUnauthorized)
	}
	got := r.Header.Get(a.header)
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

// Sign returns the X-Beacon-Signature value for a body under a key. It is the
// signing half of the shared contract, exported so a caller (a test, or a
// beacon relaying to another beacon) can produce a valid signature.
func Sign(key, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
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

// Adapt decodes the native payload into a single alert.
func (NativeAdapter) Adapt(body []byte, r *http.Request) ([]alert.Alert, error) {
	var p ingestPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("beacon: native payload: %w", err)
	}
	level, err := parseLevel(p.Level)
	if err != nil {
		return nil, err
	}
	return []alert.Alert{{
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
	}}, nil
}

// payloadTimestamp extracts a top-level RFC3339 time from a request body,
// reporting whether it was present and parseable. It reads the native contract's
// `timestamp` field and, failing that, a top-level `time` field (the Vikunja
// envelope shape), so a signing source that names its time either way is
// replay-guarded. A payload with neither is not replay-guarded.
func payloadTimestamp(body []byte) (time.Time, bool) {
	var probe struct {
		Timestamp string `json:"timestamp"`
		Time      string `json:"time"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return time.Time{}, false
	}
	raw := probe.Timestamp
	if raw == "" {
		raw = probe.Time
	}
	if raw == "" {
		return time.Time{}, false
	}
	ts, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return ts, true
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
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
