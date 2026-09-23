// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/tagwright/beacon/internal/config"
	"github.com/tagwright/beacon/internal/ingest"
	"github.com/tagwright/courier"
)

// buildAuth builds the default ingest authenticator plus any per-adapter
// overrides. Each adapter declares its own {auth_mode, sign_secret,
// signature_header}, defaulting to the global ingest settings, so vikunja can
// verify X-Vikunja-Signature with its own key while gatus stays auth_mode:
// none, without a global flag forcing hmac onto gatus. "none" is the explicit
// opt-in unauthenticated listener; "hmac" (the default) resolves the named
// signing secret by injection and a missing or empty secret is a hard error,
// never a silently open listener.
func buildAuth(cfg config.IngestConfig, resolve courier.SecretResolver) (ingest.Authenticator, map[string]ingest.Authenticator, error) {
	def, err := authFromMode(cfg.AuthMode, cfg.SignSecret, "", resolve)
	if err != nil {
		return nil, nil, err
	}
	perAdapter := make(map[string]ingest.Authenticator, len(cfg.Adapters))
	for name, a := range cfg.Adapters {
		mode := a.AuthMode
		if mode == "" {
			mode = cfg.AuthMode
		}
		secret := a.SignSecret
		if secret == "" {
			secret = cfg.SignSecret
		}
		header := a.SignatureHeader
		if header == "" && name == "vikunja" {
			header = ingest.VikunjaSignatureHeader
		}
		au, err := authFromMode(mode, secret, header, resolve)
		if err != nil {
			return nil, nil, fmt.Errorf("beacon: ingest adapter %q: %w", name, err)
		}
		perAdapter[name] = au
	}
	return def, perAdapter, nil
}

// authFromMode builds one authenticator from a mode, a secret name, and a
// signature header (empty for the default). An hmac mode with no key fails
// closed.
func authFromMode(mode, secret, header string, resolve courier.SecretResolver) (ingest.Authenticator, error) {
	if mode == "none" {
		return ingest.NoAuth{}, nil
	}
	if secret == "" {
		return nil, fmt.Errorf("beacon: ingest auth_mode hmac requires sign_secret to name a signing secret")
	}
	if resolve == nil {
		return nil, fmt.Errorf("beacon: ingest auth_mode hmac requires a secret resolver")
	}
	key, err := resolve(secret)
	if err != nil {
		return nil, fmt.Errorf("beacon: resolve ingest sign_secret %q: %w", secret, err)
	}
	if key == "" {
		return nil, fmt.Errorf("beacon: ingest sign_secret %q resolved empty", secret)
	}
	return ingest.NewHMACAuthHeader([]byte(key), header), nil
}

// serveIngest runs the ingest HTTP server until ctx is cancelled, then shuts
// it down gracefully.
func serveIngest(ctx context.Context, listen string, srv *ingest.Server, logger *slog.Logger) error {
	httpSrv := &http.Server{
		Addr:              listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()
	err := httpSrv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
