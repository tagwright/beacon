// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package config loads beacon's deployment configuration: the two ingress
// paths (each independently disableable), the operator's channel table, and
// the spool. Channels, endpoints, and secrets live here and are resolved by
// injection; a label or a POST names a channel, it never carries the
// machinery.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is beacon's full deployment configuration.
type Config struct {
	// Watch configures the container-runtime watch ingress path.
	Watch WatchConfig `yaml:"watch"`
	// Ingest configures the HTTP ingest ingress path.
	Ingest IngestConfig `yaml:"ingest"`
	// Channels is the operator's channel table, keyed by the name a label
	// or a POST refers to. Each entry configures one courier backend.
	Channels map[string]ChannelConfig `yaml:"channels"`
	// DefaultChannel is delivered to when an alert names no channel or
	// names one that is not in the table. Empty means such alerts error
	// rather than silently vanish.
	DefaultChannel string `yaml:"default_channel"`
	// Spool configures the at-least-once disk spool.
	Spool SpoolConfig `yaml:"spool"`
}

// WatchConfig configures the watch ingress path.
type WatchConfig struct {
	// Enabled turns the watch path on. A deployment can run ingest-only by
	// leaving it off.
	Enabled bool `yaml:"enabled"`
	// Runtime selects the container runtime, "docker" or "podman".
	Runtime string `yaml:"runtime"`
	// Socket is the runtime socket path. Empty uses the runtime default.
	Socket string `yaml:"socket"`
	// DefaultChannel is the operator-level default channel for containers
	// that opt in without naming one, so an unlabeled-but-covered
	// container is not silent. A per-container label overrides it.
	DefaultChannel string `yaml:"default_channel"`
}

// IngestConfig configures the HTTP ingest ingress path.
type IngestConfig struct {
	// Enabled turns the ingest path on. A deployment can run watch-only by
	// leaving it off.
	Enabled bool `yaml:"enabled"`
	// Listen is the address the HTTP endpoint binds, e.g. ":8080".
	Listen string `yaml:"listen"`
	// AuthMode is "hmac" (the default, X-Beacon-Signature), or "none" for
	// an explicit opt-in unauthenticated listener on a closed network.
	AuthMode string `yaml:"auth_mode"`
	// SignSecret names the secret that resolves to the HMAC key, resolved
	// by injection. It is a name, never the key itself.
	SignSecret string `yaml:"sign_secret"`
	// MaxSkew rejects a signed request whose payload timestamp is older
	// than this, a replay guard over the shared contract's timestamp
	// field. Zero disables the check.
	MaxSkew time.Duration `yaml:"max_skew"`
	// DefaultChannel is delivered to when an ingested alert names no
	// channel.
	DefaultChannel string `yaml:"default_channel"`
}

// ChannelConfig configures one named channel. It mirrors courier's
// ChannelConfig: a backend Type, a MinLevel, and backend-specific Settings
// whose secret-valued entries resolve by injection at send time.
type ChannelConfig struct {
	// Type selects the courier backend ("slack", "webhook", "ntfy", ...).
	Type string `yaml:"type"`
	// MinLevel is the lowest severity this channel receives
	// ("info", "warning", "error").
	MinLevel string `yaml:"min_level"`
	// Settings is backend-specific configuration passed through to
	// courier, including secret names resolved by injection.
	Settings map[string]string `yaml:"settings"`
}

// SpoolConfig configures the at-least-once disk spool.
type SpoolConfig struct {
	// Dir is the directory the spool persists undelivered alerts to. It
	// must be a durable path that survives a container recreate.
	Dir string `yaml:"dir"`
	// MaxRetries bounds in-memory retry before an alert is spooled.
	MaxRetries int `yaml:"max_retries"`
	// MaxAge bounds how long an alert is retried from the spool before it
	// is abandoned. Zero means retry indefinitely.
	MaxAge time.Duration `yaml:"max_age"`
}

// Load reads and validates a beacon config from a YAML file.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("beacon: read config %q: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("beacon: parse config %q: %w", path, err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Watch.Runtime == "" {
		c.Watch.Runtime = "docker"
	}
	if c.Ingest.Listen == "" {
		c.Ingest.Listen = ":8080"
	}
	if c.Ingest.AuthMode == "" {
		c.Ingest.AuthMode = "hmac"
	}
}

func (c *Config) validate() error {
	if !c.Watch.Enabled && !c.Ingest.Enabled {
		return fmt.Errorf("beacon: at least one ingress path must be enabled")
	}
	if c.Watch.Enabled && c.Watch.Runtime != "docker" && c.Watch.Runtime != "podman" {
		return fmt.Errorf("beacon: watch.runtime must be docker or podman, got %q", c.Watch.Runtime)
	}
	if c.Ingest.Enabled && c.Ingest.AuthMode != "hmac" && c.Ingest.AuthMode != "none" {
		return fmt.Errorf("beacon: ingest.auth_mode must be hmac or none, got %q", c.Ingest.AuthMode)
	}
	for name, ch := range c.Channels {
		if ch.Type == "" {
			return fmt.Errorf("beacon: channel %q has no type", name)
		}
	}
	return nil
}
