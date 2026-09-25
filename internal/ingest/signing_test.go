// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package ingest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Test-only signing helpers. These are the producing half of the HMAC contract
// Verify checks: only the tests here sign a body, so they live in test scope
// rather than the production package (the daemon-module deadcode gate roots at
// main and flags any production function no live path reaches). If a real
// beacon-to-beacon relay ever needs to sign outbound, move Sign back beside
// Verify and wire it there.

// NewHMACAuth builds an HMACAuth over a raw key, reading the default
// X-Beacon-Signature header.
func NewHMACAuth(key []byte) *HMACAuth {
	return &HMACAuth{key: key, header: SignatureHeader}
}

// Sign returns the X-Beacon-Signature value for a body under a key: the signing
// half of the shared contract, matching what HMACAuth.Verify accepts.
func Sign(key, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
