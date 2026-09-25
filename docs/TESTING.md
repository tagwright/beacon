# beacon testing

How beacon `00.01.00` is tested, reported honestly. Every entry below is labeled
`proven`, `compile-only`, or `untested`, and the labels are meant literally.
Where a claim rests on a test, the test is named so you can run it and check.

beacon's core is routing, ingest, and signing: pure logic with no socket, which
is covered by invariant tests, cross-language golden vectors, and a signature
tamper matrix rather than a live harness. Its socket-watch layer is covered
through the production entrypoint with fault injected at the seam. Both are
present and green.

Tests run in the `golang:1.25` toolchain container, since there is no host Go.
`go build ./...`, `go vet ./...`, and `go test ./...` are all green as of this
writing.

## Level 1, the pure core (proven)

Tested by invariant over the input space, not a handful of examples.

- Ruleset grammar and the config codec: `internal/routing/grammar.go`,
  `internal/routing/match.go`. `TestStringOrListDecode` proves the scalar-or-list
  codec both ways. `TestUnknownKeyRejected` proves a stray match key (the
  `sevrity:` typo) fails closed. `TestMatchLabelsInvariants` and
  `TestTimeWindowInvariants` cover the label and time-of-day semantics
  exhaustively: absent key, empty-string value, start-inclusive and end-exclusive
  bounds, and midnight wrap. `TestParseTimeWindowErrors` rejects every malformed
  window.
- Config validation: `internal/config/config_test.go`. `TestFailClosedValidation`
  covers the unknown-key, missing-default, empty-`to`, invalid-timezone, and
  `start==end` cases. `TestDanglingReferenceFailsLoad`, `TestCycleFailsLoad`, and
  `TestFleetDefaultRequiredForEnabledPath` cover the reference, cycle, and
  fleet-default invariants. `TestDuplicateNameAcrossMapsFailsLoad` proves a name
  cannot be used by both a channel and a ruleset.
- Cycle detection and lint: `internal/routing/validate.go`. `TestDetectCycle`
  (including a default self-reference) and `TestUnreachableRules`.
- Retention arithmetic: `internal/history/history_test.go`. `TestMaxCountEviction`
  and `TestMaxAgeEviction` prove the store stays bounded by eviction.
- Label parsing: `internal/discovery/discovery_test.go`.
  `TestSeverityParsesWithAlias` and `TestRawLabelsPassthrough`.

## Level 2, the wiring, with fault injection (proven)

Driven through the real production entrypoint `Run(Deps)` in
`internal/daemon/daemon.go` with the shared
`github.com/tagwright/core/runtime/runtimetest` fake. A fault is injected rather
than a happy-path faked.

- `TestRunFanOutSpoolsOnlyFailedLeaf` (`internal/daemon/daemon_routing_test.go`)
  is the load-bearing fan-out test. A labeled container event routes through a
  ruleset fanning to two leaves, one leaf's delivery fails, and only the failed
  leaf spools and replays while the other is not re-sent. It exercises routing,
  fan-out, the per-leaf spool, and state through the pipeline end to end.
- `TestRunWritesHistoryUnconditionally` proves the history write happens after
  routing and before the suppression gates, so a suppressed repeat is still
  recorded.
- `TestRunAtLeastOnceThroughSeam` (`internal/daemon/daemon_test.go`) injects a
  delivery failure and proves the alert spools and is replayed, never dropped.
- The resolution pipeline: `internal/policy/resolution_test.go`.
  `TestRouterMatchesOnState`, `TestFastRecovery`, `TestOrphanResolveNotifies`,
  `TestNotifyOnResolvedOffDrops`, `TestRepeatAfterOverridesDedupWindow`, and
  `TestCorrelationOnceBeforeFanOut`.
- Delivery boundary: `internal/delivery/delivery_test.go`.
  `TestDeliverUnknownLeafErrors` proves an unknown leaf errors rather than
  silently falling back. `TestMinLevelSkipsBelowThreshold` proves the sanctioned
  post-routing level drop.
- Tooling, no socket: `internal/routing/tools/tools_test.go`.
  `TestExplainFromFlags`, `TestExplainFromStdinJSON`, `TestLintReportsWarnings`,
  `TestLintErrorsOnMissingDefault`, `TestReplayEvaluatesAtRecordedTime`,
  `TestReplayEmptyStoreErrors`, and `TestScaffoldLintsClean`.

## No-socket golden vectors and tamper matrix (proven)

The stand-in for a live harness on the signing and routing core.

- Gatus golden vectors: `internal/policy/gatus_golden_test.go`.
  `TestGatusGoldenVectors` pins the consumer-visible DOWN and RECOVERED Title,
  Body, Level, and Fields, proving the migration onto the resolution engine is
  unchanged at the delivery boundary.
- Signature tamper matrix: `internal/ingest/pillarb_test.go`.
  `TestPerAdapterAuthMatrix` proves each adapter verifies its own header and key
  and rejects a request signed for the wrong header or with the wrong key.
  `TestHMACNoKeyFailsClosed` proves an hmac adapter with no key fails closed.
  `TestContractServedForEachAdapter` proves native, gatus, and vikunja route and
  an unknown adapter is 404. The vikunja mapping is pinned by
  `TestVikunjaReminderFired`, `TestVikunjaTaskOverdue`, and
  `TestVikunjaTasksOverdueList`, and the replay guard by
  `TestReplayGuardReadsTopLevelTime`.

## Untested and debt

- **The live integration harness is `untested` in this build, and its absence is
  tracked Tier-B debt.** beacon is a Tier-B tool under the Testing Standard, for
  which the live harness is strongly preferred but its absence is a tracked debt
  rather than a release blocker (unlike a Tier-A trust anchor, where the harness
  is mandatory before beta). The harness would drive the shipped image against a
  real socket with a throwaway notifier and byte-compare a delivered alert; the
  tests above instead produce and check code against a fake runtime and golden
  vectors, and do not drive a live beacon, provision a live Vikunja webhook, or
  fire one. Because there is no harness, `test/integration/LAST-RUN` records
  `operator_run: none` (nothing operator-run to attest) and the self-hosted CI
  leg is a smoke test only. Standing up the harness is a separate, tracked build
  task, not a resting state, and it is the one honest gap a would-be operator
  should weigh.
- The Podman runtime leg is `compile-only`. The runtime adapter is core's, driven
  here through the shared fake, so the Docker and Podman legs share the tested
  path but only Docker is exercised against a runtime.
- Level-3 guard tests with committed negative fixtures (an SPDX-header guard, a
  no-`replace`-in-`go.mod` guard, a release-tag raw-ref guard) are not in this
  build. The fail-closed config validation above already covers the label-typo
  class for the ruleset grammar.
