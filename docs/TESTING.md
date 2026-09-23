# beacon testing

How beacon 00.01.00 is tested, to the tagwright Testing Standard, reported
honestly. beacon is Tier B. Its core (routing, ingest, signing) is no-socket
logic that owes cross-language golden vectors and a tamper matrix rather than a
full live harness; its socket-watch layer owes the Level-2 `Run(Deps)`
fault-injection wiring test. Both are present and green.

Every path below is labeled `proven`, `compile-only`, or `untested`. Tests run
in the `golang:1.25` toolchain container (there is no host Go); `go build ./...`,
`go vet ./...`, and `go test ./...` are all green as of this writing.

## Level 1, the pure core (proven)

Tested by invariant over the input space, not a handful of examples.

- Ruleset grammar and the config codec: `internal/routing/grammar.go`,
  `internal/routing/match.go`. `TestStringOrListDecode` proves the scalar-or-list
  codec both ways; `TestUnknownKeyRejected` proves a stray match key (the
  `sevrity:` typo) fails closed; `TestMatchLabelsInvariants` and
  `TestTimeWindowInvariants` cover the label and time-of-day semantics
  exhaustively (absent key, empty-string value, start-inclusive/end-exclusive,
  midnight wrap); `TestParseTimeWindowErrors` rejects every malformed window.
- Config validation: `internal/config/config_test.go`. `TestFailClosedValidation`
  covers the unknown-key, missing-default, empty-`to`, invalid-timezone, and
  `start==end` cases; `TestDanglingReferenceFailsLoad`, `TestCycleFailsLoad`, and
  `TestFleetDefaultRequiredForEnabledPath` cover the reference, cycle, and
  fleet-default invariants; `TestDuplicateNameAcrossMapsFailsLoad` proves the
  shared namespace is unique.
- Cycle detection and lint: `internal/routing/validate.go`. `TestDetectCycle`
  (including a default self-reference) and `TestUnreachableRules`.
- Retention arithmetic: `internal/history/history_test.go`. `TestMaxCountEviction`
  and `TestMaxAgeEviction` prove the store is bounded by eviction.
- Label parsing: `internal/discovery/discovery_test.go`. `TestSeverityParsesWithAlias`
  and `TestRawLabelsPassthrough`.

## Level 2, the wiring, with fault injection (proven)

Driven through the real production entrypoint `Run(Deps)` in
`internal/daemon/daemon.go` with the shared `github.com/tagwright/core/runtime/runtimetest`
fake. Fault is injected, never a happy-path fake.

- `TestRunFanOutSpoolsOnlyFailedLeaf` (`internal/daemon/daemon_routing_test.go`)
  is the load-bearing fan-out test: a labeled container event routes through a
  ruleset fanning to two leaves, one leaf's delivery is failed, and only the
  failed leaf spools and replays while the other is not re-sent. It exercises
  routing, fan-out, the per-leaf spool, and state through the pipeline end to end.
- `TestRunWritesHistoryUnconditionally` proves the history write happens after
  routing and before the suppression gates (a suppressed repeat is still
  recorded).
- `TestRunAtLeastOnceThroughSeam` (`internal/daemon/daemon_test.go`) injects a
  delivery failure and proves the alert spools and is replayed, never dropped.
- The resolution pipeline: `internal/policy/resolution_test.go`.
  `TestRouterMatchesOnState`, `TestFastRecovery`, `TestOrphanResolveNotifies`,
  `TestNotifyOnResolvedOffDrops`, `TestRepeatAfterOverridesDedupWindow`, and
  `TestCorrelationOnceBeforeFanOut`.
- Delivery boundary: `internal/delivery/delivery_test.go`.
  `TestDeliverUnknownLeafErrors` proves an unknown leaf errors rather than
  silently falling back; `TestMinLevelSkipsBelowThreshold` proves the sanctioned
  post-routing level drop.
- Tooling (no socket): `internal/routing/tools/tools_test.go`.
  `TestExplainFromFlags`, `TestExplainFromStdinJSON`, `TestLintReportsWarnings`,
  `TestLintErrorsOnMissingDefault`, `TestReplayEvaluatesAtRecordedTime`,
  `TestReplayEmptyStoreErrors`, and `TestScaffoldLintsClean`.

## No-socket golden vectors and tamper matrix (proven)

The Tier-B substitute for a live harness on the signing and routing core.

- Gatus golden vectors: `internal/policy/gatus_golden_test.go`.
  `TestGatusGoldenVectors` pins the consumer-visible DOWN and RECOVERED Title,
  Body, Level, and Fields, proving the migration onto the resolution engine is
  unchanged at the delivery boundary.
- Signature tamper matrix: `internal/ingest/pillarb_test.go`.
  `TestPerAdapterAuthMatrix` proves each adapter verifies its own header and key
  and rejects a request signed for the wrong header or with the wrong key;
  `TestHMACNoKeyFailsClosed` proves an hmac adapter with no key fails closed;
  `TestContractServedForEachAdapter` proves native, gatus, and vikunja route and
  an unknown adapter is 404. The vikunja adapter mapping is pinned by
  `TestVikunjaReminderFired`, `TestVikunjaTaskOverdue`, and
  `TestVikunjaTasksOverdueList`; the replay guard by
  `TestReplayGuardReadsTopLevelTime`.

## Untested / debt

- The live integration harness (drive the shipped image against a real socket
  with a throwaway notifier, byte-compare a delivered alert) is `untested` in
  this build. beacon is Tier B, where the live harness is strongly preferred and
  its absence is tracked debt. This build produces and tests code only; per the
  build brief it does not rebuild, redeploy, or drive the live beacon, and it
  does not provision or fire the live Vikunja webhook. Standing up the harness is
  follow-on work.
- The Podman runtime leg is `compile-only`; the runtime adapter is core's, driven
  here through the shared fake.
- Level-3 guard tests with committed negative fixtures (SPDX-header guard,
  no-`replace`-in-`go.mod`, the release-tag raw-ref guard) are not added in this
  build and remain suite-level debt; the fail-closed config validation above
  covers the label-typo class for the ruleset grammar.
