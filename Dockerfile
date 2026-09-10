# SPDX-License-Identifier: GPL-3.0-or-later
#
# beacon daemon image. Multi-stage: a golang build stage compiles the single
# beacon binary CGO-free, a distroless static stage carries only that binary.
# The final image has no shell, no package manager, and no network tooling of
# its own.
#
# Build from the beacon repository root:
#
#   docker build -t ghcr.io/tagwright/beacon:dev .
#
# core and courier are consumed as published modules (github.com/tagwright/core,
# github.com/tagwright/courier). GOPRIVATE makes the build fetch tagwright's own
# modules directly from their source rather than through the public module proxy;
# go.sum still verifies their integrity. The build context is this one repo with
# no sibling module directories, the clean-room a committed local replace would
# fail: a stale replace pointing at ../core or ../courier breaks the build here.
#
# beacon reads the container socket to watch and inspect the fleet, and it
# listens for HTTP ingest. It is an ordinary daemon: it needs the container
# socket mounted READ-ONLY (events and inspect, never exec/stop/start, per the
# charter), but NOT --privileged and NOT host pid. Runtime mounts the operator
# provides:
#
#   - the container socket, read-only, e.g. /var/run/docker.sock:/var/run/docker.sock:ro
#   - beacon.yml, e.g. ./beacon.yml:/etc/beacon/beacon.yml:ro
#   - a durable spool volume at the configured spool.dir, so at-least-once
#     delivery survives a container recreate
#   - the secrets dir (/run/secrets/<name>), for any HMAC ingest signing key or
#     secret-valued channel setting resolved by injection

FROM golang:1.25 AS build

ENV GOPRIVATE=github.com/tagwright/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build CGO-free so the binary runs on distroless static.
RUN CGO_ENABLED=0 go build -buildvcs=false -ldflags "-s -w" -o /out/beacon ./cmd/beacon

# Stage an empty spool directory owned by the nonroot uid (65532). The runtime
# stage copies it in with that ownership so a fresh named volume mounted at
# /spool inherits nonroot ownership on first mount. Without this the process,
# which runs unprivileged and cannot chown, could not write its at-least-once
# spool to a root-owned empty volume. /spool is only the default spool.dir; a
# deployment may point spool.dir elsewhere and mount its own writable path.
RUN mkdir -p /spool && chown 65532:65532 /spool

# Distroless static, the NONROOT variant (uid 65532): beacon reads the container
# socket over the Docker Engine API and serves HTTP, neither of which needs uid 0,
# so it runs unprivileged. ca-certificates ships in this base, which beacon needs
# for any channel or ingest peer reached over HTTPS. The image ships no shell, no
# package manager, and nothing that can open a network connection on its own
# beyond the calls beacon makes.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/beacon /usr/local/bin/beacon
# The nonroot-owned spool dir, so a named volume mounted here is writable by the
# unprivileged process (see the build stage). Trailing slashes copy the empty
# directory itself, preserving its 65532 ownership.
COPY --from=build --chown=65532:65532 /spool/ /spool/

ENTRYPOINT ["beacon"]
CMD ["--config", "/etc/beacon/beacon.yml"]
