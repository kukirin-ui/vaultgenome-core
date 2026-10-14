# SPDX-License-Identifier: AGPL-3.0-or-later
#
# VaultGenome / AI Continuity Platform — reference image.
# Builds the one-command cross-hardware regeneration demo (default entrypoint)
# plus the admin CLI. Static binaries on a distroless base — no shell, no libc.
#
#   docker build -t vaultgenome .
#   docker build --build-arg VERSION=v0.3.2 --build-arg COMMIT=$(git rev-parse --short HEAD) -t vaultgenome .
#   docker run --rm vaultgenome                 # runs the demo (simulation mode)
#   docker run --rm --entrypoint acpctl vaultgenome version

# Base images pinned by digest (resolved 2026-10-13); bump the tag and the digest together.
FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
COPY . .
# .dockerignore excludes .git, so Go can embed no VCS revision and the binary
# cannot recover its own identity at runtime. Pass it in instead, the same way
# the Makefile and the release workflow do:
#   docker build --build-arg VERSION=v0.3.2 --build-arg COMMIT=$(git rev-parse --short HEAD) .
ARG VERSION=0.0.0-dev
ARG COMMIT=none
RUN LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
 && CGO_ENABLED=0 go build -trimpath -ldflags="${LDFLAGS}" -o /out/acp-demo ./cmd/acp-demo \
 && CGO_ENABLED=0 go build -trimpath -ldflags="${LDFLAGS}" -o /out/acpctl   ./cmd/acpctl

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/acp-demo /usr/local/bin/acp-demo
COPY --from=build /out/acpctl   /usr/local/bin/acpctl
ENTRYPOINT ["/usr/local/bin/acp-demo"]
