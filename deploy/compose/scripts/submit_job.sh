#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# submit_job.sh — POST a gate job to the running sagvd and poll the
# result: the job names a sealed genome in sagvd's genome.bundle_dir
# (deploy/compose/genomes, see make_genome.sh); the worker restores it in
# memory and answers its prompts; sagvd judges the answer and the job view
# carries the signed verdict. Invoked by the `demo-submit` Makefile target,
# but safe to run standalone once `make demo-up` has brought the stack up.
#
# Usage:
#   ./submit_job.sh                  # defaults: gen-0.genome / gen-0.key, 600 s deadline
#   SAGVD_URL=http://... ./submit_job.sh
#   GENOME_BUNDLE=gen-1.genome GENOME_KEY=gen-1.key ./submit_job.sh
#
# Environment (all optional):
#   SAGVD_URL      base URL of sagvd's HTTP API (default http://127.0.0.1:9080)
#   GENOME_BUNDLE  the bundle's file name in genome.bundle_dir (default gen-0.genome)
#   GENOME_KEY     its key file's name there (default gen-0.key; empty = use
#                  the escrow envelope <bundle>.escrow)
#   DEADLINE       deadline_seconds_from_now (default 600; a model load counts)
#   POLL_INTERVAL  seconds between GET polls (default 1)
#   POLL_TIMEOUT   total seconds to wait before giving up (default 600)
#   BEARER_TOKEN   REST API token; defaults to the contents of
#                  $SECRETS_DIR/sagvd/api_token (written by keygen)
#   SECRETS_DIR    secrets tree (default: ../secrets relative to this script)
#
# Exit codes:
#   0  — job reached JobStatusSucceeded: the gate opened; job view printed as JSON
#   1  — submission failed (HTTP != 202)
#   2  — poll timed out (job neither succeeded nor failed in POLL_TIMEOUT)
#   3  — job reached JobStatusFailed (a gate that refused the model prints its attempts)
#   4  — prerequisites missing (curl / jq, or no bearer token)

set -o errexit
set -o pipefail
set -o nounset

# ---- prerequisites --------------------------------------------------------

# We demand jq because the response is JSON with nested fields. A
# plain shell script with ad-hoc grep/sed over JSON would be fragile
# and silently lose negative test signal (e.g., a 202 body with an
# unexpected shape).
for tool in curl jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "submit_job.sh: missing prerequisite: $tool" >&2
    exit 4
  fi
done

# ---- defaults -------------------------------------------------------------

SAGVD_URL="${SAGVD_URL:-http://127.0.0.1:9080}"
GENOME_BUNDLE="${GENOME_BUNDLE:-gen-0.genome}"
GENOME_KEY="${GENOME_KEY-gen-0.key}"
DEADLINE="${DEADLINE:-600}"
POLL_INTERVAL="${POLL_INTERVAL:-1}"
POLL_TIMEOUT="${POLL_TIMEOUT:-600}"

# Trim any trailing slash on SAGVD_URL so the /v1 concatenation below
# never produces double slashes (which sagvd's router would 404).
SAGVD_URL="${SAGVD_URL%/}"

# The REST API requires a bearer token. Default to the one keygen wrote.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS_DIR="${SECRETS_DIR:-${SCRIPT_DIR}/../secrets}"
if [[ -z "${BEARER_TOKEN:-}" && -r "${SECRETS_DIR}/sagvd/api_token" ]]; then
  BEARER_TOKEN="$(tr -d '[:space:]' < "${SECRETS_DIR}/sagvd/api_token")"
fi
if [[ -z "${BEARER_TOKEN:-}" ]]; then
  echo "submit_job.sh: no bearer token — set BEARER_TOKEN or run 'make demo-certs'" >&2
  exit 4
fi

# ---- body -----------------------------------------------------------------

# The job names files in sagvd's genome.bundle_dir; nothing of the genome
# travels in the request. An empty GENOME_KEY leaves key_file out, so
# sagvd opens the escrow envelope beside the bundle instead.
REQUEST_BODY="$(jq -nc \
  --arg bundle "$GENOME_BUNDLE" \
  --arg key "$GENOME_KEY" \
  --argjson deadline "$DEADLINE" \
  '{
     genome: ({bundle: $bundle} + (if $key == "" then {} else {key_file: $key} end)),
     deadline_seconds_from_now: $deadline,
   }')"

# ---- submit ---------------------------------------------------------------

AUTH_HEADER=()
if [[ -n "${BEARER_TOKEN:-}" ]]; then
  AUTH_HEADER+=(-H "Authorization: Bearer ${BEARER_TOKEN}")
fi
# Workaround for `set -o nounset` + bash 3.2 (default macOS): an empty
# array expanded with [@] without :- yields "unbound variable". Pinning
# the default-empty form here keeps every curl invocation safe.
auth_args() { if [[ ${#AUTH_HEADER[@]} -gt 0 ]]; then printf '%s\n' "${AUTH_HEADER[@]}"; fi; }

echo "submit_job.sh: submitting to ${SAGVD_URL}/v1/jobs ..."
echo "  genome   = ${GENOME_BUNDLE}"
echo "  key      = ${GENOME_KEY:-<escrow envelope>}"
echo "  deadline = ${DEADLINE}s"

# Capture body and status separately so we can act on non-202s.
HTTP_RESPONSE="$(mktemp)"
trap 'rm -f "$HTTP_RESPONSE"' EXIT

HTTP_STATUS="$(curl \
  --silent \
  --show-error \
  --fail-with-body \
  --output "$HTTP_RESPONSE" \
  --write-out '%{http_code}' \
  -X POST \
  -H 'Content-Type: application/json' \
  ${AUTH_HEADER[@]+"${AUTH_HEADER[@]}"} \
  --data-binary "$REQUEST_BODY" \
  "${SAGVD_URL}/v1/jobs" \
  || true)"

if [[ "$HTTP_STATUS" != "202" ]]; then
  echo "submit_job.sh: POST /v1/jobs returned HTTP ${HTTP_STATUS}" >&2
  cat "$HTTP_RESPONSE" >&2 || true
  echo >&2
  exit 1
fi

JOB_ID="$(jq -r '.job_id' < "$HTTP_RESPONSE")"
if [[ -z "$JOB_ID" || "$JOB_ID" == "null" ]]; then
  echo "submit_job.sh: 202 response missing job_id" >&2
  cat "$HTTP_RESPONSE" >&2
  exit 1
fi

echo "submit_job.sh: accepted as job_id=${JOB_ID}"
jq -r '"  request_id  = \(.request_id)\n  state       = \(.state)\n  genome_id   = \(.genome.key_id) (\(.genome.fixtures) fixtures, \(.genome.bytes) bytes shipped)"' < "$HTTP_RESPONSE"

# ---- poll -----------------------------------------------------------------

DEADLINE_EPOCH=$(( $(date +%s) + POLL_TIMEOUT ))

while : ; do
  # We treat a non-200 from GET as a transient network blip and
  # retry within POLL_TIMEOUT — sagvd's GET /v1/jobs/{id} is a pure
  # in-memory lookup so a sustained failure here means the process
  # died, which we surface by running out of clock.
  GET_OUTPUT="$(curl \
    --silent \
    --show-error \
    --fail \
    ${AUTH_HEADER[@]+"${AUTH_HEADER[@]}"} \
    "${SAGVD_URL}/v1/jobs/${JOB_ID}" \
    || true)"

  if [[ -n "$GET_OUTPUT" ]]; then
    STATUS="$(jq -r '.status // empty' <<<"$GET_OUTPUT")"
    case "$STATUS" in
      succeeded)
        echo "submit_job.sh: job succeeded — gate $(jq -r '.gate.level' <<<"$GET_OUTPUT") at door \"$(jq -r '.gate.door' <<<"$GET_OUTPUT")\" over $(jq -r '.gate.fixtures' <<<"$GET_OUTPUT") fixtures, verdict signed by $(jq -r '.gate.signer_key_id' <<<"$GET_OUTPUT"); release decision $(jq -r '.flow.decision.decision_id' <<<"$GET_OUTPUT") (\"$(jq -r '.flow.decision.reason' <<<"$GET_OUTPUT")\") after $(jq -r '.flow.steps | length' <<<"$GET_OUTPUT") transitions, state $(jq -r '.state' <<<"$GET_OUTPUT")"
        # Pretty-print the final job view. The JSON is intentionally
        # stable across runs (sagvd writes it via JobView).
        jq . <<<"$GET_OUTPUT"
        exit 0
        ;;
      failed)
        echo "submit_job.sh: job failed — $(jq -r '.error.code' <<<"$GET_OUTPUT"): $(jq -r '.error.message' <<<"$GET_OUTPUT") (state $(jq -r '.state' <<<"$GET_OUTPUT"), decision $(jq -r '.flow.decision.reason // "none"' <<<"$GET_OUTPUT"))" >&2
        jq . <<<"$GET_OUTPUT" >&2
        exit 3
        ;;
      queued|running)
        # Keep polling.
        :
        ;;
      *)
        # Unknown status. Don't hard-fail; log and keep polling so a
        # transient schema-version mismatch between the script and
        # sagvd doesn't immediately tank the demo.
        echo "submit_job.sh: unexpected status '${STATUS}'; continuing" >&2
        ;;
    esac
  fi

  if (( $(date +%s) >= DEADLINE_EPOCH )); then
    echo "submit_job.sh: timed out after ${POLL_TIMEOUT}s waiting for job ${JOB_ID}" >&2
    echo "  last observed body:" >&2
    echo "  ${GET_OUTPUT:-<empty>}" >&2
    exit 2
  fi

  sleep "$POLL_INTERVAL"
done
