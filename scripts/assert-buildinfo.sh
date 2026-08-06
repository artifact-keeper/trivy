#!/usr/bin/env bash
# =============================================================================
# Assert that the dependency overrides are actually present in the compiled
# binary — not just in go.mod.
# =============================================================================
#
# Usage: assert-buildinfo.sh <trivy-binary> <overrides.yaml>
#
# Reads the Go build info embedded in the binary (`go version -m`), which is
# the same data Trivy's own `gobinary` analyzer reads and therefore the same
# data our CVE gate scores the image on. Arch-independent: works on a
# cross-compiled binary the builder cannot execute.
#
# For each override:
#   * the `from` (vulnerable) version MUST NOT appear   -> hard failure
#   * if the module is linked in, it MUST be at `to`    -> hard failure
#
# A module that is in the module graph but not linked into the binary is
# reported explicitly rather than silently passing, because "not linked" and
# "successfully upgraded" are very different security claims.

set -euo pipefail

BIN="${1:?usage: assert-buildinfo.sh <trivy-binary> <overrides.yaml>}"
OVERRIDES="${2:?missing overrides.yaml path}"

log() { printf '\033[1m[buildinfo]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[buildinfo] FATAL:\033[0m %s\n' "$*" >&2; exit 1; }

[ -f "${BIN}" ] || die "binary not found: ${BIN}"

INFO="$(go version -m "${BIN}")"

python3 - "${OVERRIDES}" <<'PY' > /tmp/.overrides.tsv
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1])) or {}
for ov in doc.get("overrides") or []:
    print("\t".join([str(ov["module"]), str(ov["from"]), str(ov["to"]),
                     ",".join(str(a) for a in ov["advisories"])]))
PY

failed=0
while IFS=$'\t' read -r module from to advisories; do
    [ -n "${module}" ] || continue

    # Lines look like:  dep  oras.land/oras-go/v2  v2.6.2  h1:...
    line="$(awk -v m="${module}" '($1=="dep" || $1=="mod" || $1=="=>") && $2==m {print; exit}' <<< "${INFO}" || true)"

    if grep -qE "[[:space:]]${module}[[:space:]]+${from}([[:space:]]|$)" <<< "${INFO}"; then
        printf '\033[1;31mFAIL\033[0m  %s is still %s in the binary (%s NOT fixed)\n' \
            "${module}" "${from}" "${advisories}" >&2
        failed=1
        continue
    fi

    if [ -z "${line}" ]; then
        log "NOTE  ${module} is not linked into the binary at all"
        log "      => ${advisories} is not reachable in this artifact."
        log "      (overrides.yaml still bumped the module graph; see apply-overrides output)"
        continue
    fi

    got="$(awk '{print $3}' <<< "${line}")"
    if [ "${got}" != "${to}" ]; then
        printf '\033[1;31mFAIL\033[0m  %s is %s in the binary, expected %s\n' \
            "${module}" "${got}" "${to}" >&2
        failed=1
        continue
    fi
    printf '\033[1;32mOK\033[0m    %s %s (was %s, fixes %s)\n' \
        "${module}" "${got}" "${from}" "${advisories}" >&2
done < /tmp/.overrides.tsv

rm -f /tmp/.overrides.tsv
[ "${failed}" -eq 0 ] || die "one or more overrides are NOT present in the compiled binary"
log "all overrides verified in compiled build info"
