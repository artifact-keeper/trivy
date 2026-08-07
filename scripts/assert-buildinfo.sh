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
#   * the `from` (vulnerable) version MUST NOT appear             -> failure
#   * the module MUST be linked in, at exactly `to`               -> failure
#     unless the entry sets `expect_linked: false`, which requires
#     a documented reason in `linked_justification`.
#
# Before any of that, the build info itself must look real. An earlier version
# of this script treated "module not found in the output" as an informational
# note, which meant a binary with NO build info at all — a stubbed toolchain, a
# stripped or non-Go file, a `go version -m` that errored to stdout — printed
# "all overrides verified" and exited 0. That is the failure mode this script
# exists to prevent, so the record count is now a precondition.

set -euo pipefail

BIN="${1:?usage: assert-buildinfo.sh <trivy-binary> <overrides.yaml>}"
OVERRIDES="${2:?missing overrides.yaml path}"
# A Trivy build links several hundred modules; anything near zero means we are
# not looking at real build info.
MIN_DEPS="${MIN_DEPS:-50}"

log() { printf '\033[1m[buildinfo]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[buildinfo] FATAL:\033[0m %s\n' "$*" >&2; exit 1; }

[ -f "${BIN}" ] || die "binary not found: ${BIN}"

INFO="$(go version -m "${BIN}")"

# --- precondition: this really is Go build info ----------------------------
if ! grep -qE '^[[:space:]]*(path|mod)[[:space:]]' <<< "${INFO}"; then
    die "no main-module record (path/mod) in \`go version -m ${BIN}\`.
This binary has no readable Go build info, so NOTHING below could be checked.
Refusing to report the overrides as verified."
fi

DEP_COUNT="$(grep -cE '^[[:space:]]*(dep|=>)[[:space:]]' <<< "${INFO}" || true)"
if [ "${DEP_COUNT}" -lt "${MIN_DEPS}" ]; then
    die "only ${DEP_COUNT} dependency records in the build info of ${BIN}, expected >= ${MIN_DEPS}.
Either this is not the Trivy binary or the build info is truncated. An override
cannot be verified against build info that is not there."
fi
log "build info looks sane: ${DEP_COUNT} dependency records"

TSV="$(mktemp)"
trap 'rm -f "${TSV}"' EXIT

python3 - "${OVERRIDES}" <<'PY' > "${TSV}"
import sys
try:
    import yaml
except ImportError:
    sys.exit("python3-pyyaml is required to parse overrides.yaml")
doc = yaml.safe_load(open(sys.argv[1])) or {}
for i, ov in enumerate(doc.get("overrides") or []):
    # Default: the module must be linked into the binary. Opting out is a
    # deliberate, justified choice, not a silent fallback.
    expect_linked = ov.get("expect_linked", True)
    if not expect_linked and not ov.get("linked_justification"):
        sys.exit(
            f"overrides.yaml entry #{i} ({ov.get('module')}): expect_linked is false "
            "but linked_justification is missing. Claiming a module is not linked "
            "into the binary requires stating how that was determined."
        )
    print("\t".join([
        str(ov["module"]), str(ov["from"]), str(ov["to"]),
        ",".join(str(a) for a in ov["advisories"]),
        "yes" if expect_linked else "no",
    ]))
PY

failed=0
checked=0
while IFS=$'\t' read -r module from to advisories expect_linked; do
    [ -n "${module}" ] || continue
    checked=$((checked + 1))

    # Lines look like:  dep  oras.land/oras-go/v2  v2.6.2  h1:...
    line="$(awk -v m="${module}" '($1=="dep" || $1=="mod" || $1=="=>") && $2==m {print; exit}' <<< "${INFO}" || true)"

    if grep -qE "[[:space:]]${module}[[:space:]]+${from}([[:space:]]|$)" <<< "${INFO}"; then
        printf '\033[1;31mFAIL\033[0m  %s is still %s in the binary (%s NOT fixed)\n' \
            "${module}" "${from}" "${advisories}" >&2
        failed=1
        continue
    fi

    if [ -z "${line}" ]; then
        if [ "${expect_linked}" = "yes" ]; then
            printf '\033[1;31mFAIL\033[0m  %s is not linked into the binary at all.\n' "${module}" >&2
            printf '      Expected it at %s. Either the override did not take, or the\n' "${to}" >&2
            printf '      dependency really is unreachable — in which case set\n' >&2
            printf '      expect_linked: false with a linked_justification in overrides.yaml.\n' >&2
            failed=1
        else
            log "OK    ${module} not linked (declared: expect_linked false); ${advisories} unreachable here"
        fi
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
done < "${TSV}"

[ "${failed}" -eq 0 ] || die "one or more overrides are NOT present in the compiled binary"
log "verified ${checked} override(s) against ${DEP_COUNT} dependency records"
