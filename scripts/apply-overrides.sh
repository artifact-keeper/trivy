#!/usr/bin/env bash
# =============================================================================
# Apply the reviewed dependency overrides in overrides.yaml to a checked-out
# upstream Trivy source tree.
# =============================================================================
#
# Usage: apply-overrides.sh <trivy-src-dir> <overrides.yaml> <expected-tag>
#
# Guarantees (each one fails the build rather than warning):
#
#   1. overrides.yaml was reviewed against the tag we are actually building.
#   2. Every override is still NEEDED — the pinned source really does contain
#      the `from` version. If upstream has already moved on, the override is
#      stale and MUST be deleted; we refuse to build until it is.
#   3. No override is past its `expires` date.
#   4. Nothing but the declared modules changed version. `go get` on a
#      transitive dependency can pull a wider graph update with it; we diff
#      `go list -m all` before and after and reject any surprise.
#   5. The `to` version is actually what the module graph ends up at.
#
# The point of (4) is that this file is the complete, reviewable statement of
# how our build differs from upstream's. If that stops being true, the build
# stops.

set -euo pipefail

SRC_DIR="${1:?usage: apply-overrides.sh <trivy-src-dir> <overrides.yaml> <expected-tag>}"
OVERRIDES="${2:?missing overrides.yaml path}"
EXPECTED_TAG="${3:?missing expected trivy tag}"

log() { printf '\033[1m[overrides]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[overrides] FATAL:\033[0m %s\n' "$*" >&2; exit 1; }

command -v go >/dev/null || die "go toolchain not on PATH"
command -v python3 >/dev/null || die "python3 required to parse overrides.yaml"
[ -d "${SRC_DIR}" ] || die "source dir not found: ${SRC_DIR}"
[ -f "${OVERRIDES}" ] || die "overrides file not found: ${OVERRIDES}"

# --- parse overrides.yaml into a stable TSV -------------------------------
# Emitted columns: module <TAB> from <TAB> to <TAB> expires <TAB> advisories
PARSED="$(python3 - "${OVERRIDES}" "${EXPECTED_TAG}" <<'PY'
import sys, datetime
try:
    import yaml
except ImportError:
    sys.exit("python3-pyyaml is required to parse overrides.yaml")

path, expected_tag = sys.argv[1], sys.argv[2]
with open(path) as fh:
    doc = yaml.safe_load(fh) or {}

if doc.get("version") != 1:
    sys.exit(f"overrides.yaml: unsupported schema version {doc.get('version')!r}")

reviewed_tag = doc.get("trivy_version")
if reviewed_tag != expected_tag:
    sys.exit(
        f"overrides.yaml was reviewed against {reviewed_tag!r} but the build is "
        f"pinned to {expected_tag!r}.\n"
        "Bumping TRIVY_VERSION requires re-reviewing every override: check each "
        "entry's removal_condition and delete the ones upstream has now shipped."
    )

today = datetime.date.today()
required = ("module", "from", "to", "advisories", "upstream_status",
            "removal_condition", "expires")
rows = []
for i, ov in enumerate(doc.get("overrides") or []):
    missing = [k for k in required if not ov.get(k)]
    if missing:
        sys.exit(f"overrides.yaml entry #{i}: missing required field(s): {missing}")
    expires = ov["expires"]
    if not isinstance(expires, datetime.date):
        expires = datetime.date.fromisoformat(str(expires))
    if expires < today:
        sys.exit(
            f"override for {ov['module']} EXPIRED on {expires}.\n"
            "Re-review it: either upstream has shipped the fix (delete the entry "
            "and bump TRIVY_VERSION) or it still applies (extend `expires` with a "
            "fresh review date). Expiry is deliberate — it is not a warning."
        )
    rows.append("\t".join([
        str(ov["module"]), str(ov["from"]), str(ov["to"]), str(expires),
        ",".join(str(a) for a in ov["advisories"]),
    ]))
print("\n".join(rows))
PY
)"

cd "${SRC_DIR}"

if [ -z "${PARSED}" ]; then
    log "no overrides declared — building pristine upstream ${EXPECTED_TAG}"
    exit 0
fi

# --- snapshot the module graph before we touch anything -------------------
BEFORE="$(mktemp)"; AFTER="$(mktemp)"
trap 'rm -f "${BEFORE}" "${AFTER}"' EXIT
go list -m -f '{{.Path}} {{.Version}}' all > "${BEFORE}"

# --- precondition: every override is still needed -------------------------
while IFS=$'\t' read -r module from to expires advisories; do
    [ -n "${module}" ] || continue
    actual="$(awk -v m="${module}" '$1 == m {print $2}' "${BEFORE}" | head -1)"
    if [ -z "${actual}" ]; then
        die "override for ${module}: module is not in ${EXPECTED_TAG}'s module graph at all.
This override is stale. Delete it from overrides.yaml."
    fi
    if [ "${actual}" != "${from}" ]; then
        die "override for ${module}: overrides.yaml says upstream pins ${from}, but
${EXPECTED_TAG} actually pins ${actual}.
If ${actual} >= ${to}, upstream has SHIPPED the fix — delete this override
(that is its removal_condition). Otherwise the entry needs re-review."
    fi
    log "will bump ${module} ${from} -> ${to}  (${advisories}, expires ${expires})"
done <<< "${PARSED}"

# --- apply -----------------------------------------------------------------
while IFS=$'\t' read -r module from to expires advisories; do
    [ -n "${module}" ] || continue
    log "go get ${module}@${to}"
    go get "${module}@${to}"
done <<< "${PARSED}"

# `go get` updates go.mod/go.sum but leaves the build list to be materialised.
go mod download >/dev/null

go list -m -f '{{.Path}} {{.Version}}' all > "${AFTER}"

# --- postcondition 1: each override landed --------------------------------
while IFS=$'\t' read -r module from to expires advisories; do
    [ -n "${module}" ] || continue
    got="$(awk -v m="${module}" '$1 == m {print $2}' "${AFTER}" | head -1)"
    [ "${got}" = "${to}" ] || die "override for ${module} did not take: expected ${to}, module graph resolved ${got}"
    log "OK ${module} = ${got}"
done <<< "${PARSED}"

# --- postcondition 2: NOTHING else moved ----------------------------------
# This is what keeps overrides.yaml an honest, complete diff against upstream.
DECLARED="$(cut -f1 <<< "${PARSED}" | sort -u)"
# NB: deliberately not using diff(1) — it is not present in a stock UBI 9
# builder, and `diff: command not found` inside a $(...) would make this
# guard silently pass. `sort | uniq -u` over both files is the symmetric
# difference and uses only coreutils.
UNEXPECTED="$(
    cat "${BEFORE}" "${AFTER}" \
        | sort \
        | uniq -u \
        | awk '{print $1}' \
        | sort -u \
        | grep -vxF -f <(printf '%s\n' "${DECLARED}") || true
)"
if [ -n "${UNEXPECTED}" ]; then
    die "applying the overrides also changed modules that are NOT declared in
overrides.yaml:

$(printf '%s\n' "${UNEXPECTED}" | sed 's/^/    /')

Either add them to overrides.yaml with their own justification and removal
condition, or pin them back. An undeclared divergence from upstream is not
allowed to ship."
fi

log "all overrides applied; no undeclared module changes"
