#!/usr/bin/env bash
# =============================================================================
# Prove the built image is a WORKING scanner, not just a binary that exists.
# =============================================================================
#
# Usage: verify-image.sh [image-ref]        (default: ak-trivy:dev)
#
# A build that produces a broken scanner is worse than the CVE it was meant to
# fix, because it fails open: `trivy` exiting 0 with no findings looks exactly
# like "clean". Every check here is designed to fail loudly instead.
#
#   1. VERSION    — `trivy --version` parses with the exact same logic
#                   artifact-keeper's scanner-adapter uses (parseTrivyVersion,
#                   docker/scanner-adapter/scan.go) and matches the pinned tag.
#   2. TRUST      — actually downloads the vulnerability DB over HTTPS from an
#                   OCI registry. ubi-micro ships no CA trust store; a missing
#                   one fails at first scan in production, not at build time.
#                   `--version` would never catch it. This does.
#   3. FINDINGS   — scans a fixture with known-vulnerable deps and asserts it
#                   reports something. Guards against fail-open scanners.
#   4. DEP PIN    — scans the shipped trivy binary WITH the shipped trivy and
#                   asserts the tracked module is at the fixed version and that
#                   its CVE is not reported. This is the CVE claim.
#                   Until v0.74.0 this tracked oras-go v2.6.1 -> v2.6.2, which
#                   we carried as an override in overrides.yaml. Upstream
#                   v0.74.0 pins oras-go v2.6.2 itself, so that override is
#                   gone and the check now tracks golang.org/x/mod v0.38.0 ->
#                   v0.40.0 (CVE-2026-56864/-56865), the finding that blocked
#                   artifact-keeper's v1.8.1 publish. The assertion is the same
#                   shape either way: it proves the version claim landed IN THE
#                   SHIPPED BINARY, whether it got there via upstream's pin or
#                   via one of ours.
#   5. HARDENING  — non-root numeric UID, no package manager, licences present.
#
# Requires: docker, python3.

set -euo pipefail

IMAGE="${1:-ak-trivy:dev}"
EXPECT_VERSION="${EXPECT_VERSION:-0.74.0}"
OVERRIDE_MODULE="${OVERRIDE_MODULE:-golang.org/x/mod}"
OVERRIDE_BAD="${OVERRIDE_BAD:-v0.38.0}"
OVERRIDE_GOOD="${OVERRIDE_GOOD:-v0.40.0}"
OVERRIDE_CVE="${OVERRIDE_CVE:-CVE-2026-56864}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE_VOL="ak-trivy-verify-cache"
WORK="$(mktemp -d)"
FAILURES=0

cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT

hdr()  { printf '\n\033[1m=== %s\033[0m\n' "$*"; }
pass() { printf '  \033[1;32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[1;31mFAIL\033[0m  %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

docker volume create "${CACHE_VOL}" >/dev/null

# trivy runs as UID 1001; the named volume must be writable by it.
run_trivy() {
    docker run --rm \
        -v "${CACHE_VOL}:/home/trivy/.cache/trivy" \
        -v "${REPO_ROOT}/fixtures:/fixtures:ro" \
        "${IMAGE}" "$@"
}

echo "verifying image: ${IMAGE}"
docker run --rm --user 0:0 -v "${CACHE_VOL}:/cache" --entrypoint /usr/bin/chown \
    "${IMAGE}" -R 1001:0 /cache >/dev/null 2>&1 || true

# --------------------------------------------------------------------------
hdr "1. version string is parseable and correct"
VERSION_OUT="$(run_trivy --version 2>&1 || true)"
printf '%s\n' "${VERSION_OUT}" | sed 's/^/      /'

# Mirrors parseTrivyVersion: first line starting with "Version:", value trimmed.
PARSED="$(printf '%s\n' "${VERSION_OUT}" \
    | sed -n 's/^[[:space:]]*Version:[[:space:]]*\(.*\)$/\1/p' \
    | head -1 | tr -d '[:space:]')"

if [ -z "${PARSED}" ]; then
    fail "no 'Version:' line — scanner-adapter's parseTrivyVersion would return \"\" and error out"
elif [ "${PARSED}" != "${EXPECT_VERSION}" ]; then
    fail "version is '${PARSED}', expected '${EXPECT_VERSION}'"
else
    pass "parsed version = ${PARSED}"
fi

# --------------------------------------------------------------------------
hdr "2. CA trust store works (real HTTPS vulnerability-DB download)"
if run_trivy image --download-db-only > "${WORK}/db.log" 2>&1; then
    pass "vulnerability DB downloaded over HTTPS from the OCI registry"
else
    sed 's/^/      /' "${WORK}/db.log" | tail -20
    if grep -qiE "certificate|x509|tls" "${WORK}/db.log"; then
        fail "DB download failed on TLS trust — CA certificates are MISSING from the final layer"
    else
        fail "DB download failed (see log above; may be network rather than trust store)"
    fi
fi

# tzdata: Trivy timestamps advisories and report metadata in local time.
if docker run --rm --entrypoint /usr/bin/test "${IMAGE}" -f /usr/share/zoneinfo/UTC; then
    pass "tzdata present (/usr/share/zoneinfo/UTC)"
else
    fail "tzdata missing — time-zone-dependent output will fall back to UTC-only"
fi

# --------------------------------------------------------------------------
hdr "3. an end-to-end scan actually reports findings"
run_trivy fs --scanners vuln --skip-db-update --format json --quiet \
    /fixtures/verify > "${WORK}/fixture.json" 2>"${WORK}/fixture.err" || true

python3 - "${WORK}/fixture.json" <<'PY' > "${WORK}/fixture.summary" 2>&1 || true
import json, sys
try:
    doc = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"UNPARSEABLE {e}"); sys.exit(0)
vulns = [v for r in (doc.get("Results") or []) for v in (r.get("Vulnerabilities") or [])]
print(f"COUNT {len(vulns)}")
for v in vulns[:10]:
    print(f"  {v.get('VulnerabilityID')} {v.get('PkgName')} {v.get('InstalledVersion')} {v.get('Severity')}")
PY
sed 's/^/      /' "${WORK}/fixture.summary"

FIX_COUNT="$(sed -n 's/^COUNT \([0-9]*\)$/\1/p' "${WORK}/fixture.summary" | head -1)"
if [ -z "${FIX_COUNT}" ]; then
    tail -10 "${WORK}/fixture.err" | sed 's/^/      /'
    fail "scan produced no parseable JSON report"
elif [ "${FIX_COUNT}" -eq 0 ]; then
    fail "scan of a KNOWN-VULNERABLE fixture reported 0 vulnerabilities — the scanner is failing open"
else
    pass "fixture scan reported ${FIX_COUNT} vulnerabilities"
fi

# --------------------------------------------------------------------------
hdr "4. the tracked dependency pin took effect (${OVERRIDE_CVE})"
# Scan the IMAGE with the trivy inside that same image, via a saved tarball.
# `trivy fs` on the binary path alone does not engage the gobinary analyzer,
# and more importantly an image scan is precisely what artifact-keeper's
# Docker Publish gate runs — so this measures the thing that actually gates us.
docker save "${IMAGE}" -o "${WORK}/image.tar"
chmod 0644 "${WORK}/image.tar"   # readable by UID 1001 inside the container
chmod 0755 "${WORK}"

docker run --rm \
    -v "${CACHE_VOL}:/home/trivy/.cache/trivy" \
    -v "${WORK}/image.tar:/scan/image.tar:ro" \
    "${IMAGE}" image --input /scan/image.tar --skip-db-update \
    --list-all-pkgs --format json --quiet \
    > "${WORK}/self.json" 2>"${WORK}/self.err" || true

python3 - "${WORK}/self.json" "${OVERRIDE_MODULE}" "${OVERRIDE_GOOD}" "${OVERRIDE_BAD}" "${OVERRIDE_CVE}" \
    > "${WORK}/self.summary" 2>&1 <<'PY' || true
import json, sys
path, module, good, bad, cve = sys.argv[1:6]
try:
    doc = json.load(open(path))
except Exception as e:
    print(f"UNPARSEABLE {e}"); sys.exit(0)
results = doc.get("Results") or []
pkgs = [p for r in results for p in (r.get("Packages") or [])]
vulns = [v for r in results for v in (r.get("Vulnerabilities") or [])]
found = sorted({p.get("Version") for p in pkgs if p.get("Name") == module})
print(f"MODULE_VERSIONS {' '.join(found) if found else '(module not reported)'}")
print(f"HAS_GOOD {'yes' if good in found else 'no'}")
print(f"HAS_BAD {'yes' if bad in found else 'no'}")
print(f"CVE_PRESENT {'yes' if any(v.get('VulnerabilityID') == cve for v in vulns) else 'no'}")
print(f"TOTAL_PKGS {len(pkgs)}")
print(f"TOTAL_VULNS {len(vulns)}")
for v in vulns:
    print(f"  RESIDUAL {v.get('VulnerabilityID')} {v.get('PkgName')} {v.get('InstalledVersion')} -> {v.get('FixedVersion')} [{v.get('Severity')}]")
PY
sed 's/^/      /' "${WORK}/self.summary"

get() { sed -n "s/^$1 //p" "${WORK}/self.summary" | head -1; }
if [ -z "$(get TOTAL_PKGS)" ]; then
    tail -10 "${WORK}/self.err" | sed 's/^/      /'
    fail "could not scan the shipped trivy binary"
else
    [ "$(get HAS_BAD)"  = "no"  ] && pass "${OVERRIDE_MODULE} ${OVERRIDE_BAD} is NOT present" \
                                  || fail "${OVERRIDE_MODULE} ${OVERRIDE_BAD} IS STILL PRESENT — the pin did not take"
    [ "$(get HAS_GOOD)" = "yes" ] && pass "${OVERRIDE_MODULE} ${OVERRIDE_GOOD} is present" \
                                  || fail "${OVERRIDE_MODULE} ${OVERRIDE_GOOD} not reported (got: $(get MODULE_VERSIONS))"
    [ "$(get CVE_PRESENT)" = "no" ] && pass "${OVERRIDE_CVE} is not reported against the shipped binary" \
                                    || fail "${OVERRIDE_CVE} IS STILL REPORTED"
fi

# --------------------------------------------------------------------------
hdr "5. runtime hardening"
CFG_USER="$(docker image inspect -f '{{.Config.User}}' "${IMAGE}")"
[ "${CFG_USER}" = "1001" ] && pass "runs as non-root numeric UID ${CFG_USER}" \
                           || fail "image user is '${CFG_USER}', expected numeric 1001"

RUNTIME_UID="$(docker run --rm --entrypoint /usr/bin/id "${IMAGE}" -u)"
[ "${RUNTIME_UID}" = "1001" ] && pass "effective runtime UID is ${RUNTIME_UID}" \
                              || fail "effective runtime UID is ${RUNTIME_UID}"

# Probed one path at a time with `test -f`: parsing `ls` output here would
# also swallow docker's "requested image's platform does not match" warning
# and report it as a package manager.
PKGMGR=""
for p in /usr/bin/dnf /usr/bin/microdnf /usr/bin/yum /usr/bin/rpm /usr/bin/apt-get /usr/bin/apk; do
    if docker run --rm --entrypoint /usr/bin/test "${IMAGE}" -f "${p}" 2>/dev/null; then
        PKGMGR="${PKGMGR} ${p}"
    fi
done
[ -z "${PKGMGR}" ] && pass "no package manager in the final layer" \
                   || fail "package manager present:${PKGMGR}"

for f in /licenses/LICENSE /licenses/trivy/LICENSE /licenses/trivy/NOTICE \
         /licenses/trivy/MODIFICATIONS-overrides.yaml /licenses/trivy/BUILDINFO.txt; do
    if docker run --rm --entrypoint /usr/bin/test "${IMAGE}" -f "${f}"; then
        pass "licence artefact present: ${f}"
    else
        fail "missing licence artefact: ${f} (Apache-2.0 §4 requires the notices to travel with the redistribution)"
    fi
done

# RHEL-09-215105 (CAT I). The STIG scan covers this too, but STIG is evidence
# and this is a gate: a silent regression to DEFAULT should fail the build, not
# just move a number in a report nobody reads.
CP_CONFIG="$(docker run --rm --entrypoint /usr/bin/cat "${IMAGE}" /etc/crypto-policies/config 2>/dev/null | tr -d '[:space:]' || true)"
CP_STATE="$(docker run --rm --entrypoint /usr/bin/cat "${IMAGE}" /etc/crypto-policies/state/current 2>/dev/null | tr -d '[:space:]' || true)"
if [ "${CP_CONFIG}" = "FIPS:STIG" ] && [ "${CP_STATE}" = "FIPS:STIG" ]; then
    pass "system crypto policy is FIPS:STIG (config and state agree)"
else
    fail "crypto policy is config='${CP_CONFIG}' state='${CP_STATE}', expected FIPS:STIG in both"
fi

if docker run --rm --entrypoint /usr/bin/test "${IMAGE}" -s /etc/crypto-policies/back-ends/opensslcnf.config; then
    pass "crypto-policy back-ends were generated"
else
    fail "/etc/crypto-policies/back-ends/opensslcnf.config missing or empty — policy was set but never applied"
fi

# The house pattern appends an [algorithm_sect] block that OpenSSL never reads,
# because openssl.cnf points alg_section at evp_properties. Assert the setting
# is in the section that is actually wired up.
# ubi-micro has no awk, so read the file out and inspect it here.
docker run --rm --entrypoint /usr/bin/cat "${IMAGE}" /etc/pki/tls/openssl.cnf > "${WORK}/openssl.cnf" 2>/dev/null || true
if awk '/^\[[[:space:]]*evp_properties[[:space:]]*\]/{f=1;next} /^\[/{f=0} f && /default_properties[[:space:]]*=[[:space:]]*fips=yes/{ok=1} END{exit !ok}' \
      "${WORK}/openssl.cnf"; then
    pass "openssl.cnf sets default_properties=fips=yes inside [evp_properties]"
else
    fail "openssl.cnf FIPS default_properties is missing from [evp_properties] (an orphan section would be inert)"
fi
if grep -q '^\[algorithm_sect\]' "${WORK}/openssl.cnf"; then
    fail "openssl.cnf still carries an orphan [algorithm_sect] block that OpenSSL never reads"
else
    pass "no orphan [algorithm_sect] block in openssl.cnf"
fi

# Read-only rootfs with a mounted cache must still work.
if docker run --rm --read-only --tmpfs /tmp \
      -v "${CACHE_VOL}:/home/trivy/.cache/trivy" "${IMAGE}" --version >/dev/null 2>&1; then
    pass "runs with --read-only rootfs (cache volume + tmpfs /tmp)"
else
    fail "does not run with a read-only rootfs"
fi

# --------------------------------------------------------------------------
hdr "result"
if [ "${FAILURES}" -eq 0 ]; then
    printf '\033[1;32mall checks passed\033[0m for %s\n' "${IMAGE}"
else
    printf '\033[1;31m%d check(s) failed\033[0m for %s\n' "${FAILURES}" "${IMAGE}"
    exit 1
fi
