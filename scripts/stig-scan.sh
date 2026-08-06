#!/usr/bin/env bash
# =============================================================================
# DISA STIG evaluation of a built image (OpenSCAP / SCAP Security Guide).
# =============================================================================
#
# Usage: stig-scan.sh [image-ref] [output-dir]
#
# Profile: xccdf_org.ssgproject.content_profile_stig from ssg-rhel9-ds.xml
#          ("DISA STIG for Red Hat Enterprise Linux 9"), the same profile
#          artifact-keeper's docker-publish workflow evaluates its images
#          against. See README.md "DISA STIG compliance" for the applicability
#          argument and the documented exceptions.
#
# Two deliberate differences from the equivalent steps in artifact-keeper's
# docker-publish.yml, both of which were producing no evidence there:
#
#   1. `oscap xccdf eval --chroot` DOES NOT EXIST. OpenSCAP 1.3.x rejects it
#      with "unrecognized option '--chroot'". Because those steps end in
#      `|| true`, the failure is swallowed and the artifact upload finds no
#      results file. Offline evaluation is done with OSCAP_PROBE_ROOT (or the
#      separate oscap-chroot wrapper), which is what this script uses.
#
#   2. The container filesystem is extracted AS ROOT from `docker export`.
#      Extracting as an unprivileged user rewrites every file's owner, and
#      the STIG profile has ~15 file-ownership rules that then fail for a
#      reason that has nothing to do with the image. Measured here: that
#      mistake alone moved the result from 61 pass / 5 fail to 45 pass /
#      21 fail. Compliance numbers produced that way are noise.
#
# oscap exits 2 when any rule fails, which is the normal outcome for a
# container evaluated against a host baseline. This script therefore reports
# and does not gate; the CVE gate is the blocking one.

set -euo pipefail

IMAGE="${1:-ak-trivy:dev}"
OUT_DIR="${2:-stig-out}"
SSG_VERSION="${SSG_VERSION:-v0.1.81}"
SSG_SHA256="${SSG_SHA256:-865e28b793e1e65f7f0102434bc7d962324a4b9324591e60742f1e9ce375172c}"
PROFILE="${PROFILE:-xccdf_org.ssgproject.content_profile_stig}"
SCANNER_IMAGE="${SCANNER_IMAGE:-registry.access.redhat.com/ubi9/ubi@sha256:e79f79172a6779775e1733cb4f49cd5ef03a0703c68ec46c717f93b9ac4a5e71}"
# Exact NEVR, not a floating name. The scanner version determines how rules are
# evaluated, so unpinned it is an unrecorded variable in every result. When RHEL
# retires this build the install fails loudly and this pin gets bumped — that is
# the intended behaviour, not an outage to work around with a fallback.
OSCAP_PKG="${OSCAP_PKG:-openscap-scanner-1.3.14-1.el9_8}"
# Known-good floor for the number of rules the RHEL 9 STIG profile evaluates.
# Guards against a truncated or empty log being summarised as a clean result.
MIN_RULES="${MIN_RULES:-400}"

mkdir -p "${OUT_DIR}"
OUT_DIR="$(cd "${OUT_DIR}" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

echo "== fetching SCAP Security Guide ${SSG_VERSION}"
# Pinned by sha256, like the Go toolchain tarball in the Dockerfile. GitHub
# release assets are mutable — an uploader can delete and re-upload an asset
# under the same tag — and this datastream is the sole input to every
# compliance number this script emits. Unpinned content means the evidence
# cannot be reproduced.
curl -sSfL -o "${WORK}/ssg.zip" \
  "https://github.com/ComplianceAsCode/content/releases/download/${SSG_VERSION}/scap-security-guide-${SSG_VERSION#v}.zip"
echo "${SSG_SHA256}  ${WORK}/ssg.zip" | sha256sum -c - || {
    echo "FATAL: SCAP content checksum mismatch for ${SSG_VERSION}." >&2
    echo "The release asset changed, or SSG_VERSION was bumped without bumping SSG_SHA256." >&2
    exit 1
}
mkdir -p "${WORK}/ssg"
(cd "${WORK}/ssg" && unzip -q "${WORK}/ssg.zip")
DS="$(find "${WORK}/ssg" -name 'ssg-rhel9-ds.xml' | head -1)"
[ -n "${DS}" ] || { echo "ssg-rhel9-ds.xml not found in the SSG release" >&2; exit 1; }
DS_DIR="$(dirname "${DS}")"

echo "== exporting ${IMAGE} filesystem"
CID="$(docker create "${IMAGE}")"
docker export "${CID}" -o "${WORK}/rootfs.tar"
docker rm "${CID}" >/dev/null
chmod 0644 "${WORK}/rootfs.tar"
chmod 0755 "${WORK}"

echo "== evaluating ${PROFILE}"
# oscap's exit codes: 0 = every rule passed, 1 = ERROR (bad content, bad
# profile, scanner not installed, unreadable target), 2 = evaluation completed
# with at least one failing rule. Only 0 and 2 mean "we actually assessed the
# image". Swallowing 1 with `|| true` is what turns a broken toolchain into a
# clean-looking compliance artifact, so the rc is captured and checked.
set +e
docker run --rm \
    -v "${WORK}/rootfs.tar:/rootfs.tar:ro" \
    -v "${DS_DIR}:/ssg:ro" \
    -v "${OUT_DIR}:/out" \
    "${SCANNER_IMAGE}" bash -c '
        set -e
        dnf install -y -q --nodocs "'"${OSCAP_PKG}"'" >/dev/null 2>&1 || {
            echo "FATAL: could not install '"${OSCAP_PKG}"'." >&2
            echo "If RHEL has retired that build, re-pin OSCAP_PKG in scripts/stig-scan.sh." >&2
            exit 1
        }
        rpm -q openscap-scanner > /out/oscap-version.txt
        oscap --version | head -1 >> /out/oscap-version.txt
        mkdir -p /work
        # as root: preserves the ownership the ownership rules are scored on
        tar -xf /rootfs.tar -C /work
        OSCAP_PROBE_ROOT=/work oscap xccdf eval \
            --profile "'"${PROFILE}"'" \
            --results /out/stig-results.xml \
            --report  /out/stig-report.html \
            /ssg/ssg-rhel9-ds.xml > /out/stig-eval.log 2>&1
        rc=$?
        chmod -R a+r /out
        exit ${rc}
    '
OSCAP_RC=$?
set -e

case "${OSCAP_RC}" in
    0) echo "oscap rc=0 (all rules passed)" ;;
    2) echo "oscap rc=2 (evaluation completed, some rules failed — expected)" ;;
    *)
        echo "FATAL: oscap exited ${OSCAP_RC}. This is an INFRASTRUCTURE failure," >&2
        echo "not a compliance result. No evidence is being produced." >&2
        echo "--- last 40 lines of the eval log ---" >&2
        tail -40 "${OUT_DIR}/stig-eval.log" >&2 2>/dev/null || true
        exit 1
        ;;
esac

# A results XML that is missing or empty means oscap produced no assessment
# even if it somehow exited 0/2.
[ -s "${OUT_DIR}/stig-results.xml" ] || {
    echo "FATAL: ${OUT_DIR}/stig-results.xml is missing or empty — no evidence produced." >&2
    exit 1
}
echo "scanner: $(tr '\n' ' ' < "${OUT_DIR}/oscap-version.txt" 2>/dev/null)"

echo "== summary"
python3 - "${OUT_DIR}/stig-eval.log" "${OUT_DIR}/stig-summary.md" "${IMAGE}" "${PROFILE}" \
         "${SSG_VERSION}" "${MIN_RULES}" "${OUT_DIR}/oscap-version.txt" <<'PY'
import collections, sys, os
log, out_md, image, profile, ssg, min_rules, verfile = sys.argv[1:8]
min_rules = int(min_rules)
# oscap writes "Key\r\tValue"; read with newline='' so \r survives universal newlines
txt = open(log, encoding="utf-8", errors="replace", newline="").read().replace("\r\t", "\t")
rows = []
for block in txt.split("\n\n"):
    d = dict(l.split("\t", 1) for l in block.strip().split("\n") if "\t" in l)
    if "Rule" in d and "Result" in d:
        rows.append((d.get("Title", ""), d["Rule"], d["Result"]))
c = collections.Counter(r for _, _, r in rows)
total = sum(c.values())

# A summariser with no floor will happily render an error log as
# "Rules evaluated: 0 / No failing rules." — an affirmatively reassuring
# compliance artifact produced from nothing. Refuse to emit a summary that
# is not backed by a plausible evaluation.
if total < min_rules:
    sys.exit(
        f"FATAL: parsed only {total} rule results from {log}, expected at least "
        f"{min_rules}.\nThe evaluation did not really run (truncated log, wrong "
        f"profile, or a scanner error). Refusing to write a compliance summary "
        f"that would read as a clean result."
    )

scanner = ""
if os.path.exists(verfile):
    scanner = " / ".join(l.strip() for l in open(verfile) if l.strip())

scored = c["pass"] + c["fail"]
short = lambda r: r.replace("xccdf_org.ssgproject.content_rule_", "")

lines = [
    f"### DISA STIG compliance — `{image}`", "",
    f"- **Profile**: `{profile}` (DISA STIG for Red Hat Enterprise Linux 9)",
    f"- **Content**: SCAP Security Guide {ssg}",
    f"- **Scanner**: {scanner or 'unrecorded'}",
    f"- **Rules evaluated**: {total}", "",
    "| Result | Count | Share |", "|---|---:|---:|",
]
for k, v in c.most_common():
    lines.append(f"| {k} | {v} | {100*v/total:.1f}% |")
if scored:
    lines += ["", f"**Pass rate of scored rules (pass+fail): {c['pass']}/{scored} = {100*c['pass']/scored:.1f}%**"]
lines += ["", f"{c['notapplicable']} rules are *notapplicable*: the RHEL 9 STIG is a host baseline and most of "
          "it (bootloader, kernel params, auditd, sshd, PAM, GUI, firewall, physical media) has no counterpart "
          "in a single-binary container image.", ""]
not_passing = [(t, r, res) for t, r, res in rows if res in ("fail", "error", "notchecked")]
if not_passing:
    lines += ["Rules not passing:", ""]
    for t, r, res in not_passing:
        lines.append(f"- `{short(r)}` — {t} (**{res}**)")
else:
    lines.append("No failing rules.")
open(out_md, "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
PY

echo
echo "artifacts: ${OUT_DIR}/stig-results.xml ${OUT_DIR}/stig-report.html ${OUT_DIR}/stig-summary.md"
