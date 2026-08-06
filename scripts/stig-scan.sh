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
PROFILE="${PROFILE:-xccdf_org.ssgproject.content_profile_stig}"
SCANNER_IMAGE="${SCANNER_IMAGE:-registry.access.redhat.com/ubi9/ubi@sha256:e79f79172a6779775e1733cb4f49cd5ef03a0703c68ec46c717f93b9ac4a5e71}"

mkdir -p "${OUT_DIR}"
OUT_DIR="$(cd "${OUT_DIR}" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

echo "== fetching SCAP Security Guide ${SSG_VERSION}"
curl -sSfL -o "${WORK}/ssg.zip" \
  "https://github.com/ComplianceAsCode/content/releases/download/${SSG_VERSION}/scap-security-guide-${SSG_VERSION#v}.zip"
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
docker run --rm \
    -v "${WORK}/rootfs.tar:/rootfs.tar:ro" \
    -v "${DS_DIR}:/ssg:ro" \
    -v "${OUT_DIR}:/out" \
    "${SCANNER_IMAGE}" bash -c '
        set -e
        dnf install -y -q --nodocs openscap-scanner >/dev/null 2>&1
        mkdir -p /work
        # as root: preserves the ownership the ownership rules are scored on
        tar -xf /rootfs.tar -C /work
        OSCAP_PROBE_ROOT=/work oscap xccdf eval \
            --profile "'"${PROFILE}"'" \
            --results /out/stig-results.xml \
            --report  /out/stig-report.html \
            /ssg/ssg-rhel9-ds.xml > /out/stig-eval.log 2>&1 || true
        chmod -R a+r /out
    '

echo "== summary"
python3 - "${OUT_DIR}/stig-eval.log" "${OUT_DIR}/stig-summary.md" "${IMAGE}" "${PROFILE}" "${SSG_VERSION}" <<'PY'
import collections, sys
log, out_md, image, profile, ssg = sys.argv[1:6]
# oscap writes "Key\r\tValue"; read with newline='' so \r survives universal newlines
txt = open(log, encoding="utf-8", errors="replace", newline="").read().replace("\r\t", "\t")
rows = []
for block in txt.split("\n\n"):
    d = dict(l.split("\t", 1) for l in block.strip().split("\n") if "\t" in l)
    if "Rule" in d and "Result" in d:
        rows.append((d.get("Title", ""), d["Rule"], d["Result"]))
c = collections.Counter(r for _, _, r in rows)
total = sum(c.values())
scored = c["pass"] + c["fail"]
short = lambda r: r.replace("xccdf_org.ssgproject.content_rule_", "")

lines = [
    f"### DISA STIG compliance — `{image}`", "",
    f"- **Profile**: `{profile}` (DISA STIG for Red Hat Enterprise Linux 9)",
    f"- **Content**: SCAP Security Guide {ssg}",
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
