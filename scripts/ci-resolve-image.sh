#!/usr/bin/env bash
# =============================================================================
# Resolve the artifact produced by the `build` job into a locally usable tag.
# =============================================================================
#
# Usage: ci-resolve-image.sh <ref-file> <arch> <local-tag>
#
# The build job writes a one-line ref file describing what it produced:
#
#   tar:image-<arch>.tar        PR mode — nothing was pushed anywhere, the
#                               image only exists as a tarball artifact.
#   <registry>/<repo>@sha256:…  push mode — the image was pushed BY DIGEST and
#                               that digest is what publish will assemble into
#                               the manifest list.
#
# The point of the digest form is that every downstream job — verify, the CVE
# gate, the STIG evaluation — tests the exact bytes that get published, rather
# than a second build that merely used the same Dockerfile. This build is not
# hermetic (dnf --refresh, a live git fetch, go get) and the publish step adds
# provenance and SBOM attestations, so "same inputs" would not have meant
# "same bytes".

set -euo pipefail

REF_FILE="${1:?usage: ci-resolve-image.sh <ref-file> <arch> <local-tag>}"
ARCH="${2:?missing arch}"
LOCAL_TAG="${3:?missing local tag}"

[ -f "${REF_FILE}" ] || { echo "ref file not found: ${REF_FILE}" >&2; exit 1; }
REF="$(tr -d '[:space:]' < "${REF_FILE}")"
[ -n "${REF}" ] || { echo "ref file ${REF_FILE} is empty" >&2; exit 1; }

case "${REF}" in
    tar:*)
        TARBALL="${REF#tar:}"
        [ -f "${TARBALL}" ] || { echo "tarball not found: ${TARBALL}" >&2; exit 1; }
        echo "resolving from tarball ${TARBALL}"
        # `docker load` restores whatever tag the tarball was saved under, which
        # is not necessarily the tag this job wants. Re-tag explicitly rather
        # than relying on them happening to match.
        LOAD_OUT="$(docker load -i "${TARBALL}")"
        echo "${LOAD_OUT}"
        if ! docker image inspect "${LOCAL_TAG}" >/dev/null 2>&1; then
            LOADED="$(sed -n 's/^Loaded image: //p;s/^Loaded image ID: //p' <<< "${LOAD_OUT}" | head -1)"
            [ -n "${LOADED}" ] || { echo "could not determine what ${TARBALL} loaded as" >&2; exit 1; }
            echo "re-tagging ${LOADED} as ${LOCAL_TAG}"
            docker tag "${LOADED}" "${LOCAL_TAG}"
        fi
        ;;
    *@sha256:*)
        echo "resolving from registry digest ${REF}"
        docker pull --platform "linux/${ARCH}" "${REF}"
        docker tag "${REF}" "${LOCAL_TAG}"
        ;;
    *)
        echo "unrecognised ref '${REF}' — expected 'tar:<file>' or '<repo>@sha256:<digest>'" >&2
        exit 1
        ;;
esac

# Whatever the source, the downstream job must end up with the expected tag and
# the expected architecture. A silent arch mix-up would mean the gate scored a
# different image than the one it names.
docker image inspect "${LOCAL_TAG}" >/dev/null || {
    echo "expected local tag ${LOCAL_TAG} to exist after resolution" >&2
    exit 1
}
GOT_ARCH="$(docker image inspect -f '{{.Architecture}}' "${LOCAL_TAG}")"
[ "${GOT_ARCH}" = "${ARCH}" ] || {
    echo "resolved image is ${GOT_ARCH}, expected ${ARCH}" >&2
    exit 1
}
echo "resolved ${LOCAL_TAG} (${GOT_ARCH})"
