# artifact-keeper/trivy
#
#   make build      build the image for this host's architecture
#   make verify     prove the built image is a working scanner (see scripts/)
#   make gate       run artifact-keeper's exact CVE gate config against it
#   make stig       DISA STIG evaluation, writes stig-out/
#   make buildx     multi-arch build (linux/amd64 + linux/arm64), no load
#   make all        build + verify + gate
#
# Nothing here publishes. Publishing happens only from .github/workflows/build.yml
# on a tag.

IMAGE           ?= ak-trivy:dev
PLATFORMS       ?= linux/amd64,linux/arm64
TRIVY_VERSION   ?= v0.73.0
STIG_OUT        ?= stig-out

# artifact-keeper's docker-publish.yml Trivy gate, verbatim:
#   severity: CRITICAL,HIGH   ignore-unfixed: true   exit-code: 1
GATE_ARGS ?= --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1

.PHONY: all build buildx verify gate stig sbom clean

all: build verify gate

build:
	docker buildx build --load -t $(IMAGE) --build-arg TRIVY_VERSION=$(TRIVY_VERSION) .

buildx:
	docker buildx build --platform $(PLATFORMS) -t $(IMAGE) --build-arg TRIVY_VERSION=$(TRIVY_VERSION) .

verify:
	./scripts/verify-image.sh $(IMAGE)

# Scans the image with the trivy inside that same image, using the exact
# configuration that gates artifact-keeper's publishes. Exits non-zero on a
# fixable CRITICAL/HIGH — which is the whole point of owning this image.
# `trap ... EXIT` rather than an rm after the docker run: with `set -e` an
# image-tarball temp dir would otherwise be left behind on exactly the runs that
# matter — the failing ones — and these are ~230 MB each.
gate:
	@set -eu; \
	tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT INT TERM; \
	chmod 0755 $$tmp; \
	docker save $(IMAGE) -o $$tmp/image.tar; chmod 0644 $$tmp/image.tar; \
	docker volume create ak-trivy-verify-cache >/dev/null; \
	docker run --rm -v ak-trivy-verify-cache:/home/trivy/.cache/trivy \
	    -v $$tmp/image.tar:/scan/image.tar:ro $(IMAGE) \
	    image --input /scan/image.tar $(GATE_ARGS)

stig:
	./scripts/stig-scan.sh $(IMAGE) $(STIG_OUT)

sbom:
	@set -eu; \
	tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT INT TERM; \
	chmod 0755 $$tmp; \
	docker save $(IMAGE) -o $$tmp/image.tar; chmod 0644 $$tmp/image.tar; \
	docker volume create ak-trivy-verify-cache >/dev/null; \
	docker run --rm -v ak-trivy-verify-cache:/home/trivy/.cache/trivy \
	    -v $$tmp/image.tar:/scan/image.tar:ro $(IMAGE) \
	    image --input /scan/image.tar --format cyclonedx --quiet > sbom.cdx.json; \
	echo "wrote sbom.cdx.json"

clean:
	rm -rf $(STIG_OUT) sbom.cdx.json
	-docker volume rm ak-trivy-verify-cache
