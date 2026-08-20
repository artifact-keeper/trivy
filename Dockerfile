# =============================================================================
# artifact-keeper/trivy — Trivy built from pinned upstream source on UBI 9
# =============================================================================
#
# WHY THIS IMAGE EXISTS
#   artifact-keeper's scanner-adapter used to do
#     FROM ghcr.io/aquasecurity/trivy:<tag>
#     COPY --from=trivy /usr/local/bin/trivy
#   which couples our release train to Aqua's release cadence. When a HIGH CVE
#   is fixed on Trivy's main branch but no release carries the fix, our
#   CRITICAL/HIGH fixed-only Docker Publish gate fails and the whole release
#   chain stalls with nothing we can do about it. See README.md.
#
# WHAT THIS IS NOT
#   This is not a fork. We build the exact upstream tag (TRIVY_VERSION, also
#   pinned by commit SHA) with upstream's own build flags, and apply ONLY the
#   module bumps declared in overrides.yaml — each of which upstream has
#   already made themselves. scripts/apply-overrides.sh fails the build if
#   anything undeclared changes, and fails the build if an override has gone
#   stale (i.e. upstream shipped it and the entry should be deleted).
#
# LAYOUT
#   toolchain      ubi9 + pinned upstream Go tarball   (BUILDPLATFORM, native)
#   builder        upstream source + overrides + cross-compile to TARGETARCH
#   rootfs-builder ubi9 dnf --installroot staging      (TARGETPLATFORM)
#   final          ubi9-micro + staged rootfs + binary (TARGETPLATFORM)
#
#   Mirrors the house pattern in artifact-keeper's docker/Dockerfile.openscap
#   (staged rootfs assembled in the full UBI image, copied into ubi-micro,
#   non-root 1001:0 with /sbin/nologin). Deliberate difference: the bases here
#   are pinned by DIGEST rather than by the `9.8` tag. That is a tightening,
#   not drift — see README.md "Pinning".
#
# BUILD
#   docker buildx build --platform linux/amd64,linux/arm64 -t ak-trivy:dev .
# =============================================================================

# --- base images, pinned by manifest-list digest --------------------------
# ubi9/ubi:9.8        -> sha256:e79f79... (resolved 2026-08-06)
# ubi9/ubi-micro:9.8  -> sha256:b1e86b... (resolved 2026-08-06)
# Tags are kept in the comment so a human can see which release the digest
# belongs to; the build only ever consumes the digest.
ARG UBI_IMAGE=registry.access.redhat.com/ubi9/ubi@sha256:e79f79172a6779775e1733cb4f49cd5ef03a0703c68ec46c717f93b9ac4a5e71
ARG UBI_MICRO_IMAGE=registry.access.redhat.com/ubi9/ubi-micro@sha256:b1e86b97028b8fcfb6d85f997c39e6b6b67496163ef8d80d243220a4918e8bef

# --- upstream Trivy pin: SINGLE SOURCE OF TRUTH ---------------------------
# Declared in the global scope (before any FROM) so every stage inherits the
# same value by re-declaring `ARG TRIVY_VERSION` with no default. Previously
# these defaults were repeated in the builder and runtime stages, so bumping
# only the first one — exactly what README's "how to bump" says to do —
# produced an image whose labels described the PREVIOUS release. Do not
# reintroduce a second default.
ARG TRIVY_VERSION=v0.74.0
ARG TRIVY_COMMIT=e1fd17a0ea4a8cf24bc4b4dd7e2cfbf4bb31b994


# =============================================================================
# Stage 1: Go toolchain
# =============================================================================
# Runs on BUILDPLATFORM and cross-compiles, so no QEMU for the (large) Go
# build. Trivy is CGO_ENABLED=0 and every native-looking dependency
# (modernc.org/sqlite) is pure Go, so cross-compilation is exact.
#
# WHY NOT ubi9/go-toolset: it tops out at Go 1.21, and Trivy v0.74.0's go.mod
# requires 1.26.3. We install the official upstream Go tarball, pinned by
# version AND sha256, into the UBI builder instead.
FROM --platform=$BUILDPLATFORM ${UBI_IMAGE} AS toolchain

# Trivy v0.74.0 go.mod says `go 1.26.3`. We build with the newest patch of
# that minor rather than 1.26.3 exactly: the Go stdlib is compiled into the
# binary, so the toolchain patch level directly determines which stdlib CVEs
# our own CRITICAL/HIGH gate reports against this image. Building with the
# minimum permitted patch would ship known-vulnerable stdlib on purpose.
# This is a toolchain choice, not a source divergence — no Trivy source or
# dependency is affected by it.
#
# 1.26.5 -> 1.26.7 (2026-08-20): 1.26.5's stdlib was carrying EIGHT HIGH,
# fixed findings that our own gate reports against this image —
# CVE-2026-33818 (encoding/asn1), -39821 (x/net/idna), -46600
# (x/net/dns/dnsmessage), -56853 (net/http), -56858 (html/template), -56859
# (encoding/xml), -56860 (net/url), -56862 (crypto/tls). All are fixed in
# 1.26.6; 1.26.7 is the current patch of the minor. Bumping the toolchain is
# the ONLY fix for a stdlib CVE — there is no dependency to override, which is
# why this is a GO_VERSION bump and not an overrides.yaml entry.
ARG GO_VERSION=1.26.7
ARG GO_SHA256_AMD64=ffb5f8de10c62550dfddab66b36b57030721e0a44a3218e9e1181d7b59f121ca
ARG GO_SHA256_ARM64=5a4ec883379d51ee9ce1040d5e87f8d35e20387574dd8c947feb01eabc3c1b37
ARG BUILDARCH

RUN dnf install -y --nodocs --setopt=install_weak_deps=0 \
        git-core tar gzip ca-certificates python3-pyyaml \
    && dnf clean all

RUN set -eux; \
    case "${BUILDARCH}" in \
      amd64) GO_SHA256="${GO_SHA256_AMD64}" ;; \
      arm64) GO_SHA256="${GO_SHA256_ARM64}" ;; \
      *) echo "unsupported BUILDARCH=${BUILDARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/go.tar.gz \
        "https://go.dev/dl/go${GO_VERSION}.linux-${BUILDARCH}.tar.gz"; \
    echo "${GO_SHA256}  /tmp/go.tar.gz" | sha256sum -c -; \
    tar -C /usr/local -xzf /tmp/go.tar.gz; \
    rm -f /tmp/go.tar.gz; \
    /usr/local/go/bin/go version

# GOTOOLCHAIN=local: never silently download and swap in a different toolchain
# than the one we pinned and checksummed above.
ENV PATH=/usr/local/go/bin:$PATH \
    GOPATH=/go \
    GOCACHE=/root/.cache/go-build \
    GOMODCACHE=/go/pkg/mod \
    GOTOOLCHAIN=local


# =============================================================================
# Stage 2: fetch pinned upstream source, apply overrides, build
# =============================================================================
FROM toolchain AS builder

# Inherited from the global ARGs at the top of this file — no defaults here.
# TRIVY_COMMIT is asserted against the tag so a re-tagged or moved upstream tag
# fails the build instead of silently changing what we ship.
ARG TRIVY_VERSION
ARG TRIVY_COMMIT
ARG TRIVY_REPO=https://github.com/aquasecurity/trivy.git

WORKDIR /src
RUN set -eux; \
    git init -q .; \
    git remote add origin "${TRIVY_REPO}"; \
    git fetch -q --depth 1 origin "+refs/tags/${TRIVY_VERSION}:refs/tags/${TRIVY_VERSION}"; \
    git checkout -q "${TRIVY_VERSION}"; \
    got="$(git rev-parse HEAD)"; \
    if [ "${got}" != "${TRIVY_COMMIT}" ]; then \
        echo "FATAL: ${TRIVY_VERSION} resolved to ${got}, expected ${TRIVY_COMMIT}" >&2; \
        echo "The upstream tag moved. Re-review the source before bumping TRIVY_COMMIT." >&2; \
        exit 1; \
    fi; \
    echo "upstream trivy ${TRIVY_VERSION} @ ${got}"

# Sanity-check the toolchain against upstream's own requirement rather than
# trusting the ARG default.
RUN set -eux; \
    required="$(awk '/^go /{print $2; exit}' go.mod)"; \
    have="$(go env GOVERSION | sed 's/^go//')"; \
    echo "go.mod requires >= ${required}; toolchain is ${have}"; \
    [ "$(printf '%s\n%s\n' "${required}" "${have}" | sort -V | head -1)" = "${required}" ] \
        || { echo "FATAL: toolchain ${have} is older than go.mod's ${required}" >&2; exit 1; }

# --- the ONLY divergence from upstream ------------------------------------
COPY overrides.yaml /policy/overrides.yaml
COPY scripts/apply-overrides.sh scripts/assert-buildinfo.sh /policy/
RUN chmod +x /policy/*.sh && /policy/apply-overrides.sh /src /policy/overrides.yaml "${TRIVY_VERSION}"

# --- keep the main module stamped as the upstream release ------------------
# Go derives the MAIN module's version in the embedded build info from VCS
# state: a clean tree checked out at a tag is stamped with that tag. Trivy's
# own gobinary analyzer reads that value, so it is what any scan of this image
# scores the trivy binary itself against.
#
# Applying the overrides dirties the tree, which would otherwise stamp
# `v0.0.0-<date>-<sha>+dirty`. That is not a cosmetic issue — measured against
# the pinned upstream image:
#   * pseudo-version -> Trivy reports CVE-2026-54448 (HIGH, "fixed in 0.71.0")
#     and CVE-2024-35192 against a 0.73.0 binary. Fabricated findings that
#     would fail our own gate for no reason. (Measured on 0.73.0; the
#     mechanism is not version-specific.)
#   * -buildvcs=false -> version is empty, and Trivy reports NOTHING against
#     the binary ever again. That hides real future Trivy CVEs. Strictly worse.
# Upstream's ldflags fallback (pkg/dependency/parser/golang/binary) cannot
# rescue us here: `-trimpath` stops Go recording -ldflags in buildinfo
# (go.dev/issue/63432) and `-s -w` strips the ELF symbols it reads instead.
#
# So we commit the override and move the tag onto it. The artifact IS the
# pinned Trivy release plus the declared patches and should be scored as that
# release — which is also exactly what upstream's own `-X app.ver` already
# asserts. True upstream provenance is preserved in the OCI labels, in
# /licenses/trivy/BUILDINFO.txt and in the commit's parent. Author/committer
# dates are pinned to upstream's commit date so the resulting SHA is
# reproducible.
#
# When overrides.yaml is empty — as it is at v0.74.0 — the tree is never
# dirtied and this whole block is a no-op: the checkout is already clean and
# already at the tag, so the two `test`s below just assert that. The block
# stays because the next override to be filed must not have to reinvent it.
RUN set -eux; \
    if [ -n "$(git status --porcelain)" ]; then \
        d="$(git log -1 --format=%cI)"; \
        GIT_AUTHOR_DATE="${d}" GIT_COMMITTER_DATE="${d}" \
        git -c user.name='artifact-keeper build' \
            -c user.email='build@artifact-keeper.invalid' \
            commit -aqm "artifact-keeper: apply reviewed dependency overrides (see /licenses/trivy/MODIFICATIONS-overrides.yaml)"; \
        git tag -f "${TRIVY_VERSION}" >/dev/null; \
    fi; \
    test -z "$(git status --porcelain)"; \
    test "$(git describe --tags --exact-match)" = "${TRIVY_VERSION}"

ARG TARGETOS
ARG TARGETARCH

# Build flags copied from upstream goreleaser.yml (build-linux):
#   ldflags: -s -w, -extldflags '-static',
#            -X github.com/aquasecurity/trivy/pkg/version/app.ver={{.Version}}
#   env:     CGO_ENABLED=0, GOEXPERIMENT=jsonv2
#
# {{.Version}} in goreleaser is the tag WITHOUT the leading "v", so
# `trivy --version` prints exactly `Version: 0.74.0` — byte-identical to the
# upstream release. That matters: artifact-keeper's scanner-adapter parses
# that first line (parseTrivyVersion in docker/scanner-adapter/scan.go) and a
# missing or decorated version string breaks it. AK provenance is recorded in
# the OCI labels below, NOT in the version string.
RUN set -eux; \
    VER="${TRIVY_VERSION#v}"; \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" GOEXPERIMENT=jsonv2 \
    go build -trimpath \
        -ldflags "-s -w -extldflags '-static' -X github.com/aquasecurity/trivy/pkg/version/app.ver=${VER}" \
        -o /out/trivy ./cmd/trivy; \
    ls -l /out/trivy

# In-build proof that the override reached the artifact. Reads the embedded Go
# build info (arch-independent, so it works on the cross-compiled binary) —
# the same metadata Trivy's gobinary analyzer scores. Fails the build if the
# vulnerable version is still linked.
RUN /policy/assert-buildinfo.sh /out/trivy /policy/overrides.yaml \
    && go version -m /out/trivy > /out/trivy.buildinfo.txt


# =============================================================================
# Stage 3: staged runtime rootfs
# =============================================================================
# Runs at TARGETPLATFORM (under emulation when cross-building) because dnf
# must resolve TARGET-arch RPMs. Only a handful of small packages, so the
# emulation cost is bounded.
#
# ca-certificates is NOT optional: ubi-micro ships no trust store, and Trivy
# pulls its vulnerability DB over HTTPS from an OCI registry. A missing trust
# store fails at first scan, not at build time. scripts/verify-image.sh proves
# the trust store works by actually downloading the DB.
FROM ${UBI_IMAGE} AS rootfs-builder

# RPM signature verification is ON. docker/Dockerfile.openscap and
# Dockerfile.backend pass --nogpgcheck here, which is the usual workaround for
# a fresh --installroot having no trusted keys yet. Seeding the key into the
# staged RPM database first removes the need for that, so every package that
# lands in this image has a verified Red Hat signature. In an image whose
# entire job is supply-chain assurance, installing unverified RPMs would be a
# poor look. It also satisfies the STIG's `ensure_redhat_gpgkey_installed`
# rule as a side effect, since the key stays in the shipped database.
RUN set -eux; \
    mkdir -p /mnt/rootfs/etc/pki/rpm-gpg; \
    cp /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release /mnt/rootfs/etc/pki/rpm-gpg/; \
    rpm --root /mnt/rootfs --initdb; \
    rpm --root /mnt/rootfs --import /mnt/rootfs/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release; \
    dnf install --installroot /mnt/rootfs --releasever 9 --refresh \
        --setopt=reposdir=/etc/yum.repos.d/ \
        --setopt=install_weak_deps=0 --nodocs -y \
        glibc-minimal-langpack \
        ca-certificates \
        tzdata \
        crypto-policies; \
    dnf --installroot /mnt/rootfs --releasever 9 \
        --setopt=reposdir=/etc/yum.repos.d/ upgrade -y; \
    dnf --installroot /mnt/rootfs clean all; \
    rm -rf /mnt/rootfs/var/cache/* /mnt/rootfs/var/log/* /mnt/rootfs/tmp/*

# The `upgrade` step above is what pulls z-stream errata (glibc, openssl-libs,
# ...) on top of whatever the pinned ubi-micro digest happens to carry. Note
# that it can only pull a package Red Hat has actually shipped a fix for; CVEs
# Red Hat marks "Affected"/"Will not fix" have no fixed RPM and are excluded by
# the gate's `--ignore-unfixed`. Rebuilding picks fixes up automatically.

# Non-root runtime identity. UID 1001 with GID 0 follows the house convention
# (docker/Dockerfile.openscap): group 0 keeps the image usable under
# OpenShift's arbitrary-UID SCC, which runs a random UID but always in group 0,
# so group-writable dirs stay writable. /sbin/nologin: this account must never
# be a login target.
RUN echo 'trivy:x:1001:0:Trivy Scanner:/home/trivy:/sbin/nologin' >> /mnt/rootfs/etc/passwd && \
    echo 'trivy:x:1001:' >> /mnt/rootfs/etc/group && \
    mkdir -p /mnt/rootfs/home/trivy/.cache/trivy \
             /mnt/rootfs/tmp \
             /mnt/rootfs/usr/local/bin \
             /mnt/rootfs/licenses && \
    chown -R 1001:0 /mnt/rootfs/home/trivy && \
    chmod -R g=u /mnt/rootfs/home/trivy && \
    chmod 1777 /mnt/rootfs/tmp

# --- STIG hardening (container-applicable subset) --------------------------
# Same controls as docker/Dockerfile.openscap. See README.md "DISA STIG" for
# the profile we evaluate against and the documented N/A exceptions.

# RHEL-09-215105 / SV-258241r1184293_rule / CCE-83450-7 — configure_crypto_policy.
# SEVERITY: high (CAT I). This is the highest-severity rule the profile scores
# against this image, and it is satisfiable at build time.
#
# The rule does NOT test host FIPS mode. It reads files that live inside the
# image: /etc/crypto-policies/config, state/current, and the generated
# back-ends/. The STIG profile refines var_system_crypto_policy to the
# `fips_stig` selector, whose value is the literal string "FIPS:STIG", and
# SSG's own remediation is simply `update-crypto-policies --set FIPS:STIG`.
#
# UBI 9's crypto-policies package ships no STIG.pmod (only AD-SUPPORT,
# ECDHE-ONLY, NO-ENFORCE-EMS, NO-SHA1, OSPP, PQ, SHA1), so the module has to be
# authored before the policy can reference it. Contents are the standard RHEL 9
# STIG module: no SHA-1 in certificates, 2048-bit RSA floor.
#
# The generator is a Python script with no --root option and the staged rootfs
# has no interpreter, so the policy is generated here and the resulting tree is
# copied in. Both sides are the same UBI 9 base and the same crypto-policies
# package (aligned by the upgrade below), and every generated artefact is
# architecture-independent text.
#
# NOTE ON WHAT THIS DOES AND DOES NOT BUY: see README "FIPS". Trivy is built
# CGO_ENABLED=0 and never links OpenSSL, so this configures the image's crypto
# policy for any OTHER consumer of it — it does not make Trivy's own TLS
# FIPS-validated, and this image does not claim FIPS-validated cryptography.
RUN set -eux; \
    dnf upgrade -y --nodocs crypto-policies crypto-policies-scripts; \
    mkdir -p /etc/crypto-policies/policies/modules; \
    printf '# DISA STIG for Red Hat Enterprise Linux 9 policy module\nsha1_in_certs = 0\nmin_rsa_size = 2048\n' \
        > /etc/crypto-policies/policies/modules/STIG.pmod; \
    update-crypto-policies --no-reload --set FIPS:STIG; \
    test "$(update-crypto-policies --show)" = "FIPS:STIG"; \
    rm -rf /mnt/rootfs/etc/crypto-policies; \
    cp -a /etc/crypto-policies /mnt/rootfs/etc/crypto-policies; \
    test "$(cat /mnt/rootfs/etc/crypto-policies/config)" = "FIPS:STIG"; \
    test "$(cat /mnt/rootfs/etc/crypto-policies/state/current)" = "FIPS:STIG"; \
    test -s /mnt/rootfs/etc/crypto-policies/back-ends/opensslcnf.config

# FIPS-preferred OpenSSL EVP defaults.
#
# The house pattern (docker/Dockerfile.openscap) appends a `[algorithm_sect]`
# block to openssl.cnf. That block is INERT: the pinned UBI 9 openssl.cnf sets
# `alg_section = evp_properties` and ships `[ evp_properties ]` deliberately
# empty, so OpenSSL never reads a section by any other name. Writing into the
# section openssl.cnf actually points at is the difference between configuring
# something and appending a comment.
RUN set -eux; \
    cnf=/mnt/rootfs/etc/pki/tls/openssl.cnf; \
    test -f "${cnf}"; \
    grep -q '^[[:space:]]*alg_section[[:space:]]*=[[:space:]]*evp_properties' "${cnf}"; \
    sed -i '/^\[[[:space:]]*evp_properties[[:space:]]*\]/a default_properties = fips=yes' "${cnf}"; \
    awk '/^\[[[:space:]]*evp_properties[[:space:]]*\]/{f=1;next} /^\[/{f=0} f && /default_properties[[:space:]]*=[[:space:]]*fips=yes/{found=1} END{exit !found}' "${cnf}"

# RHEL-09-213010 / disable core dumps (a core of a scanner process can contain
# registry credentials and scanned artifact contents).
RUN mkdir -p /mnt/rootfs/etc/security/limits.d && \
    echo "* hard core 0" > /mnt/rootfs/etc/security/limits.d/50-coredump.conf

# RHEL-09-412035 / bound concurrent sessions.
RUN echo "* hard maxlogins 10" > /mnt/rootfs/etc/security/limits.d/50-maxlogins.conf

# RHEL-09-611010 / no empty passwords.
RUN sed -i 's/\bnullok\b//g' /mnt/rootfs/etc/pam.d/* 2>/dev/null || true

# RHEL-09-411030 / restrictive default umask. login.defs covers the accounts
# path; accounts_umask_etc_profile and accounts_umask_etc_bashrc are separate
# scored rules that read the shell init files, so set all three.
RUN set -eux; \
    if [ -f /mnt/rootfs/etc/login.defs ]; then \
      sed -i 's/^UMASK.*/UMASK\t\t077/' /mnt/rootfs/etc/login.defs; \
    fi; \
    for f in /mnt/rootfs/etc/profile /mnt/rootfs/etc/bashrc; do \
      [ -f "${f}" ] || continue; \
      if grep -qE '^[[:space:]]*umask' "${f}"; then \
        sed -i 's/^[[:space:]]*umask.*/umask 077/' "${f}"; \
      else \
        printf '\numask 077\n' >> "${f}"; \
      fi; \
      sed -i 's/umask 022/umask 077/g' "${f}"; \
      grep -n umask "${f}"; \
    done

# RHEL-09-214010 / the Red Hat release GPG key must be present in the shipped
# RPM database so package provenance stays verifiable inside the image. It was
# imported above (before any package was installed); assert it survived, since
# the staged rootfs's rpmdb is the one that ends up in the final image.
RUN set -eux; \
    rpm --root /mnt/rootfs -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' | grep -q .

# Zero the machine-id so every container instance is not identifiable as the
# same host, and so the value is not baked into a published layer.
RUN rm -f /mnt/rootfs/etc/machine-id && \
    touch /mnt/rootfs/etc/machine-id && \
    chmod 0444 /mnt/rootfs/etc/machine-id

RUN rm -rf /mnt/rootfs/var/cache/* /mnt/rootfs/var/log/* /mnt/rootfs/tmp/* && \
    mkdir -p /mnt/rootfs/tmp && chmod 1777 /mnt/rootfs/tmp


# =============================================================================
# Stage 4: runtime — ubi9-micro (no package manager)
# =============================================================================
FROM ${UBI_MICRO_IMAGE}

# Inherited from the global ARGs at the top of this file — no defaults here,
# so the labels can never describe a different release than the one built.
ARG TRIVY_VERSION
ARG TRIVY_COMMIT
ARG SOURCE_REVISION=unknown

COPY --from=rootfs-builder /mnt/rootfs /
COPY --from=builder /out/trivy /usr/local/bin/trivy

# Upstream ships these report templates in its own image at /contrib; keep the
# same path so `--format template --template "@contrib/sarif.tpl"` works
# exactly as it does against ghcr.io/aquasecurity/trivy.
COPY --from=builder /src/contrib/ /contrib/

# Apache-2.0 §4 redistribution: carry upstream's LICENSE and NOTICE, plus our
# own statement of what we changed. README.md restates this in prose.
COPY --from=builder /src/LICENSE  /licenses/trivy/LICENSE
COPY --from=builder /src/NOTICE   /licenses/trivy/NOTICE
COPY --from=builder /out/trivy.buildinfo.txt /licenses/trivy/BUILDINFO.txt
COPY overrides.yaml /licenses/trivy/MODIFICATIONS-overrides.yaml
COPY LICENSE /licenses/LICENSE

# Cache dir must be writable. Declared as a VOLUME so a `--read-only` rootfs
# still gets a writable cache under Docker; under Kubernetes VOLUME is ignored,
# so mount an emptyDir at TRIVY_CACHE_DIR (see README.md "Read-only rootfs").
ENV HOME=/home/trivy \
    TRIVY_CACHE_DIR=/home/trivy/.cache/trivy \
    TMPDIR=/tmp \
    SSL_CERT_FILE=/etc/pki/tls/certs/ca-bundle.crt
VOLUME ["/home/trivy/.cache/trivy"]

USER 1001

LABEL org.opencontainers.image.title="artifact-keeper trivy" \
      org.opencontainers.image.description="Aqua Security Trivy ${TRIVY_VERSION}, built from pinned upstream source on Red Hat UBI 9 with documented, auditable dependency overrides. Redistribution of Apache-2.0 software with modifications; see /licenses." \
      org.opencontainers.image.version="${TRIVY_VERSION}" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.source="https://github.com/artifact-keeper/trivy" \
      org.opencontainers.image.url="https://github.com/artifact-keeper/trivy" \
      org.opencontainers.image.documentation="https://github.com/artifact-keeper/trivy/blob/main/README.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="artifact-keeper" \
      org.opencontainers.image.base.name="registry.access.redhat.com/ubi9/ubi-micro:9.8" \
      org.artifactkeeper.trivy.upstream.repository="https://github.com/aquasecurity/trivy" \
      org.artifactkeeper.trivy.upstream.tag="${TRIVY_VERSION}" \
      org.artifactkeeper.trivy.upstream.commit="${TRIVY_COMMIT}" \
      org.artifactkeeper.trivy.modifications="/licenses/trivy/MODIFICATIONS-overrides.yaml"

ENTRYPOINT ["/usr/local/bin/trivy"]
