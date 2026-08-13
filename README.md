# artifact-keeper/trivy

Aqua Security's [Trivy](https://github.com/aquasecurity/trivy), built from **pinned
upstream source** on a hardened **Red Hat UBI 9** base, published on
artifact-keeper's cadence at `ghcr.io/artifact-keeper/trivy`.

**This is not a fork.** We build the exact upstream tag with upstream's own
build flags and apply only the dependency bumps recorded in
[`overrides.yaml`](overrides.yaml) — each of which upstream has already made
themselves. Every override carries a removal condition and an expiry date, and
the build fails if one goes stale.

---

## Why this exists

artifact-keeper's scanner-adapter image used to obtain Trivy this way:

```dockerfile
FROM ghcr.io/aquasecurity/trivy:0.73.0 AS trivy
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
```

That couples our release train to Aqua's release cadence, and the failure mode
is not theoretical:

**CVE-2026-50163** ([GHSA-fxhp-mv3v-67qp](https://github.com/advisories/GHSA-fxhp-mv3v-67qp),
HIGH) — a hardlink entry with a relative `Linkname` in `oras.land/oras-go/v2`
resolves against the process CWD instead of the extraction directory, so a
crafted OCI artifact can write outside it. Reachable from Trivy: oras-go
performs the OCI pulls behind `trivy image`, `trivy sbom` and the
vulnerability-DB download. Fixed in oras-go 2.6.2.

Trivy's `main` branch bumped to 2.6.2. **No Trivy release carries it.** v0.73.0,
the latest release, still pins 2.6.1. Measured with the pinned upstream image:

```
$ trivy image --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 \
      ghcr.io/aquasecurity/trivy:0.73.0

usr/local/bin/trivy (gobinary)   Total: 1 (HIGH: 1, CRITICAL: 0)
  oras.land/oras-go/v2  CVE-2026-50163  HIGH  fixed  v2.6.1  ->  2.6.2
exit status 1
```

That single finding fails artifact-keeper's Docker Publish security gate, which
cascades into skipping every multi-arch manifest merge and stalls the whole
release chain — with no upstream release to upgrade to. Owning the image means
we can apply the fix upstream already made, on our own schedule, without
forking anything.

The same image scanned with the same configuration:

```
$ make gate
/w/img.tar (redhat 9.8)   0
usr/local/bin/trivy       0
exit status 0
```

It happened again a week later, which is the point of owning the image:

**CVE-2026-71556** ([GHSA-hc8v-wwc9-vgxm](https://github.com/advisories/GHSA-hc8v-wwc9-vgxm),
HIGH, CVSS 7.1) — `github.com/go-git/go-git/v5` worktree operations (checkout,
status, add) resolve symlinks without confining resolution to the worktree
boundary, so a crafted repository can make go-git read or write outside the
working directory. Reachable from Trivy: go-git is a direct dependency and backs
the `trivy repo` scanner, which clones a remote repository and then walks its
worktree. CVE-2026-71557 (MEDIUM) in the same module writes outside the
reference-storage directory via an unsanitised ref name. Both fixed in go-git
5.19.2; Trivy `main` pins 5.19.2, no release does. Measured against the
**previously published** image, `v0.73.0-r1`, whose only gating finding it was:

```
$ trivy image --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 \
      ghcr.io/artifact-keeper/trivy:0.73.0-r1

usr/local/bin/trivy (gobinary)   Total: 1 (HIGH: 1, CRITICAL: 0)
  github.com/go-git/go-git/v5  CVE-2026-71556  HIGH  fixed  v5.19.1  ->  5.19.2
exit status 1
```

Note the shape: `v0.73.0-r1` was gate-clean when it was published on 2026-08-07
and failed on 2026-08-13 without a single byte changing. Nothing regressed —
the advisory was published against a dependency the image already shipped. That
is the same lesson as the oras-go entry and the reason the weekly rebuild and
`upstream-watch` exist: a green scan is a statement about a moment, not a
property of an image.

`scripts/verify-image.sh` still asserts only the module named in
`OVERRIDE_MODULE` (default `oras.land/oras-go/v2`) — it predates there being
more than one override. That is not a coverage hole today, because
`scripts/assert-buildinfo.sh` iterates every entry in `overrides.yaml`
generically and fails the build on any that is absent, at the wrong version, or
unlinked. Generalising `verify-image.sh` the same way is worth doing before a
third override lands.

---

## Override policy

An override in `overrides.yaml` is justified only when **all** of these hold:

1. It fixes a CVE our own CRITICAL/HIGH fixed-only gate flags in the image.
2. **Upstream has already made the same bump** — on `main`, or in a merged PR.
   We do not get ahead of upstream's judgement about their own dependencies.
3. No upstream *release* carries the fix yet.

Each entry records the module, from- and to-version, the advisories, the
upstream status with a reference, a **removal condition**, and an **expiry
date**. This file is the complete statement of how our build differs from
upstream, and the build enforces that:

| Guard | Where | Behaviour |
|---|---|---|
| `overrides.yaml` reviewed against a different tag than we are building | `apply-overrides.sh` | **fails the build** |
| An override is past its `expires` date | `apply-overrides.sh` | **fails the build** |
| Upstream no longer pins the `from` version (fix has shipped) | `apply-overrides.sh` | **fails the build** — the entry must be deleted |
| `go get` moved any module not declared in `overrides.yaml` | `apply-overrides.sh` | **fails the build** |
| The override is not present in the compiled binary's Go build info | `assert-buildinfo.sh` | **fails the build** |
| The binary has no readable Go build info, or implausibly few dependency records | `assert-buildinfo.sh` | **fails the build** — it refuses to report "verified" when it checked nothing |
| A declared module is not linked into the binary at all | `assert-buildinfo.sh` | **fails the build** unless the entry sets `expect_linked: false` *and* a `linked_justification` |
| The upstream tag moved off the pinned commit | `Dockerfile` | **fails the build** |

### Dropping an override when upstream ships the fix

1. Check the new upstream release: `git show v0.74.0:go.mod | grep oras.land/oras-go`
2. Bump `TRIVY_VERSION` / `TRIVY_COMMIT` in the `Dockerfile` and `trivy_version`
   in `overrides.yaml`.
3. Delete the entry. If you forget, the build stops with
   `overrides.yaml says upstream pins v2.6.1, but v0.74.0 actually pins v2.6.2`
   and tells you to delete it. Staleness is caught mechanically, not by
   remembering.

Overrides are applied with `go get module@version`, not `go mod edit -replace`,
so the version recorded in the binary's Go build info — and therefore in any
SBOM or scan — is the real upgraded version rather than a replacement arrow.

---

## Apache-2.0 redistribution notice

Trivy is licensed under the Apache License 2.0. **This image is a
redistribution of Apache-2.0 licensed software in modified form.** Apache-2.0
§4(b) requires modified files to carry prominent notices stating that they were
changed, and §4(a)/§4(d) require the licence and NOTICE to travel with the
distribution. Accordingly:

* **The modifications are**: the dependency version bumps listed in
  `overrides.yaml`, and nothing else. No Trivy source file is patched.
* The image carries, under `/licenses`:
  * `trivy/LICENSE` and `trivy/NOTICE` — upstream's, from the built tag
  * `trivy/MODIFICATIONS-overrides.yaml` — the exact modifications
  * `trivy/BUILDINFO.txt` — the full resolved dependency set of the built binary
  * `LICENSE` — this repository's, also Apache-2.0
* OCI labels record the upstream repository, tag and commit.

Trivy is a trademark of Aqua Security Software Ltd. This is an unofficial
rebuild and is not endorsed by or affiliated with Aqua Security.

---

## What the image is

| | |
|---|---|
| Runtime base | `registry.access.redhat.com/ubi9/ubi-micro` (no package manager) |
| Builder base | `registry.access.redhat.com/ubi9/ubi` |
| Trivy | `v0.73.0` @ `40c73e5d6166dcc0346a1ab4e94499d1572854e4` |
| Go toolchain | 1.26.5 (official tarball, sha256-pinned) |
| Platforms | `linux/amd64`, `linux/arm64` |
| User | `1001:0`, `/sbin/nologin` |
| Entrypoint | `/usr/local/bin/trivy` |
| Size | ~230 MB (upstream's alpine image is ~177 MB — see below) |

### Pinning

Base images are pinned by **manifest-list digest**, not by tag:

```dockerfile
ARG UBI_IMAGE=registry.access.redhat.com/ubi9/ubi@sha256:e79f79...
ARG UBI_MICRO_IMAGE=registry.access.redhat.com/ubi9/ubi-micro@sha256:b1e86b...
```

This is a **deliberate difference** from artifact-keeper's
`docker/Dockerfile.openscap`, which uses the floating `9.8` tag. It is a
tightening, not drift: `9.8` is republished with z-stream errata, so two builds
of the same commit can produce different images. The tag each digest belongs to
is kept in a comment next to it, and the `dnf upgrade` step in the rootfs
builder still pulls current errata on every build, so pinning the digest costs
nothing in patch currency.

The Trivy tag is additionally pinned by commit SHA and asserted at build time,
so a moved or re-pushed upstream tag fails the build rather than silently
changing what we ship. `TRIVY_VERSION` and `TRIVY_COMMIT` are declared **once**,
as global `ARG`s above the first `FROM`, and inherited by every stage. They used
to be repeated in two stages, which meant following the bump instructions below
and updating only the first pair produced an image whose OCI labels described
the previous release.

Everything else that feeds a result is pinned too, on the same reasoning:

| Input | Pin | Why |
|---|---|---|
| Go toolchain | version + sha256 | Determines the stdlib CVEs in the binary |
| Upstream Trivy | tag + commit SHA | A moved tag would change what we ship |
| Base images | manifest-list digest | `9.8` is republished |
| SCAP datastream | release tag + **sha256** | GitHub release assets are mutable, and this content is the sole input to every compliance number `stig-scan.sh` emits |
| `openscap-scanner` | exact NEVR | The scanner version changes how rules evaluate; unpinned it is an unrecorded variable in every result. Its version is recorded in the STIG artifacts. |

### Go toolchain choice

Trivy v0.73.0's `go.mod` requires `go 1.26.3`. We build with **1.26.5**, the
newest patch of that minor. The Go standard library is compiled into the
binary, so the toolchain patch level directly determines which stdlib CVEs our
gate reports against this image; building with the minimum permitted patch
would ship known-vulnerable stdlib on purpose. This is a toolchain choice, not
a source divergence — no Trivy source or dependency is affected. The build
asserts the toolchain satisfies `go.mod` rather than trusting the pin.

`ubi9/go-toolset` is not used: it tops out at Go 1.21.

### Version string compatibility

`trivy --version` prints exactly `Version: 0.73.0`, byte-identical to the
upstream release, because we pass upstream's own goreleaser ldflag
(`-X github.com/aquasecurity/trivy/pkg/version/app.ver=0.73.0`). This matters:
artifact-keeper's scanner-adapter parses that first line (`parseTrivyVersion`
in `docker/scanner-adapter/scan.go`) and errors out on a missing or decorated
string. artifact-keeper provenance lives in OCI labels, not in the version.

The **main module** version embedded in Go build info is likewise `v0.73.0`.
That is not cosmetic. Trivy's own `gobinary` analyzer reads it, so it decides
what any scan scores the binary against:

| Build approach | Reported as | Consequence |
|---|---|---|
| Dirty tree (naive) | `v0.0.0-20260803094430-40c73e5d6166+dirty` | Trivy reports CVE-2026-54448 (HIGH, "fixed in 0.71.0") and CVE-2024-35192 against a 0.73.0 binary. Fabricated findings that fail our own gate. |
| `-buildvcs=false` | *(empty)* | Trivy reports **nothing** against the binary, ever. Hides real future Trivy CVEs. Strictly worse. |
| **What we do** | `v0.73.0` | Same as upstream. Real Trivy CVEs land; fabricated ones do not. |

Trivy's ldflags fallback cannot rescue this: `-trimpath` stops Go recording
`-ldflags` in build info ([go.dev/issue/63432](https://go.dev/issue/63432)) and
`-s -w` strips the ELF symbols it reads instead. So the build commits the
override and moves the tag onto that commit, leaving a clean tree at the tag.
The artifact *is* Trivy 0.73.0 plus the declared patches and is scored as such;
true upstream provenance is preserved in the OCI labels, in
`/licenses/trivy/BUILDINFO.txt`, and in the commit's parent.

### Size

~230 MB against upstream's ~177 MB. The Trivy binary is 153.9 MB in our build
versus 154.2 MB in upstream's — essentially identical, which is a useful check
that the build flags really do match. The entire delta is the base: UBI 9 micro
plus glibc, ca-certificates, tzdata and crypto-policies against Alpine's musl.
That is the price of UBI, paid deliberately for the STIG/FIPS posture and Red
Hat's errata stream.

---

## Hardening

* Runs as non-root numeric UID **1001**, group **0**, shell `/sbin/nologin`.
  GID 0 follows the house convention from `Dockerfile.openscap` and keeps the
  image usable under OpenShift's arbitrary-UID SCC, which assigns a random UID
  but always group 0.
* **No package manager** in the final layer (`ubi-micro` ships none, and the
  staged rootfs is assembled in a separate builder stage). Verified by
  `verify-image.sh`.
* The runtime rootfs is built with `dnf --installroot` and then `dnf upgrade`,
  so each build pulls current z-stream errata rather than inheriting whatever
  the pinned base digest happened to carry.
* **RPM signature verification is on.** `Dockerfile.openscap` and
  `Dockerfile.backend` pass `--nogpgcheck` — the usual workaround for a fresh
  `--installroot` having no trusted keys yet. Here the Red Hat release key is
  seeded into the staged RPM database *before* the first package is installed,
  so `gpgcheck=1` holds and every package that lands in the image has a
  verified signature. Installing unverified RPMs into an image whose whole job
  is supply-chain assurance would be a poor look.
* STIG hardening applied to the staged rootfs. The controls that the profile
  actually scores against a container image are the system crypto policy
  (`FIPS:STIG`) and umask in `login.defs` / `/etc/profile` / `/etc/bashrc` —
  see the delta table under [DISA STIG](#disa-stig-compliance) for exactly
  which rules move. The rest — core dumps disabled, `maxlogins` bounded,
  `nullok` stripped from PAM, zeroed `machine-id` — are defence-in-depth
  carried over from the house pattern and score nothing here; they are kept
  because they cost nothing, not because they earn a number.
* **The OpenSSL FIPS setting is in the section OpenSSL actually reads.** The
  house pattern appends a `[algorithm_sect]` block to `openssl.cnf`. That block
  is inert: the pinned UBI 9 `openssl.cnf` sets `alg_section = evp_properties`
  and ships `[ evp_properties ]` deliberately empty, so a section by any other
  name is never consulted. We write `default_properties = fips=yes` into
  `[evp_properties]`, and `verify-image.sh` fails the build if an orphan
  `[algorithm_sect]` reappears.

### FIPS

**This image does not provide FIPS-validated cryptography, and nothing in it
should be read as claiming otherwise.**

The `configure_crypto_policy` STIG rule is satisfied: the image ships
`FIPS:STIG` in `/etc/crypto-policies/config` and `state/current`, with
generated back-ends, and `openssl.cnf` requests `fips=yes` EVP properties. That
is a real, checkable configuration state, and it is what the rule measures.

It is also almost entirely inert for Trivy itself. Trivy is built
`CGO_ENABLED=0`: it uses Go's own crypto, never links OpenSSL, never reads
`/etc/crypto-policies`, and does not inherit host FIPS mode. Running this
container on a `fips=1` host does **not** put Trivy's TLS on a validated
module. An earlier version of this README said "deploy on a FIPS-enabled host
if FIPS is required" — that was wrong for a static Go binary, and precisely the
kind of sentence that becomes a customer finding. It has been removed.

What the crypto policy in this image *does* buy: a correct, STIG-conformant
system policy for any other consumer of the image's OpenSSL/GnuTLS/NSS
configuration, and one less CAT I finding for an auditor to chase.

If FIPS-validated cryptography for Trivy's own TLS is ever a requirement, the
route is a `GOEXPERIMENT=boringcrypto` or `GOFIPS140` toolchain build, which
changes the binary rather than the configuration around it. That is tracked as
future work; it is not done, and this image must not be presented as satisfying
a FIPS requirement until it is.

### On the shell

`ubi-micro` ships `bash` and a small `coreutils`; we do not remove them, and
the image genuinely does not need them (Trivy is a static `CGO_ENABLED=0`
binary; the only `exec` paths in Trivy are plugin execution and an optional
`python` lookup, neither of which goes through a shell).

The reason is scanner honesty rather than laziness. The final layer's RPM
database is the one from the staged rootfs; deleting binaries that database
still lists would make every scan and SBOM of this image describe a filesystem
that does not exist — reporting `bash` CVEs for a `bash` that is gone, and
inviting the reflex of suppressing them in `.trivyignore`. We would rather ship
a shell the scanner can see than hide one it cannot. If you need a
shell-less variant, remove it *and* the corresponding rpmdb entries together,
in that order.

### Read-only rootfs

Trivy needs a writable cache directory. `TRIVY_CACHE_DIR` is set to
`/home/trivy/.cache/trivy` and declared as a `VOLUME`.

```bash
# Docker
docker run --rm --read-only --tmpfs /tmp \
  -v trivy-cache:/home/trivy/.cache/trivy \
  ghcr.io/artifact-keeper/trivy image alpine:3.20
```

```yaml
# Kubernetes — VOLUME is ignored there, so mount it explicitly
securityContext:
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 1001
volumeMounts:
  - { name: trivy-cache, mountPath: /home/trivy/.cache/trivy }
  - { name: tmp,         mountPath: /tmp }
volumes:
  - { name: trivy-cache, emptyDir: {} }
  - { name: tmp,         emptyDir: {} }
```

---

## Verification

A build that produces a broken scanner is worse than the CVE it was meant to
fix, because it fails open: `trivy` exiting 0 with no findings looks exactly
like "clean". `make verify` (`scripts/verify-image.sh`) proves otherwise.

| Check | Why it is not redundant |
|---|---|
| `trivy --version` parses with `parseTrivyVersion`'s exact logic and equals the pinned tag | A decorated or missing version breaks the scanner-adapter |
| Downloads the vulnerability DB over HTTPS from an OCI registry | `ubi-micro` ships **no CA trust store**. A missing one fails at first scan in production, not at build. `--version` would never catch it. |
| `/usr/share/zoneinfo/UTC` exists | tzdata is not in `ubi-micro` either |
| Scans a fixture with known-vulnerable deps and asserts findings > 0 | Catches a scanner that fails open |
| Scans the image with the Trivy inside it and asserts oras-go is 2.6.2, is not 2.6.1, and CVE-2026-50163 is absent | This is the CVE claim, measured the way the gate measures it |
| Crypto policy is `FIPS:STIG` in both `config` and `state/current`, back-ends generated | A regression to `DEFAULT` should fail a gate, not just move a number in a report nobody reads |
| `default_properties = fips=yes` is inside `[evp_properties]`, and no orphan `[algorithm_sect]` exists | The house pattern's block is in a section `openssl.cnf` never points at, so it configures nothing |
| Non-root UID, no package manager, `/licenses` present, runs `--read-only` | Hardening and licence-compliance regressions |

These scripts are written to fail **closed**, which took two corrections worth
recording:

* `stig-scan.sh` used to end the OpenSCAP run with `|| true`, and its
  summariser had no floor on rule count. Feed it an error log — scanner not
  installed, bad profile, truncated output — and it rendered
  "Rules evaluated: 0 / **No failing rules.**" and exited 0, straight into a
  90-day compliance artifact. That is worse than the `|| true` it criticises in
  `docker-publish.yml`: that one produces *no* evidence, this produced
  affirmatively reassuring *false* evidence. It now distinguishes oscap's exit
  codes (0 and 2 mean it ran; anything else is an infrastructure failure that
  aborts), requires a non-empty results XML, and refuses to write a summary
  backed by fewer than 400 parsed rule results.
* `assert-buildinfo.sh` treated "module not found in the build info" as an
  informational note, so a binary with **no build info at all** printed
  "all overrides verified" and exited 0. It now requires a main-module record
  and at least 50 dependency records before it checks anything, and treats a
  declared-but-unlinked module as a failure unless the override entry sets
  `expect_linked: false` with a written `linked_justification`.

Two checks are built into the Dockerfile itself, so a broken build never
produces an image at all: the override must be present in the compiled binary's
Go build info (`assert-buildinfo.sh`, arch-independent so it works on the
cross-compiled binary), and the upstream tag must resolve to the pinned commit.

```bash
make build    # this host's architecture
make verify   # functional proof
make gate     # artifact-keeper's exact CVE gate config
make stig     # DISA STIG evaluation -> stig-out/
make buildx   # linux/amd64 + linux/arm64
```

---

## DISA STIG compliance

**Profile evaluated: `xccdf_org.ssgproject.content_profile_stig`** — *DISA STIG
for Red Hat Enterprise Linux 9* — from `ssg-rhel9-ds.xml` in
[SCAP Security Guide v0.1.81](https://github.com/ComplianceAsCode/content/releases/tag/v0.1.81).
This is the same profile artifact-keeper's `docker-publish.yml` evaluates its
own images against.

Applicability follows the DoD Enterprise DevSecOps **Container Hardening
Process Guide (V1R2), Appendix B**, and the DISA **Container Platform SRG**: a
container image is assessed against the OS baseline of its base layer for the
controls that exist inside the image, while controls belonging to the host, the
kernel, or the container platform are the platform's responsibility and are
documented as not applicable rather than silently dropped. The RHEL 9 STIG is a
host baseline, so most of it has no counterpart in a single-binary image.

### Current result, against the baseline

The number that matters is not the absolute pass rate — it is how much of it
this repository is responsible for. So here is both. Measured on `linux/arm64`,
SSG v0.1.81, openscap-scanner 1.3.14, 484 rules, using `make stig`:

| Result | Stock `ubi9-micro` | This image |
|---|---:|---:|
| notapplicable | 417 (86.2%) | 417 (86.2%) |
| pass | 61 (12.6%) | **65 (13.4%)** |
| fail | 5 (1.0%) | **1 (0.2%)** |
| notchecked | 1 (0.2%) | 1 (0.2%) |
| **Scored pass rate** | **61 / 66 = 92.4%** | **65 / 66 = 98.5%** |

**Read that honestly: the base image already scores 92.4%, and the *notapplicable*
count is identical.** Our hardening moves exactly four rules:

| Rule | Severity | How |
|---|---|---|
| `package_crypto-policies_installed` | medium | `crypto-policies` added to the staged rootfs |
| `configure_crypto_policy` | **high (CAT I)** | author `STIG.pmod`, `update-crypto-policies --set FIPS:STIG` |
| `accounts_umask_etc_profile` | medium | umask 077 in `/etc/profile` |
| `accounts_umask_etc_bashrc` | medium | umask 077 in `/etc/bashrc`, including the conditional `umask 022` |

Everything else in the hardening list — core dumps, `maxlogins`, PAM `nullok`,
`machine-id` — moves nothing the profile scores. It is kept as
defence-in-depth, not claimed as compliance.

Stated plainly: this image passes 98.5% of the rules that can be scored against
it, 86% of the RHEL 9 STIG does not apply to a container image at all, and the
majority of the pass rate is inherited from Red Hat's base image rather than
earned here. It is **not** "STIG compliant" in any absolute sense, and no image
can be — a STIG is assessed against a running system.

CI runs this on every build for both architectures and uploads
`stig-results.xml`, `stig-report.html`, the scanner version and a Markdown
summary as artifacts with 90-day retention.

### Documented exceptions

Same discipline as `overrides.yaml`: an exception has an owner, a review date,
an expiry, and a condition that would remove it.

| Rule | Result | Severity | Owner | Reviewed | Expires | Why | Removal condition |
|---|---|---|---|---|---|---|---|
| `network_configure_name_resolution` | fail | medium | artifact-keeper platform | 2026-08-06 | 2027-02-06 | `/etc/resolv.conf` is injected by the container runtime at start time and is not part of any image. Writing one into the image would be overwritten at run time, so satisfying this rule inside an image is not possible — only the platform can. | Remove if the deployment platform is ever assessed as one unit with the image, in which case the platform's resolver config carries this control and the exception moves there. |
| `security_patches_up_to_date` | notchecked | high | artifact-keeper platform | 2026-08-06 | 2027-02-06 | Requires the RHEL OVAL patch feed, which the SSG datastream does not carry, so OpenSCAP cannot evaluate it at all. It is not failing — it is unevaluated. | Covered more strictly by the blocking CVE gate (`--severity CRITICAL,HIGH --ignore-unfixed --exit-code 1`) plus the weekly rebuild. Remove this entry if the OVAL feed is added to the evaluation and the rule starts scoring. |

`configure_crypto_policy` **was** on this list and is not any more. It was
waived on the reasoning that FIPS is a host property. That reasoning was wrong
in two ways worth recording, because it is an easy mistake to repeat: the rule
does not test host FIPS mode at all — it reads `/etc/crypto-policies/config`,
`state/current` and the generated `back-ends/`, all of which live inside the
image — and it is **high severity (CAT I)**, the most serious rule the profile
scores here. It is now fixed rather than waived, by DISA's own documented
remediation. See [FIPS](#fips) for what that does and does not buy.

Nothing is suppressed to make these numbers look better: there is no
`.trivyignore` in this repository and no tailoring file that deselects rules.

### A note on the evaluation method

Two mistakes silently destroy STIG evidence, and both are present in the
equivalent steps in artifact-keeper's `docker-publish.yml`:

1. **`oscap xccdf eval --chroot` does not exist.** OpenSCAP 1.3.x rejects it
   with `unrecognized option '--chroot'`. Because those steps end in `|| true`,
   the failure is swallowed and the upload finds no results file. Offline
   evaluation uses `OSCAP_PROBE_ROOT` (or the separate `oscap-chroot` wrapper),
   which is what `scripts/stig-scan.sh` does.
2. **The filesystem must be extracted as root.** Extracting `docker export` as
   an unprivileged user rewrites every file's owner, and the profile has ~15
   file-ownership rules that then fail for reasons unrelated to the image.
   Measured here, that mistake alone moved the result from 61 pass / 5 fail to
   45 pass / 21 fail.

The STIG job is also a **sibling** of the CVE gate in CI, not a dependant. In
`docker-publish.yml` the STIG steps share a job with the Trivy scan, so an
unrelated CVE finding exits the job and the evidence upload never runs.
Compliance evidence should not disappear as collateral damage of a CVE.

---

## CI

| Job | Blocking | What it does |
|---|---|---|
| `build` (amd64, arm64) | yes | Builds each arch **once**. On non-PR events pushes it to GHCR **by digest**; on PRs produces a local tarball instead |
| `verify` (amd64, arm64) | yes | `scripts/verify-image.sh` against that exact digest |
| `cve-gate` (amd64, arm64) | **yes** | `--severity CRITICAL,HIGH --ignore-unfixed --exit-code 1`, plus SARIF and a CycloneDX SBOM |
| `stig` (amd64, arm64) | no (evidence) | OpenSCAP evaluation; still fails on infrastructure errors. Artifacts retained 90 days |
| `publish` | tags only | `buildx imagetools create` over the gated digests, then provenance attestation. **Does not rebuild** |

### Bytes tested == bytes published

`needs:` orders jobs; it does not make two builds identical. This build is
deliberately non-hermetic — `dnf --refresh` for current errata, a live
`git fetch` of the upstream tag, `go get` for the overrides — the GHA cache is
evictable, and a publish-time rebuild would additionally carry provenance and
SBOM attestations the tested build never had. A rebuild at publish time would
therefore sign bytes no scanner ever saw.

So `build` pushes each architecture by digest, `verify`/`cve-gate`/`stig` pull
those exact digests, and `publish` only assembles a manifest list from them.
The manifest digest that gets attested is the one covering the gated per-arch
images. `publish` fails if it does not find exactly two per-arch digests.

Pull requests build, verify, scan and evaluate but push nothing at all —
`build` keeps the image as a tarball artifact and `publish` is skipped.

### Scheduling

| Workflow | Cadence | Does |
|---|---|---|
| `build.yml` | weekly (Mon 04:17 UTC) | Full rebuild at the **same** pinned Trivy version. This is what makes the `dnf upgrade` errata story real: a newly-fixable CRITICAL/HIGH in the UBI base surfaces as a red build here instead of silently blocking an artifact-keeper release later. Weekly rather than daily because it is two arches of a full Go build, and daily publishes would churn the digest for consumers pinning it. |
| `upstream-watch.yml` | daily (06:41 UTC) | Checks whether a newer upstream Trivy **release** exists. Does not build. Does not bump. Opens or updates one tracking issue per upstream version, pre-answering whether each override is still needed against the new tag. |

`upstream-watch` deliberately does not open a bump PR. `apply-overrides.sh`
fails the build when the pinned source no longer contains an override's `from`
version, because that is the signal the override should be **deleted** — and
deciding that upstream's fix really is the same fix is a human judgement. A bot
that produced a green bump PR would be routing around the one control this
repository is built on. `workflow_dispatch` remains the emergency lever on both.

Every action is pinned to a commit SHA.

---

## How artifact-keeper consumes this image

`docker/Dockerfile.scanner-adapter` currently does:

```dockerfile
FROM ghcr.io/aquasecurity/trivy:0.73.0 AS trivy
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
```

Repointing it is a **separate change in the artifact-keeper repository** and is
not part of this repo. When it happens it becomes:

```dockerfile
FROM ghcr.io/artifact-keeper/trivy:0.73.0 AS trivy
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
```

The binary is drop-in: same version string, same `contrib/*.tpl` templates at
the same path, same flags. The adapter's `ProbeVersion` still reads
`Version: 0.73.0`.

Alternatively, run this image directly as the scanner rather than copying the
binary out of it — that is the configuration the hardening and STIG posture in
this repository actually describe.

---

## Repository layout

```
Dockerfile                    multi-stage UBI 9 build
overrides.yaml                the ONLY divergence from upstream, with expiry
Makefile                      build / verify / gate / stig / sbom
scripts/apply-overrides.sh    applies overrides; fails on stale or undeclared change
scripts/assert-buildinfo.sh   proves the override is in the compiled binary
scripts/verify-image.sh       proves the image is a working scanner
scripts/stig-scan.sh          OpenSCAP DISA STIG evaluation
scripts/ci-resolve-image.sh   resolves the build job's output (digest or tarball)
fixtures/verify/              deliberately vulnerable fixture for the scan test
.github/workflows/build.yml   build, verify, gate, STIG, publish-on-tag, weekly rebuild
.github/workflows/upstream-watch.yml  daily upstream-release check; files an issue, never bumps
```

## Licence

Apache-2.0. See [LICENSE](LICENSE), and the redistribution notice above for
Trivy's own Apache-2.0 licence and NOTICE.
