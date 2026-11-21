# MaliSec trust center

A public record of every [Temper](https://github.com/MaliSec/temper)
release: each image's digest and tags, how to verify it, and its
vulnerability findings at release time and as of today.

Images, digests and findings come from signed release records; VEX
statements come from Temper's main branch:

- **Releases.** `trust fetch` downloads each release's manifest and
  keeps it only if its signature names Temper's release workflow at that
  release's tag. A release's scans and VEX files are kept only if they
  match the sha256 its manifest records. A release that fails any check
  stops the build.
- **Findings at release.** From the scans file: every finding both
  scanners (Grype and Trivy) reported when the release was cut. Releases
  before 2026.11.21 recorded counts only.
- **Findings now.** `trust rescan` scans the newest release's images
  against today's scanner databases, using each platform's SBOM from its
  attestation, verified against the same release workflow.
- **Status.** Temper's [VEX statements](https://github.com/MaliSec/temper/tree/main/vex)
  as of one commit of its main branch, which the site names; they reach
  main only through reviewed pull requests. They apply to every release,
  so a statement made after a release covers it too. A finding a statement
  shows is fixed in the shipped package or does not affect the image is
  counted as reviewed, not open; the scanners' own findings stay listed.
  Each release also carries the statements as of its cut, in its signed
  VEX file.

Each Temper release, and each change to Temper's `vex/`, rebuilds the site.
A daily run (04:47 UTC) rescans the newest release. The HTML and the JSON feed
(`/api/`) are rendered from the same data.

## Build locally

Needs Go, `gh`, `cosign`, `grype` and `trivy` (Temper's
`scripts/install-tools.sh` installs the pinned versions):

```sh
go build -o bin/trust ./cmd/trust
./bin/trust fetch
./bin/trust rescan
./bin/trust build -vex ../temper/vex -vex-commit "$(git -C ../temper rev-parse HEAD)"
```

Without `-vex`, each release shows the statements in its own VEX file.

Open `site/index.html`.

## JSON feed

- `api/index.json`: every image line with its current release, digest and
  finding counts, and every release.
- `api/images/<image>.json`: one image's lines, current findings,
  findings at release and history.
- `api/releases/<release>.json`: one release's images and counts.

A finding is one vulnerability in one package, across both platforms and
both scanners, at the higher severity when the scanners disagree. A
statement applies to a finding with the same vulnerability (or an alias),
image repository and exact package version.

## License

Apache-2.0.
