# MaliSec trust center

A public record of every [Temper](https://github.com/MaliSec/temper)
release: each image's digest and tags, how to verify it, and its
vulnerability findings at release time and as of today.

Everything on the site comes from signed release records:

- **Releases.** `trust fetch` downloads each release's manifest and
  keeps it only if its signature names Temper's release workflow at that
  release's tag. A release's scans file is kept only if it matches the
  sha256 its manifest records. A release that fails either check stops the
  build.
- **Findings at release.** From the scans file: every finding both
  scanners (Grype and Trivy) reported when the release was cut. Releases
  before 2026.11.21 recorded counts only.
- **Findings now.** `trust rescan` scans the newest release's images
  against today's scanner databases, using each platform's SBOM from its
  attestation, verified against the same release workflow.

The site is rebuilt daily at 04:47 UTC, after Temper's nightly release,
and the HTML and the JSON feed (`/api/`) are rendered from the same data.

## Build locally

Needs Go, `gh`, `cosign`, `grype` and `trivy` (Temper's
`scripts/install-tools.sh` installs the pinned versions):

```sh
go build -o bin/trust ./cmd/trust
./bin/trust fetch
./bin/trust rescan
./bin/trust build
```

Open `site/index.html`.

## JSON feed

- `api/index.json`: every image line with its current release, digest and
  finding counts, and every release.
- `api/images/<image>.json`: one image's lines, current findings,
  findings at release and history.
- `api/releases/<release>.json`: one release's images and counts.

A finding is one vulnerability in one package, across both platforms and
both scanners, at the higher severity when the scanners disagree.

## License

Apache-2.0.
