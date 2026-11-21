package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const sbomPredicate = "https://spdx.dev/Document/v2.3"

type target struct{ name, arch, repo, digest string }

// rescanTargets: every platform image of the newest verified release.
func rescanTargets(r Release) []target {
	var ts []target
	for name, mi := range r.Manifest.Images {
		for arch, d := range mi.Platforms {
			ts = append(ts, target{name, arch, mi.Repository, d})
		}
	}
	sort.Slice(ts, func(i, j int) bool {
		if ts[i].name != ts[j].name {
			return ts[i].name < ts[j].name
		}
		return ts[i].arch < ts[j].arch
	})
	return ts
}

// rescan scans the newest release's images against today's databases.
// Each SBOM comes from its attestation, verified against the release
// workflow, so nothing is pulled and nothing unverified is scanned. Grype
// runs in parallel; Trivy one at a time, as its database is a single
// file that concurrent runs contend on.
func rescan(ctx context.Context, src Source, data string, jobs int) error {
	releases, err := loadReleases(data)
	if err != nil {
		return err
	}
	if len(releases) == 0 {
		return fmt.Errorf("no verified releases under %s", data)
	}
	current := releases[0]
	out := filepath.Join(data, "rescan")
	if err := os.RemoveAll(out); err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	sboms, err := os.MkdirTemp("", "trust-sbom-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(sboms)

	if _, err := command(ctx, "grype", "db", "update"); err != nil {
		return err
	}
	if _, err := command(ctx, "trivy", "image", "--download-db-only", "--quiet"); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu       sync.Mutex
		firstErr error
	)
	fail := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		if firstErr == nil {
			firstErr = err
			cancel()
		}
	}

	ts := rescanTargets(current)
	if len(ts) == 0 {
		return fmt.Errorf("release %s lists no platform images", current.Tag)
	}
	// The first verification alone: gh downloads and caches Sigstore's
	// trust root on first use, and parallel first uses collide on that cache.
	if err := sbomAndGrype(ctx, src, ts[0], sboms, out); err != nil {
		return err
	}
	trivyQ := make(chan target, len(ts))
	sem := make(chan struct{}, jobs)
	var wg sync.WaitGroup
	trivyQ <- ts[0]
	for _, t := range ts[1:] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			if err := sbomAndGrype(ctx, src, t, sboms, out); err != nil {
				fail(err)
				return
			}
			trivyQ <- t
		}()
	}
	var trivyWG sync.WaitGroup
	trivyWG.Add(1)
	go func() {
		defer trivyWG.Done()
		for t := range trivyQ {
			if ctx.Err() != nil {
				continue
			}
			res, err := command(ctx, "trivy", "sbom", "--quiet", "--skip-db-update", "--scanners", "vuln",
				"--format", "json", sbomPath(sboms, t))
			if err == nil {
				err = os.WriteFile(filepath.Join(out, t.name+"."+t.arch+".trivy.json"), res, 0o644)
			}
			if err != nil {
				fail(fmt.Errorf("trivy %s/%s: %w", t.name, t.arch, err))
				continue
			}
			fmt.Printf("rescan: %s/%s\n", t.name, t.arch)
		}
	}()
	wg.Wait()
	close(trivyQ)
	trivyWG.Wait()
	if firstErr != nil {
		return firstErr
	}
	return writeRescanMeta(ctx, out, current.Tag)
}

func sbomPath(dir string, t target) string { return filepath.Join(dir, t.name+"."+t.arch+".spdx.json") }

func sbomAndGrype(ctx context.Context, src Source, t target, sboms, out string) error {
	args := []string{"attestation", "verify", "oci://" + t.repo + "@" + t.digest, "-R", src.Repo,
		"--signer-workflow", src.Repo + "/" + src.SignerWorkflow, "--predicate-type", sbomPredicate, "--format", "json"}
	var res []byte
	var err error
	// A verifier that cannot initialise (trust root or registry unreachable
	// for a moment) is retried; a failed verification is not.
	for attempt := 1; attempt <= 3; attempt++ {
		res, err = command(ctx, "gh", args...)
		if err == nil || !strings.Contains(err.Error(), "no valid Sigstore verifiers could be initialized") {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt) * 5 * time.Second):
		}
	}
	if err != nil {
		return fmt.Errorf("no verified SBOM for %s/%s (%s): %w", t.name, t.arch, t.digest, err)
	}
	sbom, err := attestedPredicate(res)
	if err != nil {
		return fmt.Errorf("%s/%s: %w", t.name, t.arch, err)
	}
	if err := os.WriteFile(sbomPath(sboms, t), sbom, 0o644); err != nil {
		return err
	}
	res, err = command(ctx, "grype", "sbom:"+sbomPath(sboms, t), "-o", "json")
	if err != nil {
		return fmt.Errorf("grype %s/%s: %w", t.name, t.arch, err)
	}
	return os.WriteFile(filepath.Join(out, t.name+"."+t.arch+".grype.json"), res, 0o644)
}

// attestedPredicate: the SBOM in gh attestation verify's JSON output.
func attestedPredicate(b []byte) ([]byte, error) {
	var res []struct {
		VerificationResult struct {
			Statement struct {
				PredicateType string          `json:"predicateType"`
				Predicate     json.RawMessage `json:"predicate"`
			} `json:"statement"`
		} `json:"verificationResult"`
	}
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}
	if len(res) == 0 || res[0].VerificationResult.Statement.PredicateType != sbomPredicate ||
		len(res[0].VerificationResult.Statement.Predicate) == 0 {
		return nil, fmt.Errorf("no SBOM in the verified attestation")
	}
	return res[0].VerificationResult.Statement.Predicate, nil
}

func writeRescanMeta(ctx context.Context, out, release string) error {
	gv, err := command(ctx, "grype", "version", "-o", "json")
	if err != nil {
		return err
	}
	gdb, err := command(ctx, "grype", "db", "status", "-o", "json")
	if err != nil {
		return err
	}
	tv, err := command(ctx, "trivy", "version", "--format", "json")
	if err != nil {
		return err
	}
	var g struct {
		Version string `json:"version"`
	}
	var gs struct {
		Built string `json:"built"`
	}
	var t struct {
		Version string `json:"Version"`
		DB      struct {
			UpdatedAt string `json:"UpdatedAt"`
		} `json:"VulnerabilityDB"`
	}
	for _, x := range []struct {
		b []byte
		v any
	}{{gv, &g}, {gdb, &gs}, {tv, &t}} {
		if err := json.Unmarshal(x.b, x.v); err != nil {
			return err
		}
	}
	meta := Rescan{
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
		Release:   release,
		Scanners: map[string]ScannerInfo{
			"grype": {Version: g.Version, DB: "built " + gs.Built},
			"trivy": {Version: t.Version, DB: "built " + t.DB.UpdatedAt},
		},
	}
	return writeJSON(filepath.Join(out, "meta.json"), meta)
}
