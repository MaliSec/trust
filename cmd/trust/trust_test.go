package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

func TestParseCounts(t *testing.T) {
	got := parseCounts("amd64: critical=0 high=1 medium=4 low=3 negligible=1 unknown=0 kev=0; arm64: critical=2 high=0 medium=0 low=0 unknown=0 kev=1")
	want := map[string]map[string]int{
		"amd64": {"critical": 0, "high": 1, "medium": 4, "low": 3, "negligible": 1, "unknown": 0, "kev": 0},
		"arm64": {"critical": 2, "high": 0, "medium": 0, "low": 0, "unknown": 0, "kev": 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseCounts = %v", got)
	}
}

func TestTagLess(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"2026.11.19", "2026.11.20", true},
		{"2026.11.19", "2026.11.19.1", true},
		{"2026.11.19.2", "2026.11.19.10", true},
		{"2026.11.30.9", "2026.12.01", true},
		{"2026.11.20", "2026.11.19.5", false},
	} {
		if got := tagLess(c.a, c.b); got != c.want {
			t.Errorf("tagLess(%s, %s) = %v", c.a, c.b, got)
		}
	}
}

func raw(id, sev, pkg, ver string, fixed ...string) RawFinding {
	f := RawFinding{ID: id, Severity: sev, FixedIn: fixed}
	f.Package.Name, f.Package.Version = pkg, ver
	return f
}

// One vulnerability seen on both platforms by both scanners is one row,
// at the higher severity, with every platform and scanner listed.
func TestGroup(t *testing.T) {
	kev := raw("CVE-3", "low", "zlib", "1.3")
	kev.KEV = true
	fs := group(map[string]map[string][]RawFinding{
		"amd64": {"grype": {raw("CVE-1", "medium", "glibc", "2.44"), raw("CVE-2", "low", "glibc", "2.44")},
			"trivy": {raw("CVE-1", "high", "glibc", "2.44", "2.45")}},
		"arm64": {"grype": {raw("CVE-1", "medium", "glibc", "2.44"), kev}},
	})
	if len(fs) != 3 {
		t.Fatalf("want 3 rows, got %d: %+v", len(fs), fs)
	}
	if fs[0].ID != "CVE-3" || !fs[0].KEV {
		t.Errorf("known-exploited findings sort first: %+v", fs[0])
	}
	one := fs[1]
	if one.ID != "CVE-1" || one.Severity != "high" || one.Fix != "fixed in 2.45" ||
		!reflect.DeepEqual(one.Platforms, []string{"amd64", "arm64"}) ||
		!reflect.DeepEqual(one.Scanners, []string{"grype", "trivy"}) {
		t.Errorf("CVE-1 merged wrong: %+v", one)
	}
	if fs[2].Fix != "no fix yet" {
		t.Errorf("CVE-2 fix = %q", fs[2].Fix)
	}
	c := count(fs)
	if c.High != 1 || c.Low != 2 || c.KEV != 1 || c.Total() != 3 {
		t.Errorf("count = %+v", c)
	}
}

// The rescan's normalization matches Temper's scripts/scans-json.sh.
func TestNormalize(t *testing.T) {
	g, err := normalizeGrype([]byte(`{"matches": [
	  {"vulnerability": {"id": "CVE-2", "severity": "Negligible", "fix": {"versions": [], "state": ""}},
	   "relatedVulnerabilities": [{"id": "GHSA-x"}],
	   "artifact": {"name": "pkg", "version": "1.0", "type": "apk"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(g) != 1 || g[0].Severity != "negligible" || g[0].FixState != "unknown" || g[0].Related[0] != "GHSA-x" || g[0].Package.Type != "apk" {
		t.Errorf("grype = %+v", g)
	}
	tr, err := normalizeTrivy([]byte(`{"Results": [{"Type": "wolfi", "Vulnerabilities": [
	  {"VulnerabilityID": "CVE-1", "Severity": "MEDIUM", "PkgName": "pkg", "InstalledVersion": "1.0", "FixedVersion": "1.1, 1.2", "Status": "fixed"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(tr) != 1 || tr[0].Severity != "medium" || !reflect.DeepEqual(tr[0].FixedIn, []string{"1.1", "1.2"}) || tr[0].Package.Type != "wolfi" {
		t.Errorf("trivy = %+v", tr)
	}
}

func TestSignerIdentity(t *testing.T) {
	src := Source{Repo: "MaliSec/temper", SignerWorkflow: ".github/workflows/temper-release-build.yml"}
	want := `^https://github\.com/MaliSec/temper/\.github/workflows/temper-release-build\.yml@refs/tags/2026\.11\.21$`
	if got := src.signerIdentity("2026.11.21"); got != want {
		t.Fatalf("signerIdentity = %s", got)
	}
}

// verifyRelease refuses an unsigned or unverifiable manifest, a missing or
// altered scans file the manifest records, and ignores one it does not.
func TestVerifyRelease(t *testing.T) {
	src := Source{Repo: "MaliSec/temper", SignerWorkflow: "w.yml"}
	scans := []byte(`{"schema": 1}`)
	sum := sha256.Sum256(scans)
	good := hex.EncodeToString(sum[:])

	cosignOK := true
	var gotArgs []string
	command = func(_ context.Context, name string, args ...string) ([]byte, error) {
		gotArgs = append([]string{name}, args...)
		if !cosignOK {
			return nil, errors.New("signature invalid")
		}
		return nil, nil
	}
	t.Cleanup(func() { command = runCommand })

	for _, c := range []struct {
		name               string
		sha                string // scans_sha256 in the manifest; "" = none
		bundle, scansFile  bool
		scansBody          []byte
		cosign             bool
		wantKeep, wantFail bool
	}{
		{name: "verified with scans", sha: good, bundle: true, scansFile: true, scansBody: scans, cosign: true, wantKeep: true},
		{name: "no scans recorded", bundle: true, scansFile: true, scansBody: scans, cosign: true},
		{name: "no bundle", sha: good, scansFile: true, scansBody: scans, cosign: true, wantFail: true},
		{name: "bad signature", sha: good, bundle: true, scansFile: true, scansBody: scans, wantFail: true},
		{name: "scans missing", sha: good, bundle: true, cosign: true, wantFail: true},
		{name: "scans altered", sha: good, bundle: true, scansFile: true, scansBody: []byte(`{"schema": 2}`), cosign: true, wantFail: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			m := filepath.Join(dir, "m.yaml")
			body := "cut_at: \"x\"\n"
			if c.sha != "" {
				body += "scans_sha256: \"" + c.sha + "\"\n"
			}
			must(t, os.WriteFile(m, []byte(body), 0o644))
			if c.bundle {
				must(t, os.WriteFile(m+".sigstore.json", []byte("{}"), 0o644))
			}
			s := filepath.Join(dir, "s.json")
			if c.scansFile {
				must(t, os.WriteFile(s, c.scansBody, 0o644))
			}
			cosignOK = c.cosign
			keep, err := verifyRelease(context.Background(), src, "2026.11.21", m, s)
			if (err != nil) != c.wantFail || keep != c.wantKeep {
				t.Fatalf("keep=%v err=%v", keep, err)
			}
			if c.bundle && !slices.Contains(gotArgs, src.signerIdentity("2026.11.21")) {
				t.Fatalf("cosign not called with the release identity: %v", gotArgs)
			}
		})
	}
}

func TestAttestedPredicate(t *testing.T) {
	if _, err := attestedPredicate([]byte(`[{"verificationResult": {"statement": {"predicateType": "https://slsa.dev/provenance/v1", "predicate": {}}}}]`)); err == nil {
		t.Fatal("a provenance attestation was accepted as an SBOM")
	}
	b, err := attestedPredicate([]byte(`[{"verificationResult": {"statement": {"predicateType": "` + sbomPredicate + `", "predicate": {"spdxVersion": "SPDX-2.3"}}}}]`))
	if err != nil || string(b) != `{"spdxVersion": "SPDX-2.3"}` {
		t.Fatalf("predicate = %s, %v", b, err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestRescanName(t *testing.T) {
	for _, c := range []struct{ in, image, arch, scanner string }{
		{"python-3.13.amd64.grype.json", "python-3.13", "amd64", "grype"},
		{"static.arm64.trivy.json", "static", "arm64", "trivy"},
	} {
		image, arch, scanner, ok := rescanName(c.in)
		if !ok || image != c.image || arch != c.arch || scanner != c.scanner {
			t.Errorf("rescanName(%s) = %s %s %s %v", c.in, image, arch, scanner, ok)
		}
	}
	for _, bad := range []string{"meta.json", "x.amd64.syft.json", "amd64.grype.json", "x.grype"} {
		if _, _, _, ok := rescanName(bad); ok {
			t.Errorf("rescanName(%s) accepted", bad)
		}
	}
}
