package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

// verifyRelease refuses an unsigned or unverifiable manifest, and a missing
// or altered scans or VEX file the manifest records; it ignores one the
// manifest does not record.
func TestVerifyRelease(t *testing.T) {
	src := Source{Repo: "MaliSec/temper", SignerWorkflow: "w.yml"}
	body := []byte(`{"schema": 2}`)
	sum := sha256.Sum256(body)
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
		scansSHA, vexSHA   string // recorded in the manifest; "" = none
		bundle, cosign     bool
		scansFile, vexFile []byte // nil = absent
		want               kept
		wantFail           bool
	}{
		{name: "verified with scans and vex", scansSHA: good, vexSHA: good, bundle: true, cosign: true, scansFile: body, vexFile: body, want: kept{true, true}},
		{name: "nothing recorded", bundle: true, cosign: true, scansFile: body, vexFile: body},
		{name: "scans only", scansSHA: good, bundle: true, cosign: true, scansFile: body, vexFile: body, want: kept{scans: true}},
		{name: "no bundle", scansSHA: good, cosign: true, scansFile: body, wantFail: true},
		{name: "bad signature", scansSHA: good, bundle: true, scansFile: body, wantFail: true},
		{name: "scans missing", scansSHA: good, bundle: true, cosign: true, wantFail: true},
		{name: "scans altered", scansSHA: good, bundle: true, cosign: true, scansFile: []byte(`{}`), wantFail: true},
		{name: "vex missing", vexSHA: good, bundle: true, cosign: true, wantFail: true},
		{name: "vex altered", vexSHA: good, bundle: true, cosign: true, vexFile: []byte(`{}`), wantFail: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			m := filepath.Join(dir, "m.yaml")
			mb := "cut_at: \"x\"\n"
			if c.scansSHA != "" {
				mb += "scans_sha256: \"" + c.scansSHA + "\"\n"
			}
			if c.vexSHA != "" {
				mb += "vex_sha256: \"" + c.vexSHA + "\"\n"
			}
			must(t, os.WriteFile(m, []byte(mb), 0o644))
			if c.bundle {
				must(t, os.WriteFile(m+".sigstore.json", []byte("{}"), 0o644))
			}
			s, v := filepath.Join(dir, "s.json"), filepath.Join(dir, "v.json")
			if c.scansFile != nil {
				must(t, os.WriteFile(s, c.scansFile, 0o644))
			}
			if c.vexFile != nil {
				must(t, os.WriteFile(v, c.vexFile, 0o644))
			}
			cosignOK = c.cosign
			got, err := verifyRelease(context.Background(), src, "2026.11.21", m, s, v)
			if (err != nil) != c.wantFail || got != c.want {
				t.Fatalf("kept=%+v err=%v", got, err)
			}
			if c.bundle && !slices.Contains(gotArgs, src.signerIdentity("2026.11.21")) {
				t.Fatalf("cosign not called with the release identity: %v", gotArgs)
			}
		})
	}
}

// A statement covers a finding only for its vulnerability (or an alias),
// the image's repository, and the exact Wolfi package version.
func TestVEXLookup(t *testing.T) {
	var doc VEXDoc
	must(t, json.Unmarshal([]byte(`{"statements": [{"vulnerability": {"name": "CVE-1"}, "status": "fixed", "status_notes": "n",
	  "products": [{"@id": "pkg:oci/node?repository_url=ghcr.io/malisec/temper/node",
	                "subcomponents": [{"@id": "pkg:apk/wolfi/glibc-2.44@2.44-r24"}]}]}]}`), &doc))
	f := raw("CVE-1", "medium", "glibc-2.44", "2.44-r24")
	f.Package.Type = "apk"
	if v := doc.lookup("ghcr.io/malisec/temper/node", f); v == nil || v.Status != "fixed" || v.Text() != "n" {
		t.Fatalf("lookup = %+v", v)
	}
	alias := f
	alias.ID, alias.Related = "GHSA-x", []string{"CVE-1"}
	other := f
	other.Package.Version = "2.44-r25"
	npm := f
	npm.Package.Type = "npm"
	for name, c := range map[string]struct {
		repo string
		f    RawFinding
		want bool
	}{
		"alias":           {"ghcr.io/malisec/temper/node", alias, true},
		"other version":   {"ghcr.io/malisec/temper/node", other, false},
		"other image":     {"ghcr.io/malisec/temper/python", f, false},
		"not a Wolfi apk": {"ghcr.io/malisec/temper/node", npm, false},
	} {
		if got := doc.lookup(c.repo, c.f) != nil; got != c.want {
			t.Errorf("%s: matched = %v", name, got)
		}
	}
	var none *VEXDoc
	if none.lookup("ghcr.io/malisec/temper/node", f) != nil {
		t.Error("a release without a VEX file matched")
	}
}

// A finding a statement shows is fixed or not affected is counted as
// reviewed, not by severity, sorts after open findings, and does not say
// "no fix yet".
func TestReviewedFindings(t *testing.T) {
	fixed := raw("CVE-1", "high", "glibc-2.44", "2.44-r24")
	fixed.VEX = &VEXInfo{Status: "fixed", Notes: "n"}
	open := raw("CVE-2", "low", "zlib", "1.3")
	fs := group(map[string]map[string][]RawFinding{"amd64": {"grype": {fixed, open}}})
	if fs[0].ID != "CVE-2" || fs[1].VEX == nil || fs[1].Fix != "fixed in the shipped package" {
		t.Fatalf("rows = %+v", fs)
	}
	if c := count(fs); c.High != 0 || c.Low != 1 || c.Reviewed != 1 || c.Total() != 1 {
		t.Errorf("count = %+v", c)
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
