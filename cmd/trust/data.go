package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Manifest is a Temper release manifest (scripts/cut-registry.sh), already
// signature-checked by trust fetch.
type Manifest struct {
	CutAt       string                   `yaml:"cut_at"`
	GitCommit   string                   `yaml:"git_commit"`
	ScanDB      string                   `yaml:"scan_db"`
	ScanDBTrivy string                   `yaml:"scan_db_trivy"`
	Scans       string                   `yaml:"scans"`
	ScansSHA256 string                   `yaml:"scans_sha256"`
	Images      map[string]ManifestImage `yaml:"images"`
}

type ManifestImage struct {
	Repository string            `yaml:"repository"`
	Release    string            `yaml:"release"`
	Primary    bool              `yaml:"primary"`
	Line       string            `yaml:"line"`
	LineTag    string            `yaml:"line_tag"`
	Digest     string            `yaml:"digest"`
	VulnsGrype string            `yaml:"vulns_at_cut"`
	VulnsTrivy string            `yaml:"vulns_trivy_at_cut"`
	Platforms  map[string]string `yaml:"platforms"`
}

// Scans is a release's temper-<release>.scans.json (Temper's scripts/scans-json.sh).
type Scans struct {
	Scanners map[string]ScannerInfo `json:"scanners"`
	Images   map[string]struct {
		Platforms map[string]struct {
			Grype []RawFinding `json:"grype"`
			Trivy []RawFinding `json:"trivy"`
		} `json:"platforms"`
	} `json:"images"`
}

type ScannerInfo struct {
	Version string `json:"version"`
	DB      string `json:"db"`
}

// RawFinding is one scanner's report of one vulnerability in one package
// on one platform.
type RawFinding struct {
	ID       string   `json:"id"`
	Related  []string `json:"related,omitempty"`
	Severity string   `json:"severity"`
	KEV      bool     `json:"kev,omitempty"`
	Package  struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Type    string `json:"type"`
	} `json:"package"`
	FixState string   `json:"fix_state,omitempty"`
	Status   string   `json:"status,omitempty"`
	FixedIn  []string `json:"fixed_in"`
}

// Release is one verified release on disk: releases/<tag>/.
type Release struct {
	Tag      string
	Manifest Manifest
	Scans    *Scans // nil: the release predates scans files
}

var releaseTag = regexp.MustCompile(`^\d{4}\.\d{2}\.\d{2}(\.[1-9]\d*)?$`)

func loadReleases(dir string) ([]Release, error) {
	entries, err := os.ReadDir(filepath.Join(dir, "releases"))
	if err != nil {
		return nil, err
	}
	var out []Release
	for _, e := range entries {
		if !e.IsDir() || !releaseTag.MatchString(e.Name()) {
			continue
		}
		r := Release{Tag: e.Name()}
		base := filepath.Join(dir, "releases", e.Name())
		b, err := os.ReadFile(filepath.Join(base, "manifest.yaml"))
		if err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal(b, &r.Manifest); err != nil {
			return nil, fmt.Errorf("%s: manifest: %w", e.Name(), err)
		}
		if b, err := os.ReadFile(filepath.Join(base, "scans.json")); err == nil {
			r.Scans = &Scans{}
			if err := json.Unmarshal(b, r.Scans); err != nil {
				return nil, fmt.Errorf("%s: scans: %w", e.Name(), err)
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return tagLess(out[j].Tag, out[i].Tag) })
	return out, nil
}

// tagLess orders date tags: 2026.11.19 < 2026.11.19.1 < 2026.11.19.10 < 2026.11.20.
func tagLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		if i >= len(pa) {
			return true
		}
		if i >= len(pb) {
			return false
		}
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x < y
		}
	}
	return false
}

// Rescan is today's scan of the current release's SBOMs (trust rescan):
// rescan/meta.json and rescan/<image>.<arch>.{grype,trivy}.json.
type Rescan struct {
	ScannedAt string                 `json:"scanned_at"`
	Release   string                 `json:"release"`
	Scanners  map[string]ScannerInfo `json:"scanners"`
	// image -> arch -> scanner -> findings
	Findings map[string]map[string]map[string][]RawFinding `json:"-"`
}

func loadRescan(dir string) (*Rescan, error) {
	b, err := os.ReadFile(filepath.Join(dir, "rescan", "meta.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r := &Rescan{Findings: map[string]map[string]map[string][]RawFinding{}}
	if err := json.Unmarshal(b, r); err != nil {
		return nil, fmt.Errorf("rescan meta: %w", err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "rescan", "*.json"))
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if filepath.Base(f) == "meta.json" {
			continue
		}
		// <image>.<arch>.<scanner>.json; image names can contain dots (python-3.13).
		image, arch, scanner, ok := rescanName(filepath.Base(f))
		if !ok {
			return nil, fmt.Errorf("unexpected rescan file %s", f)
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var fs []RawFinding
		if scanner == "grype" {
			fs, err = normalizeGrype(b)
		} else {
			fs, err = normalizeTrivy(b)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if r.Findings[image] == nil {
			r.Findings[image] = map[string]map[string][]RawFinding{}
		}
		if r.Findings[image][arch] == nil {
			r.Findings[image][arch] = map[string][]RawFinding{}
		}
		r.Findings[image][arch][scanner] = fs
	}
	return r, nil
}

func rescanName(base string) (image, arch, scanner string, ok bool) {
	rest, ok := strings.CutSuffix(base, ".json")
	if !ok {
		return "", "", "", false
	}
	i := strings.LastIndex(rest, ".")
	if i < 0 {
		return "", "", "", false
	}
	rest, scanner = rest[:i], rest[i+1:]
	j := strings.LastIndex(rest, ".")
	if j <= 0 || (scanner != "grype" && scanner != "trivy") {
		return "", "", "", false
	}
	return rest[:j], rest[j+1:], scanner, true
}

// normalizeGrype and normalizeTrivy match scripts/scans-json.sh in Temper,
// so release-time and current findings compare field for field.
func normalizeGrype(b []byte) ([]RawFinding, error) {
	var doc struct {
		Matches []struct {
			Vulnerability struct {
				ID             string `json:"id"`
				Severity       string `json:"severity"`
				KnownExploited []any  `json:"knownExploited"`
				Fix            struct {
					Versions []string `json:"versions"`
					State    string   `json:"state"`
				} `json:"fix"`
			} `json:"vulnerability"`
			Related []struct {
				ID string `json:"id"`
			} `json:"relatedVulnerabilities"`
			Artifact struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Type    string `json:"type"`
			} `json:"artifact"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	out := make([]RawFinding, 0, len(doc.Matches))
	for _, m := range doc.Matches {
		f := RawFinding{
			ID:       m.Vulnerability.ID,
			Severity: lowerOr(m.Vulnerability.Severity, "unknown"),
			KEV:      len(m.Vulnerability.KnownExploited) > 0,
			FixState: lowerOr(m.Vulnerability.Fix.State, "unknown"),
			FixedIn:  m.Vulnerability.Fix.Versions,
		}
		for _, r := range m.Related {
			f.Related = append(f.Related, r.ID)
		}
		f.Package.Name, f.Package.Version, f.Package.Type = m.Artifact.Name, m.Artifact.Version, m.Artifact.Type
		out = append(out, f)
	}
	return out, nil
}

func normalizeTrivy(b []byte) ([]RawFinding, error) {
	var doc struct {
		Results []struct {
			Type            string `json:"Type"`
			Vulnerabilities []struct {
				ID        string `json:"VulnerabilityID"`
				Severity  string `json:"Severity"`
				PkgName   string `json:"PkgName"`
				Installed string `json:"InstalledVersion"`
				Fixed     string `json:"FixedVersion"`
				Status    string `json:"Status"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	var out []RawFinding
	for _, r := range doc.Results {
		for _, v := range r.Vulnerabilities {
			f := RawFinding{ID: v.ID, Severity: lowerOr(v.Severity, "unknown"), Status: lowerOr(v.Status, "unknown")}
			for _, x := range strings.Split(v.Fixed, ", ") {
				if x != "" {
					f.FixedIn = append(f.FixedIn, x)
				}
			}
			f.Package.Name, f.Package.Version, f.Package.Type = v.PkgName, v.Installed, r.Type
			out = append(out, f)
		}
	}
	return out, nil
}

func lowerOr(s, def string) string {
	if s == "" {
		return def
	}
	return strings.ToLower(s)
}

var countRe = regexp.MustCompile(`(critical|high|medium|low|negligible|unknown|kev)=(\d+)`)

// parseCounts reads a manifest count string:
// "amd64: critical=0 high=0 medium=1 ...; arm64: ..." -> arch -> severity -> n.
func parseCounts(s string) map[string]map[string]int {
	out := map[string]map[string]int{}
	for _, part := range strings.Split(s, ";") {
		arch, rest, ok := strings.Cut(strings.TrimSpace(part), ":")
		if !ok {
			continue
		}
		m := map[string]int{}
		for _, kv := range countRe.FindAllStringSubmatch(rest, -1) {
			n, _ := strconv.Atoi(kv[2])
			m[kv[1]] = n
		}
		out[strings.TrimSpace(arch)] = m
	}
	return out
}
