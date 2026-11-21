package main

import (
	"path"
	"sort"
	"strings"
)

var severityRank = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "negligible": 1, "unknown": 0}

// Count is the number of distinct findings (vulnerability and package)
// across platforms and scanners: open findings by severity, and those a
// VEX statement shows the image is not exposed to (fixed, not affected).
type Count struct {
	Critical, High, Medium, Low, Negligible, Unknown, KEV int
	Reviewed                                              int
}

// Total is the number of open findings.
func (c Count) Total() int {
	return c.Critical + c.High + c.Medium + c.Low + c.Negligible + c.Unknown
}

// Finding is one vulnerability in one package, as reported for an image by
// any scanner on any platform.
type Finding struct {
	ID        string   `json:"id"`
	Related   []string `json:"related,omitempty"`
	Severity  string   `json:"severity"`
	KEV       bool     `json:"kev"`
	Package   string   `json:"package"`
	Version   string   `json:"version"`
	Fix       string   `json:"fix"` // "fixed in …", "no fix yet", "won't fix"
	FixedIn   []string `json:"fixed_in,omitempty"`
	Platforms []string `json:"platforms"`
	Scanners  []string `json:"scanners"`
	VEX       *VEXInfo `json:"vex,omitempty"`
}

type Entry struct {
	Name      string            `json:"name"` // manifest name, e.g. node-24
	Line      string            `json:"line,omitempty"`
	Release   string            `json:"release"`
	Tags      []string          `json:"tags"`
	Digest    string            `json:"digest"`
	Platforms map[string]string `json:"platforms"`

	Now      []Finding `json:"findings_now"`
	NowCount Count     `json:"count_now"`

	AtRelease       []Finding `json:"findings_at_release"`
	AtReleaseCount  Count     `json:"count_at_release"`
	AtReleaseDetail bool      `json:"at_release_detail"` // false: counts from the manifest only

	History []HistoryRow `json:"history"`
}

type HistoryRow struct {
	Release string `json:"release"`
	Digest  string `json:"digest"`
	CutAt   string `json:"cut_at"`
	Count   Count  `json:"count_at_release"`
}

type Image struct {
	Name       string   `json:"name"` // repository basename, e.g. node
	Repository string   `json:"repository"`
	FIPS       bool     `json:"fips"`
	Entries    []*Entry `json:"lines"`
}

type ReleaseView struct {
	Tag      string         `json:"release"`
	CutAt    string         `json:"cut_at"`
	Commit   string         `json:"git_commit"`
	ScanDB   []string       `json:"scan_db"`
	HasScans bool           `json:"scans"`
	Entries  []ReleaseEntry `json:"images"`
}

type ReleaseEntry struct {
	Name       string `json:"name"`
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	Count      Count  `json:"count_at_release"`
}

type Site struct {
	Project     string
	SourceRepo  string // MaliSec/temper
	GeneratedAt string
	Rescan      *Rescan
	VEX         *VEXSource // nil: each release's own VEX document
	Images      []*Image
	Releases    []ReleaseView
}

// build assembles the site. With current statements (the source's vex/ at
// one commit), every release's findings carry them, so a statement made
// after a release applies to it; without, each release's own VEX document.
func build(project, sourceRepo, generatedAt string, releases []Release, rescan *Rescan, current *VEXDoc, vexSrc *VEXSource) *Site {
	s := &Site{Project: project, SourceRepo: sourceRepo, GeneratedAt: generatedAt, Rescan: rescan, VEX: vexSrc}
	vexFor := func(r Release) *VEXDoc {
		if current != nil {
			return current
		}
		return r.VEX
	}
	if len(releases) == 0 {
		return s
	}
	byRepo := map[string]*Image{}
	newest := releases[0]
	for name, mi := range newest.Manifest.Images {
		repo := path.Base(mi.Repository)
		img := byRepo[repo]
		if img == nil {
			img = &Image{Name: repo, Repository: mi.Repository, FIPS: strings.HasSuffix(repo, "-fips")}
			byRepo[repo] = img
		}
		e := &Entry{Name: name, Line: mi.Line, Release: newest.Tag, Digest: mi.Digest, Platforms: mi.Platforms}
		if mi.Primary {
			e.Tags = append(e.Tags, newest.Tag)
		}
		if mi.LineTag != "" {
			e.Tags = append(e.Tags, mi.LineTag)
		}
		e.AtRelease, e.AtReleaseCount, e.AtReleaseDetail = atRelease(newest, name, vexFor(newest))
		if rescan != nil && rescan.Release == newest.Tag {
			e.Now = group(withVEX(rescan.Findings[name], vexFor(newest), mi.Repository))
			e.NowCount = count(e.Now)
		}
		for _, r := range releases {
			if ri, ok := r.Manifest.Images[name]; ok {
				_, c, _ := atRelease(r, name, vexFor(r))
				e.History = append(e.History, HistoryRow{Release: r.Tag, Digest: ri.Digest, CutAt: r.Manifest.CutAt, Count: c})
			}
		}
		img.Entries = append(img.Entries, e)
	}
	for _, img := range byRepo {
		// The primary line first, then older lines.
		sort.Slice(img.Entries, func(i, j int) bool { return img.Entries[i].Name < img.Entries[j].Name })
		s.Images = append(s.Images, img)
	}
	sort.Slice(s.Images, func(i, j int) bool { return s.Images[i].Name < s.Images[j].Name })

	for _, r := range releases {
		rv := ReleaseView{Tag: r.Tag, CutAt: r.Manifest.CutAt, Commit: r.Manifest.GitCommit,
			ScanDB: []string{r.Manifest.ScanDB, r.Manifest.ScanDBTrivy}, HasScans: r.Scans != nil}
		for name, mi := range r.Manifest.Images {
			_, c, _ := atRelease(r, name, vexFor(r))
			rv.Entries = append(rv.Entries, ReleaseEntry{Name: name, Repository: mi.Repository, Digest: mi.Digest, Count: c})
		}
		sort.Slice(rv.Entries, func(i, j int) bool { return rv.Entries[i].Name < rv.Entries[j].Name })
		s.Releases = append(s.Releases, rv)
	}
	return s
}

// atRelease: the release-time findings from the scans file, with doc's
// statements, or, for a release without one, the highest per-platform
// counts in the manifest.
func atRelease(r Release, name string, doc *VEXDoc) ([]Finding, Count, bool) {
	if r.Scans != nil {
		img, ok := r.Scans.Images[name]
		if !ok {
			return nil, Count{}, true
		}
		byArch := map[string]map[string][]RawFinding{}
		for arch, p := range img.Platforms {
			byArch[arch] = map[string][]RawFinding{"grype": p.Grype, "trivy": p.Trivy}
		}
		if doc != nil {
			byArch = withVEX(byArch, doc, r.Manifest.Images[name].Repository)
		}
		fs := group(byArch)
		return fs, count(fs), true
	}
	mi := r.Manifest.Images[name]
	var c Count
	for _, m := range parseCounts(mi.VulnsGrype) {
		c.Critical = max(c.Critical, m["critical"])
		c.High = max(c.High, m["high"])
		c.Medium = max(c.Medium, m["medium"])
		c.Low = max(c.Low, m["low"])
		c.Negligible = max(c.Negligible, m["negligible"])
		c.Unknown = max(c.Unknown, m["unknown"])
		c.KEV = max(c.KEV, m["kev"])
	}
	return nil, c, false
}

// withVEX: the findings with doc's statement on each, if any.
func withVEX(byArch map[string]map[string][]RawFinding, doc *VEXDoc, repository string) map[string]map[string][]RawFinding {
	out := map[string]map[string][]RawFinding{}
	for arch, byScanner := range byArch {
		out[arch] = map[string][]RawFinding{}
		for scanner, fs := range byScanner {
			cp := make([]RawFinding, len(fs))
			for i, f := range fs {
				f.VEX = doc.lookup(repository, f)
				cp[i] = f
			}
			out[arch][scanner] = cp
		}
	}
	return out
}

// group merges per-platform, per-scanner findings into one row per
// vulnerability and package. Scanners that disagree on severity are shown
// at the higher one.
func group(byArch map[string]map[string][]RawFinding) []Finding {
	type key struct{ id, pkg string }
	rows := map[key]*Finding{}
	for arch, byScanner := range byArch {
		for scanner, fs := range byScanner {
			for _, f := range fs {
				k := key{f.ID, f.Package.Name}
				row := rows[k]
				if row == nil {
					row = &Finding{ID: f.ID, Severity: f.Severity, Package: f.Package.Name, Version: f.Package.Version}
					rows[k] = row
				}
				if severityRank[f.Severity] > severityRank[row.Severity] {
					row.Severity = f.Severity
				}
				row.KEV = row.KEV || f.KEV
				row.Related = union(row.Related, f.Related...)
				row.FixedIn = union(row.FixedIn, f.FixedIn...)
				row.Platforms = union(row.Platforms, arch)
				row.Scanners = union(row.Scanners, scanner)
				if row.VEX == nil && f.VEX != nil {
					v := *f.VEX
					row.VEX = &v
				}
				if f.FixState == "wont-fix" || f.Status == "will_not_fix" {
					row.Fix = "won't fix"
				}
			}
		}
	}
	out := make([]Finding, 0, len(rows))
	for _, r := range rows {
		switch {
		case r.VEX != nil && r.VEX.Status == "fixed":
			r.Fix = "fixed in the shipped package"
		case len(r.FixedIn) > 0:
			r.Fix = "fixed in " + strings.Join(r.FixedIn, ", ")
		case r.Fix == "":
			r.Fix = "no fix yet"
		}
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.VEX.Reviewed() != b.VEX.Reviewed() {
			return !a.VEX.Reviewed()
		}
		if a.KEV != b.KEV {
			return a.KEV
		}
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] > severityRank[b.Severity]
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Package < b.Package
	})
	return out
}

func count(fs []Finding) Count {
	var c Count
	for _, f := range fs {
		if f.VEX.Reviewed() {
			c.Reviewed++
			continue
		}
		switch f.Severity {
		case "critical":
			c.Critical++
		case "high":
			c.High++
		case "medium":
			c.Medium++
		case "low":
			c.Low++
		case "negligible":
			c.Negligible++
		default:
			c.Unknown++
		}
		if f.KEV {
			c.KEV++
		}
	}
	return c
}

func union(s []string, add ...string) []string {
	for _, a := range add {
		found := false
		for _, x := range s {
			if x == a {
				found = true
				break
			}
		}
		if !found {
			s = append(s, a)
		}
	}
	sort.Strings(s)
	return s
}
