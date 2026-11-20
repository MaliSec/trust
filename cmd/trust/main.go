// trust builds the trust center: a static site and a JSON feed of every
// verified release of a project, its images, and their scan findings at
// release time and as of the latest rescan.
//
// Usage:
//
//	trust fetch  [-data DIR]            download and verify every release
//	trust rescan [-data DIR] [-jobs N]  scan the newest release's SBOMs today
//	trust build  [-data DIR] [-out DIR] render the site and the feed
//
// Common flags: -repo (MaliSec/temper), -workflow (the release workflow),
// -prefix (release asset prefix), -project (display name).
package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed templates/*.html templates/style.css
var assets embed.FS

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: trust fetch|rescan|build [flags]")
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	data := fs.String("data", "data/temper", "verified releases and rescans")
	repo := fs.String("repo", "MaliSec/temper", "source repository")
	workflow := fs.String("workflow", ".github/workflows/temper-release-build.yml", "the release workflow that signs releases")
	prefix := fs.String("prefix", "temper", "release asset prefix")
	project := fs.String("project", "Temper", "project name")
	out := fs.String("out", "site", "output directory (build)")
	jobs := fs.Int("jobs", 4, "parallel SBOM fetches and Grype scans (rescan)")
	_ = fs.Parse(os.Args[2:])
	src := Source{Repo: *repo, SignerWorkflow: *workflow, Prefix: *prefix}
	ctx := context.Background()
	var err error
	switch cmd {
	case "fetch":
		err = fetch(ctx, src, *data)
	case "rescan":
		err = rescan(ctx, src, *data, max(1, *jobs))
	case "build":
		err = run(*data, *out, *project, *repo, time.Now().UTC())
	default:
		err = fmt.Errorf("unknown command %q (fetch, rescan, build)", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "trust:", err)
		os.Exit(1)
	}
}

func run(data, out, project, repo string, now time.Time) error {
	releases, err := loadReleases(data)
	if err != nil {
		return err
	}
	if len(releases) == 0 {
		return fmt.Errorf("no verified releases under %s", data)
	}
	rescan, err := loadRescan(data)
	if err != nil {
		return err
	}
	if rescan != nil && rescan.Release != releases[0].Tag {
		return fmt.Errorf("rescan is of %s, the newest release is %s", rescan.Release, releases[0].Tag)
	}
	s := build(project, repo, now.Format(time.RFC3339), releases, rescan)

	tpl, err := template.New("").Funcs(funcs).ParseFS(assets, "templates/*.html")
	if err != nil {
		return err
	}
	write := func(name, tmpl, title string, v any) error {
		return render(tpl, filepath.Join(out, name), tmpl, page{Root: depth(name), Title: title, Site: s, Data: v})
	}
	if err := write("index.html", "index.html", "Images", nil); err != nil {
		return err
	}
	if err := write("releases/index.html", "releases.html", "Releases", s.Releases); err != nil {
		return err
	}
	for _, img := range s.Images {
		if err := write("images/"+img.Name+".html", "image.html", img.Name, img); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(out, "api", "images", img.Name+".json"), img); err != nil {
			return err
		}
	}
	for _, r := range s.Releases {
		if err := write("releases/"+r.Tag+".html", "release.html", "Release "+r.Tag, r); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(out, "api", "releases", r.Tag+".json"), r); err != nil {
			return err
		}
	}
	if err := writeJSON(filepath.Join(out, "api", "index.json"), indexJSON(s)); err != nil {
		return err
	}
	css, err := assets.ReadFile("templates/style.css")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(out, "style.css"), css)
}

// indexJSON is the feed's entry point: every image line with its current
// release and finding counts, and every release.
func indexJSON(s *Site) any {
	type line struct {
		Image     string `json:"image"`
		Name      string `json:"name"`
		Line      string `json:"line,omitempty"`
		Release   string `json:"release"`
		Digest    string `json:"digest"`
		Now       *Count `json:"count_now,omitempty"`
		AtRelease Count  `json:"count_at_release"`
	}
	type doc struct {
		Project     string   `json:"project"`
		GeneratedAt string   `json:"generated_at"`
		Rescan      *Rescan  `json:"rescan,omitempty"`
		Lines       []line   `json:"lines"`
		Releases    []string `json:"releases"`
	}
	d := doc{Project: s.Project, GeneratedAt: s.GeneratedAt, Rescan: s.Rescan}
	for _, img := range s.Images {
		for _, e := range img.Entries {
			l := line{Image: img.Name, Name: e.Name, Line: e.Line, Release: e.Release, Digest: e.Digest, AtRelease: e.AtReleaseCount}
			if s.Rescan != nil {
				c := e.NowCount
				l.Now = &c
			}
			d.Lines = append(d.Lines, l)
		}
	}
	for _, r := range s.Releases {
		d.Releases = append(d.Releases, r.Tag)
	}
	return d
}

type page struct {
	Root  string // relative path to the site root: "" or "../"
	Title string
	Site  *Site
	Data  any
}

func render(tpl *template.Template, file, name string, p page) error {
	var b strings.Builder
	if err := tpl.ExecuteTemplate(&b, name, p); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	return writeFile(file, []byte(b.String()))
}

func depth(name string) string {
	return strings.Repeat("../", strings.Count(name, "/"))
}

func writeJSON(file string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(file, append(b, '\n'))
}

func writeFile(file string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	return os.WriteFile(file, b, 0o644)
}

var funcs = template.FuncMap{
	"short": func(d string) string {
		d = strings.TrimPrefix(d, "sha256:")
		if len(d) > 12 {
			return d[:12]
		}
		return d
	},
	"join": strings.Join,
	"tag":  func(repo, tag string) string { return repo + ":" + tag },
	"cveURL": func(id string) string {
		switch {
		case strings.HasPrefix(id, "CVE-"):
			return "https://nvd.nist.gov/vuln/detail/" + id
		case strings.HasPrefix(id, "GHSA-"):
			return "https://github.com/advisories/" + id
		default:
			return "https://osv.dev/vulnerability/" + id
		}
	},
}
