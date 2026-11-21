package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const oidcIssuer = "https://token.actions.githubusercontent.com"

// Source is a project whose releases the trust center records.
type Source struct {
	Repo           string // MaliSec/temper
	SignerWorkflow string // .github/workflows/temper-release-build.yml
	Prefix         string // release asset prefix: temper
}

// signerIdentity is the only certificate identity a release's manifest
// signature is accepted from: the release workflow, at that release's tag.
func (s Source) signerIdentity(tag string) string {
	return "^" + regexp.QuoteMeta("https://github.com/"+s.Repo+"/"+s.SignerWorkflow+"@refs/tags/"+tag) + "$"
}

// fetch downloads every release and keeps the ones that verify. A release
// that fails verification stops the build: the site must not show a
// partial or unverified history as if it were complete.
func fetch(ctx context.Context, src Source, data string) error {
	out, err := command(ctx, "gh", "release", "list", "-R", src.Repo, "--limit", "1000", "--json", "tagName")
	if err != nil {
		return err
	}
	var list []struct {
		TagName string `json:"tagName"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return err
	}
	n := 0
	for _, r := range list {
		if !releaseTag.MatchString(r.TagName) {
			continue
		}
		if err := fetchRelease(ctx, src, data, r.TagName); err != nil {
			return err
		}
		n++
	}
	if n == 0 {
		return fmt.Errorf("no releases in %s", src.Repo)
	}
	return nil
}

func fetchRelease(ctx context.Context, src Source, data, tag string) error {
	tmp, err := os.MkdirTemp("", "trust-"+tag+"-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	m := src.Prefix + "-" + tag + ".manifest.yaml"
	s := src.Prefix + "-" + tag + ".scans.json"
	v := src.Prefix + "-" + tag + ".vex.json"
	if _, err := command(ctx, "gh", "release", "download", tag, "-R", src.Repo, "-D", tmp,
		"-p", m, "-p", m+".sigstore.json", "-p", s, "-p", v); err != nil {
		return err
	}
	keep, err := verifyRelease(ctx, src, tag, filepath.Join(tmp, m), filepath.Join(tmp, s), filepath.Join(tmp, v))
	if err != nil {
		return fmt.Errorf("%s: %w", tag, err)
	}

	dir := filepath.Join(data, "releases", tag)
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for from, to := range map[string]string{m: "manifest.yaml", m + ".sigstore.json": "manifest.yaml.sigstore.json"} {
		if err := os.Rename(filepath.Join(tmp, from), filepath.Join(dir, to)); err != nil {
			return err
		}
	}
	note := ""
	for _, r := range []struct {
		keep     bool
		from, to string
	}{{keep.scans, s, "scans.json"}, {keep.vex, v, "vex.json"}} {
		if !r.keep {
			continue
		}
		if err := os.Rename(filepath.Join(tmp, r.from), filepath.Join(dir, r.to)); err != nil {
			return err
		}
		note += ", " + strings.TrimSuffix(r.to, ".json")
	}
	fmt.Printf("fetch: %s verified%s\n", tag, note)
	return nil
}

// kept: which of a release's optional files are covered by its manifest
// signature, and so used.
type kept struct{ scans, vex bool }

// verifyRelease checks the manifest's signature and, for each file whose
// sha256 the manifest records (scans, VEX), that the file is there and
// matches. A file the manifest does not record is not covered by the
// signature and is not kept.
func verifyRelease(ctx context.Context, src Source, tag, manifest, scans, vex string) (kept, error) {
	if _, err := os.Stat(manifest + ".sigstore.json"); err != nil {
		return kept{}, fmt.Errorf("no signed manifest")
	}
	if _, err := command(ctx, "cosign", "verify-blob", "--bundle", manifest+".sigstore.json",
		"--certificate-identity-regexp", src.signerIdentity(tag),
		"--certificate-oidc-issuer", oidcIssuer, manifest); err != nil {
		return kept{}, fmt.Errorf("manifest signature does not verify: %w", err)
	}
	b, err := os.ReadFile(manifest)
	if err != nil {
		return kept{}, err
	}
	var mf Manifest
	if err := yaml.Unmarshal(b, &mf); err != nil {
		return kept{}, fmt.Errorf("manifest: %w", err)
	}
	var k kept
	if k.scans, err = recorded(scans, "scans", mf.ScansSHA256); err != nil {
		return kept{}, err
	}
	if k.vex, err = recorded(vex, "VEX", mf.VEXSHA256); err != nil {
		return kept{}, err
	}
	return k, nil
}

// recorded: whether a file the manifest may record (by sha256) is to be
// kept, and an error if the manifest records it but it is missing or differs.
func recorded(file, what, want string) (bool, error) {
	if want == "" {
		return false, nil
	}
	b, err := os.ReadFile(file)
	if os.IsNotExist(err) {
		return false, fmt.Errorf("the manifest records a %s file the release does not have", what)
	}
	if err != nil {
		return false, err
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != want {
		return false, fmt.Errorf("%s file does not match the manifest's sha256", what)
	}
	return true, nil
}
