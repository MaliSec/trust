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
	if _, err := command(ctx, "gh", "release", "download", tag, "-R", src.Repo, "-D", tmp,
		"-p", m, "-p", m+".sigstore.json", "-p", s); err != nil {
		return err
	}
	scans, err := verifyRelease(ctx, src, tag, filepath.Join(tmp, m), filepath.Join(tmp, s))
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
	if scans {
		if err := os.Rename(filepath.Join(tmp, s), filepath.Join(dir, "scans.json")); err != nil {
			return err
		}
		note = ", with scans"
	}
	fmt.Printf("fetch: %s verified%s\n", tag, note)
	return nil
}

// verifyRelease checks the manifest's signature and, when the manifest
// records one, the scans file's sha256. It reports whether the scans file
// is to be kept: a scans file the manifest does not record is not covered
// by the signature and is ignored.
func verifyRelease(ctx context.Context, src Source, tag, manifest, scans string) (bool, error) {
	if _, err := os.Stat(manifest + ".sigstore.json"); err != nil {
		return false, fmt.Errorf("no signed manifest")
	}
	if _, err := command(ctx, "cosign", "verify-blob", "--bundle", manifest+".sigstore.json",
		"--certificate-identity-regexp", src.signerIdentity(tag),
		"--certificate-oidc-issuer", oidcIssuer, manifest); err != nil {
		return false, fmt.Errorf("manifest signature does not verify: %w", err)
	}
	b, err := os.ReadFile(manifest)
	if err != nil {
		return false, err
	}
	var mf Manifest
	if err := yaml.Unmarshal(b, &mf); err != nil {
		return false, fmt.Errorf("manifest: %w", err)
	}
	if mf.ScansSHA256 == "" {
		return false, nil
	}
	sb, err := os.ReadFile(scans)
	if os.IsNotExist(err) {
		return false, fmt.Errorf("the manifest records a scans file the release does not have")
	}
	if err != nil {
		return false, err
	}
	sum := sha256.Sum256(sb)
	if hex.EncodeToString(sum[:]) != mf.ScansSHA256 {
		return false, fmt.Errorf("scans file does not match the manifest's sha256")
	}
	return true, nil
}
