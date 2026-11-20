package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// command runs an external tool (gh, cosign, grype, trivy). Tests replace it.
var command = runCommand

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	var out, errb bytes.Buffer
	c := exec.CommandContext(ctx, name, args...)
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, lastLines(errb.String(), 3))
	}
	return out.Bytes(), nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
