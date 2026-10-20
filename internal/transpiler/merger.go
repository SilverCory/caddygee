package transpiler

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MergeFragments reads all *.caddyfile fragment files from dir, sorts them
// alphabetically for deterministic output, and assembles them into a complete
// Caddyfile. opts.CloudRun controls whether the Cloud Run global block and
// server-level directives are prepended. opts.ListenAddress sets the bind address.
func MergeFragments(dir string, opts Options) (string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.caddyfile"))
	if err != nil {
		return "", fmt.Errorf("globbing fragments: %w", err)
	}
	sort.Strings(matches)

	var b strings.Builder

	if opts.CloudRun {
		b.WriteString(cloudRunGlobalBlock(opts.AdminAddress, opts.TrustedProxies))
	}

	addr := opts.ListenAddress
	if addr == "" {
		addr = ":8080"
	}
	fmt.Fprintf(&b, "\n%s {\n", addr)

	if opts.CloudRun {
		b.WriteString(cloudRunServerDirectives)
	}

	for _, f := range matches {
		data, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("reading fragment %s: %w", filepath.Base(f), err)
		}
		content := strings.TrimRight(string(data), "\n")
		if content == "" {
			continue
		}
		fmt.Fprintf(&b, "\n\t# --- fragment: %s ---\n", filepath.Base(f))
		b.WriteString(content)
		b.WriteByte('\n')
	}

	b.WriteString("}\n")
	return b.String(), nil
}
