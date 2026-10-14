package transpiler

import (
	"caddygee/internal/apigee"
)

// Emit converts the parsed bundle to the requested output format.
// It returns the generated config as a string (Caddyfile) or JSON bytes.
func Emit(bundle *apigee.Bundle, opts Options) (string, error) {
	cfg, err := Transpile(bundle, opts)
	if err != nil {
		return "", err
	}
	switch opts.Format {
	case "json":
		b, err := EmitJSON(cfg)
		if err != nil {
			return "", err
		}
		return string(b), nil
	default:
		return EmitCaddyfile(cfg, opts)
	}
}
