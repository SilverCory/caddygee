// Command caddy is a custom Caddy build with the caddygee apigeecompat modules
// baked in. It is identical to the standard Caddy binary except that the
// apigeecompat middleware modules are registered at startup via the blank import.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// Required to register Caddy's built-in modules.
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	// Register the caddygee apigeecompat middleware modules.
	_ "caddygee/modules/apigeecompat"
)

func main() {
	caddycmd.Main()
}
