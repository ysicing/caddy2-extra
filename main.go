package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// Import standard Caddy modules
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	// Import the GFWReport plugin
	_ "github.com/ysicing/caddy2-extra/gfwreport"
)

func main() {
	caddycmd.Main()
}
