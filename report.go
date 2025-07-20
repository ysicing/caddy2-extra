package caddy2extra

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/ysicing/caddy2-extra/report"
)

// init registers the plugin with Caddy
func init() {
	// Register the module
	caddy.RegisterModule(&report.ReportHandler{})

	// Register the Caddyfile directive
	httpcaddyfile.RegisterHandlerDirective("report", report.ParseCaddyfile)
}
