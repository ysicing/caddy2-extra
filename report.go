package caddy2extra

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/ysicing/caddy2-extra/report"
)

// Plugin information
const (
	PluginName    = "report"
	PluginVersion = "1.0.0"
	PluginAuthor  = "ysicing"
)

// init registers the plugin with Caddy
func init() {
	// Register the module
	caddy.RegisterModule(&report.ReportHandler{})

	// Register the Caddyfile directive
	httpcaddyfile.RegisterHandlerDirective(PluginName, report.ParseCaddyfile)
}

// GetPluginInfo returns information about the plugin
func GetPluginInfo() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers." + PluginName,
		New: func() caddy.Module { return new(report.ReportHandler) },
	}
}
