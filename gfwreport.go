package caddy2extra

import (
	"github.com/ysicing/caddy2-extra/gfwreport"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

// Plugin information
const (
	PluginName    = "gfwreport"
	PluginVersion = "1.0.0"
	PluginAuthor  = "GFWReport Team"
)

// init registers the plugin with Caddy
func init() {
	// Register the module
	caddy.RegisterModule(gfwreport.GFWReportHandler{})

	// Register the Caddyfile directive
	httpcaddyfile.RegisterHandlerDirective(PluginName, gfwreport.ParseCaddyfile)
}

// GetPluginInfo returns information about the plugin
func GetPluginInfo() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers." + PluginName,
		New: func() caddy.Module { return new(gfwreport.GFWReportHandler) },
	}
}
