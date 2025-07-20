package main

import (
	"fmt"
	"log"

	"github.com/caddyserver/caddy/v2"
	
	// Import the GFWReport plugin to test registration
	_ "github.com/ysicing/caddy2-extra/gfwreport"
)

// testModuleRegistration verifies that the plugin is properly registered
func testModuleRegistration() {
	fmt.Println("Testing GFWReport plugin registration...")
	
	// Get module info for our plugin
	moduleInfo, err := caddy.GetModule("http.handlers.gfwreport")
	if err != nil {
		log.Fatalf("✗ Plugin module not found: %v", err)
	}
	
	fmt.Printf("✓ Plugin module found: %s\n", moduleInfo.ID)
	
	// Create a new instance
	instance := moduleInfo.New()
	if instance == nil {
		log.Fatal("✗ Failed to create module instance")
	}
	
	fmt.Printf("✓ Module instance created successfully: %T\n", instance)
	
	// Test if it implements the required interfaces
	if _, ok := instance.(caddy.Module); !ok {
		log.Fatal("✗ Module does not implement caddy.Module interface")
	}
	
	fmt.Println("✓ Module implements caddy.Module interface")
	
	// Test CaddyModule method
	if caddyModule, ok := instance.(caddy.Module); ok {
		info := caddyModule.CaddyModule()
		fmt.Printf("✓ Module ID: %s\n", info.ID)
	}
	
	fmt.Println("✓ All tests passed! Plugin is properly registered.")
}

func main() {
	testModuleRegistration()
}
