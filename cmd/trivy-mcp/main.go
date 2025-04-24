package main

import (
	"github.com/aquasecurity/trivy-plugin-mcp/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/log"
)

func main() {
	if err := run(); err != nil {
		log.Fatal("Fatal error", log.Err(err))
	}
}

func run() error {
	cmd := commands.NewCmd()
	return cmd.Execute()
}
