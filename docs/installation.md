# Installation Guide

The Trivy MCP Server Plugin allows you to integrate Trivy's security scanning capabilities with VS Code and other MCP-enabled tools through the Model Context Protocol (MCP).

## Prerequisites

- Trivy should be installed on your system
- VS Code (v1.99.0 or higher), Cursor, JetBrains IDE, or Claude Desktop for MCP integration

## Installing the Plugin

You can use Trivy's built-in plugin management system to install the MCP plugin:

```sh
trivy plugin install mcp
```

This command will install the latest version of the Trivy MCP plugin.

## Verifying Installation

To verify that the plugin was installed correctly, you can list all installed plugins:

```sh
trivy plugin list
```

You should see the MCP plugin in the list of installed plugins.

## Next Steps

- See the [Quick Start Guide](./quickstart.md) to begin using the plugin
- Configure the plugin for your specific IDE:
  - [VS Code Integration](./ide/vscode.md)
  - [Cursor Integration](./ide/cursor.md)
  - [JetBrains IDE Integration](./ide/jetbrains.md)
  - [Claude Desktop Integration](./ide/claude.md)
