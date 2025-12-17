# Quick Start Guide

This guide will help you get up and running with the Trivy MCP Server Plugin quickly.

## Installation

If you haven't installed the plugin yet:

```sh
trivy plugin install mcp
```

See the [Installation Guide](./installation.md) for more details.

## Starting the MCP Server

To start the Trivy MCP server:

```sh
trivy mcp
```

By default, this will start the server using stdio transport, which is suitable for most IDE integrations.

## Basic Configuration Options

You can customize the server behavior with these options:

| Option                       | Values         | Default | Description                           |
| ---------------------------- | -------------- | ------- | ------------------------------------- |
| `--transport` / `-t`         | `streamable-http`, `sse`, `stdio` | `stdio` | Transport protocol for the MCP Server |
| `--host` / `-H`              |                | `localhost` | Host/interface to listen on (network transports) |
| `--port` / `-p`              |                | 23456   | Port for network transport modes      |
| `--trivy-binary`             |                |         | Custom Trivy binary path (optional)   |
| `--use-aqua-platform` / `-a` | `true/false`   | `false` | Enable Aqua Platform integration      |
| `--debug`                    | `true/false`   | `false` | Enable debug logging                  |

Examples with different transports:

```sh
# Streamable HTTP transport
trivy mcp --transport streamable-http --host localhost --port 8080

# SSE transport
trivy mcp --transport sse --host localhost --port 8080

# Listen on all interfaces (allows remote connections)
trivy mcp --transport sse --host 0.0.0.0 --port 8080
```

## IDE Configuration

The Trivy MCP Server Plugin works with various IDEs, including VS Code, Cursor, JetBrains IDEs, and Claude Desktop.

For detailed configuration instructions for each IDE, see:

- [VS Code Integration](./ide/vscode.md)
- [Cursor Integration](./ide/cursor.md)
- [JetBrains IDE Integration](./ide/jetbrains.md)
- [Claude Desktop Integration](./ide/claude.md)

## Basic Usage

Once configured, you can use natural language to ask security-related questions in your IDE's chat interface. Make sure to use the chat window in "Agent" mode, not "Ask" mode.

Example queries:

```
Are there any vulnerabilities or misconfigurations in this project?
```

```
Find all HIGH severity vulnerabilities in this codebase
```

For more example queries, see the [Example Queries](./example-queries.md) page.

## Next Steps

- Explore [Authentication](./authentication.md) to integrate with Aqua Platform
- Try out different [Example Queries](./example-queries.md) to learn more about what you can do
