# Configuration Options

The Trivy MCP Server Plugin offers various configuration options to customize its behavior according to your needs.

## Server Configuration Options

When starting the Trivy MCP server, you can use the following command-line options:

| Option              | Values         | Default | Description                                             |
| ------------------- | -------------- | ------- | ------------------------------------------------------- |
| `--transport` / `-t`| `sse`, `stdio` | `stdio` | Transport protocol for the MCP Server                   |
| `--port` / `-p`     |                | 23456   | Port for SSE transport mode                             |
| `--trivy-binary`    |                |         | Custom Trivy binary path (optional)                     |
| `--use-aqua-platform`  / `a`      | `true/false`   | `false` | Enable Aqua Platform integration                        |
| `--debug`           | `true/false`   | `false` | Enable debug logging                                    |

## Transport Protocols

### stdio Transport

The stdio transport is the default option and is best for direct integration with IDEs like VS Code, Cursor, and JetBrains.

To explicitly use stdio transport:

```sh
trivy mcp --transport stdio
```

### SSE (Server-Sent Events) Transport

The SSE transport runs the MCP server over HTTP, which can be useful for network-based integrations.

To use SSE transport:

```sh
trivy mcp --transport sse --port 23456
```

## Aqua Platform Integration

If you've configured Aqua Platform authentication (see [Authentication](./authentication.md)), you can enable integration with:

```sh
trivy mcp --use-aqua-platform
```

Or with the shorthand flag:

```sh
trivy mcp -a
```

When Aqua Platform integration is enabled, scans will include:
- Enhanced vulnerability detection
- **Assurance policy evaluation** - automatic compliance checking against your organization's security policies
- Advanced reporting and analytics

Policy failures are prominently displayed and marked as high-priority issues that must be addressed.

## Debug Mode

For troubleshooting or development purposes, you can enable debug logging:

```sh
trivy mcp --debug
```

## Using a Custom Trivy Binary

If you need to use a specific version of Trivy, you can specify the path to the binary:

```sh
trivy mcp --trivy-binary /path/to/custom/trivy
```
