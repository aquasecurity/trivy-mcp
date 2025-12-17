# Configuration Options

The Trivy MCP Server Plugin offers various configuration options to customize its behavior according to your needs.

## Server Configuration Options

When starting the Trivy MCP server, you can use the following command-line options:

| Option              | Values         | Default | Description                                             |
| ------------------- | -------------- | ------- | ------------------------------------------------------- |
| `--transport` / `-t`| `streamable-http`, `sse`, `stdio` | `stdio` | Transport protocol for the MCP Server                   |
| `--host` / `-H`     |                | `localhost` | Host/interface to listen on (for network transports)   |
| `--port` / `-p`     |                | 23456   | Port for network transport modes                        |
| `--trivy-binary`    |                |         | Custom Trivy binary path (optional)                     |
| `--use-aqua-platform`  / `-a`      | `true/false`   | `false` | Enable Aqua Platform integration                        |
| `--debug`           | `true/false`   | `false` | Enable debug logging                                    |

## Transport Protocols

### stdio Transport

The stdio transport is the default option and is best for direct integration with IDEs like VS Code, Cursor, and JetBrains.

To explicitly use stdio transport:

```sh
trivy mcp --transport stdio
```

### Streamable HTTP Transport

The streamable HTTP transport provides a modern HTTP-based MCP server implementation with streaming support.

To use streamable HTTP transport:

```sh
trivy mcp --transport streamable-http --host localhost --port 8080
```

### SSE (Server-Sent Events) Transport

The SSE transport runs the MCP server over HTTP using Server-Sent Events, which can be useful for network-based integrations.

To use SSE transport:

```sh
trivy mcp --transport sse --host localhost --port 23456
```

## Network Configuration

For network-based transports (`streamable-http` and `sse`), you can configure the listening interface:

### Listen on localhost only (default, secure)
```sh
trivy mcp --transport sse --host localhost --port 8080
```

### Listen on all interfaces (allows remote connections)
```sh
trivy mcp --transport sse --host 0.0.0.0 --port 8080
```

### Listen on specific interface
```sh
trivy mcp --transport sse --host 192.168.1.100 --port 8080
```

**Security Note**: Using `0.0.0.0` allows connections from any network interface. Only use this if you need remote access and understand the security implications.

**IDE Integration Note**: Most IDE integrations (VS Code, Cursor, JetBrains, Claude Desktop) work best with the default `stdio` transport. Network transports are primarily useful for custom integrations or remote access scenarios.

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
