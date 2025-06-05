# Trivy MCP Server Plugin

This plugin starts a Model Context Protocol (MCP) server that integrates Trivy's security scanning capabilities with VS Code and other MCP-enabled tools.

## Features

- **Natural Language Scanning**: Ask questions about security issues in natural language
- **Multiple Scan Types**:
  - Filesystem scanning for local projects
  - Container image vulnerability scanning
  - Remote repository security analysis
- **Integration with Aqua Platform**: Optional integration with Aqua Security's platform for enhanced scanning capabilities
- **Flexible Transport**: Support for both stdio and SSE (Server-Sent Events) transport protocols
- **IDE Integration**: Seamless integration with VS Code, Cursor, JetBrains IDEs, and Claude Desktop

## Quick Start

### Installation

```sh
trivy plugin install mcp
```

### Starting the Server

```sh
trivy mcp
```

## Documentation

For comprehensive documentation, please see the [docs](./docs) directory:

- [Installation Guide](./docs/installation.md)
- [Quick Start Guide](./docs/quickstart.md)
- [Configuration Options](./docs/configuration.md)
- [IDE Integration](./docs/ide)
  - [VS Code](./docs/ide/vscode.md)
  - [Cursor](./docs/ide/cursor.md)
  - [JetBrains IDE](./docs/ide/jetbrains.md)
  - [Claude Desktop](./docs/ide/claude.md)
- [Example Queries](./docs/example-queries.md)
- [Authentication](./docs/authentication.md)

## Example Query

After setting up the plugin and configuring your IDE, you can start asking security-related questions:

```
Are there any vulnerabilities or misconfigurations in this project?
```

For more examples, see the [Example Queries](./docs/example-queries.md) page.

## License

MIT License - see the [LICENSE](./LICENSE) file for details.
