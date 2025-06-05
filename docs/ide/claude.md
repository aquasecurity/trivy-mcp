# Claude Desktop Integration

This guide explains how to configure and use the Trivy MCP Server Plugin with Claude Desktop.

## Prerequisites

- Claude Desktop app installed
- Trivy MCP Plugin installed (see [Installation Guide](../installation.md))

## Configuring the MCP Server in Claude Desktop

1. Open Settings and choose the `Developer` settings
2. Click the `Edit Config` button, which will direct you to the configuration file (typically `claude_desktop_config.json`)
3. Add or update the `mcpServers` block:

```json
{
   "mcpServers": {
      "trivy": {
         "command": "trivy",
         "args": [
            "mcp"
         ]
      }
   }
}
```

4. Restart Claude to apply the configuration change
5. Check Settings -> Developer to ensure the server has been added successfully

## Using the MCP Server in Claude Desktop

1. Open a new chat in Claude Desktop
2. Type a query related to security scanning, such as:
   ```
   Are there any vulnerabilities in this project?
   ```

## Example Queries for Claude Desktop

See the [Example Queries](../example-queries.md) page for a comprehensive list of queries you can use with the Trivy MCP Server Plugin.
