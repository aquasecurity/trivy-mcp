# JetBrains IDE Integration

This guide explains how to configure and use the Trivy MCP Server Plugin with JetBrains IDEs.

## Prerequisites

- Any JetBrains IDE (IntelliJ IDEA, PyCharm, WebStorm, etc.) with the CoPilot Extension installed
- Trivy MCP Plugin installed (see [Installation Guide](../installation.md))

## Configuring the MCP Server in JetBrains IDEs

1. Open CoPilot Chat and choose `Agent (Preview)` from the tabs at the top
2. At the bottom of the chat window, select the tools icon and choose `Add More Tools...`
3. The `mcp.json` file will be opened. Add the following block or update the existing `servers` block to add `trivy`:

```json
{
 "servers": {
     "trivy": {
         "type": "stdio",
         "command": "trivy",
         "args": ["mcp"]
     }
 }
}
```

## Using the MCP Server in JetBrains IDEs

1. Open the CoPilot Chat panel in your JetBrains IDE
2. Ensure you are using the Agent (Preview) mode
3. Type a query related to security scanning, such as:
   ```
   Are there any vulnerabilities in this project?
   ```

## Example Queries for JetBrains IDEs

See the [Example Queries](../example-queries.md) page for a comprehensive list of queries you can use with the Trivy MCP Server Plugin.
