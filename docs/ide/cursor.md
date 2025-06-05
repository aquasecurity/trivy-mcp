# Cursor Integration

This guide explains how to configure and use the Trivy MCP Server Plugin with Cursor IDE.

## Prerequisites

- Cursor IDE installed
- Trivy MCP Plugin installed (see [Installation Guide](../installation.md))

## Configuring the MCP Server in Cursor

1. Press `F1` to open the command palette
2. Search for `"Cursor Settings"`
3. On the opened Settings view, choose `MCP` from the left side bar
4. Click `"Add new global MCP Server"`
5. Add or update the `mcpServers` block:

```json
{
   "mcpServers": {
      "trivy": {
         "type": "command",
         "command": "trivy",
         "args": [ "mcp"]
      }
   }
}
```

## Optimizing Cursor for Security Scanning

To get the most out of Trivy MCP in Cursor, you can add hints to run Trivy at appropriate times:

1. Press `F1` to open the command palette
2. Search for `"Cursor Settings"`
3. On the opened Settings view, choose `Rules` from the left side bar
4. Add the following block to the `User Rules`:

```text
After making changes in any of the package dependency/manifest files, scan the project for security vulnerabilities.
Fixes should only be according to the desired version reported by the scanner.
If the scanner reports a fix unrelated to our change, ignore it.
After performing the fix, scan the project for security vulnerabilities again.
```

> **Note:** You can customize this text to better suit your workflow and needs.

## Using the MCP Server in Cursor

1. Open the Chat panel in Cursor
2. Ensure you are using the Agent mode (not Ask mode)
3. Type a query related to security scanning, such as:
   ```
   Are there any vulnerabilities in this project?
   ```

## Example Queries for Cursor

See the [Example Queries](../example-queries.md) page for a comprehensive list of queries you can use with the Trivy MCP Server Plugin.
