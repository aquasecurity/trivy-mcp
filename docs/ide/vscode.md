# VS Code Integration

This guide explains how to configure and use the Trivy MCP Server Plugin with Visual Studio Code.

## Prerequisites

- Visual Studio Code v1.99.0 or higher
- Trivy MCP Plugin installed (see [Installation Guide](../installation.md))

## Configuring the MCP Server in VS Code

1. Press `F1` to open the command palette
2. Search for `"Preferences: Open User Settings (JSON)"`
3. Find or create the `"mcp"` block and add a server as shown below:

```json
"mcp": {
   "servers": {
      "Trivy MCP": {
         "command": "trivy",
         "args": [
            "mcp"
         ]
      }
   }
}
```

4. When you save the settings, an annotation will appear to `Start` the server

## Optimizing VS Code for Security Scanning

To get the most out of Trivy MCP in VS Code, you can add hints to run Trivy at appropriate times:

1. Press `F1` to open the command palette
2. Search for `"Preferences: Open User Settings (JSON)"`
3. Add or update the `"github.copilot.chat.codeGeneration.instructions"` setting:

```json
"github.copilot.chat.codeGeneration.instructions": [
   {
      "text": "After making changes to packages or manifest files, scan for security vulnerabilities.\n Fixes should only be according to the desired version reported by the scanner.If the scanner reports a fix unrelated to our change, ignore it.After performing the fix, scan the project for security vulnerabilities again. If changes are made to infrastructure as code files such as Terraform, CloudFormation, Kubernetes manifests, Dockerfiles etc, run a scan for security vulnerabilities and misconfigurations. Fixes should only be according to the desired version reported by the scanner. If the scanner reports a fix unrelated to our change, ignore it. After performing the fix, scan the project for security vulnerabilities and misconfigurations again."
   }
]
```

> **Note:** You can customize this text to better suit your workflow and needs.

## Using the MCP Server in VS Code

1. Open the Copilot Chat panel in VS Code
2. Ensure you are using the Agent mode (not Ask mode)
3. Type a query related to security scanning, such as:
   ```
   Are there any vulnerabilities in this project?
   ```

## Example Queries for VS Code

See the [Example Queries](../example-queries.md) page for a comprehensive list of queries you can use with the Trivy MCP Server Plugin.
