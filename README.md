# Trivy MCP Server Plugin

This plugin starts a Model Context Protocol (MCP) server that integrates Trivy's security scanning capabilities with VS Code and other MCP-enabled tools.

> [!IMPORTANT]
> This is early stage development of the MCP Server, so you should assume things won't work great for now

## Features

- **Natural Language Scanning**: Ask questions about security issues in natural language
- **Multiple Scan Types**:
  - Filesystem scanning for local projects
  - Container image vulnerability scanning
  - Remote repository security analysis
- **Integration with Aqua Platform**: Optional integration with Aqua Security's platform for enhanced scanning capabilities
- **Flexible Transport**: Support for both stdio and SSE (Server-Sent Events) transport protocols
- **VS Code Integration**: Seamless integration with VS Code's chat interface

## Installing the plugin

To install the plugin you can use Trivy's plugin management system

```sh
trivy plugin install mcp
```

The will install the latest version of the plugin

## Starting the plugin

You're now ready to start the plugin, this will launch an MCP server that Cursor or VSCode can interact with. For now, the instructions will focus on VSCode

```sh
trivy mcp
```

### Available Options

| Option              | Values         | Default | Description                                             |
| ------------------- | -------------- | ------- | ------------------------------------------------------- |
| `--transport` / `-t`| `sse`, `stdio` | `stdio` | Transport protocol for the MCP Server                   |
| `--port` / `-p`     |                | 23456   | Port for SSE transport mode                             |
| `--trivy-binary`    |                |         | Custom Trivy binary path (optional)                     |
| `--use-aqua-platform`  / `a`      | `true/false`   | `false` | Enable Aqua Platform integration                        |
| `--debug`           | `true/false`   | `false` | Enable debug logging                                    |



## Authentication

The MCP Server supports integration with Aqua Platform through the `auth` subcommand:

```sh
# Save Aqua Platform credentials
trivy mcp auth login --key "YOUR_AQUA_KEY" --secret "YOUR_AQUA_SECRET" --region "YOUR_REGION"

# Clear saved credentials
trivy mcp auth logout

# Verify saved credentials
trivy mcp auth status
```

### Available Auth Options
| Option            | Description                                    |
| ---------------- | ---------------------------------------------- |
| `--key`          | Aqua Platform API key                          |
| `--secret`       | Aqua Platform API secret                       |
| `--region`       | Aqua Platform region (e.g., 'us-east-1')      |

After configuring credentials, you can use Aqua Platform features by starting the server with the `--use-aqua-platform` flag:

```sh
trivy mcp --use-aqua-platform
```

Credentials are securely stored in the platform specific key chain.

## Configuring the MCP Server for clients

### VS Code

Now, we need to configure the server in VSCode to start using as an agent

#### Prereqs

- \>= version 1.99.0 of VS Code


#### Configuring the plugin
You can configure the Trivy mcp to start itself or use the sse http endpoint

1. In VS Code, press `F1`
2. Search for `"Preferences: Open User Settings (JSON)"`
3. Find or create the `"mcp"` block and add a server as below
   ```json
   "mcp": {
      "servers": {
         "Trivy MCP": {
            "command": "trivy",
            "args": [
               "mcp",
            ]
         }
      }
   }
   ```
4. When you save, an annotation will appear to `Start` the server

### JetBrains IDE

Configuring the JetBrains suite of IDEs requireds a recent version of the IDE and the CoPilot Extension

1. Open CoPilot Chat and choose `Agent (Preview)` from the tabs at the top
2. At the bottom of the chat window, select the tools icon and choose `Add More Tools...`
3. The `mcp.json` file will be opened, add the following block up update the existing servers block to add `trivy`
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

### Claude Desktop

MCP Servers can be added to the Claude Desktop app

1. Open Settings and choose the `Developer` settings
2. Click `Edit Config` button, and open the file it points you to - something like `claude_desktop_config.json`
3. Add or update the servers block
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
   ````
4. Restart Claude to pickup the config change and check Settings -> Developer to ensure it's been added


## Example Queries

> [!IMPORTANT]
> Make sure to use the chat window in `Agent` mode, not `Ask` mode

### Local Project Analysis
```text
Are there any vulnerabilities or misconfigurations in this project?
```
```text
Find all HIGH severity vulnerabilities in this codebase
```
```text
Generate a CycloneDX SBOM for this project
```

### Container Image Scanning
```text
Does the python:3.12 image have any vulnerabilities?
```
```text
Show me all critical security issues in the nginx:latest image
```
```text
What are the licenses used by dependencies in the node:18 image?
```

### Repository Analysis
```text
What are the vulnerabilities in github.com/aquasecurity/trivy-ci-test?
```
```text
Check for misconfigurations in kubernetes/kubernetes repository
```

### Advanced Usage
```text
Scan this project for secrets and license issues only
```
```text
Generate an SPDX SBOM and show me any dependency vulnerabilities
```
```text
What security issues were fixed in the latest version of this image?
```
