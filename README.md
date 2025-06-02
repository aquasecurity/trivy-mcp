# Trivy MCP Server Plugin

This plugin starts a Model Context Protocol (MCP) server that integrates Trivy's security scanning capabilities with VS Code and other MCP-enabled tools.

- [Trivy MCP Server Plugin](#trivy-mcp-server-plugin)
  - [Features](#features)
  - [Installing the plugin](#installing-the-plugin)
  - [Starting the plugin](#starting-the-plugin)
    - [Available Options](#available-options)
  - [Configuring the MCP Server for clients](#configuring-the-mcp-server-for-clients)
    - [VS Code](#vs-code)
    - [Cursor](#cursor)
    - [JetBrains IDE](#jetbrains-ide)
    - [Claude Desktop](#claude-desktop)
  - [Example Queries](#example-queries)
    - [Local Project Analysis](#local-project-analysis)
    - [Container Image Scanning](#container-image-scanning)
    - [Repository Analysis](#repository-analysis)
    - [Advanced Usage](#advanced-usage)
  - [Authentication](#authentication)
    - [Available Auth Options](#available-auth-options)


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

You're now ready to start the plugin, this will launch an MCP server that Cursor or VS Code can interact with. For now, the instructions will focus on VS Code

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

## Configuring the MCP Server for clients

### VS Code

Now, we need to configure the server in VS Code to start using as an agent. You need to by using >=v1.99.0 of VS Code

You can configure the Trivy mcp to start itself or use the sse http endpoint

1. Press `F1` to open the command palette
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

#### Getting the most in VS Code

If you want to get Trivy to run at sensible times, you can add a section to your `settings.json` to give a hint to VS Code

> [!IMPORTANT]
> This text can be tuned by you to get the most out of the agent, it will likely change as we further improve the MCP Server

1. Press `F1` to open the command palette
2. Search for `"Preferences: Open User Settings (JSON)"`
3. Add or update the `"github.copilot.chat.codeGeneration.instructions"` setting


   ```json
   "github.copilot.chat.codeGeneration.instructions": [
      {
         "text": "After making changes to packages or manifest files, scan for security vulnerabilities.\n Fixes should only be according to the desired version reported by the scanner.If the scanner reports a fix unrelated to our change, ignore it.After performing the fix, scan the project for security vulnerabilities again. If changes are made to infrastructure as code files such as Terraform, CloudFormation, Kubernetes manifests, Dockerfiles etc, run a scan for security vulnerabilities and misconfigurations. Fixes should only be according to the desired version reported by the scanner. If the scanner reports a fix unrelated to our change, ignore it. After performing the fix, scan the project for security vulnerabilities and misconfigurations again."
      }
   ]
   ```

### Cursor

Cursor is very similar to VS Code for configuration

1. Press `F1` to open the command pallete
2. Search for `"Cursor Settings"`
3. On the opened Settings view, choose `MCP` from the left side bar
4. Click `"Add new global MCP Server"`
5. Add or update the `mcpServers` block
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

#### Getting the most in Cursor

As with VSCode, you can add hints to run Trivy at sensible times

> [!IMPORTANT]
> This text can be tuned by you to get the most out of the agent, it will likely change as we further improve the MCP Server

1. Press `F1` to open the command pallete
2. Search for `"Cursor Settings"`
3. On the opened Settings view, choose `Rules` from the left side bar
4. Add the following block to the `User Rules`
   ```text
   After making changes in any of the package dependency/manifest files, scan the project for security vulnerabilities.
   Fixes should only be according to the desired version reported by the scanner.
   If the scanner reports a fix unrelated to our change, ignore it.
   After performing the fix, scan the project for security vulnerabilities again.
   ```


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
