# Trivy MCP Server Plugin - _EXPERIMENTAL WIP_

This plugin starts an MCP Server that can be used as a gateway to Trivy

> [!IMPORTANT]
> This is early stage development of the MCP Server, so you should assume things won't work great for now

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

### Options

Along with the usual global flags supported by Trivy, the following flags are available for the MCP server. For now, you don't need to specify any of them

| Argument             | Options        | Default | Description                                             |
| -------------------- | -------------- | ------- | ------------------------------------------------------- |
| `--transport` / `-t` | `sse`, `stdio` | `stdio` | The transport of MCP Server to run                      |
| `--port` / `-p`      |                | 23456   | The port to launch the MCP server on                    |
| `--trivy-binary`     |                |         | Optionally provide a binary to use instead of core code |

## Configuring the MCP Server in VSCode

Now, we need to configure the server in VSCode to start using as an agent

### Prereqs

- \>= version 1.99.0 of VS Code

### Configuring the plugin

You can configure the Trivy mcp to start itself or use the sse http endpoint
#### Configuring for stdio

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
               "-t",
               "stdio"
            ]
         }
      }
   }
   ```
4. When you save, an annotation will appear to `Start` the server

#### Configuring for SSE HTTP

1. Start the MCP Server
   ```sh
   trivy mcp -t sse -p 23456
   ```
2. In VS Code, press `F1`
3. Search for `"Preferences: Open User Settings (JSON)"`
4. Find or create the `"mcp"` block and add a server as below
   ```json
   "mcp": {
      "servers": {
         "Trivy SSE": {
            "type": "sse",
            "url": "http://localhost:23456/sse"
         }
      }
   }
   ```
5. When you save, an annotation will appear to `Start` the server



## Some sample prompts

> [!IMPORTANT]
> Ensure that the chat window is in `Agent` mode not `Ask`

### Filesystem scanning

With an open project, why not try;

```text
Are there any vulnerabilities or misconfigurations in this project?
```

### Image scanning

You can ask about images to get information

```text
Does the python:3.12 image have any vulnerabilities?
```

### Repository scanning

Find out about a remote repository

```text
What are the vulnerabilities in github.com/aquasecurity/trivy-ci-test
```
