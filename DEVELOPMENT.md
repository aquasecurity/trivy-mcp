# Local Development

These steps should get you up and running while the development is being done

## Prereqs

- Go (1.24.1)
- make
- Trivy installed

## Installing the Trivy Plugin

Normally, when installing a Trivy plugin you would do `trivy plugin install <pluginName>`, as this isn't a public repo just yet, we need to do it manually for now.

1. Create the plugin path and setup the manifest file
   ```sh
   make add-plugin-manifest
   ```
2. Install the plugin
   ```ssh
   make install-plugin
   ```

## Run the MCP Server

You can now run the MCP Server using 

```sh
trivy mcp
```

Return to the instructions on [configuring VSCode](README.md#configuring-the-mcp-server-in-vscode) in the [README.md](README.md)