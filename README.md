# Trivy MCP Plugin

This plugin starts an MCP Server that can be used as a gateway to Trivy

> [!IMPORTANT]
> This is early stage development of the MCP Server, so some setup is required

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

## Starting the plugin

You're now ready to start the plugin, this will launch an MCP server that Cursor or VSCode can interact with. For now, the instructions will focus on VSCode

```sh
trivy mcp 
```

### Options

Along with the usual global flags supported by Trivy, the following flags are available for the MCP server. For now, you don't need to specify any of them

| Argument         | Options | Default | Description                                             |
| ---------------- | ------- | ------- | ------------------------------------------------------- |
| --transport / -t | sse     | sse     | The transport of MCP Server to run                      |
| --port / -p      |         | 23456   | The port to launch the MCP server on                    |
| --trivy-binary   |         |         | Optionally provide a binary to use instead of core code |

## Configuring the MCP Server in VSCode

Now, we need to configure the server in VSCode to start using as an agent

### Prereqs

- \>= version 1.99.0 of VSCode

### Configuring the plugin

1. Press `F1`
2. Search for "MCP: Add Server" 
3. Choose HTTP (server-sent events) 
4. Set the url to http://localhost:23456/sse 
5. Give it a name like trivy mcp 
6. Saving to User Settings 
7. The settings.json should open
8. Find the new server, there will be an annotation to `Start` 


## Some sample prompts

> [!IMPORTANT]
> Ensure that the chat window is in `Agent` mode not `Ask`

### Filesystem scanning

With an open project, why not try;

```sh
Are there any vulnerabilities or misconfigurations in this project?
```

### Image scanning

You can ask about images to get information

```sh
Does the python:3.12 image have any vulnerabilities?
```

### Repository scanning

Find out about a remote repository

```sh
What are the vulnerabilities in github.com/aquasecurity/trivy-ci-test
```
