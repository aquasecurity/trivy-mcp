# Authentication

The Trivy MCP Server Plugin supports integration with Aqua Platform through its authentication system, enabling enhanced scanning capabilities.

## Aqua Platform Authentication

You can configure the MCP Server to use Aqua Platform with the `auth` subcommand.

### Logging In

To save your Aqua Platform credentials:

```sh
trivy mcp auth login --key "YOUR_AQUA_KEY" --secret "YOUR_AQUA_SECRET" --region "YOUR_REGION"
```

### Authentication Options

| Option            | Description                                    |
| ---------------- | ---------------------------------------------- |
| `--key`          | Aqua Platform API key                          |
| `--secret`       | Aqua Platform API secret                       |
| `--region`       | Aqua Platform region (e.g., 'us-east-1')      |

### Checking Authentication Status

To verify your saved credentials:

```sh
trivy mcp auth status
```

### Logging Out

To clear your saved credentials:

```sh
trivy mcp auth logout
```

## Credential Storage

Credentials are securely stored in your platform's specific keychain.

## Using Aqua Platform Features

After configuring credentials, you can start the MCP server with Aqua Platform integration enabled:

```sh
trivy mcp --use-aqua-platform
```

Or using the shorthand flag:

```sh
trivy mcp -a
```
