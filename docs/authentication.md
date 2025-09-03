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

## Assurance Policy Support

When using Aqua Platform integration, the MCP server automatically evaluates assurance policies during scans. Assurance policies define security and compliance rules that must be met.

### Policy Evaluation

Assurance policies are automatically evaluated when scanning with Aqua Platform integration enabled. Policy failures are prominently displayed in scan results with:

- ⚠️ **Policy failure warnings** that must be addressed
- **Policy name and ID** for identification  
- **Failure reason** explaining why the policy failed
- **Priority indication** that these issues require immediate attention

### Exit Codes

When assurance policies fail, Trivy may return exit code 13, which is handled gracefully by the MCP server while still reporting the policy failures.