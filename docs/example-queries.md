# Example Queries

This page provides example queries you can use with the Trivy MCP Server Plugin to scan your projects, container images, and repositories for security vulnerabilities and other issues.

> **Important:** Make sure to use the chat window in `Agent` mode, not `Ask` mode when working with the MCP server.

## Local Project Analysis

These queries help you analyze the security of your local projects:

```
Are there any vulnerabilities or misconfigurations in this project?
```

```
Find all HIGH severity vulnerabilities in this codebase
```

```
Generate a CycloneDX SBOM for this project
```

## Container Image Scanning

Use these queries to scan container images for vulnerabilities and other issues:

```
Does the python:3.12 image have any vulnerabilities?
```

```
Show me all critical security issues in the nginx:latest image
```

```
What are the licenses used by dependencies in the node:18 image?
```

## Repository Analysis

Scan remote repositories for security issues:

```
What are the vulnerabilities in github.com/aquasecurity/trivy-ci-test?
```

```
Check for misconfigurations in kubernetes/kubernetes repository
```

## Advanced Usage

Advanced queries for more specific scanning needs:

```
Scan this project for secrets and license issues only
```

```
Generate an SPDX SBOM and show me any dependency vulnerabilities
```

```
What security issues were fixed in the latest version of this image?
```
