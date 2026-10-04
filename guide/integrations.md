# Integrations — Connecting to Your Development, API, and AI Platform Tools

**English** | [日本語](integrations.ja.md)

A CyberRiskScape threat model does not have to stay inside the diagram: it connects to the tools you use to design,
build, and verify. This page lists the products you can integrate with and their use cases. See each page for the
details.

> Product names are trademarks of their respective owners. Each page explains how to use the product with
> CyberRiskScape; none is provided, certified, or endorsed by the product's vendor.

---

## How to connect

### Through MCP, directly from AI agents

CyberRiskScape **ships an MCP (Model Context Protocol) server**. Register it with an MCP-capable AI agent (Claude Code,
GitHub Copilot, Cursor, and others) and the agent can query threats and propose diagram updates while it designs. You
can also run it side by side with other vendors' MCP servers (such as Snyk) in the same agent.

For setup, see **[Using It from Coding Agents — MCP Server Setup Guide](mcp-integration.md)**.

- It makes no outbound calls (it also works in air-gapped environments)
- It can only read and write inside the directory you specify, and it cannot accept risks or change assessments.
  People make the final call in the PR

### Through files and the CLI

Importing configuration files, exporting verification requests, and diff checks in CI run on files and the CLI
(`dist-cli/main.js`). None of them call the product's API, so no API keys or paid plans are needed.

---

## Products you can integrate with

| Product | How it connects | Use cases | Page |
|---|---|---|---|
| **Claude Code** | MCP | Look up threats while designing, update the diagram, self-review before a PR | [MCP setup guide](mcp-integration.md), [use cases](mcp-use-cases.md) |
| **GitHub Copilot** (VS Code, coding agent) | MCP | Hand off an issue, from updating the diagram to checking threats | [MCP setup guide](mcp-integration.md), [use cases](mcp-use-cases.md) (§5) |
| **Cursor** | MCP | Query threats from inside the editor | [MCP setup guide](mcp-integration.md), [use cases](mcp-use-cases.md) (§6) |
| **Snyk** | MCP (side by side, through the agent) | Cross-check the threat model's important threats with code vulnerability scan results | [Use cases](mcp-use-cases.md) (§7) |
| **GitHub Actions** | CLI, GitHub Action | Detect new threats from diagram diffs and block the PR; ask for reviews with execution triggers | [Integrating with AI-Driven Development CI](ci-integration.md) |
| **Kong AI Gateway** | Configuration import (decK kong.yaml) | Generate the diagram from configuration; watch for new threats from configuration changes in PRs | [Threat Modeling Kong AI Gateway](kong-ai-gateway.md) |
| **Postman** (Postman CLI, Newman) | Export of verification requests (Collection v2.1) | Check whether detected threats hold in the implementation and keep the checks as CI regression tests | [Verifying Threats with Postman](postman.md) |
| **Salesforce Agentforce** | Dedicated stencils, threat rules, and template | Assess a Service agent setup; watch agent-definition changes in PRs | [Threat Modeling Salesforce Agentforce](agentforce.md) |
| **Okta** | MCP (side by side, through the agent), dedicated stencils and threat rules | Cross-check diagram NHIs against existing service apps; confirm identity strength from the authentication method; find unused NHIs | [Threat Modeling NHIs and Identity Platforms](nhi-identity.md) |
| **SailPoint** | MCP (side by side, through the agent), IGA stencil and threat rules | Find the least access that can be requested instead of excessive permissions | [Threat Modeling NHIs and Identity Platforms](nhi-identity.md) |
| **CyberArk (Idira)** | Conjur policy import, MCP (side by side, through the agent), PAM stencil and threat rules | Draft a diagram of NHIs and secret read paths from the policy; cross-check diagram NHIs against Secrets Manager workloads | [Threat Modeling NHIs and Identity Platforms](nhi-identity.md) |
| **Anthropic `defending-code-reference-harness`** | `THREAT_MODEL.md`-compatible export | Use the threat model as input to an AI-driven vulnerability review | [Turning Your Threat Model into a Security Context](security-context.md) |

---

## Choose by goal

| You want to | Use |
|---|---|
| Have an AI agent help with threat modeling | MCP (Claude Code, GitHub Copilot, Cursor) |
| Catch missed threat-model updates in PRs | GitHub Actions |
| Draw the diagram from existing configuration | Kong AI Gateway |
| Confirm that the threats you flagged are actually closed | Postman |
| Assess a product-specific setup as is | Salesforce Agentforce |
| Surface the risks of NHIs such as service accounts and AI agents | Okta, SailPoint, CyberArk (Idira) |
| Put the threat model to work in vulnerability review | Anthropic `defending-code-reference-harness`, Snyk |

---

## What to read next

- Get the big picture — [Getting Started](getting-started.md)
- Connect over MCP — [Using It from Coding Agents](mcp-integration.md)
- All guide pages — [CyberRiskScape Guide](README.md)
