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
| **Claude Code** (working directory) | Working-directory import (`import-repo`; package.json, requirements.txt, .env, .mcp.json and `.claude/` settings; settings of agents other than `.claude/` are not read) | Generate a diagram of the development environment and its dependency packages; watch changes to dependencies and permission settings in PRs | [Turning a Working Directory into a Threat Model](repo-import.md) |
| **GitHub Copilot** (VS Code, coding agent) | MCP | Hand off an issue, from updating the diagram to checking threats | [MCP setup guide](mcp-integration.md), [use cases](mcp-use-cases.md) (§5) |
| **Cursor** | MCP | Query threats from inside the editor | [MCP setup guide](mcp-integration.md), [use cases](mcp-use-cases.md) (§6) |
| **Snyk** | MCP (side by side, through the agent) | Cross-check the threat model's important threats with code vulnerability scan results | [Use cases](mcp-use-cases.md) (§7) |
| **GitHub Actions** | CLI, GitHub Action | Detect new threats from diagram diffs and block the PR; ask for reviews with execution triggers | [Integrating with AI-Driven Development CI](ci-integration.md) |
| **Kong AI Gateway** | Configuration import (decK kong.yaml, AI Gateway 2.x kongctl declarative file) | Generate the diagram from configuration; watch for new threats from configuration changes in PRs | [Threat Modeling Kong AI Gateway](kong-ai-gateway.md) |
| **Postman** (Postman CLI, Newman) | Export of verification requests (Collection v2.1) | Check whether detected threats hold in the implementation and keep the checks as CI regression tests | [Verifying Threats with Postman](postman.md) |
| **MITRE ATT&CK Navigator** (BAS, CTEM, and SOC tools that import layers) | Export of a Navigator layer (JSON) | Hand over the techniques to emulate on an attack scenario's routes, and confirm the routes cut on the diagram are also closed on the live system | [Where to cut the attack path](agentic-attacker-paths.md) (§6) |
| **Salesforce Agentforce** | Dedicated stencils, threat rules, and template | Assess a Service agent setup; watch agent-definition changes in PRs | [Threat Modeling Salesforce Agentforce](agentforce.md) |
| **Okta** | MCP (side by side, through the agent), dedicated stencils and threat rules | Cross-check diagram NHIs against existing service apps; confirm identity strength from the authentication method; find unused NHIs | [Threat Modeling NHIs and Identity Platforms](nhi-identity.md) |
| **SailPoint** | MCP (side by side, through the agent), IGA stencil and threat rules | Find the least access that can be requested instead of excessive permissions | [Threat Modeling NHIs and Identity Platforms](nhi-identity.md) |
| **CyberArk (Idira)** | Conjur policy import, MCP (side by side, through the agent), PAM stencil and threat rules | Draft a diagram of NHIs and secret read paths from the policy; cross-check diagram NHIs against Secrets Manager workloads | [Threat Modeling NHIs and Identity Platforms](nhi-identity.md) |
| **ScopeSentry** | Export import (Export JSON), API import (MCP, read-only) | Generate an exposure diagram from your own ASM assets, vulnerabilities, and takeover reports; assess subdomain takeover; catch new exposure by diffing periodic imports | [Turning ScopeSentry Results into a Diagram](scopesentry.md) |
| **Shodan** | Export import (`shodan download` .json.gz) | Generate a diagram of exposed services; catch newly opened ports by diffing against the previous import; reduce exposure along CISA's four steps | [Reducing Internet Exposure](exposure-reduction.md) |
| **Anthropic `defending-code-reference-harness`** | `THREAT_MODEL.md`-compatible export | Use the threat model as input to an AI-driven vulnerability review | [Turning Your Threat Model into a Security Context](security-context.md) |
| **Veracode** | Example setup (Veracode CLI and Findings API combined with `THREAT_MODEL.md`, `findings-report`, and the Postman export) | Build the threat model into a flow that fixes SAST and DAST findings with AI, as context, prioritization, and regression tests; use the Postman export as the DAST scan scope | [Fixing Veracode Findings with AI](veracode-remediation.md) |
| **Prowler** | Findings import (`import-prowler`; OCSF output of AWS checks, CLI only) | Replace "assumed because unset" posture and attack surface attributes with measurements; cross-check FAIL checks against the threats on the diagram | [Putting Prowler Findings on the Diagram](prowler.md) |
| **Trivy** | Results import (vulnerabilities as CycloneDX via `import-sbom`; IaC misconfigurations and secrets as SARIF via `import-sarif`; CLI only) | Link dependency vulnerabilities to nodes as components and prioritize them by KEV and attack paths; keep misconfigurations and secrets as findings on nodes | [Vulnerability Management with OSS Scanners](oss-vulnerability-management.md) |
| **Syft / Grype** | SBOM and vulnerability import (CycloneDX via `import-sbom`; CLI only) | Keep Syft SBOMs as the component inventory; link Grype vulnerabilities to components and prioritize them by KEV and attack paths | [Vulnerability Management with OSS Scanners](oss-vulnerability-management.md) §8 |
| **ZAP** | Results import (the Automation Framework `sarif-json` report via `import-sarif`; CLI only) | Map findings on running applications to threats on the diagram through the CWE mapping | [Vulnerability Management with OSS Scanners](oss-vulnerability-management.md) §5 |
| **Nuclei** | Results import (`import-nuclei`; JSONL / JSON; CLI only) | Prioritize CVE findings by KEV and attack paths; map CWE findings to threats on the diagram | [Vulnerability Management with OSS Scanners](oss-vulnerability-management.md) §6 |
| **Strix** | Result conversion (`convert-strix`: findings.sarif → penetration-test registry YAML → `import-pentest`; CLI only) and context hand-over (RoE and THREAT_MODEL.md via `--instruction-file`; the CRS MCP server registered with read tools only) | Show results confirmed with PoCs as "Verified by Strix" on threat cards; let Strix look up the threat model during the assessment | [Vulnerability Management with OSS Scanners](oss-vulnerability-management.md) §7 |
| **Metasploit** | Export conversion and import (`db_export -f xml` via `convert-metasploit` → `import-pentest`; hosts and services via `import-metasploit-assets`; CLI only) | Show exploited vulnerabilities as "verified" on threat cards; put hosts and services in the Asset tab | [Vulnerability Management with OSS Scanners](oss-vulnerability-management.md) §9 |
| **CyberStrikeAI** | Vulnerability conversion (`convert-cyberstrikeai`: a saved API response JSON, or the API (GET only; token in an environment variable) → penetration-test registry YAML → `import-pentest`) and asset import (`import-aipentest-assets --format cyberstrikeai`, shown in the Asset tab; CLI only) | Show vulnerabilities that a person marked confirmed in autonomous AI penetration testing as "verified" on threat cards. A person decides the threat and node in the registry | [Vulnerability Management with OSS Scanners](oss-vulnerability-management.md) §4 |
| **CycloneDX and SPDX** | Component import (`import-sbom`; CLI only) and export (`export-spdx` and `export-sbom-ai`; also from the screen) | Link SBOM, CBOM, and AI BOM components to nodes, check them in the Asset tab, and export them in standard formats ([guide](sbom.md)) |
| **Cisco AI Defense** (skill-scanner / mcp-scanner) | Findings cross-reference (`findings-report --skill-scanner / --mcp-scanner`; result files, CLI only) | Cross-reference agent skill and MCP server scan results with the diagram's threats through an AITech mapping table; find what is left undrawn | [Cross-Reference Agent Skill and MCP Server Scan Results with the Threat Model](ai-scanners.md) |
| **Cloudflare security-audit** (skill) | Findings import (`findings.json` and `coverage-ledger.json`; screen and CLI `import-security-audit`) | Show findings confirmed in the source and needs-confirmation findings that depend on the deployment on threat cards, and line up their preconditions with the diagram's facts | [Putting AI Source-Audit Findings on the Diagram](security-audit.md) |
| **Velociraptor** | Importing collections (extracted folders), artifact hints in the investigation plan, and the EDR / DFIR server stencil and threat rules | When you suspect a compromise, decide which artifacts to collect on the nodes along the attack routes, and overlay the collections on the nodes as a report | [Scoping and reporting a suspected-compromise investigation](compromise-investigation.md) |

---

## Choose by goal

| You want to | Use |
|---|---|
| Have an AI agent help with threat modeling | MCP (Claude Code, GitHub Copilot, Cursor) |
| Catch missed threat-model updates in PRs | GitHub Actions |
| Draw the diagram from existing configuration | Kong AI Gateway, CyberArk (Idira) Conjur, Shodan, ScopeSentry, a Claude Code working directory (`import-repo`) |
| Confirm that the threats you flagged are actually closed | Postman |
| Scope and focus a penetration test | Test plan export ([guide](pentest-plan.md); any provider) |
| Emulate the attack routes cut on the diagram with BAS | ATT&CK Navigator layer export ([guide](agentic-attacker-paths.md) §6) |
| Declare the permitted scope before running an AI pentesting tool yourself | Rules of engagement (RoE) / scope declaration export ([guide](agentic-pentest-operation.md) §5) |
| Assess a product-specific setup as is | Salesforce Agentforce |
| Surface the risks of NHIs such as service accounts and AI agents | Okta, SailPoint, CyberArk (Idira) |
| Inventory and reduce what is exposed to the internet | Shodan |
| Put the threat model to work in vulnerability review | Anthropic `defending-code-reference-harness`, Snyk |
| Build a flow that fixes vulnerability findings with AI | Veracode |
| Reflect cloud scan results (AWS) in the diagram's attributes | Prowler |
| Manage the results of OSS assessment tools with priorities based on attack paths | Trivy, Syft / Grype, ZAP, Nuclei, CyberStrikeAI, Strix, Metasploit ([guide](oss-vulnerability-management.md)) |
| Put attack techniques that actually worked in a penetration test on threat cards | Strix, CyberStrikeAI, Metasploit ([guide](oss-vulnerability-management.md)) |
| Cross-reference agent skill / MCP server scan results with the diagram | Cisco AI Defense (skill-scanner / mcp-scanner) |
| Put AI source-audit findings on the diagram, separating verified from needs-confirmation | Cloudflare security-audit |
| Decide where to look and report the results when you suspect a compromise | Velociraptor and the bundled triage script ([guide](compromise-investigation.md)) |

---

## What to read next

- Get the big picture — [Getting Started](getting-started.md)
- Connect over MCP — [Using It from Coding Agents](mcp-integration.md)
- All guide pages — [CyberRiskScape Guide](README.md)
