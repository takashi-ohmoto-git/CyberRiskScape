# CyberRiskScape Guide

**English** | [日本語](README.ja.md)

Documentation for people using CyberRiskScape. For the project overview, the feature list and how
to build it, see the [repository README](../README.md).

Nothing here needs to be installed — you can follow along in the
[live demo](https://takashi-ohmoto-git.github.io/CyberRiskScape/).

## Pages

| Page | What it covers |
|---|---|
| **[Getting Started](getting-started.md)** | What the tool does, what you would use it for, how the screen is laid out, and every canvas operation — placing components, drawing connections and trust boundaries, zooming and panning — with screenshots |
| **[Your First Threat Model](first-threat-model.md)** | A full walkthrough using an AI chatbot: creating a project, choosing a depth layer, placing components, connecting them and setting trust boundaries |
| **[Creating and Using Templates](templates.md)** | Exporting and importing diagrams as JSON, plus the AI chatbot template this guide uses |
| **[Reading the Threat Panel](reading-threats.md)** | How to read what was detected, prioritize with a risk score, record your treatment decisions, and export the result |
| **[Assessing Risk in Analytics](analytics-assessment.md)** | Scoring risk and recording risk treatment and control implementation status, all on one screen |
| **[Exporting PDF Reports and Diagram Images](report-export.md)** | Producing a PDF report for a CISO or executives (one-page summary, top 10, per-layer appendix) and PNG images of the diagram, and how to read the indicators |
| **[Supporting PQC Migration](pqc-migration.md)** | Drawing a design on the PQC layer, splitting a path into segments at the nodes that terminate or decrypt encryption, reading each segment's termination verdict, likelihood and PQC verdict, and exporting a simple CSV report as candidate rows for a cryptographic inventory |
| **[Attack Path Analysis](attack-paths.md)** | Enumerate the routes from attacker to target and find the choke points where one control covers the most routes |
| **[The Compliance Map](compliance-map.md)** | Check how threats map to NIST CSF, the NIST AI RMF and Japan's AI Business Operator Guidelines, from either direction |
| **[Turning Your Threat Model into an AI-Readable Security Context](security-context.md)** | Exporting a finished threat model as Markdown, using it as the input to an AI vulnerability review, and why that works |
| **[Integrations](integrations.md)** | The products you can integrate with (Claude Code, GitHub Copilot, Cursor, Snyk, GitHub Actions, Kong, Postman, Salesforce Agentforce, and more), how they connect (MCP, files and the CLI), and their use cases — the entry point to each product page |
| **[Integrating with AI-Driven Development CI](ci-integration.md)** | Treating a saved project JSON as a source-of-record file: the headless CLI, the GitHub Action, trigger-based review, CODEOWNERS and branch protection, and running on a closed network |
| **[Using It from Coding Agents](mcp-integration.md)** | Setting up the MCP server so that Claude Code, GitHub Copilot and other agents can query threats and update the diagram: client configuration, the tools, safeguards, and how it pairs with the PR gate |
| **[MCP Use Cases](mcp-use-cases.md)** | MCP in practice, by scenario: early-design research, turning key threats into tasks, checking the impact of a new component, self-review before a PR, using it with GitHub Copilot and Cursor, pairing with Snyk, and deciding what to allow |
| **[Threat Modeling Salesforce Agentforce](agentforce.md)** | Mapping Agentforce building blocks to CyberRiskScape types, a diagram template for a customer-facing Service agent, the threats worth watching (such as ForcedLeak-style indirect prompt injection through externally writable CRM fields), which rules fire and what is not detected, and watching agent-definition changes in a PR |
| **[Threat Modeling an SDV](sdv.md)** | Mapping SDV building blocks (ECUs, zone controllers, gateway, TCU, OBD-II, V2X, OTA, vehicle PKI) to the Vehicle (SDV) types, a zonal-architecture diagram template, the 19 rules based on UN R155 Annex 5 and their threat-number mapping, reading attack paths from the TCU or OBD-II port to driving-critical ECUs, the link to PQC migration (firmware signatures, termination verdicts), and the limits (not a substitute for type approval or a TARA) |
| **[Threat Modeling Kong AI Gateway](kong-ai-gateway.md)** | Drafting a diagram automatically from a Kong Gateway declarative configuration (decK kong.yaml) in the UI or CLI, how the configuration maps to types, the threats worth watching in an AI Gateway setup (Routes without authentication, tools exposed over MCP, the limits of guardrails, RAG, the control plane), and watching kong.yaml changes in a PR |
| **[Threat Modeling NHIs and Identity Platforms](nhi-identity.md)** | How to draw service accounts, workload identities, OAuth clients, RPA bots, privileged access management (PAM) and identity governance (IGA), the threats based on the OWASP NHI Top 10, and pairing with the Okta, SailPoint and CyberArk (Idira) MCP servers to cross-check the diagram against the real state of your identities |
| **[Reducing Internet Exposure](exposure-reduction.md)** | Following the four steps of CISA's Internet Exposure Reduction Guidance (assess, decide what must stay exposed, reduce risk, reassess regularly): draw the exposures you find with Shodan and Censys (web, VPN, RDP, databases, local LLMs; generated automatically from a Shodan export), show the effect as the difference in threats before and after, and catch exposures that come back with the CLI |
| **[Checking IPA's October 2026 Alert with a Membership-Site Diagram](ipa-alert-2026-10.md)** | Taking the 17 measures in IPA's alert on unauthorized-access incidents (public-facing applications, external services, held data) and checking them one by one on a simple membership site (front-end server, web form, payment API): what to look at in the diagram and what to enter, recording operational posture (log retention, encryption at rest, patches, account review, data held, last review date), listing the state of the 17 items in the alert checklist (screen, CSV, CLI), seeing the statuses change after remediation, and keeping it up to date (review dates, CI) |
| **[Verifying Threats with Postman](postman.md)** | Exporting check requests as a Postman Collection for the detected threats that can be verified over HTTP (no authentication, plaintext, BOLA, BFLA, rate limiting, management plane, prompt injection, system prompt disclosure, MCP tool descriptors), and running them in Postman, the Postman CLI or Newman to confirm countermeasures |
| **[Secure by Design and Threat Modeling in AI-Driven Development](ai-driven-development.md)** | How to run the threat model as a source of record that AI reads and writes and people decide on, in development where AI handles design, implementation and review; what CyberRiskScape enables at each stage (planning, design, implementation, review, verification, assessment, operations); threat modeling AI itself; where the line between AI and people sits; and a staged rollout. A map to the other guides |
| **[An Introduction to Secure by Design](secure-by-design.md)** | The thinking behind the tool: what Secure by Design means, why it is being asked for now, the four roles threat modeling plays, and CyberRiskScape as a Security Context Layer that executives, planners, security, audit and CI all share. Based on the CISA-led joint guidance |

## Where to start

- **You want to try the tool** — start with [Getting Started](getting-started.md).
- **You want to build one end to end** — go to [Your First Threat Model](first-threat-model.md).
- **You would rather skip the drawing** — import the [template](templates.md).
- **You have a diagram but do not know what to do with the findings** — read [Reading the Threat Panel](reading-threats.md).
- **You need to assess and record the findings** — see [Assessing Risk in Analytics](analytics-assessment.md).
- **You need to report to a CISO or executives** — read [Exporting PDF Reports and Diagram Images](report-export.md).
- **You are in charge of PQC migration and need to find where encryption changes along a path** — read [Supporting PQC Migration](pqc-migration.md).
- **You need to decide where to start mitigating** — read [Attack Path Analysis](attack-paths.md).
- **You need to line the work up against a standard** — see [The Compliance Map](compliance-map.md).
- **You want to feed your threat model to an AI vulnerability review** —
  see [Turning Your Threat Model into an AI-Readable Security Context](security-context.md).
- **You want to wire the threat model into CI as a reviewed, source-of-record file** —
  read [Integrating with AI-Driven Development CI](ci-integration.md).
- **You want coding agents to query threats and update the diagram while they design** —
  read [Using It from Coding Agents](mcp-integration.md).
- **You want to connect other tools and products** — see [Integrations](integrations.md) for the list of products and how they connect.
- **You want to threat-model a Salesforce Agentforce setup** — read [Threat Modeling Salesforce Agentforce](agentforce.md).
- **You want to threat-model an SDV or connected-car design** — read [Threat Modeling an SDV](sdv.md). You can start from the zonal-architecture template.
- **You want to threat-model a Kong Gateway (AI Gateway) setup** — read [Threat Modeling Kong AI Gateway](kong-ai-gateway.md). You can draft the diagram from kong.yaml.
- **You want to surface the risks of NHIs such as service accounts and AI agents** — read [Threat Modeling NHIs and Identity Platforms](nhi-identity.md).
- **You want to inventory and reduce what is exposed to the internet** — read [Reducing Internet Exposure](exposure-reduction.md). You can start from Shodan and Censys results.
- **You want to check your own diagram against a published alert (the IPA alert of October 2026) and keep the state up to date** — read [Checking IPA's October 2026 Alert with a Membership-Site Diagram](ipa-alert-2026-10.md). You can start from the membership-site template.
- **You want to check whether detected threats hold in the implementation** — read [Verifying Threats with Postman](postman.md).
- **You want the big picture of keeping threat modeling going in AI-driven development** — read [Secure by Design and Threat Modeling in AI-Driven Development](ai-driven-development.md).
- **You want to explain to someone why this work matters** —
  [An Introduction to Secure by Design](secure-by-design.md) is written to be read on its own.

Every page is available in both English and Japanese; use the language links at the top of each one.

From "Your First Threat Model" onward, every chapter works on **the same AI chatbot diagram**
(round-trip flows, 56 threats), so the same components and threats carry across chapters. ("Getting Started" is the exception: it uses the
sample diagram the app opens with.)
