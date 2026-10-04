# Secure by Design and Threat Modeling in AI-Driven Development — What You Can Do with CyberRiskScape

**English** | [日本語](ai-driven-development.ja.md)

This page explains **how to keep doing Secure by Design and threat modeling** in development where AI
handles much of the design, implementation and review (AI-driven development), and **what
CyberRiskScape now lets you do** about it, following the stages of development.
Individual operations are left to each guide; this page is written as the map that connects them.

Reading [An Introduction to Secure by Design](secure-by-design.md) first will make the underlying idea easier to follow.

---

## 1. What got harder about threat modeling in AI-driven development

| Change | Effect on threat modeling |
|---|---|
| Human review cannot keep up with the speed at which AI writes code | "Draw it once at the start and stop" lets the diagram drift from reality quickly |
| AI casually adds external APIs, SaaS, MCP servers and agent tools | Trust boundaries and external interfaces multiply week by week |
| Decisions are scattered across chat logs | "Why did we design it this way?" and "which risks did we accept?" cannot be traced later |
| AI does not know the organization's own premises (what to protect, what was accepted) | AI-written code and reviews diverge from what matters to the organization |
| AI (LLMs, agents) goes inside the system | Threats that classic STRIDE alone does not catch increase: prompt injection, excessive privilege, a sprawl of NHIs and more |

In other words, the threat model has to be treated not as **a deliverable you make once**, but as
**a source of record that AI reads and writes and that people keep making decisions on**.

---

## 2. The basic idea — three roles: source of record, AI and people

CyberRiskScape is built to run the threat model with three roles.

| Role | What it does | What it is in CyberRiskScape |
|---|---|---|
| **Source of record** | Keeps the structure, the threats and the record of decisions in one place | The saved project JSON, committed to the repository. It holds the diagram, detected threats, responses, risk assessments and control implementation status |
| **AI** | Reads the source of record, proposes updates to the structure and shows the impact of a diff | The MCP server (agents look up threats and update the diagram) and the headless CLI (analysis, diff, import, export) |
| **People** | Decide which risks to accept, the priorities and whether something goes to production | The app's screens (Analytics and the threat panel) and PR review (CODEOWNERS, branch protection, the diff gate) |

It is distinctive in making clear **what is not left to AI**. Through the MCP server you can change only
the structure (nodes, edges, boundaries, attributes, annotations); you cannot change risk acceptance,
false-positive verdicts, risk assessments or control implementation status. People record these in the
app and approve them on the PR.

---

## 3. What you can do at each stage of development

### 3.1 Planning and requirements — look up threats without a diagram

| What you can do | Feature | Guide |
|---|---|---|
| Once you have decided to "use an LLM, a vector DB and external tools", have the agent look up the threats that may apply to each type | MCP `lookup_threat_rules` | [MCP Use Cases — Design, Review and Pairing with Other Tools](mcp-use-cases.md) §1 |
| Start from a common architecture (AI chatbot, Salesforce Agentforce, contact center, NHI and identity platform, external exposure) | Templates | [Creating and Using Templates](templates.md) |
| Write down at the outset what you protect and from whom (system name, purpose, business impact, security objectives; attacker and target) | Project information and attacker components | [Your First Threat Model — Drawing an AI Chatbot](first-threat-model.md) |

### 3.2 Design — build the diagram with AI and see the impact of changes right away

| What you can do | Feature | Guide |
|---|---|---|
| Have the agent update the diagram, and check the change in threats and the matching execution triggers **before writing** | MCP `apply_model_changes` (`dryRun`) | [MCP Use Cases — Design, Review and Pairing with Other Tools](mcp-use-cases.md) §3 |
| Draft a diagram from existing configuration (API gateway configuration, secrets-management policy, observed external exposure) | Imports from Kong (decK), CyberArk (Idira) Conjur and Shodan | [Threat Modeling Kong AI Gateway — Draft a Diagram from Your decK Configuration](kong-ai-gateway.md), [Threat Modeling NHIs and Identity Platforms — Pairing with Okta, SailPoint and CyberArk (Idira)](nhi-identity.md) §6, [Reducing Internet Exposure — Running CISA's Four Steps with Shodan, Censys and CyberRiskScape](exposure-reduction.md) §4.4 |
| Threats appear as soon as you draw (intrinsic threats that appear from placement alone, and path-dependent threats that appear from connection conditions) | Automatic threat detection | [Reading the Threat Panel](reading-threats.md) |

### 3.3 Implementation — make the threat model an input to AI

| What you can do | Feature | Guide |
|---|---|---|
| Have the agent turn important threats into implementation tasks | MCP `analyze_threats` and `get_threat` | [MCP Use Cases — Design, Review and Pairing with Other Tools](mcp-use-cases.md) §2 |
| Hand the threat model to AI vulnerability assessment as its premise (what you protect, what you accepted). False positives drop, and severity is recalibrated to the organization's context | `THREAT_MODEL.md`-compatible Markdown export | [Turning Your Threat Model into an AI-Readable Security Context](security-context.md) |
| Cross-check the results of code vulnerability scanning against the threat model's important threats | Use together with the Snyk MCP server | [MCP Use Cases — Design, Review and Pairing with Other Tools](mcp-use-cases.md) §7 |

### 3.4 Review — make design changes always go through human judgment

| What you can do | Feature | Guide |
|---|---|---|
| Judge on a code or IaC PR whether "the change requires a threat model update" (new trust boundary, external interface, authentication, expanded agent capability, etc.; T1–T8) | Execution triggers and the GitHub Action | [Integrating with AI-Driven Development CI — Treating the Threat Model as a Source-of-Record File](ci-integration.md) §3 |
| On a model PR, show newly appeared threats and changes to responses (acceptance and false positives are marked "approval required") in the PR comment, and block on a threshold | `diff --fail-on` and SARIF | [Integrating with AI-Driven Development CI — Treating the Threat Model as a Source-of-Record File](ci-integration.md) |
| Have the agent self-review its own changes before opening a PR | MCP `diff_models` | [MCP Use Cases — Design, Review and Pairing with Other Tools](mcp-use-cases.md) §4 |

### 3.5 Testing and verification — confirm that the threats you flagged are really closed

| What you can do | Feature | Guide |
|---|---|---|
| For threats that can be checked over HTTP (no authentication, plaintext, BOLA, BFLA, rate limiting, prompt injection, system prompt disclosure and so on), export check requests and make them regression tests in CI | Postman Collection export | [Verifying Threats with Postman — Export Check Requests from Detected Threats](postman.md) |

### 3.6 Assessment and reporting — set priorities, keep decisions and explain them

| What you can do | Feature | Guide |
|---|---|---|
| Record the risk assessment, response and control implementation status for each threat | Analytics | [Assessing Risk in Analytics](analytics-assessment.md) |
| Find where a single control covers the most attack paths (the chokepoint) | Attack path analysis | [Attack Path Analysis](attack-paths.md) |
| Show the mapping to NIST CSF, NIST AI RMF and Japan's AI Business Operator Guidelines | Compliance map | [The Compliance Map](compliance-map.md) |
| Report to the CISO and executives with a one-page summary and the top 10 | PDF report and diagram PNG | [Exporting PDF Reports and Diagram Images](report-export.md) |

### 3.7 Operations — keep finding where the diagram and reality have drifted

| What you can do | Feature | Guide |
|---|---|---|
| Draw the services exposed to the internet from observation, and detect newly opened ports from the diff against last time | Shodan import and `diff` | [Reducing Internet Exposure — Running CISA's Four Steps with Shodan, Censys and CyberRiskScape](exposure-reduction.md) |
| Cross-check the NHIs in the diagram (service accounts, OAuth clients and so on) against what actually exists in the identity platform | Use together with the Okta, SailPoint and CyberArk (Idira) MCP servers | [Threat Modeling NHIs and Identity Platforms — Pairing with Okta, SailPoint and CyberArk (Idira)](nhi-identity.md) §5 |

---

## 4. Threat-modeling AI itself

The systems you build in AI-driven development contain AI itself. CyberRiskScape handles threats specific to AI and agents alongside STRIDE.

- **You can switch the view between three perspectives**: Human Centric (STRIDE), AI / LLM and Agent-Centric.
- **Rules based on published sources**: OWASP Top 10 for LLM Applications, OWASP Agentic Security (ASI), MITRE ATLAS, CSA MAESTRO,
  Anthropic's zero trust (for AI agents), the OWASP Non-Human Identities Top 10 and others (each rule cites its source).
- **You can draw AI building blocks as types**: LLM model, AI agent, Sub-agent, MCP server, Agent memory, Vector DB / RAG,
  AI Gateway, Guardrail, and the NHIs that agents use (Service account, Workload identity, OAuth client).
- **You can declare an agent's character through attributes**: autonomy (Agency), the scope of impact on compromise (Blast Radius) and identity strength (Identity Tier).
  Unset values are evaluated as the worst case, so threats are never rated lightly unless you declare otherwise.
- **Threats decided by path are told apart**: direct prompt injection (user → LLM) and indirect injection through externally writable data (the web, email, CRM fields and so on)
  are detected separately, by the direction of the connection and the type of the peer.

---

## 5. The boundary between AI and people — what to delegate and what not to

| | Delegate to AI (agents, CI) | People do |
|---|---|---|
| Diagram | Drafts, proposed updates, imports (after checking the impact with `dryRun`) | Check that the content matches reality, and approve applying it |
| Threats | Enumeration, diffs, judging which triggers apply, summarizing important threats | Assessing severity and setting priorities |
| Decisions | — | Accepting risk, judging false positives, recording control implementation status (cannot be changed from MCP) |
| Reaching production | Block at the diff gate | Approval by CODEOWNERS and branch protection |

Safety mechanisms are built in as well.

- **No external communication.** The MCP server and CLI work even in closed networks. Integration with products only reads
  files (configuration, exports) and does not call the products' APIs.
- **The scope of reading and writing is limited.** The MCP server works only inside the directory you specify, and rejects writes whose
  version (`revision`) does not match, so it does not overwrite a file a person saved at the same time.
- **Secrets are not read.** Imports use only structural information (names, types, hostnames and so on) and discard authentication headers, credentials, banner bodies and the like.

---

## 6. Where to start — staged adoption

| Stage | What to do | What you get |
|---|---|---|
| 1. Draw one | From a template or an import, make one diagram of the target system and assess the threats in Analytics | A shared understanding of what you protect and from whom, and priorities |
| 2. Make it the source of record | Put the project JSON in the repository, and add a diff gate and CODEOWNERS to CI | Design changes always go through human judgment |
| 3. Connect AI | Register the MCP server with your coding agent | You can look up threats during design and see the impact of changes right away |
| 4. Connect the surroundings | Configuration imports, verification with Postman, Security Context export, regular assessment with Shodan | Design, implementation, verification and operations are connected by one threat model |

Stage 1 alone has value. From stage 2 on, you can meet, for threat modeling, the four conditions of "AI-driven development" set out in
[Integrating with AI-Driven Development CI — Treating the Threat Model as a Source-of-Record File](ci-integration.md)
(a process in which AI handles several stages; a source of record that is not a chat log; a designated person making the final call; and a documented process and allowed inputs).

---

## 7. Limitations

- **The threats detected are those the threat library covers.** Completeness is not guaranteed. Structures not drawn in the diagram are not assessed.
- **AI proposals and cross-checks are estimates.** For agent updates to the diagram and cross-checks against other products, verify the evidence and have a person approve.
- **This does not prove conformance with Secure by Design.** The diagram and the threat list are a starting point for an organization's effort, and are not
  a basis for claiming conformance with SSDF, the CRA or similar.
- **The CLI and MCP server evaluate only the bundled rules.** Custom rules saved in the browser are not covered.

---

## What to read next

- The idea behind it — [An Introduction to Secure by Design](secure-by-design.md)
- Build the source of record and human judgment into CI — [Integrating with AI-Driven Development CI — Treating the Threat Model as a Source-of-Record File](ci-integration.md)
- Connect to agents — [Using It from Coding Agents — MCP Server Setup Guide](mcp-integration.md)
- The list of products you can connect — [Integrations — Connecting to Your Development, API, and AI Platform Tools](integrations.md)
