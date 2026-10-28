# Threat Modeling Kong AI Gateway — Draft a Diagram from Your decK or kongctl Configuration

**English** | [日本語](kong-ai-gateway.ja.md)

> Kong is a trademark of Kong Inc. This page explains how to threat-model a Kong Gateway setup with
> CyberRiskScape; it is not provided, certified, or endorsed by Kong Inc. Plugin names and configuration
> formats follow the official documentation at the time of writing (October 2026). Check the linked official
> sources for the latest information.

---

## 1. What this page covers and prerequisites

- How to **draft a diagram automatically** from a Kong Gateway declarative configuration (decK `kong.yaml`),
  from the UI or the CLI
- Which parts of the configuration become which CyberRiskScape component types and connection attributes
- The threats **actually detected** on the generated diagram, and the threats worth watching in an AI Gateway setup
- Watching `kong.yaml` changes in a PR and failing CI when new threats appear
- What this import **cannot tell** (attributes you need to fill in on the diagram)
- Drafting a diagram from an AI Gateway 2.x kongctl declarative file (§7)

**Background: Kong Gateway and decK** (per the official documentation at the time of writing)

- Kong Gateway is an API gateway built from **Services** (upstream APIs), **Routes** (which requests go to which
  Service), **Plugins** (authentication, rate limiting, logging and so on), and **Consumers** (API users).
- **decK** is the official tool for managing this configuration declaratively in a file (`kong.yaml`). Plugins are
  either written at the top level with `service:` / `route:` pointing at their target, or nested under a Service
  or Route ([source 1](#references)).
- **Kong AI Gateway** is the name for the set of AI plugins: `ai-proxy` (connecting to LLM providers), guard plugins
  such as `ai-prompt-guard`, `ai-rag-injector` (RAG), `ai-mcp-proxy` (MCP), and more ([source 2](#references)).

**Background: AI Gateway 2.x and kongctl** (per the official documentation at the time of writing)

- Kong AI Gateway was reworked as 2.x, and configuration management moved from decK (Services, Routes, Plugins)
  to **kongctl** (the AI Gateway entities on Konnect: AI Model, Model Provider, MCP Server, Agent, Policy,
  Auth Strategy and more) ([source 6](#references), [7](#references), [8](#references)). Everything above describes
  the decK (1.x) form. Importing 2.x is covered in §7.
- Which import to use depends on the configuration file you have ([source 9](#references)).

| Your configuration | Import to use |
|---|---|
| 1.x / Kong Gateway decK `kong.yaml` | **"Select Kong config (decK)"** in the UI, `import-kong` in the CLI (§3) |
| 2.x kongctl declarative file (`ai_gateways` and so on) | **"Select Kong config (kongctl)"** in the UI, `import-kongctl` in the CLI (§7) |
| kongctl driving decK (`control_planes[]._deck.files`) | Pass the **decK files** that `_deck.files` points to to `import-kong`. Passing a kongctl file that has only `control_planes` to `import-kongctl` produces an error saying so |

**Assumed knowledge**: the basic operations in [Getting Started](getting-started.md) and the import steps in
[Creating and Using Templates](templates.md).

---

## 2. Mapping the configuration to CyberRiskScape types

The import **only translates the configuration into diagram elements**. Threats are detected by the same threat
rules as any other diagram.

| kong.yaml element | CyberRiskScape type / attribute | Notes |
|---|---|---|
| Kong Gateway itself | `GATEWAY` (API gateway) / `AI_GATEWAY` | Services that use AI plugins go through the AI Gateway, the rest through the API gateway. If both exist, two gateways are drawn |
| Admin API (management plane) | `API_CONTROL_PLANE` (API control plane) | Always drawn — a configuration file implies a management plane |
| Service (ordinary API) | `BACKEND_API` (Backend API) | Named after the Service. An https upstream URL means encrypted, http means plaintext |
| Service + `ai-proxy` | `LLM` | Named "provider / model". External providers such as OpenAI sit on the internet side (an Internet boundary); ollama, vllm and llama sit inside the organization |
| Service + `ai-proxy-advanced` | `LLM` (one per target) | Each load-balancing target becomes its own LLM |
| Service + `ai-mcp-proxy` | `MCP_SERVER` (MCP server) | |
| Service + `ai-a2a-proxy` | `AGENT` (AI agent) | |
| `ai-rag-injector` | `DB` (Vector DB / RAG) | Drawn as a retrieval path into the LLM (`semantic: rag_retrieval`) |
| Guard plugins | `GUARDRAIL` (Guardrail) | `ai-prompt-guard`, `ai-semantic-prompt-guard`, `ai-semantic-response-guard`, `ai-sanitizer`, `ai-lakera-guard`, `ai-azure-content-safety`, `ai-aws-guardrails`, `ai-gcp-model-armor`, `ai-custom-guardrail` |
| `vaults` / `{vault://…}` references | `SECRETS_VAULT` (Secrets manager) | |
| Authentication plugins | "Authentication" on the client → gateway connection | `key-auth`, `basic-auth`, `hmac-auth`, `jwt`, `oauth2`, `openid-connect`, `ldap-auth`, `mtls-auth` and others. The method is set per plugin: `key-auth` and `hmac-auth` → API key, `basic-auth` and `ldap-auth` → ID/password, `jwt`, `oauth2` and `openid-connect` → token, `mtls-auth` → certificate (§8) |
| Route `protocols` | "Encryption" on the client → gateway connection | Plaintext if any Route allows `http` |
| `ip-restriction` and logging plugins | Attack-surface attributes of the API gateway | Set source-IP restriction and access logging to "yes" |
| Consumers | Not drawn | Only the count is shown; credentials are not read |

**Secrets are not read.** Only names, types, host names and model names are extracted. Authentication header
values, consumer API keys, and the user name, password and query in URLs never reach the diagram.

**The client → gateway connection is drawn once**, using the **weakest authentication** among the Services
reachable through Routes. Per-Service authentication is listed in the gateway's description.

---

## 3. How to import

### 3.1 From the UI

1. Open **Template** in the left sidebar and choose the **Import** tab.
2. Press **"Select Kong config (decK)"** and choose `kong.yaml` (or JSON).
3. The counts for the generated diagram and the source configuration (services, routes, plugins, consumers)
   are shown. Press **"Apply"** to replace the active layer with the generated diagram (Undo restores it).

![Importing a Kong configuration](../assets/guide/kong/01-import.png)

A sample to try is in [`templates/kong-ai-gateway.yaml`](templates/kong-ai-gateway.yaml) (it contains no real
credentials; the API key is a vault reference).

### 3.2 From the CLI

```bash
npm ci && npm run build:cli
node dist-cli/main.js import-kong kong.yaml --out model.json
node dist-cli/main.js analyze model.json --format md
```

`import-kong` writes a project JSON with the diagram on L1. You can open it with "File (Save / Open)" in the UI
or pass it straight to `analyze` and `diff`. For the CLI in general, see
[Integrating with AI-Driven Development CI](ci-integration.md).

---

## 4. Example of a generated diagram

The sample configuration has three Services: an ordinary API protected by OpenID Connect (`orders-api`), a
support chat that connects to OpenAI through `ai-proxy` (`support-chat`, with `key-auth`, `ai-prompt-guard` and
`ai-rag-injector`), and `internal-tools`, which exposes internal tools over MCP (no authentication, http allowed).

![Diagram generated from a Kong configuration](../assets/guide/kong/02-overview.png)

This sample produces **74 threats** (9 Critical, 40 High, 25 Medium) at the time of writing.

### 4.1 Assumptions on the diagram (attributes to review after importing)

- **The API gateway's global IP, WAF, DDoS protection and management-plane restrictions** cannot be read from
  `kong.yaml`, so they are left unset (assumed insecure). Set the gateway's attributes to match your environment.
- **Authentication strength**: if OIDC enforces MFA, raise the client → gateway connection to "MFA".
- **Connections to backends** are drawn as "internal network, no authentication" (the common setup that trusts
  traffic forwarded by the gateway). Change them if you use mutual TLS or similar.

---

## 5. Threats worth watching

### 5.1 Routes without authentication and plaintext paths

The `internal-tools` Route has no authentication plugin and allows `http`. Because the weakest path is used,
the client → AI Gateway connection becomes "no authentication, plaintext, over the internet".

| Threat | Severity | Element |
|---|---|---|
| Unauthenticated public-network path (`stride-edge-unauth-internet-001`) | Critical | Client → AI Gateway |
| Plaintext communication (`stride-edge-plain-encryption-001`) | High | Same, and AI Gateway → `internal-tools` |

One missing setting on one Route lowers the assessment for every path through the same gateway. This is
"one added line of configuration widens the attack surface" in action, and exactly where the CI watch in §6 helps.

### 5.2 Internal tools exposed over MCP

A Service with `ai-mcp-proxy` is drawn as an MCP server, and MCP-specific threats appear.

| Threat | Severity |
|---|---|
| Tool descriptor poisoning / line jumping (`mcp-tool-descriptor-poisoning-001`) | Critical |
| MCP server impersonation / typosquatting (`mcp-server-impersonation-typosquatting-001`) | High |

![Threats on the MCP server](../assets/guide/kong/03-mcp.png)

### 5.3 Guardrails are a probabilistic defense

`ai-prompt-guard` is drawn as a guardrail. Even with the guardrail, direct and indirect prompt injection
(`owasp-llm01-prompt-injection-001`, `atlas-aml-t0051-indirect-prompt-injection-001`) remain on the LLM. The
guardrail itself also gets a threat for "relying on it alone can be bypassed".

| Threat | Severity |
|---|---|
| Single reliance on a guardrail (limits of probabilistic defense) (`zt-guardrail-probabilistic-bypass-001`) | Medium |

![Threat on the guardrail](../assets/guide/kong/05-guardrail.png)

> **Note** — The current threat rules do not mark LLM threats as mitigated just because a guardrail is present.
> A regex deny list (`ai-prompt-guard`) can be bypassed by rephrasing, so leaving the threats open is the safer
> assessment. Record what you have implemented under "Control status" on the threat card.

### 5.4 Provenance of documents injected by RAG

`ai-rag-injector` is drawn as a retrieval path from the vector DB into the LLM, so the path by which instructions
planted in retrieved documents reach the LLM is assessed.

| Threat | Severity |
|---|---|
| Missing provenance / signature checks on RAG documents (`agentic-rag-retrieval-provenance-gap-001`) | High |
| Vector and embedding weaknesses (`owasp-llm08-vector-embedding-weaknesses-001`) | High |

### 5.5 Control plane and secrets manager

Whoever obtains Admin API credentials can rewrite authentication and routing for every API under management.
The vault is where API keys are concentrated.

| Threat | Severity | Element |
|---|---|---|
| Configuration tampering in the API control plane (`api-control-plane-config-tampering-001`) | High | API control plane |
| Remote access to the management plane (`api-control-plane-internet-exposure-001`) | Critical | When a connection from the internet side to the control plane is drawn |
| Concentration of privilege in the secrets manager (`api-secrets-vault-concentration-001`) | High | Secrets manager |

![Threat on the control plane](../assets/guide/kong/04-control-plane.png)

### 5.6 Backend authorization and the gateway

| Threat | Severity | Element |
|---|---|---|
| Broken object and property level authorization (BOLA / BOPLA) (`api-backend-object-level-authorization-001`) | High | Backend API |
| Authorization boundary gaps (`stride-gateway-elevation-of-privilege-001`) | High | API gateway |
| Log concentration in the AI Gateway (`zt-ai-gateway-log-concentration-001`) | Medium | AI Gateway |

A gateway can validate tokens and scopes, but it does not know **who owns a record**. That BOLA can only be
checked in the backend is a natural discussion point for a design review.

---

## 6. Use case: watching kong.yaml changes in a PR

If your decK configuration is in Git, you can build a diagram from the configuration before and after each PR and
gate on **newly introduced threats** only.

```bash
# Build a project JSON from the configuration before (main) and after (the PR)
git show origin/main:kong.yaml > base-kong.yaml
node dist-cli/main.js import-kong base-kong.yaml --out base.json
node dist-cli/main.js import-kong kong.yaml --out head.json

# Exit 1 (block the PR) if there are new threats of High or above
node dist-cli/main.js diff base.json head.json --format md --fail-on High --out result.md
```

Element IDs are derived from Service names and the like, so adding a Service does not change the identity of
existing elements. For example, adding a Service that connects to an external LLM (Anthropic via `ai-proxy`) lists
the added threats and flags the execution triggers **T1 (new trust boundary), T6 (new third-party integration) and
T8 (change to models, training data or RAG sources)**. For wiring this into GitHub Actions, see
[Integrating with AI-Driven Development CI](ci-integration.md).

---

## 7. Importing from AI Gateway 2.x (kongctl)

AI Gateway 2.x is declared with **entities** (AI Model, Model Provider, MCP Server, Agent, Policy, Auth Strategy and
so on) instead of plugins. You can read a kongctl declarative file and draft a diagram in the same way. Threats are
detected by the same threat rules as any other diagram.

### 7.1 Mapping kongctl entities to types

| kongctl element | CyberRiskScape type / attribute | Notes |
|---|---|---|
| Gateway (`ai_gateways[]`) | `AI_GATEWAY` (AI Gateway) | Placed inside the organization regardless of `deployment_type`. The description records `deployment_type` and the `proxy_urls` hosts |
| Konnect (management plane) | `API_CONTROL_PLANE` (API control plane) | Kong's SaaS, so it sits on the internet side. It connects to the gateway with mTLS using the data plane certificate, so authentication is "certificate" |
| Model `targets` | `LLM` (LLM model) | One per target, named "provider / model". ollama, vllm and llama2 sit inside the organization; the rest on the internet side |
| MCP server: `passthrough-listener`, `upstream-server` | `MCP_SERVER` (MCP server) | Placed behind the gateway |
| MCP server: `conversion-listener` | `MCP_SERVER` (served by Kong) + `BACKEND_API` (Backend API) | Kong itself serves the REST API as MCP. The REST API behind it is drawn separately |
| MCP server: `listener` | `MCP_SERVER` (served by Kong) | Connections are drawn to the MCP servers named in `sources` |
| MCP server: `conversion-only` | `BACKEND_API` | When referenced from a `listener`'s `sources`, it is connected from the listener |
| Agent | `AGENT` (AI agent) | Placed behind the gateway |
| Where an upstream is placed | Decided by the host in `config.url` | `localhost`, private IPs, host names without a dot, and names ending in `.internal`, `.local`, `.svc`, `.cluster.local`, `.lan` or `.corp` are inside the organization; everything else is on the internet side. With no URL, inside and plaintext are assumed |
| Guard policies | `GUARDRAIL` (Guardrail) | Same list as §2. Only policies that are **enabled** and either `global: true` or attached through some entity's `policies` |
| `config.llm` of `ai-request-transformer` / `ai-response-transformer` | `LLM` | Drawn as the model called for the transformation |
| vectordb (model `config.balancer`, policy `config.vectordb`) | `DB` (Vector DB / RAG) | The label carries the strategy (redis, pgvector) |
| `ai_gateway_vaults`, `{vault://…}` references | `SECRETS_VAULT` (Secrets manager) | |
| Auth strategy | "Authentication" on the client → gateway connection | `key-auth` → API key, `openid-connect` → token. An entity with none attached has **no authentication**. The **weakest** among the published entities (models, agents, Kong-served MCP, `passthrough-listener`) is used for the single connection; per-entity authentication is listed in the gateway's description |
| `proxy_urls` `protocol` | "Encryption" on the client → gateway connection | Encrypted if all are https. If any is http, or `proxy_urls` is missing, **plaintext is assumed** and the description says so |
| Consumers | Not drawn | Only the count is shown |

- Child entities (`ai_gateway_models` and so on) are read in **both** forms: at the top level with `ai_gateway:`
  pointing at the parent, and nested under `ai_gateways[]`.
- **The contents of `!secret` and `!env` are not read.** Provider `config.auth`, an auth strategy's `client_id` /
  `client_secret`, upstream authentication values and consumer credentials never reach the diagram. URLs are used
  only for their host name and scheme.

### 7.2 How to import

**From the UI**: open **Template** in the left sidebar, choose the **Import** tab, press **"Select Kong config
(kongctl)"** and choose the declarative file (YAML). The counts of gateways, models, MCP servers, agents, policies and
consumers are shown; press **"Apply"** to replace the active layer with the generated diagram (Undo restores it).

**From the CLI**:

```bash
npm ci && npm run build:cli
node dist-cli/main.js import-kongctl ai-gateway.yaml --out model.json
node dist-cli/main.js analyze model.json --format md
```

You can also export the declarative file from an existing AI Gateway with kongctl (CyberRiskScape itself does not
call the Konnect API). The following is the example from the official documentation ([source 7](#references)). To also
diagram MCP servers, agents, policies and so on, add the corresponding resources to `--resources` (check the accepted
names with `kongctl dump declarative --help`).

```bash
kongctl dump declarative \
  --default-namespace my-namespace \
  --resources ai_gateways,ai_gateway_models,ai_gateway_model_providers \
  --pat "$KONNECT_TOKEN" > ai-gateway.yaml
```

A sample to try is in [`templates/kong-ai-gateway-v2.yaml`](templates/kong-ai-gateway-v2.yaml) (it contains no real
credentials; every secret is a placeholder read from an environment variable).

### 7.3 The sample diagram

The sample has these entities:

- A chat model `chat` that lists OpenAI and ollama side by side (OpenID Connect, with `ai-prompt-guard`)
- `orders-tools`, which converts a REST API into MCP tools (API key)
- `docs-mcp`, which passes through to an external MCP server (no client-side auth strategy; it connects to the upstream MCP server with a token)
- `support-agent` with **no auth strategy attached** (an example of exposure without authentication)
- A guardrail (`ai-prompt-guard`) and a global semantic cache (vector DB: redis)

This sample produces **113 threats** (25 Critical, 59 High, 29 Medium) in §4 of the CLI's `analyze --format md`
at the time of writing.

**Attributes to review after importing**

- **Managed / serverless gateways**: the data plane runs in Kong's cloud, so it is no longer inside your
  organization. Check `deployment_type` (shown in the description) and revisit which boundary the gateway sits in
- **Authentication strength**: if OIDC enforces MFA, raise the client → gateway connection to "MFA"
- **Connections to Kong-served MCP** are drawn as "no authentication, inside the organization", treating them as
  the same process as the gateway
- **Connections to upstreams**: authentication from the gateway to a backend (such as mutual TLS) is assumed to be
  API-key-equivalent if `config.upstream.auth` exists and none otherwise. Change it to match reality

### 7.4 Use case: watching kongctl declarative file changes in a PR

The flow is the same as §6. Element IDs are derived from names, so adding an entity does not change the identity of
existing elements.

```bash
# Build a project JSON from the declarative file before (main) and after (the PR)
git show origin/main:ai-gateway.yaml > base-ai-gateway.yaml
node dist-cli/main.js import-kongctl base-ai-gateway.yaml --out base.json
node dist-cli/main.js import-kongctl ai-gateway.yaml --out head.json

# Exit 1 (block the PR) if there are new threats of High or above
node dist-cli/main.js diff base.json head.json --format md --fail-on High --out result.md
```

---

## 8. Limitations

- **A plugin does not make a threat "mitigated".** The import only builds the diagram; control status is not set
  automatically
- **Authentication strength is estimated conservatively.** The method comes from the plugin type, and when one service has several
  authentication plugins the weakest is used. Whether MFA or passkeys are required depends on the IdP and cannot be read
  from `kong.yaml`, so the diagram does not show it
- **The client → gateway connection is a single edge** assessed at the weakest Route. If you need per-Route
  assessment, split the client on the diagram and redraw the connections
- **The gateway's global IP, WAF, DDoS protection and management-plane restrictions are unknown** (§4.1). The
  Kong Konnect API is not called
- One file is read. If your configuration is split across several decK files, merge them first (for example with
  `deck file merge`)
- Consumers, Upstreams (load-balancing targets) and Workspaces are not drawn
- The automatic layout is simple and connections may cross. Tidy the layout as needed
- Plugin names and configuration formats follow the official documentation at the time of writing. Plugins the
  import does not know are simply ignored
- **Limits of the 2.x (kongctl) import**
  - The documentation at the time of writing has no field for the destination URL of a self-hosted LLM, so whether
    one is inside the organization is decided by the provider type alone (ollama, vllm or llama2)
  - References that point by id, such as `!lookup {id: …}`, cannot be resolved: a parent gateway falls back to the
    first gateway, and other references are treated as unresolved
  - A policy's `condition` (CEL) and per-consumer scoping are not read
  - The gateway is placed inside the organization regardless of `deployment_type` (§7.3)

---

## References

1. decK (Kong's declarative configuration tool) — getting started — <https://developer.konghq.com/deck/get-started/>
2. Kong AI plugins — <https://developer.konghq.com/plugins/?category=ai>
3. AI Proxy plugin — <https://developer.konghq.com/plugins/ai-proxy/>
4. OWASP API Security Top 10 2023 — <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
5. OWASP Top 10 for LLM Applications 2025 — <https://genai.owasp.org/llm-top-10/>
6. AI Gateway 2.x concepts — <https://developer.konghq.com/ai-gateway/ai-gateway-v2-concepts/>
7. Managing AI Gateway with kongctl — <https://developer.konghq.com/ai-gateway/kongctl/>
8. AI Gateway entities — <https://developer.konghq.com/ai-gateway/entities/>
9. kongctl and decK — <https://developer.konghq.com/kongctl/kongctl-and-deck/>

---

## What to read next

- How to read detected threats — [Reading the Threat Panel](reading-threats.md)
- Finding where to defend along paths — [Attack Path Analysis](attack-paths.md)
- Requiring diagram updates in PRs — [Integrating with AI-Driven Development CI](ci-integration.md)
- The same flow for another product — [Threat Modeling Salesforce Agentforce](agentforce.md)
