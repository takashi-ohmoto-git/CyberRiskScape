# Threat Modeling Salesforce Agentforce — A Diagram Template and the Existing Rules

**English** | [日本語](agentforce.ja.md)

> Salesforce, Agentforce and Einstein are trademarks of Salesforce, Inc. This page describes how to
> threat-model an Agentforce setup in CyberRiskScape. It is not provided, certified or endorsed by
> Salesforce. Product behavior changes over time, so check the official sources linked below for the latest.

---

## 1. What this page covers, and assumptions

- How to **map** Agentforce building blocks to CyberRiskScape component types
- A **diagram template** built around a customer-facing Service agent (load it and use it as is), and the
  threats that are **actually detected** on it
- Which existing rule fires on which component for the threats worth watching in Agentforce, such as
  indirect prompt injection through CRM fields that outsiders can write to
- Two ways to use it with Git: watching agent-definition changes in a PR, and having a coding agent draft the diagram

**Background: what Agentforce is** (based on the official documentation as of writing)

- Agentforce is Salesforce's agent platform. A customer-facing **Service agent** runs as a dedicated
  agent user, while an internal **Employee agent** runs as the signed-in user ([source 1](#references)).
- Agents do their work by calling **actions** (Apex, Flow, prompts, external services and so on). Reasoning
  runs on the Atlas reasoning engine or a bring-your-own LLM (BYOLLM), and the **Einstein Trust Layer**
  provides data masking, prompt defense, toxicity detection and similar protections ([source 2](#references)).
- Salesforce officially recommends managing agent definitions as **metadata** (for example Agent Script
  `.agent` files) in Git and promoting them through CI/CD ([source 3](#references)).

**Assumed knowledge:** the operations in [Getting Started](getting-started.md) and the import steps in
[Creating and Using Templates](templates.md).

> **About confidence levels** — Where the body of the official documentation could not be checked directly,
> the text says "based on an excerpt of the official documentation". Always check the official source for the
> latest. Facts that could not be confirmed, or that rest only on secondary reports, are left out of this page.

---

## 2. Mapping Agentforce to CyberRiskScape types

| Agentforce building block | CyberRiskScape type | Modeling notes |
|---|---|---|
| Service agent (customer-facing) | `AGENT` | Set `agency`, `blastRadius` and `identityTier`. The permissions of the dedicated agent user guide `blastRadius` |
| Employee agent (internal) | `AGENT` | Runs with the signed-in user's permissions. Connect it from a `USER` (Employee) |
| Sub-agent / `connected_subagent` | `SUB_AGENT` (or `AGENT` plus an edge) | Express delegation with an edge of `semantic: delegation` |
| Reasoning engine / BYOLLM | `LLM` | |
| Einstein Trust Layer | `EINSTEIN_TRUST_LAYER` (dedicated library "Salesforce Agentforce") | Place it between the agent and the LLM. The dedicated rules (§4.2, §4.5, §4.7) fire on **agents connected to this type**. You can disable the library in the left sidebar; this only removes it from the palette and does not change placed diagrams, threat detection or saved data |
| Actions (Apex, Flow, prompt, standard action) | `TOOL` | From the agent, `semantic: tool_invocation`. Note the run permission (user / system) in the description |
| External MCP server (`mcpTool://`) | `MCP_SERVER` | Place it outside the org (in an Internet boundary) |
| External API (`externalService://`, Named Credential target) | `SAAS` or `EXTERNAL_ENTITY` | Place it outside the org (in an Internet boundary) |
| CRM objects (leads, cases, accounts) | `CRM` | Draw the externally writable entry points (such as Web-to-Lead) from a separate `USER` / `EXTERNAL_ENTITY` |
| Data Cloud retrieval (retriever) | `DB` | Use `semantic: rag_retrieval` on the return flow |
| Web-to-Lead, Experience Cloud, messaging | `USER` (Guest) / `EXTERNAL_ENTITY` | Place them in the external boundary (Internet) |
| Hand-off to a human (`@utils.escalate`) | `HUMAN_OPERATOR` | |
| Agentforce Voice | `PBX` → `STT` → `AGENT` → `TTS` | See §4.8 |

> **Note** — This mapping is a simplification for deciding which rules apply to which component. For example,
> merging Flow and Apex into one `TOOL` does not change how the rules apply. If you want to evaluate them
> with different run permissions, split the `TOOL` and write the run context in each description.

---

## 3. An example diagram

This template puts a customer-facing Service agent and an internal Employee agent on one canvas.

![Agentforce Service agent diagram](../assets/guide/agentforce/01-overview.png)

| File | Contents |
|---|---|
| [`templates/agentforce-service-agent.en.json`](templates/agentforce-service-agent.en.json) | English |
| [`templates/agentforce-service-agent.ja.json`](templates/agentforce-service-agent.ja.json) | Japanese |

**What is in it:** 14 components, 25 data flows, 3 trust boundaries (customers and outsiders = Internet,
the Salesforce org = Internal, external API / external MCP server = Internet).

- **Customer-facing flow** — customer → Service agent → Trust Layer → LLM. The Service agent uses actions
  (Flow / Apex), Data Cloud retrieval, an external API, an external MCP server and hand-off to a human
- **A ForcedLeak-style path** — an outside third party writes to the CRM through a web form (the Web-to-Lead
  equivalent) → the actions return the CRM record → the Employee agent reads it → there is an output path to
  an external URL. In the picture, the red line enters the CRM from "External third party (web form)" at the
  lower left, and the path continues CRM → actions → Employee agent → external URL

Import works the same way as in [the templates page](templates.md). Open **Template** in the left sidebar,
choose **Import**, select the JSON, and apply it.

**After loading, 103 threats** are detected (19 Critical, 61 High, 23 Medium).

### 3.1 Assumptions in the diagram (placeholder attributes)

The attributes in the template are **placeholders for a typical setup**. Change them to fit your environment.

| Element | Setting | Why, and when to change it |
|---|---|---|
| Service agent | `agency: Bounded`, `blastRadius: Tenant`, `identityTier: LabelOnly` | Assumes the dedicated agent user's permissions reach across the org. Lower `blastRadius` if you have narrowed them |
| Employee agent | `agency: Bounded`, `blastRadius: Tenant`, `identityTier: Cryptographic` | Assumes it runs with the signed-in employee's permissions (with SSO) |
| Actions (Flow / Apex) | `agency: Bounded`, `blastRadius: Tenant` | The run context does not show in the diagram. Check it in the description |
| Edge `auth` | `Password` for internal and external connections | Change it to the real mechanism (OAuth, Named Credential, etc.) |
| Web form → CRM | `auth: None`, `network: Internet` | Represents an entry point anyone outside can write to |

> **Why the Employee agent does not read the CRM directly** — In a real Agentforce setup the agent often reads
> records **through an action** (standard action, Flow, Apex, retrieval and so on), so the template connects
> CRM → actions → agent. A **direct input path** from a `CRM` node to an agent is also detected as indirect
> prompt injection by a general-purpose rule (`owasp-llm01-indirect-business-record-001`, High; it covers paths
> from `CRM`, `MAIL`, `CHAT`, `OTHER_APP` and `SAAS` to an agent). Even in the through-an-action form, the existing
> rule that reads action responses (`atlas-aml-t0051-…`) fires. Check your real read path against your own setup.

---

## 4. Threats to watch

Each item below lists "the rules CyberRiskScape detects" and "what it means in Agentforce". The
**parenthetical after a rule name is the component it fires on.** In addition to the general-purpose rules, there are
**three Agentforce-specific rules** (`sf-agentforce-…`) that fire on the Einstein Trust Layer type or on an agent connected to it (§7). **What is not detected is stated plainly too.**

### 4.1 Indirect prompt injection through externally writable CRM fields

**The case: ForcedLeak.** Reported by the security company Noma Labs in 2025 (CVSS 9.4). According to the
discoverer's write-up, an attacker put malicious instructions in the description field of a Web-to-Lead form;
when an employee asked the agent about that lead, the agent followed the instructions and could send CRM data
to the outside through an expired domain that was still on the allowlist. Salesforce is described as having
responded, for example by enforcing the Trusted URL allowlist ([source 4](#references); the details of the
response come from the discoverer's write-up, so check Salesforce's official statements).

The structural point is that **the attacker never talks to the agent directly.** The internal agent reads data
that an outsider wrote as "data" and treats it as an instruction.

**Rules detected** (confirmed on the template)

| Rule | Severity | Fires on | How to read it |
|---|---|---|---|
| Indirect prompt injection (`atlas-aml-t0051-…`) | High | Employee agent, Service agent | Action responses (including CRM records) and Data Cloud / external MCP responses enter the agent's input |
| Indirect prompt injection through business-app data (`owasp-llm01-indirect-business-record-001`) | High | An agent connected directly from `CRM`, `MAIL`, `CHAT`, `OTHER_APP` or `SAAS` | A path where the agent reads records, mail or chat that an outsider can write. **It is detected even when a CRM node is connected directly** (this template goes CRM → actions → agent, so this row does not appear and the row above does). `LINE` is treated as the user's direct input and is out of scope |
| Lethal Trifecta (`maestro-lethal-trifecta-001`) | Critical | Employee agent, Service agent | "Attacker-controlled data in × access to sensitive data × ability to send out". **It fires from the agent's blast-radius attribute (Tenant / CrossTenant / Admin), not from the connections in the diagram.** Treat it as a prompt to check, across the whole diagram, that at least one of the three is cut |
| Chained abuse of legitimate tools (`anthropic-zt-tool-chaining-001`) | High | Employee agent, Service agent | Combining an internal CRM lookup with an outbound send |
| Uncontrolled egress (`maestro-agent-internet-egress-001`) | High | The "Output to external URL" data flow and others | A path that sends data to a destination outside the allowlist |
| Spoofing (`stride-edge-unauth-internet-001`) | Critical | The "Web-to-Lead submission" and "Output to external URL" data flows | An unauthenticated entry or exit over the public network |
| Sensitive system access by external collaborators (`zt-external-collaborator-broad-access-001`) | High | The "Web-to-Lead submission" and "Inquiry" data flows | A guest-class actor reaching a sensitive system (CRM, agent) |

![Indirect prompt injection on the Employee agent](../assets/guide/agentforce/02-indirect-injection.png)

(This screenshot shows the rule that reads action responses.) The screen above shows the Employee agent selected with the "detection basis" of the indirect prompt
injection opened. It shows that the rule fires when there is an input-direction connection to the target node.

![Lethal Trifecta on the Employee agent](../assets/guide/agentforce/03-lethal-trifecta.png)

**What to check in Agentforce**

- Which fields of the objects the agent reads **receive externally writable input** (the Web-to-Lead
  description, messaging, email, Experience Cloud input fields and so on)
- Whether an agent that reads such a record has an **outbound path** (external URL, external API, external
  MCP, email sending and so on)
- Whether retrieved text is treated as **untrusted input** and instruction-like text is neutralized
  (the rule's mitigations: label retrieved content as untrusted, run sensitive tools only on explicit user
  instruction)
- Whether the Trusted URL allowlist contains **unused or expired domains** (§4.5)

### 4.2 The Service agent's run-as user and permissions

- A Service agent runs as a **dedicated agent user** (Einstein Agent license), and an Employee agent runs as
  the **signed-in user** (based on an excerpt of the official documentation; [source 1](#references))
- A new agent's permissions start at zero, and Salesforce's official blog recommends a **dedicated user with
  least privilege for each agent** ([source 5](#references))
- Salesforce's GitHub (`forcedotcom/sf-skills`, operating notes for AI agents; **not official product
  documentation**) says a Service agent does not respect sharing rules. Always confirm how sharing rules apply
  in the official documentation

**Rules detected**

| Rule | Severity | Fires on |
|---|---|---|
| Absence of agent identity (`anthropic-zt-agent-identity-attribution-001`) | High | Service agent (because of `identityTier: LabelOnly`; the Employee agent is `Cryptographic`, so it does not fire) |
| Excessive privilege from the run user and the actions' run context (`sf-agentforce-runtime-privilege-001`, **dedicated**) | High (Medium if `blastRadius` is `ReadOnly` / `Self`) | Employee agent, Service agent connected to the Trust Layer |
| Confused deputy / privilege inheritance on delegation (`anthropic-zt-confused-deputy-001`) | High | Employee agent, Service agent |
| Cross-session privilege retention (`anthropic-zt-memory-privilege-retention-001`) | High | Employee agent, Service agent |

The dedicated rule **raises a checklist** that fits how Agentforce decides permissions (the run user and the actions' run context); it does not read the real permissions.

**Not detected** — **No rule evaluates how sharing rules apply, what a permission set contains, or effective
permissions themselves.** The diagram expresses them through `blastRadius` (the impact if compromised), and a
person reviews permission-set contents (UC1 watches permission-set changes in a PR).

### 4.3 Actions that run with system permissions

An action follows the permissions of the Apex or Flow it points to. Flow has kinds of run context (user,
system and so on), and the official blog recommends `with sharing` and user mode for Apex (based on an excerpt
of the official documentation; [source 6](#references)). **Whether something runs in system mode cannot be
decided from the metadata alone.**

**Rules detected**

| Rule | Severity | Fires on |
|---|---|---|
| Tool poisoning / rug pull (`anthropic-zt-tool-poisoning-rug-pull-001`) | Critical | Actions |
| Output trust boundary violation (`maestro-tool-output-handling-001`) | High | Actions |
| Privilege escalation risk (`maestro-tool-edge-001`) | High | The actions ⇄ CRM data flow |
| Runaway autonomous action (`maestro-agent-runaway-001`) | Critical | Employee agent, Service agent |
| Excessive privilege from the run user and the actions' run context (`sf-agentforce-runtime-privilege-001`, **dedicated**) | High | Agents connected to the Trust Layer (the same rule as §4.2; its mitigations include Apex `with sharing` and Flow user context) |

**Not detected** — No rule tells you that "this action runs in system mode". Actions remain the general-purpose `TOOL`; the dedicated rule fires on the agent side and only prompts a review. For such actions, write the run
context in the description and raise `blastRadius` to match reality.

### 4.4 Human confirmation for write actions (`require_user_confirmation`)

The action attribute `require_user_confirmation` inserts a **human confirmation step** before execution. The
default is described as `False` (according to operating notes for AI agents on Salesforce's GitHub; **not
official product documentation**, so check the official sources for the latest). Consider `True` for
**write actions and actions with side effects**, such as updating records, refunds and sending email. That the
customer side owns least privilege, guardrails, monitoring and human confirmation in custom actions is
presented officially as part of Salesforce's shared-responsibility model ([source 7](#references)).

**Rules detected** — `maestro-agent-runaway-001` (Critical; the mitigation includes "human approval for
dangerous actions") and `owasp-asi09-human-agent-trust-exploitation-001` (Medium; people approving on the
strength of the agent's confident wording). In the diagram, a design where a person approves sensitive
operations is expressed as `agency: Bounded`.

**Not detected** — Whether `require_user_confirmation` is actually `True` is reflected neither in the diagram
nor in detection. A person must check the Agent Script.

### 4.5 Outbound data and Trusted URLs

In response to ForcedLeak, Salesforce is described as having started to **enforce the Trusted URL allowlist**
(from September 2025; [source 4](#references); check the official sources for Salesforce's details). In
ForcedLeak, an **expired domain** left on the allowlist was reported to be abused. An allowlist is not "add it
and forget it"; it needs periodic review.

**Rules detected**

| Rule | Severity | Fires on |
|---|---|---|
| External exfiltration through URLs embedded in agent output (leftover Trusted URL domains) (`sf-agentforce-output-url-exfiltration-001`, **dedicated**) | High | Employee agent, Service agent connected to the Trust Layer |
| Uncontrolled egress (`maestro-agent-internet-egress-001`) | High | The "Output to external URL" flow and the connections to the external API and external MCP server |

The external URL node also gets spoofing and repudiation rules. The dedicated rule checks the path where rendering a URL (image or link) embedded in a response sends CRM data out, and the Trusted URL review (the ForcedLeak details come from the discoverer's write-up, as noted above).

**Not detected** — The contents of the allowlist (for example, expired domains) cannot be evaluated.

### 4.6 Tool poisoning from external MCP servers

Agentforce can call external MCP servers (Beta; there is an allowlist and server review). **Salesforce itself
names tool poisoning as a threat** ([source 8](#references)). There are also Salesforce-hosted MCP servers that
let an outside AI operate Salesforce (they follow the calling user's permissions; [source 9](#references)).
That is the opposite direction and is outside this template.

**Rules detected**

| Rule | Severity | Fires on |
|---|---|---|
| Tool descriptor poisoning / line jumping (`mcp-tool-descriptor-poisoning-001`) | Critical | External MCP server |
| MCP server impersonation / typosquatting (`mcp-server-impersonation-typosquatting-001`) | High | External MCP server |
| Prompt input from outside the trust boundary (`maestro-agent-untrusted-ingress-001`) | High | Data flows such as "tool response" |
| Direct exposure across the trust boundary (`stride-edge-internet-exposed-sensitive-001`) | Critical | Response data flows from the external MCP server and external API to the Service agent |

![Tool descriptor poisoning on the external MCP server](../assets/guide/agentforce/04-mcp-poisoning.png)

### 4.7 Limits of prompt-injection detection

The Trust Layer has a prompt-injection detection feature. However, the official documentation as of writing
(based on a search excerpt) describes it as **Beta, off by default, and English (US) only**
([source 10](#references); **check the official source for the latest**). If you operate in Japanese, or have
not turned the feature on, design on the assumption that you cannot rely on detection.

**Rules detected** — Limits on the scope of the Trust Layer's detection (`sf-agentforce-trust-layer-detection-gap-001`,
**dedicated**, Medium) appears on the `EINSTEIN_TRUST_LAYER` node (grounded in the official notes of Beta, off by default and English only, and in guardrails being a probabilistic defense; on this type it appears in place of the general-purpose reliance-on-a-guardrail rule). The mitigation is to put
**deterministic controls** behind the guardrail (an action allowlist, least privilege, restricted output
destinations, human approval).

![Limits on the Trust Layer's detection scope](../assets/guide/agentforce/06-trust-layer-gap.png)

The screen above shows the Einstein Trust Layer node selected with the card of the dedicated rule (Medium) open.

### 4.8 Agentforce Voice

Agentforce Voice is **cascaded** (speech recognition → reasoning → speech synthesis), not a direct
speech-to-speech model ([source 11](#references)). The telephony layer is Salesforce Voice plus partner
telephony (Amazon Connect, Genesys and others; [source 12](#references)).

Because it is cascaded, **the transcript becomes the reasoning input as is.** Instructions mixed into what is
spoken can act as injection, and attacks that mislead speech recognition with inaudible audio and the like are
known ([source 14](#references)). If you also use voiceprint authentication, keep in mind it can be defeated
by synthetic speech made from recordings. NIST SP 800-63B-4 says biometric comparison based on voice must not
be used ([source 13](#references)).

This template does not include Voice (to keep the diagram readable). To draw it, use the PBX → STT → agent →
TTS part of [the contact center template](templates.md#the-contact-center-template) as a reference. That
template detects, among others, mis-recognition from adversarial audio (`voice-stt-adversarial-audio-001`),
voiceprint bypass with a cloned voice (`voice-voiceprint-clone-bypass-001`), direct prompt injection on the
agent, and impersonation with synthetic speech (`voice-synthetic-media-impersonation-001`).

> **Not confirmed** — We could not confirm an official statement that the Trust Layer's protections extend to
> the voice path. Check the official sources before adopting it.

---

## 5. Finding where to defend with attack path analysis

[Attack path analysis](attack-paths.md) shows, among the routes from an outside third party to the Employee
agent, **where one control would cover the most routes**. The screen below is the template with one attacker
added (connected to the outside third party, with the Employee agent as the objective). **This attacker is not
part of the template.** Add one yourself to try it.

![Attack path analysis](../assets/guide/agentforce/05-attack-path.png)

- There are 2 routes, and both pass through "external third party (web form) → CRM → actions → … → Employee agent"
- The chokepoints are **the outside entry point, the CRM and the actions** (2 of 2 routes pass through each).
  In other words, limiting writes from the web form to the CRM, how CRM fields are handled, and how action
  output is handled are the places that matter most in this setup
- Risks have not been assessed yet, so the costs are provisional values derived from severity

---

## 6. Use cases

### UC1: Require a threat model update in the PR when agent definitions change

**Situation** — You manage agent definitions, actions and permission sets in Git. You want to stop a PR that
adds a sub-agent or an action from merging without a threat model update.

Line up the Salesforce DX paths in the `watch-paths` of the GitHub Action from
[Integrating with AI-Driven Development CI](ci-integration.md).

```yaml
- uses: takashi-ohmoto-git/CyberRiskScape@v0.2.0   # pin to a commit SHA in production
  with:
    model: threat-model/project.json
    fail-on: High
    watch-paths: |
      force-app/**/aiAuthoringBundles/**
      force-app/**/genAiPlannerBundles/**
      force-app/**/genAiPlugins/**
      force-app/**/genAiFunctions/**
      force-app/**/permissionsets/**
      force-app/**/flows/**
      force-app/**/classes/**
```

Each `watch-paths` line is treated as a git pathspec (glob). We confirmed that the lines above match files
under `force-app/main/default/…`.

| What changes | Triggers that may apply | What to look at |
|---|---|---|
| `aiAuthoringBundles`, `genAiPlannerBundles` (agent definitions) | **T7** Expanded agent capability | New sub-agents, actions or external MCP servers; raised autonomy |
| `genAiPlugins`, `genAiFunctions` (sub-agents, actions) | **T7** | Whether a new action can write or send data out; whether `require_user_confirmation` is set |
| `permissionsets` (permission sets) | **T3** Authentication / authorization, **T7** | Whether the agent user's permissions grew |
| `flows`, `classes` (action implementations) | **T7**, **T5** Sensitive data on a new path | Whether it runs in system mode; which objects it reads and writes |
| External service registrations and Named Credentials, if you add them | **T6** New third-party integration | Whether a new external service receives customer data |

To also watch directories for external service registrations and Named Credentials, as in the last row,
check where your repository keeps that metadata and add it to `watch-paths` (directory names follow your
Salesforce DX project layout).

**Flow**

1. Open a PR that changes an agent definition or similar
2. If the model JSON was not updated, the Action posts the **execution-trigger checklist T1 to T8** on the PR
   and fails
3. A person either updates the diagram or decides no update is needed and applies the
   `threat-model-not-needed` label (agree internally on who may apply it;
   [CI page §4.3](ci-integration.md))

**Limits** — `watch-paths` only sees that a file changed. **It does not evaluate whether the content of the
change is dangerous.** `permissionsets`, `flows` and `classes` change often and can be noisy, so start with
`aiAuthoringBundles` and `genAi*` only, and add more as you see how it goes.

### UC2: Have a coding agent read the `.agent` file and draft the diagram

**Situation** — You have an agent defined in Agent Script (`.agent`) but no diagram. You want a coding agent
(Claude Code, GitHub Copilot and so on) to draft one. This assumes the MCP server from
[Using It from Coding Agents](mcp-integration.md) is already set up.

**Example instruction to the agent**

```text
Read the .agent files under force-app/main/default/aiAuthoringBundles/ and turn this agent's
structure into a CyberRiskScape diagram.
- Add the agent, the actions (by target kind), external services and external MCP servers, using the
  types you confirm with list_component_types
- Set the semantic of actions to tool_invocation. Put external services and external MCP servers in an Internet boundary
- List the write actions whose require_user_confirmation is False and report them
- Do not read the contents of Flow or Apex; report them as "needs confirmation"
First show me, with dryRun, the threats that would be added.
```

**Tool flow the agent calls**

1. `list_component_types` — confirm the available types (`AGENT`, `TOOL`, `MCP_SERVER`, `SAAS` and so on)
2. `get_model` — get the existing model's nodes, boundaries and `revision`
3. `apply_model_changes` (`dryRun: true`) — send nodes, edges and boundaries in one call. Attributes
   (`agentAttributes`) and `semantic` can be specified. It returns the added threats without writing
4. `apply_model_changes` (without `dryRun`) — write it if the content is right
5. `analyze_threats`, `get_threat` — read the detected threats and their basis

**What a person does** — Review and complete the draft. **The agent can only work from what is written in the
`.agent` file.**

- The **contents** of Flow and Apex (whether it runs in system mode, which objects it touches) and the agent
  user's **effective permissions** (permission sets, sharing rules) cannot be seen from `.agent`. A person
  checks them and reflects them in `blastRadius` and the description
- Externally writable CRM fields (Web-to-Lead and so on) do not appear in `.agent`. **A person adds the entry points**
- Risk assessment, acceptance and control implementation status cannot be changed by the agent. A person
  sets them in the app
- Writes go straight to the file in the working tree, so commit before you start

### (Reference) Using it with the Salesforce DX MCP server

Salesforce publishes a Salesforce DX MCP server (`@salesforce/mcp`; [source 15](#references)). **The only
agent-related tool it provides is running agent tests (`run_agent_test`).** It is not a tool for reading agent
definitions or retrieving their structure.

So the division of labor is: CyberRiskScape handles the diagram and threats, and the Salesforce DX MCP server
handles running the agent tests. The two servers do not talk to each other; the agent connects them. The
Salesforce DX MCP server requires authentication to an org, so check the terms of use and the permissions of
what it connects to in Salesforce's official documentation.

---

## 7. Limits

- **There are three dedicated rules, designed to fire on agents connected to the Trust Layer type.** If you do not
  place the Trust Layer in the diagram, the agent-side dedicated rules (output URL, run privilege) do not appear.
  Everything else is evaluated by existing general-purpose rules. **Salesforce-specific settings cannot be
  evaluated**: sharing rules, the contents of the Trusted URL allowlist, the value of `require_user_confirmation`,
  and whether something runs in system mode
- **Two-hop paths (window → CRM → agent) cannot be judged precisely; the result is an approximation.** The
  general-purpose rules look at a direct input path to the agent, so a path where an outside window writes to the
  CRM, an action reads the CRM and the agent receives that response is supplemented by the rule that reads
  action responses and by attack-path analysis (§5)
- **Flow and Apex remain the general-purpose `TOOL`.** Run context and action kind do not change how rules apply
- **There is no automatic diagram generation from metadata.** A coding agent can read `.agent` and draft one,
  as in UC2, but the result is not guaranteed to be the same each time and needs human review
- **The template's attributes are placeholders** (§3.1). The number of detections changes with how you set
  attributes and connections
- **Salesforce's behavior can change.** Beta features (external MCP, prompt-injection detection) change
  especially often, so check the official sources for the latest
- The ForcedLeak details come from the discoverer's write-up. Check the official sources for Salesforce's own statements

---

## References

Confidence levels: we distinguish official information we could check directly from excerpts of official
documentation whose body we could not check directly. The body text says "based on an excerpt of the official
documentation" for the latter.

1. Run-as users for Employee agents and Service agents (based on an excerpt of the official documentation) —
   <https://help.salesforce.com/s/articleView?id=ai.agent_employee_agent_considerations.htm>
2. Einstein Trust Layer (based on an excerpt of the official documentation) —
   <https://developer.salesforce.com/docs/einstein/genai/guide/trust.html>
3. Agent development lifecycle (manage metadata in Git, promote through CI/CD) —
   <https://architect.salesforce.com/docs/architect/fundamentals/guide/agent-development-lifecycle>
4. ForcedLeak (Noma Labs, the discoverer's write-up) — <https://noma.security/noma-labs/forcedleak>
5. Best practices for a secure Agentforce implementation (official blog) —
   <https://www.salesforce.com/blog/best-practices-for-secure-agentforce-implementation-2/>
6. Best practices for building Agentforce Apex actions (official blog) —
   <https://developer.salesforce.com/blogs/2025/07/best-practices-for-building-agentforce-apex-actions>
7. Salesforce's shared responsibility and the security measures customers own (official) —
   <https://help.salesforce.com/s/articleView?id=005315874&language=en_US&type=1>
8. Agentforce MCP (official blog; mentions tool poisoning) —
   <https://www.salesforce.com/blog/agentforce-mcp/>
9. General availability of Salesforce-hosted MCP servers (official blog) —
   <https://developer.salesforce.com/blogs/2026/04/salesforce-hosted-mcp-servers-are-now-generally-available>
10. Configuring prompt-injection detection (based on an excerpt of the official documentation; body not checked) —
    <https://help.salesforce.com/s/articleView?language=en_US&id=ai.generative_ai_trust_configure_prompt_injection_detection.htm>
11. How Agentforce Voice is built (official engineering blog) —
    <https://engineering.salesforce.com/how-ai-driven-testing-enabled-sub-second-latency-for-agentforce-voice/>
12. Agentforce Voice telephony (official) —
    <https://help.salesforce.com/s/articleView?id=005226934&language=en_US&type=1>
13. NIST SP 800-63B-4 §3.2.3.2 (biometric comparison based on voice must not be used) —
    <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63B-4.pdf>
14. DolphinAttack (attacks on speech recognition with inaudible voice commands, academic paper) —
    <https://arxiv.org/abs/1708.09537>
15. Salesforce DX MCP server (Salesforce's GitHub) — <https://github.com/salesforcecli/mcp>

The Agent Script specification and parser (<https://github.com/salesforce/agentscript>, Apache-2.0) and the
`sf agent` commands (<https://github.com/salesforcecli/plugin-agent>) are also published on Salesforce's GitHub.

---

## What to read next

- How to read detected threats — [Reading the Threat Panel](reading-threats.md)
- Finding where to defend from the routes — [Attack Path Analysis](attack-paths.md)
- Requiring diagram updates in PRs — [Integrating with AI-Driven Development CI](ci-integration.md)
- Using it from coding agents — [MCP Use Cases](mcp-use-cases.md)
