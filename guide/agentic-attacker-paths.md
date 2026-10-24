# Deciding where to cut the attack path when an attacker abuses an agentic penetration-testing tool

**English** | [日本語](agentic-attacker-paths.ja.md)

> This page assumes an attacker abuses an autonomous, agentic penetration-testing tool.
> It restates the capabilities such tools have **today** in a defender's terms, and walks through deciding,
> on CyberRiskScape's attack path analysis, **where to cut so the attacker's exploration stops**.
>
> No product name, internal mechanism, or attack procedure appears here. The "capabilities" below are the general properties common to this class of tool.
> Counts depend on your diagram — measure them on yours.

---

## 1. What this page covers, and assumptions

- Restate the capabilities of an autonomous attack agent as **four properties** to design against
- Follow those capabilities on your [attack path analysis](attack-paths.md) diagram to find the **starting point, footholds, and chained branches**
- Which choke points prune the most branches of the attacker's exploration tree
- Why controls that "only make it tedious" merely buy time against an autonomous attacker (connects to [the existing guide, §4](ai-agent-attack-2026-10.md))

This page continues from [Attack Path Analysis](attack-paths.md); read that first for how to place an attacker component and read choke points.
Defending the tool when **your own team runs it legitimately** is covered separately in [Running an agentic penetration-testing tool yourself](agentic-pentest-operation.md).

---

## 2. Four properties this class of tool has today

When an attacker uses this class of tool, the defender designs assuming all four are present.

| Property | What it means for the defender |
|---|---|
| **Autonomous, parallel, persistent** | The tool decomposes a goal, runs work in parallel, and keeps trying without rest — not a human following steps. → Evaluate controls by **whether human response keeps up**, even if detection works |
| **Widens an exploration tree from each finding** | From one finding (a weakness, a credential, internal info) it dynamically chooses what to try next and extends lateral branches. → A control must read one move ahead: "where does the attacker go next after I close this?" |
| **Starts from externally visible assets** | It can ingest an inventory of exposed assets (the external attack surface) and start exploring from there. → The first entry is "what is visible from outside." Inventory exposure first |
| **Mines responses tirelessly** | It full-text-searches the responses it exchanged and uses any secrets, internal addresses, or tokens mixed in as the next foothold. → "What you put in responses" is the design that matters |

These four do more than make attacks **faster and more numerous** — they change **how the exploration tree widens**. Your attack path diagram is the mirror image of that tree.

[MITRE ATLAS](https://atlas.mitre.org/) (release 2026.09), the knowledge base of attack techniques against AI systems, defines the behavior of autonomous attack agents as techniques. They map to the four properties as follows.

| Property | Corresponding ATLAS technique |
|---|---|
| Autonomous, parallel, persistent | [AML.T0124 Autonomous Attack Orchestration](https://atlas.mitre.org/techniques/AML.T0124) |
| Widens an exploration tree from each finding | [AML.T0117 Autonomous Attack-Path Adaptation](https://atlas.mitre.org/techniques/AML.T0117) |
| Starts from externally visible assets | [AML.T0116 Autonomous Reconnaissance](https://atlas.mitre.org/techniques/AML.T0116) |
| Mines responses tirelessly | No dedicated technique. The closest is [AML.T0126 Automated Collection](https://atlas.mitre.org/techniques/AML.T0126) |

The first three (T0124, T0117, T0116) are cited as sources of the attacker card `zt-agentic-attacker-ai-accelerated-001` (§3, §6).

---

## 3. Follow the capabilities on the attack path diagram

Once [attack path analysis](attack-paths.md) has enumerated routes from the attacker component to the target, overlay the four properties:

- **Starting point (externally visible assets)** — Is the entry the attacker component connects to an externally exposed asset? Public portals, APIs, management surfaces, VPNs qualify. This is the root of the exploration tree.
- **Footholds (info mixed into responses)** — Do mid-route hops fire rules for verbose errors, bulk retrieval, or embedded secrets? These are the nodes where "a response produces the next move."
  - `api-error-response-disclosure-001` (detailed errors leak internal structure)
  - `api-bulk-data-harvesting-001` (bulk retrieval leaks data in volume)
  - `api-mobile-embedded-secret-001`, `api-dev-workspace-secret-exposure-001` (secrets in responses / artifacts)
- **Chained branches (lateral movement from a finding)** — Does a captured credential or secret open the next hop to another component? If secrets are concentrated in one place, stepping on it widens the branches all at once.
  - `api-secrets-vault-concentration-001`, `nhi-long-lived-secret-001`, `zt-credential-sprawl-static-secret-001`

Placing the attacker as an **"Agentic Attacker"** component brings up the attacker card `zt-agentic-attacker-ai-accelerated-001`, which surfaces the control re-readings that assume this "autonomous, accelerating" attacker.

---

## 4. Where to cut so the exploration stops

Use the choke points from attack path analysis (the element where one control covers the most routes) as pruning of the exploration tree, in this order:

1. **Remove the root (eliminate the starting point)** — Put externally exposed entries behind zero trust access that only relays verified devices and users. With no route that reaches, no tree grows. Place an identity-aware proxy / ZTNA in front of business APIs, cut the line from attacker/device to the gateway, and confirm the route disappears from the route table ([Reducing Internet Exposure](exposure-reduction.md)).
2. **Cut the footholds (put nothing in responses)** — Trim response fields to the minimum, return no verbose errors, leave no secrets in artifacts. If a full-text search finds nothing, no next move is born.
3. **Collapse the chaining nodes (stop lateral movement)** — Replace concentrated secret stores and long-lived static credentials with short-lived, purpose-bound, sender-constrained ones. Even if stepped on, if it reaches no other component, the branch stops at one hop.

Each time you secure one choke point, re-read the route table with "Residual routes only" and check **where the attacker turns next**, one move ahead. An autonomous tool re-explores tirelessly after you close something.

---

## 5. Telling apart controls that "only make it tedious"

An autonomous attacker breaks through **controls that are merely tedious** without tiring. Rate limiting alone, hard-to-guess IDs alone, non-standard ports alone — raise the number of attempts and they "get through eventually," so they buy time rather than stop the attack.

For each hop, judge whether the control behind its evidence (the firing threat) "only makes it tedious" or "makes it impossible." The list is in [the existing guide, §4](ai-agent-attack-2026-10.md). This does not mean rate limiting, monitoring, and WAF are unnecessary — they set **the ceiling on how much is taken and the time to notice**. But against an autonomous tool's speed, first build the "cannot pass" from the design of reach, authentication, authorization, and retained data, then layer these on top.

---

## 6. Confirm with BAS that the cut routes are also closed on the live system

Cutting a route on the diagram does not tell you whether it is closed on the live system. Export the attack path's techniques as a **MITRE ATT&CK Navigator layer (JSON)**
and hand it, as candidates for "what to emulate", to BAS (breach and attack simulation), CTEM, or SOC tools that can import Navigator layers.

### 6.1 From the UI

Open **Report** in the left sidebar and click **"ATT&CK Navigator layer (JSON)"**. The techniques for the whole diagram are exported.
Techniques on the top routes of an attack scenario carry "Scenario" metadata, and techniques from threats on a choke point carry "Choke point" metadata.

### 6.2 From the CLI (limit to one scenario)

```bash
npm ci && npm run build:cli
node dist-cli/main.js export-attack-navigator model.json --node C2 --out scenario-c2.json
```

Pass to `--node` the ID of an attacker node that has an OBJECTIVE set. Only threats on the nodes and edges of that scenario's top routes are included.
Without it, you get the same whole-diagram layer as the UI. Either the UI or the CLI is enough.

### 6.3 Example workflow

1. Put a control on a choke point (§4)
2. Hand that scenario's layer to BAS, emulate the techniques, and confirm they are detected and blocked
3. Record the result in "Control implementation status" on the threat panel, and re-check where the attacker turns next with "Residual routes only" in [Attack Path Analysis](attack-paths.md)

**Limits:** Techniques are taken from the ATT&CK IDs written in the threat rules' sources (references). Rules without an ATT&CK ID in their sources are not included.
AI-specific threats often carry ATLAS IDs, which do not appear in Navigator's Enterprise matrix, so they are listed in the layer description. Coverage is not guaranteed.
The three ATLAS techniques in §2 (T0124, T0117, T0116) come from the attacker card, so they appear in the description of the whole-diagram layer but not in a layer narrowed with `--node` (narrowing keeps only the threats on the route's nodes and edges).
What is exported is a list of candidate techniques to emulate; it contains no attack procedures.

---

## 7. Assumptions and limits

- **The verdict is based on the diagram.** Public assets and routes you did not draw are not evaluated. The quality of the diagram is the quality of the analysis.
- **It does not tell you whether a vulnerability exists.** A rule shows that "this question applies to this route," not that a live vulnerability is present (no substitute for scanning or penetration testing).
- **It cannot measure detection speed.** You can enter log collection, retention, and destinations, but whether detection and response keep up with the attack's autonomous speed must be confirmed by live drills and tests.
- **Counts change on your diagram.** The rule IDs here are candidates that fire on a matching diagram.

---

## Read next

- [Running an agentic penetration-testing tool yourself](agentic-pentest-operation.md) — defending the platform itself when you run it legitimately
- [Preparing for automated attacks by AI agents (October 2026)](ai-agent-attack-2026-10.md) — the sister page, driven by reports and showing effect as count differences
- [Attack Path Analysis](attack-paths.md) — reading choke points, the route table, and evidence
- [Reducing Internet Exposure](exposure-reduction.md) — inventorying and reducing exposure to remove the starting point
