# Putting BloodHound CE Results on the Diagram — Backing Threats with Real AD Permission Data

**English** | [日本語](bloodhound.ja.md)

> Product names on this page are names of their respective owners. This page explains how to import the results of BloodHound Community Edition (CE)
> queries into CyberRiskScape. It is not provided, certified, or endorsed by the developers of BloodHound; the use of the names is descriptive.
> Response formats and edge names follow the official source code as of the time of writing (November 2026). Check the official information for the latest.

> **Scope** — Connect BloodHound and collect data only for **an AD that you manage or are authorized to assess**.
> CyberRiskScape does not connect to AD and does not run collectors (SharpHound and the like). It only reads the results of BloodHound CE queries.

---

## 1. What this page covers and prerequisites

BloodHound CE (SpecterOps, Apache-2.0) is an OSS tool that analyzes the permissions and attack paths of Active Directory (AD) and Entra ID as a graph.
CyberRiskScape does not draw AD objects on the diagram. Instead, it takes the results of BloodHound queries (Cypher) as **findings** and attaches them to the directory (AD) node and the certificate authority (CA) node on the diagram.
Threats that were raised from the configuration "by assumption" (abuse of delegation, abuse of replication rights, and so on) are **backed by real data**.

The first stage covers AD only (Entra ID is planned).

**Prerequisites**

- A CyberRiskScape project JSON to attach findings to, with a **directory** (AD) node on the diagram. If you use AD CS (Certificate Services), also place a **certificate authority (CA)** (section 3).
- A BloodHound CE that you run yourself, with collected data already ingested. **Collection is done on the BloodHound side.**
- Node.js. Build the CLI first (`npm ci && npm run build:cli`).
- **CLI only.** The output project JSON can be loaded on screen with **Template** → **Import**.

**Background for this page**: the operations in [Getting Started](getting-started.md) and [Reading the Threat Panel](reading-threats.md).

---

## 2. What it can do

It sends the 10 bundled queries to BloodHound, counts the matching principals, and links them to the corresponding threats.

| Query | Corresponding threat | Attached to |
|---|---|---|
| Enabled users that are Kerberoasting targets (have an SPN) | Offline cracking of tickets the directory issues (Kerberoasting / AS-REP roasting) | Directory |
| Enabled users that do not require pre-authentication (AS-REP targets) | Same as above | Directory |
| Non-Tier Zero principals with replication rights (DCSync) | Bulk extraction of the credential corpus by abusing directory replication rights | Directory |
| Non-Tier Zero principals that can read local administrator passwords (LAPS) | Excessive read permissions on local administrator passwords (LAPS) | Directory |
| Computers with unconstrained delegation enabled | Abuse of Kerberos delegation (impersonating any user) | Directory |
| Principals with constrained or resource-based constrained delegation (RBCD) | Same as above | Directory |
| Non-Tier Zero principals that can modify a GPO | Lateral movement and persistence through tampering with distributed directory policy | Directory |
| Principals that can take the domain through certificate template or CA misconfiguration (AD CS ESC family) | Impersonating any user through misconfigured certificate templates | CA |
| Principals that can take the domain by NTLM relay to certificate enrollment | NTLM relay to certificate enrollment interfaces | CA |
| Principals that can forge certificates with the CA key (GoldenCert) | Forging certificates by stealing the CA private key or administrative rights | CA |

- The "non-Tier Zero" queries do not count principals that carry BloodHound's **Tier Zero mark** (domain admins, directory servers, and others that legitimately hold the permission). The judgment is left to BloodHound.
- The queries and mappings are read-only (`MATCH … RETURN`). Write Cypher is forbidden by the bundled mapping, and BloodHound CE itself rejects it by default.

---

## 3. Preparing the diagram

Findings are attached to nodes on the diagram. Place these two kinds.

| Node | What it represents |
|---|---|
| **Directory** (Identity & Access) | AD. Findings on Kerberoasting, delegation, replication rights, LAPS, and GPOs are attached here |
| **Certificate authority (CA)** (Identity & Access; **a new type**) | The certificate authority of AD CS, if you use it. Includes certificate templates and enrollment interfaces (web enrollment, RPC). AD CS findings are attached here |

The CA type comes with these three threat rules. If you use AD CS, place it on the diagram.

- Impersonating any user through misconfigured certificate templates
- NTLM relay to certificate enrollment interfaces
- Forging certificates by stealing the CA private key or administrative rights

If you do not place a CA, AD CS findings are attached to the directory node.

---

## 4. Importing

There are two entry points. Either one is enough.

### 4.1 Import through the API (CLI only)

Pass a BloodHound API token (token ID and token key) in environment variables. The token is neither saved nor printed.

```bash
export BLOODHOUND_TOKEN_ID=<token ID>
export BLOODHOUND_TOKEN_KEY=<token key>
node dist-cli/main.js import-bloodhound my-project.json --api https://bloodhound.example.com -o out.json
```

- It sends **only the bundled queries** to `POST /api/v2/graphs/cypher` with signed requests. Read-only.
- `https` only (`http` is allowed for `localhost`).

### 4.2 Import from files

To run the queries yourself on BloodHound, print the bundled queries.

```bash
node dist-cli/main.js import-bloodhound --print-queries
```

The output is JSON with each query's id, title, and Cypher. Run each query, save the response JSON as `<query id>.json` in a folder, and point to that folder.

```bash
node dist-cli/main.js import-bloodhound my-project.json --in ./bh-responses -o out.json
```

A response for zero matches (HTTP 404 with `resource not found`) is also read as zero.

### 4.3 Which node the findings go to

| Finding | Attached to |
|---|---|
| Everything except AD CS | The directory, if the diagram has exactly one. If there are several, `--node C1` (C number or node ID) |
| AD CS findings | The CA. If there are several, `--ca-node C2`. If there is no CA, the directory |

To import per domain, use `--scope` (default `default`). **Re-importing replaces the findings of the same scope.** Findings of other scopes remain.

```bash
node dist-cli/main.js import-bloodhound my-project.json --api https://bloodhound.example.com \
  --node C1 --ca-node C2 --scope corp.example.com -o out.json
```

`--report <md|json>` selects the format of the per-query count report (default `md`, to standard output).

---

## 5. Reading the results

- **Threat cards**: the card of a backed threat shows a "**Confirmed by BloodHound**" mark. The mark shows that the threat was confirmed with real data rather than assumed.
- **Reports**: the findings also appear in `findings-report` and `findings-priority`, and in the SARIF export.
- **Counts**: one finding corresponds to one query. Its text includes the number of affected principals and the asset names (section 6).

To see in what order the principals can be followed to a compromise, use the BloodHound screen (section 7).

---

## 6. What is stored about people

| Kind | Handling |
|---|---|
| User names | **Not stored.** Only the count is kept |
| Names of computers, groups, GPOs, OUs, certificate templates, CAs, and domains | Kept as asset information (up to 20 per finding) |
| Internal identifiers such as SIDs | Not stored |

---

## 7. Limits

- **The attack path itself (in what order it is followed) is viewed in BloodHound.** CyberRiskScape goes as far as the counts and the mapping to threats.
- The "attack path findings" API of BloodHound **Enterprise** is not used. Only the Cypher of CE.
- Collection (SharpHound and the like) is done by you on the BloodHound side.
- The first stage covers AD only. Entra ID is planned.
- It was verified by running the official BloodHound CE docker-compose locally and importing the test collection data from the official repository (2026-11-15: API signing, handling of zero matches, detection of AD CS ESC (3 findings), and exclusion of Tier Zero). **It has not been verified against the AD of a real organization.**

---

## 8. References

- BloodHound (SpecterOps): https://github.com/SpecterOps/BloodHound

---

## 9. What to read next

- [Reading the Threat Panel](reading-threats.md) — how to read the marks and rationale on a threat card
- [Vulnerability Management with OSS Scanners](oss-vulnerability-management.md) — the common flow for prioritizing findings on attack paths
- [Threat Modeling NHIs and Identity Platforms](nhi-identity.md) — how to draw directory and IdP threats
