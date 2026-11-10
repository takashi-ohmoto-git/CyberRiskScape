# Migrate a Microsoft Threat Modeling Tool Threat Model — Import a .tm7 and See the Differences in the Migration Report

**English** | [日本語](threat-modeling-tool.ja.md)

> Microsoft Threat Modeling Tool is a product of Microsoft Corporation. This page explains how to import a threat model (.tm7) made with
> Microsoft Threat Modeling Tool into CyberRiskScape. It is not provided, certified, or endorsed by Microsoft; the use of the name is descriptive.
> There is no public specification for .tm7, so the import is built from the shape of files created with Microsoft Threat Modeling Tool 7.3
> (file format 4.3) as of the time of writing (November 2026). Verification used fictional samples and test models made by the author.

---

## 1. What this page covers and prerequisites

- How to import the .tm7 of Microsoft Threat Modeling Tool (TMT below) as a CyberRiskScape project (from the screen, or with `import-tm7` on the CLI)
- **What goes where** on import. Because the purpose is migration, **no information is dropped** (people's names, the justification for a threat decision, and notes are all kept)
- How to read the **migration report**, which cross-checks the threats you set in TMT against the threats CyberRiskScape detects from the same diagram
- What a person should check after the import, and the **limits**

**Prerequisites**

- You have a .tm7 saved from TMT (verified with files created by TMT 7.3).
- The screen alone is enough. To use the CLI, Node.js must run and the CLI must be built (`npm ci && npm run build:cli`).
- The .tm7 is only read in your own browser (or the CLI). It is not sent anywhere.

**Background knowledge for this page**: the basics in [Getting Started](getting-started.md) and [Reading the Threat Panel](reading-threats.md).

---

## 2. Steps

### 2.1 Import from the screen

1. Open **Template** and choose the **Import** tab.
2. Press **"Select .tm7 (Microsoft Threat Modeling Tool)"** and choose a .tm7.
3. The imported counts (nodes, edges, boundaries, annotations, threats, mitigation statuses) and the **number of items needing confirmation** are shown.
4. When you apply it, **the current project is replaced with the imported content** (you are asked to confirm). Save the project first if you need to.

### 2.2 Import with the CLI

```bash
node dist-cli/main.js import-tm7 model.tm7 --out project.json --report migration-report.md
```

- `--out`: the imported project JSON. You can open it from **Template** → **Import** on the screen. It also works as input to other commands such as `analyze`.
- `--report`: also writes the migration report (Markdown) (§4).
- `--locale en`: writes node descriptions, annotations, and the report in English (the default is Japanese).
- The counts and the elements needing confirmation (name and reason) are shown on standard error.

To rebuild only the migration report later (for example after entering attributes):

```bash
node dist-cli/main.js migration-report project.json --out migration-report.md   # --format json for JSON
```

On the screen, the project menu in the left sidebar shows **"Migration report from TMT (Markdown)"** (only when there are threats imported from TMT).

---

## 3. What goes where

### 3.1 The diagram

| TMT | CyberRiskScape | Notes |
|---|---|---|
| Element (process, external entity, data store) | Node | The type is decided by the mapping table (§3.2). The position follows the center of the TMT shape |
| Element name | Node name | |
| Element type, re-selected attributes, Out Of Scope and its reason | Recorded in the node **description** with a `[TMT]` prefix | Attributes left at the default selection are not written (the original value can be told from the type) |
| Data flow | Edge (same direction as TMT) | The name, protocol (HTTP / HTTPS, etc.), and description are also imported |
| Data flow "Provides Confidentiality" | Edge encryption (Yes → TLS, No → plaintext) | If unknown, it is treated as plaintext (the bad value) |
| Data flow "Source Authenticated" | Edge authentication (Yes → password, otherwise → none) | TMT has no authentication method, so it is set conservatively. Raise it to match reality |
| Trust boundary drawn as a box (CorpNet, etc.) | Boundary (CorpNet is an internal macro-segment) | An edge whose two ends are inside the same box gets path VPC; any other edge gets Internet |
| **Trust boundary drawn as a line** (Internet Boundary, etc.) | **Annotation** (with coordinates) + needs confirmation | A CyberRiskScape boundary is a "region", so it cannot be drawn as is (§5) |
| Data flow not connected to anything | Annotation (with coordinates) + needs confirmation | |
| Notes | Annotation (with the author and date) | |
| Multiple diagrams (tabs) | Layers L1, L2, L3, L0 in order from the first | The fifth and later are not imported; their names are shown |

### 3.2 Type mapping

Only types whose meaning clearly matches become dedicated types; everything else goes to the basic DFD types (Process, Data store, External entity).
Moving a type changes which threat rules apply, so anything doubtful is not moved.

| TMT type | CyberRiskScape type |
|---|---|
| Web Server, Web Application | Front-end Server |
| Web Service | Backend API |
| Human User | User |
| Browser | PC (the user's device) |
| Authorization Provider | IdP |
| External Web Application, External Web Service | SaaS |
| SQL Database, Non Relational Database | Database |
| Cloud Storage | Storage |
| HTTP, HTTPS, IPsec, SMB, etc. | Edge protocol |
| Thread, Registry, Named Pipe, Virtual Machine, etc. | Basic DFD types such as Process and Data store |

**Types from Azure templates or custom templates**, even when not in the mapping table, are imported as their parent type (Process, External entity, or Data store).
The original type is kept in the node description with `[TMT] needs confirmation`.

### 3.3 Model information and threats

| TMT | CyberRiskScape |
|---|---|
| Threat Model Name, High Level System Description | Project name and purpose |
| Owner, Reviewer, Contributors, Assumptions, External Dependencies | Project owner, reviewer, stakeholders, assumptions, external dependencies (editable in the project edit dialog, and included in the report) |
| Threat (title, description, STRIDE category, Priority) | A **manual threat**, tied to that data flow's edge. Priority goes into severity |
| State Mitigated / Not Applicable / Needs Investigation | Mitigation implementation status Implemented / Not applicable / Needs action |
| Justification, who changed it, change date | The implementation status note, changer, and date |
| All fields of a threat (ID, kind, original state, etc.) | Saved as is, without reinterpretation, as the manual threat's original record |

A threat still untouched in TMT (Not Started) is imported without an implementation status.

> When you change the implementation status on the screen, the changer display disappears. CyberRiskScape does not know who is operating it, and keeping it
> would show another person's change under the original person's name. The original TMT changer remains in the manual threat's original record.

---

## 4. How to read the migration report

The report cross-checks the threats imported from TMT against the threats CyberRiskScape detects from the same diagram, by **element (edge and its two ends) × STRIDE category**.
TMT threats are generic STRIDE questions and do not map one to one onto CyberRiskScape rules, so they are not matched by name.
An "overlap" only shows that a concrete threat answers the same question; it does not mean they are the same threat.

| Section | Content | How to use it |
|---|---|---|
| 1. Overview | The number of TMT threats (by status), detected threats (by severity), overlaps, and threats raised on unset assumptions | Grasp the scale of the migration |
| 2. Decisions to revisit | Threats you set Mitigated or Not Applicable in TMT where the same element and category still has a detected threat that is not suppressed (with the changer) | **Look here first.** Check whether the premise of the TMT decision also holds for the concrete threat |
| 3. Mapping per TMT threat | All of them, with the detected threats that matched | See whether anything was missed in the handover |
| 4. Threats only CyberRiskScape detected | Detected threats that overlap with no TMT threat (highest severity first, with the assumption mark) | Perspectives missing from TMT's default templates (concrete threats per type, AI, agents, and so on) |
| 5. Next steps | What to do after the import | Same as §5 |

Elements carry the same display IDs as the screen (C1, DF1, and so on), so elements with the same name can be told apart.

---

## 5. What to check after the import

1. **Look at `[TMT] needs confirmation`.** It applies to types not in the mapping table, trust boundaries drawn as lines, and unconnected edges.
   - Redraw a trust boundary drawn as a line with a CyberRiskScape boundary (a region), using the annotation's coordinates as a guide. An element on the
     internet side is treated as Internet if you do not put it in any boundary.
   - Reconnect an unconnected edge to the elements at its two ends.
2. **Look at the "assumed because unset" threats.** Attributes left "Not Selected" in TMT are treated as the bad value in CyberRiskScape
   (an unset attribute is treated like the dangerous value). Enter the actual authentication method, encryption, attack surface, operational posture, and so on, and the assumed threats disappear.
3. **Record the decisions in section 2 of the migration report again as CyberRiskScape's response policy and implementation status.**

---

## 6. Limits

- There is no public specification for .tm7, so the file is read to match the shape that was checked (TMT 7.3, file format 4.3). Depending on the version it may
  not be readable, or some parts may be missing. After the import, compare the counts of elements, edges, and threats with the TMT screen.
- TMT templates' **threat generation conditions are not used**. Threats are raised again by CyberRiskScape's threat engine.
- Information TMT does not have, such as authentication method (MFA, certificate, and so on) and data kinds, is not imported. Enter it after the import.
- There is no export (CyberRiskScape → .tm7).
- Importing from the screen replaces the current project.

---

## 7. Related

- [Reading the Threat Panel](reading-threats.md) — the "assumed because unset" mark, and recording the response policy and implementation status
- [Integrations](integrations.md)
