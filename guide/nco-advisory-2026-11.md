# Checking the November 2026 Japanese Government Advisory with a Member-Site and App Diagram

**English** | [日本語](nco-advisory-2026-11.ja.md)

> This page shows how to check the measures in the National Cybersecurity Office (Cabinet Secretariat, Japan) advisory
> "Measures against unauthorized access that leads to leaks of personal information: thoroughly applying basic measures for websites and mobile apps"
> (published 5 November 2026; [reference 1](#references)) using CyberRiskScape diagrams, imports, exports and the checklist,
> with a fictional member website and mobile app as the example.
> The National Cybersecurity Office did not write, certify or endorse this page. The advisory is summarized here, not reproduced.
> Always read the original for the exact measures and the latest information. Counts and outputs are measured values at the time of writing (November 2026).
> All organization names, host names and CVE numbers in the examples are fictional (IP addresses are from the documentation ranges; CVEs start with `CVE-2099-`).
> The original advisory is in Japanese. This page is the English translation of the Japanese guide.

---

## 1. What this page covers and prerequisites

- How to check each measure in the advisory (operations: 1-(1) to 1-(3); design and development: 2-(1) to 2-(3); supply chain: 3-(1) and 3-(2))
  **in CyberRiskScape: which screen or command**
- A diagram (template) of a fictional member website and mobile app, and the threats it produces
- The command sequence that **overlays vulnerability findings, SBOMs and externally visible assets on the diagram and decides what to fix first** (section 5)
- The 12-item **advisory checklist**, and how to use it to stop a release in CI

**Summary of the advisory**

Unauthorized access that leads to leaks of personal information continues. The advisory asks organizations to apply basic measures
to their websites and mobile apps without exception. It rests on two ideas.

1. **With AI, combinations of vulnerabilities and weak settings that are each rated low can become a foothold for intrusion.**
   Fixing only the high-rated ones is not enough.
2. **Keep reconciling your own inventory of assets with what is actually visible from the outside.**
   Look for public services you did not know about, and admin consoles you thought were closed.

**What CyberRiskScape covers**

CyberRiskScape **derives threats from the design (the diagram) and overlays other products' results on it to give them context.**
It does **not** run scans or ASM, **keep** vulnerability or end-of-support databases, **judge** license compliance, or **evaluate** contractors.
It does not say "exploitable" or "can detect". It outputs **facts and recommendations** that can be read from the diagram and the imported records; people decide (section 8).

**Prerequisites**

- Background: [Getting Started](getting-started.md), [Reading the Threat Panel](reading-threats.md), [Creating and Using Templates](templates.md)
- The commands here use `dist-cli/main.js`, built with `npm run build:cli` ([CI integration](ci-integration.md)).
  You need Node.js. You do not need Python or an external network
- The SBOM, KEV and ASM files **come from other products or public sources that you prepare yourself** (CyberRiskScape neither ships nor fetches them).
  This page uses tiny fictional samples placed alongside the template
- **The CLI prints its reports in Japanese.** The output excerpts below are shown as the CLI prints them, with English glosses in parentheses

---

## 2. The example system: load the template and check the structure

A **fictional system** is drawn on one layer.

- Members use a website (browser) and a smartphone app. A reverse proxy (including a CDN) sits in front of the entry points
- The website is a front-end server; the app calls the member API through an API gateway. The member API uses the member database (personal information) and a storage for forms and images
- The **admin console** sits behind a path-based routing rule of the front reverse proxy. The console itself has no global IP
- A contractor's staff do maintenance from a maintenance VPN appliance through a bastion
- A CI pipeline deploys to the member API. **The production member database and the CI share one cloud account (a management boundary)**
- The attacker (using AI to look for combinations of weak points) has the member database as the objective

| File | Content |
|---|---|
| [`templates/nco-advisory-2026-11.en.json`](templates/nco-advisory-2026-11.en.json) ([Japanese](templates/nco-advisory-2026-11.ja.json)) | The template. Load it in the app ([how to load](templates.md#3-importing)) |
| [`templates/nco-advisory-2026-11-project.en.json`](templates/nco-advisory-2026-11-project.en.json) ([Japanese](templates/nco-advisory-2026-11-project.ja.json)) | The same diagram as a project JSON, which you can pass straight to the CLI (section 5) |
| `templates/nco-sample-*` | Fictional samples for section 5 (two SBOMs, one KEV file, one Shodan-style observation file, one host-to-node map) |

**Diagram contents:** 16 components, 17 data flows, 5 boundaries (3 trust boundaries, 1 management boundary, 1 development segment).
Loading it detects **140 threats** (Critical 14, High 73, Medium 53; measured).

| Place | What is drawn (type) |
|---|---|
| External boundary (Internet) | Member (`User`, containing a smartphone), maintenance contractor staff (`User`, trust = contractor), attacker (`Agentic Attacker`) |
| Public segment (Public Area) | Front reverse proxy / CDN (`Reverse Proxy`), member site (`Front-end Server`), API gateway, IdP, maintenance VPN appliance |
| Internal segment (Internal) | Admin console (`Admin Console`), member API (`Backend API`), bastion, member DB (`Database`, containing personal information), storage for forms and images (`Storage`), CI pipeline |
| Management boundary (accounts, etc.) | Encloses the member DB, the storage and the CI pipeline. The CI is further inside a "Development" segment |

**Deliberately left unset.** The admin console's "remote access restriction", the API gateway's "rate limit",
the posture of the bastion, the VPN appliance, the IdP and the CI pipeline, and more are empty.
CyberRiskScape treats **unset the same as a bad value** when deriving threats. The screen marks them "assumed", and the mark disappears when you enter the real state.

**Threats directly tied to the advisory** (measured right after loading)

| Threat | Where | Severity |
|---|---|---|
| Reaching the management plane through the front proxy's routing rules | C10 Admin console | High |
| Brute force / credential stuffing against login and password-reset entry points | C6 Member site, C7 API gateway | Medium |
| Brute force / credential stuffing against the IdP login | C8 IdP | High |
| Caller identification by a secret embedded in browser JavaScript | DF4 (member browser to API gateway) | Medium |
| Sensitive-system access by an external collaborator (contractor) | DF7 (contractor to VPN appliance) | Medium |
| Production data sharing a management boundary with development and CI | C13 Member DB, C15 Storage | High |

> **Drawing note.** The admin console uses the `Admin Console` type, not `Front-end Server`, so that threats specific to management planes fire.
> Its "Global IP" is entered as "No" to express "we think it is not exposed".
> A line from the front proxy still produces the reach-through-the-proxy threat.

---

## 3. The advisory's measures and CyberRiskScape

"Output" lists what actually appeared for this diagram. "Does not do" is **outside the tool's scope** and needs another means.
**Where several means exist, any one is enough** (for example, ASM from Shodan or ScopeSentry; an SBOM in CycloneDX or SPDX).

### 3.1 Operations and management

| Requirement | Where to look in CyberRiskScape / what to do | Output | Does not do |
|---|---|---|---|
| **1-(1)** Know your assets (software composition) and fix vulnerabilities | Attach your SBOM to nodes with `import-sbom`. Match the KEV catalog with `import-kev`, fill patch posture with `fill-patch-status`, and read P1 to P4 with `findings-priority`. Accept delivered SBOMs with `sbom-report` | Per-finding priority with reasons (exposure, reachable targets, KEV, chains); nodes without an SBOM; parts with an empty license field | Detecting vulnerabilities, keeping vulnerability or end-of-support data, judging license compliance |
| **1-(2)** Continuously know and minimize the attack surface (do not expose admin, debug, test or DB-admin) | Save externally visible assets with `import-shodan --into` or `import-scopesentry --into`, and reconcile them with the diagram's "externally exposed" input using `asm-reconcile`. Draw admin consoles with the `Admin Console` type. Look up an alert's IP or host with `context` | "Visible from outside but not in the diagram" and "entered as not exposed but visible" lists; reaching the management plane through the front proxy | Running ASM. Anything not observed is not listed (out of observation range) |
| **1-(3)** Continuous testing and monitoring (including AI) | `export-test-plan --changed-from` makes a re-test plan for only what changed. `export-detection-requirements` lists behaviors to monitor on attack paths and the segments where logs do not reach monitoring | Re-test target nodes, monitoring requirements, segments where logs do not arrive | Running tests or monitoring. It never says "can detect" |

### 3.2 Design and development

| Requirement | Where to look in CyberRiskScape / what to do | Output | Does not do |
|---|---|---|---|
| **2-(1)** Security by design (threat modeling, requirements, no public admin, zero trust, cloud account separation) | Drawing the diagram and deriving threats is the threat modeling. `export-requirements` (also in the left sidebar) drafts the requirements to decide at design time. Draw management boundaries to check that production and dev/CI do not share one | A requirement list with tiers (Foundation / Enterprise / Advanced); the shared-management-boundary threat | Deciding which requirements to adopt (people decide); checking real cloud settings |
| **2-(2)** API security (authn/z, rate limiting, credential stuffing) | Enter the **rate limit** attack-surface attribute on public entry points. Draw APIs as `Backend API` / `API Gateway`. Use the threat cards' check points for authorization flaws (BOLA, BFLA) | Brute-force / credential-stuffing threats (API and IdP), authorization flaws, secrets embedded in browsers and apps | Verifying the authorization implementation (use API tests) |
| **2-(3)** Pre-release vulnerability testing (scope, ASVS) | `export-test-plan` fixes the scope and test points; each point carries OWASP ASVS 5.0 requirement IDs as references. Import SARIF results with `import-sarif`, and stop the release with `analyze --fail-on-findings` while findings at or above the threshold remain | Test scope, points and ASVS references; the number of remaining findings | Running the tests |

### 3.3 Supply chain

| Requirement | Where to look in CyberRiskScape / what to do | Output | Does not do |
|---|---|---|---|
| **3-(1)** Control contractors and connection paths (MFA, IP restriction, open only during work, logs, remove accounts after work) | Draw contractors as `User` (trust = contractor) and enter the real authentication on the lines to the VPN and bastion. `export-contractor-paths` (also in the left sidebar) lists paths in **priority order for switching to MFA**. A user whose trust is unset is also treated as someone not confirmed to be an employee | A list of connection paths (authentication, MFA-equivalent or not, source IP restriction, logs); the threat of a standing maintenance connection | Evaluating contractors. Identification is a heuristic, and each row is a "candidate to check". Whether the link is open only during work and whether accounts were removed must be checked on the real systems |
| **3-(2)** Manage OSS and external libraries (SBOM, vulnerability matching, licenses, acceptance) | `import-sbom` stores parts and the license field. `sbom-report` shows parts not tied to the diagram, old BOMs and parts with an empty license field. When a serious vulnerability is announced, `context --purl` shows which nodes are affected | Each part's link to a node, finding counts, empty license fields | Judging license compliance or accepting/rejecting a delivery |

---

## 4. List the state of 12 items with the advisory checklist

In the left sidebar's **Report** menu, open the **advisory checklist** and choose `nco-advisory-2026-11` (after you choose a layer, it lists
each item's status, the nodes to check and how to check). The CLI gives the same list.

```bash
node dist-cli/main.js checklist guide/templates/nco-advisory-2026-11-project.en.json \
  --id nco-advisory-2026-11 --format md --as-of 2026-11-07
```

```text
## 集計  (Summary)

要対応 11; 未入力 0; リスク受容 0; 問題なし 0; 対象なし 1
(Action needed 11; Unset 0; Risk accepted 0; No issue 0; Not applicable 1)
```

(The result is the same before and after the section 5 imports.) The mapping between the 12 items and the advisory's measures is below
(CyberRiskScape's own interpretation).

| Item | Content | Advisory measure | State for this diagram |
|---|---|---|---|
| nco-01 | Know software composition and fix vulnerabilities | 1-(1) | Action needed |
| nco-02 | Public exposure of admin consoles / admin APIs, and front-proxy routing rules | 1-(2) | Action needed |
| nco-03 | Exposed debug features, test environments and DB admin functions | 1-(2) | Action needed |
| nco-04 | Public settings of cloud storage and firewalls | 1-(2) | Action needed |
| nco-05 | Log collection and monitoring for suspicious access | 1-(3) | Action needed |
| nco-06 | API authorization flaws (BOLA, BFLA) | 2-(2) | Action needed |
| nco-07 | Credentials embedded in apps and source code | 2-(2) | Action needed |
| nco-08 | Brute force against authentication and password reset, and rate limiting | 2-(2) | Action needed |
| nco-09 | Pre-release testing (injection, code execution, SSRF) | 2-(3) | Action needed |
| nco-10 | Contractor connection paths and MFA | 3-(1) | Action needed |
| nco-11 | Review of contractor accounts and admin rights after work | 3-(1) | Action needed |
| nco-12 | Know OSS and external libraries, and first response | 3-(2) | Not applicable |

- **2-(1) Security by design** cannot be judged by particular threat rules, so it is not a checklist item.
  Use the `export-requirements` list for it
- **nco-12 is "Not applicable"** because the diagram has no node of the checklist's target type (package dependencies).
  SBOM parts are stored as parts attached to nodes (section 5). To draw an app repository's dependencies, create package-dependency nodes with
  `import-repo` ([Importing a repository](repo-import.md))
- "No issue" means **nothing came up within what the diagram represents**. It does not mean the real systems have no problem
- The end of the list shows nodes whose last review date is unrecorded or older than 30 days

The item definitions are in [`data/checklists/nco-advisory-2026-11.yaml`](../data/checklists/nco-advisory-2026-11.yaml).
The meaning of the states and the routine for keeping them up to date are the same as in [Checking IPA's October 2026 Alert with a Membership-Site Diagram](ipa-alert-2026-10.md).

---

## 5. The command sequence: import, prioritize, reconcile, export

From here, put the diagram in a working directory and run the commands in order.
Pass each command's `-o` (`--out`) output to the next command to chain them
(the original `member-site.json` is never rewritten).

```bash
cp guide/templates/nco-advisory-2026-11-project.en.json member-site.json
```

To use a diagram made in the app, use the project JSON saved from **File (Save / Open)** in the left sidebar.

### 5.1 Import the SBOM (1-(1), 3-(2))

`--node` sets the node that the SBOM's parts attach to (the C number shown on screen).
`--scope` is the range replaced on re-import. **Either CycloneDX or SPDX is enough.**
CycloneDX `vulnerabilities` are stored as findings, except those a VEX marks `not_affected` and similar.

```bash
node dist-cli/main.js import-sbom member-site.json --sbom guide/templates/nco-sample-sbom.cdx.json \
  --scope web-app --node C6 -o step1.json
```

```text
- scope: web-app
- 保存 2 件（software 2）                  (2 parts saved)
- 指摘 1 件（除外 1 件）                   (1 finding, 1 excluded)
  - 除外: VEX の状態が not_affected・false_positive・resolved のもの   (excluded: VEX state not_affected / false_positive / resolved)
部品を取り込みました（保存 2 / 上限で除外 0、指摘 1 / VEX 等で除外 1）        (exit code 0)
```

Import the API-side SBOM under a different scope.

```bash
node dist-cli/main.js import-sbom step1.json --sbom guide/templates/nco-sample-sbom-api.cdx.json \
  --scope api --node C11 -o step2.json
# 部品を取り込みました（保存 1 / 上限で除外 0、指摘 1 / VEX 等で除外 0）        (exit code 0)
```

### 5.2 Match KEV and fill patch posture (1-(1))

`import-kev` matches findings' CVEs against a CISA KEV catalog (JSON) **that you prepare yourself**. The catalog is not bundled, and there is no network access.
Download the latest catalog from CISA's public page. This page uses a tiny fictional catalog
([`templates/nco-sample-kev.json`](templates/nco-sample-kev.json), listing only `CVE-2099-0001`).
Being listed in KEV is the fact that CISA has confirmed exploitation. Not being listed does not mean "not exploited".

```bash
node dist-cli/main.js import-kev step2.json --kev guide/templates/nco-sample-kev.json -o step3.json
```

```text
- 照合した指摘（CVE を持つもの）: 2 件 / 印を付けた指摘: 1 件 / 印を外した指摘: 0 件
  (findings with a CVE matched: 2 / marked: 1 / unmarked: 0)
## ノード別（印を付けた指摘）  (by node)
- C6 会員サイト: 1 件
KEV と照合しました（対象 2 / 印を付けた 1 / 外した 0）        (exit code 0)
```

`fill-patch-status` sets posture **patch = unset** to "Missing" on nodes that have a finding with a CVE.
It never overwrites an entered value and never writes "up to date" (having no findings does not prove up to date).

```bash
node dist-cli/main.js fill-patch-status step3.json -o step4.json
```

```text
- 補完したノード: 1 件  (nodes filled: 1)
- 見送り: 入力済み 1 / 型がパッチ状況を持たない 0 / ノードに結びつかない指摘 0  (skipped: already entered 1 / ...)
- L1 会員サイト（FRONT_END_SERVER）: CVE-2099-0001
パッチ状況を補完しました（補完 1 件）        (exit code 0)
```

### 5.3 Read finding priority: combinations of low ratings (1-(1))

`findings-priority` overlays stored findings on attack paths and outputs a recommended priority (P1 to P4) with reasons.
**It does not change the original severity.** It is a recommendation; people decide.

```bash
node dist-cli/main.js findings-priority step4.json
```

```text
- 指摘 2 件 / 連鎖 3 件   (2 findings / 3 chains)

## P1（先に確認）（2 件）  (P1: check first, 2)
| CVE-2099-0002 example-image-lib@1.0.5 | CycloneDX | Medium | C11 会員 API | 入口（仮定） | C16 CI パイプライン（1 ホップ）、C13 会員 DB（1 ホップ）、… | — |
| CVE-2099-0001 example-web-framework@4.2.1 | CycloneDX | Medium | C6 会員サイト | 入口（仮定） | C8 IdP（3 ホップ）、…、C13 会員 DB（4 ホップ） | あり（2099-01-01） |

## 組み合わさると標的に届く連鎖  (chains that reach a target when combined)
- 経路上で指摘が 2 つ以上のノードに並ぶ連鎖 3 件のうち、個々の指摘はすべて Medium 以下 3 件。
  (of 3 chains with findings on 2 or more nodes, all 3 have only Medium-or-lower findings)
- 【個々は低いが連鎖で届く】攻撃者 → C6 会員サイト → C11 会員 API → C13 会員 DB（指摘の深刻度: Medium / Medium）
  (low individually, but reaches the target as a chain: attacker -> C6 -> C11 -> C13)
                                                                              (exit code 0)
```

This is the advisory's central idea. **Both findings are Medium.** Alone, that rating gets postponed.
But they sit on one path (attacker to member site to member API to member DB), so they are shown as a chain. A finding listed in KEV is a candidate to check first.

- "入口（仮定） (entry point, assumed)" means exposure was judged by assuming a bad value for unset attack-surface attributes
- The output may carry the note "path enumeration hit its limit, so chains may be missing". It did for this diagram. Read chains as "at least these"

### 5.4 Overlay externally visible assets and reconcile (1-(2))

Save ASM results as assets. **Either Shodan or ScopeSentry is enough.**
(`import-scopesentry --into` has the same shape. See [Importing ScopeSentry](scopesentry.md).)
`--map` maps host names or IPs to diagram nodes (hosts left out stay "unmapped").

```bash
node dist-cli/main.js import-shodan guide/templates/nco-sample-shodan.json --into step4.json \
  --scope shodan-2026-11 --map guide/templates/nco-sample-asm-map.json --out step5.json
```

```text
Shodan のサービスを資産として保存しました（サービス 3 / CVE の識別子 0 / 未対応のホスト 1）
(saved 3 services as assets / 0 CVE identifiers / 1 unmapped host)        (exit code 0)
```

`asm-reconcile` is a read-only report that **lists mismatches** between what ASM observed and the diagram's "externally exposed" (Global IP) input.
It does not judge which is right. The exit code is always 0.

```bash
node dist-cli/main.js asm-reconcile step5.json
```

```text
- 観測した資産 3 件 / 図に無い 1 件 / 非公開と入力 1 件 / 未入力 0 件 / 公開と入力したが観測に無い 3 件
  (3 observed / 1 not in the diagram / 1 entered as not exposed / 0 unset / 3 entered as exposed but not observed)

## 図に無いのに外から見える（1 件）  (visible from outside but not in the diagram)
| 203.0.113.51 | 203.0.113.51 | 22 | ssh | Shodan | 2026-11-03T03:05:00.000Z |

## 非公開と入力したのに外から見える（1 件）  (entered as not exposed but visible)
| 203.0.113.50 | 203.0.113.50 | 8443 | https | Shodan | 2026-11-03T03:00:00.000Z | C10 Admin console |
```

- **Visible from outside but not in the diagram:** a public service missing from the inventory (the diagram). An SSH service is visible. Draw it in the diagram or close it
- **Entered as not exposed but visible:** the admin console (C10). The diagram says "no global IP", but it is reachable from outside
  through the front reverse proxy. This is the advisory's "admin console we thought was closed"
- "Entered as exposed but not observed" means outside the observation range, or an outdated diagram

Look up an alert's host, IP or part in the diagram with `context` (read-only). The MCP `lookup_context` does the same
([Using it over MCP](mcp-integration.md)).

```bash
node dist-cli/main.js context step5.json --host admin.example.com
```

```text
## 一致 1（asset）  (match 1)
- ノード: L1 C10 Admin console（ADMIN_CONSOLE）  (node)
- 信頼境界: ROUNDED（Internal）  (trust boundary)
- 前段: C5 Front reverse proxy / CDN（REVERSE_PROXY）  (front)
- 露出: 入口／届く標的: C16 CI pipeline（2 ホップ）、C13 Member DB（2 ホップ）、C8 IdP…（3 ホップ）  (exposure: entry point / reachable targets)
### 脅威（8 件）  (8 threats)
- High 前段の振り分けルールを経由した管理面への到達 [web-remote-management-exposure]  (reaching the management plane via front-proxy routing)
- High パスワード・API キー単独の認証 / 公衆網 [password-only-internet-channel]
…                                                                              (exit code 0)
```

You can look up a part too. Leaving out the version in `--purl` includes other versions.

```bash
node dist-cli/main.js context step5.json --purl pkg:npm/example-web-framework
# node: L1 C6 Member site (FRONT_END_SERVER) / 15 threats / 1 finding (CVE-2099-0001, recommended P1, KEV listed, in 3 chains)
```

### 5.5 Accept the SBOM (3-(2))

`sbom-report` **assists acceptance** of stored SBOMs. It lists the link to the diagram, age, finding counts and empty license fields.
It judges neither pass/fail nor license compliance. The exit code is always 0.

```bash
node dist-cli/main.js sbom-report step5.json
```

```text
- 保存済みの部品 3 件（CycloneDX・SPDX から取り込んだもの）/ SBOM の無いノード 8 件 / ライセンス欄が空の部品 1 件
  (3 parts stored / 8 nodes without an SBOM / 1 part with an empty license field)

## 取り込み単位ごとの状況  (per import unit)
| example-sbom-generator | web-app | 2 | C6 Member site | 2026-10-15T00:00:00.000Z | — |
| example-sbom-generator | api    | 1 | C11 Member API | 2026-10-15T00:00:00.000Z | — |

## 脆弱性（CycloneDX の vulnerabilities 由来の指摘）  (vulnerabilities)
| C6  | Critical 0 | High 0 | Medium 1 | Low 0 | KEV 1 |
| C11 | Critical 0 | High 0 | Medium 1 | Low 0 | KEV 0 |
```

- Ask the supplier about parts with an empty license field (`example-logger`). **A person decides whether a license is acceptable**
- "Nodes without an SBOM" are nodes of types that declare patch/dependency posture but have no attached parts. Use it as a list of whom to ask for SBOMs

### 5.6 Export requirements, contractor paths, detection requirements and a re-test plan (1-(3), 2-(1), 3-(1))

All exports are **drafts** derived from the diagram. People decide what to adopt and the priority.

```bash
node dist-cli/main.js export-requirements step5.json --out requirements.md
# (L1, 129 requirements, 6 requirements for contractors)

node dist-cli/main.js export-contractor-paths step5.json --out contractor-paths.md
# (L1, 1 path)

node dist-cli/main.js export-detection-requirements step5.json --out detection.md
# (L1, 7 target nodes, 37 monitoring requirements, 7 paths)

node dist-cli/main.js export-test-plan step5.json --out test-plan.md
# (L1, 6 entry points, 1 attack scenario, 140 focus test items, 0 out of scope)
```

(All exit with code 0. `--format` also accepts `csv` and `json` for some; see `--help`.)

- **Requirement list (2-(1)):** requirements are each threat's mitigations split into Foundation / Enterprise / Advanced.
  Choose the tiers you need at design time and carry them into requirement documents and contractor specifications. It is also available from the left sidebar's Report
- **Contractor paths (3-(1)):** one row appears for this diagram (the contractor's staff member to the maintenance VPN appliance to the bastion),
  shown with ID/password authentication (not MFA-equivalent) and reaching the member DB and personal information beyond the bastion.
  Lines from members' browsers and apps to the API gateway are normal use and are not counted.
  Identification is an estimate from attributes, lines and types, so treat each row as a "candidate to check".
  The order is the priority for switching to MFA. For paths that cannot take MFA, substitute source IP restriction, opening only during work and operation logs
- **Detection requirements (1-(3)):** for each node on paths from the attacker to the target, the behaviors to monitor and the logs needed.
  For this diagram every path reads "logs are not readable as reaching monitoring" (no log destination is entered).
  Check separately whether detection really works
- **Test plan (2-(3)):** each threat's check points carry OWASP ASVS 5.0 requirement IDs as references (for example `V8.4.2`, `V13.1.2`).
  Use it as the starting point for agreeing scope and points with the test provider. Test only systems you manage or have permission to test

**Re-test only what changed (1-(3)).** After changing the diagram, narrow the re-test to the difference from the previous model.
This example compares with the diagram before the CI pipeline was added (`before-ci.json`).

```bash
node dist-cli/main.js export-test-plan step5.json --changed-from before-ci.json --out retest.md
# (L1, 0 entry points, 0 attack scenarios, 4 focus test items, 0 out of scope)
```

```text
**再診断の対象ノード**  (re-test target nodes)
- C16 CI pipeline
```

The 140 focus items shrink to 4 for the added node.
For the previous model, pass the earlier project JSON you saved (for example, an older version from `git`).

### 5.7 Fix the diagram and the counts change (2-(2))

Actually put per-account and per-source attempt limits on the public entry points, then enter the attack-surface attribute **rate limit** as "Yes"
and run `diff`. The brute-force / credential-stuffing threats (2: member site and API gateway) and the threat of bulk personal-data retrieval through the API
(API gateway; High) go away, 3 in total.

```bash
node dist-cli/main.js diff step5.json rate-limited.json
```

```text
- 追加: 0 件  (added: 0)
- 解消: 3 件  (resolved: 3)
```

Do not only change the input: **change the real state first, then enter it** (an input is a declaration, not an observation). Distributed attempts are not stopped
by count limits alone. Also check the threat card's measures (failure-rate detection, MFA, passkeys, and so on).

### 5.8 Stop the release in CI (1-(3), 2-(3))

On a project JSON that holds the results of testing (SARIF or SBOM vulnerabilities), exit code 1 stops the pipeline when **stored findings**
reach the threshold. Trial-only findings and accepted findings are not counted.

```bash
node dist-cli/main.js analyze step5.json --fail-on-findings Medium --format md > /dev/null
# --fail-on-findings Medium: 2 stored findings at or above the threshold (excluding trial-only and accepted).
#   - [Medium] CycloneDX: CVE-2099-0001 example-web-framework@4.2.1 @ Member site
#   - [Medium] CycloneDX: CVE-2099-0002 example-image-lib@1.0.5 @ Member API
# (exit code 1)

node dist-cli/main.js analyze step5.json --fail-on-findings High --format md > /dev/null
# (exit code 0: no stored findings at High or above)
```

`--fail-on` counts the **threats** derived from the diagram (in `diff`, new threats). `--fail-on-findings` counts imported **findings**. You can use both.
For wiring into CI, see [CI integration](ci-integration.md).
We recommend first printing the list without stopping, and adding the stop once the work has progressed.

---

## 6. Keeping the diagram up to date

1. **Re-import SBOM, KEV and ASM.** Importing again with the same `--scope` replaces the earlier data. Re-importing KEV refreshes the marks (marks are removed from findings no longer listed)
2. **Reconcile observation and diagram regularly, for example monthly.** `asm-reconcile --previous previous.json` compares newly visible and no-longer-visible observations
3. **Narrow the re-test on every change.** `export-test-plan --changed-from`
4. **Empty the checklist's "stale nodes" list.** Updating each node's last-review date works as in section 7 of the [IPA alert guide](ipa-alert-2026-10.md)
5. **For the next advisory, just add a YAML file.** Checklists are YAML in `data/checklists/` and appear in both the screen and the CLI

---

## 7. What the diagram cannot show and what to check on the real systems

| Measure | What the diagram cannot tell | How to check |
|---|---|---|
| Fixing vulnerabilities | Actual patch state, end of support | Scanning real systems, vendor information. Posture inputs are declarations |
| Minimizing public services | Services outside the observation range | Keep running ASM. Only imported ranges are reconciled |
| Authorization implementation | Whether BOLA/BFLA really are absent | API tests (use `export-test-plan` points) |
| Attempt limits and distributed-attempt detection | Whether the limits work | Attempts against the authentication entry (in an environment you are allowed to test) |
| Contractor control | Whether the link opens only during work, whether accounts were removed | Contracts and operations with the contractor, account reviews |
| OSS management | Whether a license is acceptable, BOM completeness | Legal and procurement judgment, checking with whoever produced the SBOM |

---

## 8. Limits

- **CyberRiskScape is not a scanner, ASM or EDR.** It only adds context to imported results. What is not observed does not appear
- **It keeps no vulnerability or end-of-support database.** Findings are the content of the SBOMs and test results you import. KEV is a match against a file you prepare
- **It does not judge license compliance, evaluate contractors or accept deliveries.** It lists facts
- **It never says "exploitable" or "can detect".** Priority is a recommendation with reasons; people decide. Listed in KEV means CISA confirmed exploitation; not listed does not mean not exploited
- **It calls no LLM.** Exports are generated mechanically from rules and data
- **Path enumeration can be incomplete when it hits its limit.** Read chains as "at least these"
- The mapping between checklist items and threat rules or types is **CyberRiskScape's own interpretation**, not defined by the National Cybersecurity Office

---

## References

1. National Cybersecurity Office, Cabinet Secretariat, "Measures against unauthorized access that leads to leaks of personal information: thoroughly applying basic measures for websites and mobile apps" (5 November 2026, in Japanese)
   <https://www.cyber.go.jp/pdf/press/261105_taiou.pdf>
2. CISA, "Known Exploited Vulnerabilities Catalog" <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
3. OWASP, "Application Security Verification Standard" <https://owasp.org/www-project-application-security-verification-standard/>
4. CycloneDX specification <https://cyclonedx.org/specification/overview/>

## Next reads

- [Checking IPA's October 2026 Alert with a Membership-Site Diagram](ipa-alert-2026-10.md): reading the checklist, and keeping it up to date
- [Checking NICT's October 2026 A2B Attack Alert with a Member-App Diagram](a2b-attack-2026-10.md): attacks that analyze the app and target backend APIs
- [Importing an SBOM](sbom.md): SBOM formats and import
- [Reducing Internet Exposure](exposure-reduction.md): inventorying and reducing public assets
- [Penetration Test Plan](pentest-plan.md): agree scope with the test provider
- [Security Context Layer](security-context.md): the idea of overlaying imported results on the diagram
