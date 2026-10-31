# Cross-Reference Agent Skill and MCP Server Scan Results with the Threat Model (Cisco AI Defense skill-scanner / mcp-scanner)

**English** | [日本語](ai-scanners.ja.md)

> Cisco, skill-scanner, and mcp-scanner are names of their respective owners. Cisco is a trademark of Cisco Systems, Inc. This page explains how to
> cross-reference the results written by Cisco AI Defense's skill-scanner / mcp-scanner with a CyberRiskScape threat model. It is not provided,
> certified, or endorsed by the developers of these scanners and does not imply any affiliation; the use of the names is descriptive. The output
> format of the scanners follows the official sources as of the time of writing (October 2026). Check the official information for the latest.

> **Scope of scanning** — Scan only **skills and MCP servers you manage or are authorized to assess**. The cross-referencing on this page only reads
> result files that already exist. It does not connect to the scanners or to the Cisco AI Defense API and does not run any new scan.

---

## 1. What this page covers and prerequisites

- How to **cross-reference the result files of the agent skill scanner (skill-scanner) and the MCP server scanner (mcp-scanner) with the threats detected from the diagram**
  (`findings-report --skill-scanner` / `--mcp-scanner`). You can see which findings say the same thing as a threat on the diagram, and which findings have no counterpart on the diagram (candidates for something left undrawn)
- How to narrow the scope to one skill or MCP server (`--node`)
- How to use it as a severity gate in CI (`--fail-on`)
- What is not read (handling of secrets) and the **limits**

**Prerequisites**

- The diagram (a CyberRiskScape project JSON) has nodes for the skills or MCP servers.
- A scanner result file (JSON). The scanners are written in Python (§3). **Either scanner alone is enough.**
- Node.js. Build the CLI first (`npm ci && npm run build:cli`).
- **CLI only.** You cannot load a result file from the screen (§10).

**Choosing a route (any one is enough)**: you can start from any **one** of the following. You do not need all of them.

| Route | Good when | Prerequisites |
|---|---|---|
| skill-scanner only | You are adding skills used in your organization | Python 3.11 or later (the official docs state CPython 3.11–3.14); installing the scanner |
| mcp-scanner only | You are adding MCP servers (built or adopted) | Python 3.11 or later; a reachable server or a config file |
| Both | You use both skills and MCP servers | Both of the above. Run the cross-reference once per scanner |

**Background for this page**: the operations in [Getting Started](getting-started.md) and [Reading the Threat Panel](reading-threats.md).

---

## 2. Why combine them

| | Scanner (skill-scanner / mcp-scanner) | CyberRiskScape |
|---|---|---|
| Unit it looks at | A **component** (one skill, one MCP server and its tools) | The **whole** (how agents, data, permissions, and paths connect) |
| Question it answers | Does this component **contain anything bad?** | If this component is abused, **how far does it reach?** |

A single finding is worth fixing, but the scanner alone cannot tell **where that finding lands on the diagram** (the permissions the agent holds, the data it is connected to).
Conversely, zero findings does not mean safe. The skill-scanner README itself says that no findings is not a guarantee of no threats, and that for
important uses scanner results should be paired with manual review and threat modeling (source: "Scope and Limitations" in the official README; reference link 1).

The cross-referencing on this page does that combination mechanically.

1. The AITech / AISubtech classification codes on the scanner's findings are turned into threat library `canonicalId`s by a **mapping table** (§7)
2. Among the threats detected from the diagram, find the ones with the same `canonicalId`
3. If found, "the diagram's threat is confirmed in code"; if not, "no matching threat on the diagram" (a candidate for something left undrawn)

---

## 3. Run the scanner

### 3.1 skill-scanner

```bash
pip install cisco-ai-skill-scanner
skill-scanner scan ./my-skill --use-llm --format json --output skill-result.json
skill-scanner scan-all ./skills --recursive --use-llm --format json --output skill-result.json
```

- The `--format json` output is what is read: a single skill, or the combined form that `scan-all` writes for several skills. Both can be read.
- **LLM judging (`--use-llm`) is optional and needs an API key for an LLM provider (which may be paid).** The option to use the Cisco AI Defense API (`--use-aidefense`) is the same.
- **A rules-only scan (without `--use-llm`) detects only a limited set.** The official docs say every recommended setup runs the LLM judge, and that rules alone catch only part of the malicious skills.
  See the official README for choosing settings (reference link 1).
- The classification codes in the result (`AITech-…` / `AISubtech-…`) are the key for the cross-reference.

### 3.2 mcp-scanner

```bash
uv tool install --python 3.13 cisco-ai-mcp-scanner
# One server
mcp-scanner --analyzers yara --format raw --server-url https://mcp.example.com/mcp > mcp-result.json
# Output only the array of results (--raw)
mcp-scanner --analyzers yara --raw --server-url https://mcp.example.com/mcp > mcp-result.json
# All servers written in local config files
mcp-scanner --analyzers yara --raw known-configs > mcp-known-configs.json
```

- Three forms can be read: `--format raw`, `--raw`, and `known-configs --raw`. Human-oriented displays such as `summary` and `table` cannot be read.
- `--analyzers yara` is a rules-only scan and needs no API key. **The LLM analyzer (`llm`) and the Cisco AI Defense analyzer (`api`) are optional and need a key (which may be paid).**
  Rules alone detect only a limited set. See the official README for choosing analyzers (reference link 2).
- **Scanning a stdio server starts that server's process.** Run untrusted ones in an isolated environment.
- The result also contains items whose scan did not complete (`status` other than `completed`). They are counted as "items whose scan did not complete" in §6.

> CyberRiskScape **only reads these result files**. It does not run the scanners and does not call the Cisco AI Defense or LLM APIs.

---

## 4. Cross-reference

### 4.1 Commands

```bash
npm run build:cli
node dist-cli/main.js findings-report my-project.json --skill-scanner skill-result.json
node dist-cli/main.js findings-report my-project.json --mcp-scanner mcp-result.json --node C3
```

| Option | Meaning |
|---|---|
| `<project.json>` | The project JSON of the diagram to cross-reference (required) |
| `--skill-scanner <file>` / `--mcp-scanner <file>` | Scanner result. Specify **exactly one**, counting `--veracode` |
| `--node <C-number>` | The target node (optional). See §5 |
| `--format <md\|json>` | Output format. Default `md` |
| `--fail-on <Critical\|High\|Medium\|Low>` | Exit 1 if a finding lands on a threat of the given severity or higher on the diagram (§9) |
| `--layer`, `--framework`, `--locale`, `--out` | Target layer, framework, display language, and output file (same as the other `findings-report` uses) |

- Neither the input project JSON nor the result file is modified.
- A one-line count of open, matched, not in the diagram, and unmapped findings is written to standard error.
- Use `--locale en` for English output.

### 4.2 Example run (the bundled fictional samples)

The following output comes from the **fictional** samples bundled in the repository (a diagram of three nodes: a business agent, an invoice skill, and an internal search MCP; the scanner results are fictional too).

```bash
node dist-cli/main.js findings-report \
  src/features/findings-report/__fixtures__/cisco-sample-project.json \
  --skill-scanner src/features/findings-report/__fixtures__/skill-scanner-single.json \
  --locale en
```

```text
Cross-referenced (open 4, matched 2, not in diagram 0, unmapped 2, excluded SCA 0 / closed 0)
```

```text
# Scan findings vs. threat model

skill-scanner findings cross-referenced with the threats detected in the diagram, through an AITech taxonomy mapping table. Findings whose classification is not in the table appear under "Findings that could not be mapped".

- Open findings: 4
- Matching a diagram threat: 2 (threats: 5)
- No matching threat in the diagram: 0
- Could not be mapped: 2

## Diagram threats confirmed in code

### direct-prompt-injection

Diagram threats:
- [L1] Critical Direct prompt injection — C1 業務エージェント (owasp-llm01-prompt-injection-001)

- Findings: 1 (max severity HIGH)
  - #sk-001 [HIGH] AISubtech-1.1.1 Prompt injection: override of prior instructions (invoice-helper/SKILL.md:12)

(tool-descriptor-poisoning and excessive-agency follow in the same form)
```

(The "top findings to check", "findings with no matching diagram threat", "could not be mapped", and "gate" sections are omitted.) The node labels (業務エージェント = business agent) come from the sample diagram, which is in Japanese.

An example with the MCP server result narrowed to `C3` (the internal search MCP) and `--fail-on High`:

```bash
node dist-cli/main.js findings-report \
  src/features/findings-report/__fixtures__/cisco-sample-project.json \
  --mcp-scanner src/features/findings-report/__fixtures__/mcp-scanner-envelope.json \
  --node C3 --fail-on High --locale en
```

```text
Target node: C3 (only threats on this node, its edges, the nodes across those edges, and its containing parent/children are cross-referenced)

- Open findings: 3
- Matching a diagram threat: 2 (threats: 3)
- No matching threat in the diagram: 0
- Could not be mapped: 1
- Items whose scan did not complete: 1 (an unscanned item is not necessarily safe)

## Gate result

FAIL (2 finding(s) backed by an unsuppressed threat at or above High)
```

The exit code is 1. Use `--format json` for machine processing (the keys are fixed in English: `summary`, `confirmed`, `notInModel`, `unmapped`, `priority`, `gate`, and so on).

---

## 5. `--node` — narrow the scope

With `--node C3`, findings are cross-referenced only with these threats on the diagram. Without it, the whole diagram is used.

- Threats of the node itself
- Threats of the **links** touching the node
- Threats of the **nodes at the other end** of those links
- Threats of the node's **parent and children** (containment)

**Why wider than the node itself**: the malicious code of a skill or MCP server **runs on the agent that calls it**.
So a finding's impact reaches not only the skill itself but also the agents and data connected to it.
([Prowler](prowler.md), which brings in cloud scan results, looks at the settings of the resource itself, so it uses "the node itself only". This one is widened by a step.)

If the C-number given to `--node` is not in the target layer, it fails (exit code 2) and the IDs you can specify are shown.

---

## 6. How to read the result

| Heading | Meaning | What to do |
|---|---|---|
| Diagram threats confirmed in code | The finding's classification matches the same `canonicalId` as a threat detected on the diagram | Decide the order of fixes from both the diagram threat's severity and the finding's severity. Also check the mitigations on the threat card |
| Findings with no matching diagram threat (candidates for something left undrawn) | The classification is in the table, but the diagram shows no such threat | The component may not be on the diagram, or its attributes or links may be missing. **Add it to the diagram** |
| Findings that could not be mapped | The classification is not in the table, or no classification is attached | Handle it as a scanner finding on its own. Consider whether adding it to the table is worthwhile |
| Items whose scan did not complete | mcp-scanner `status` other than `completed` (`partial`, `failed`, `skipped`) | **Items that were not scanned are not necessarily safe.** Fix the cause (connection, key, timeout) and rerun |

- "Top findings to check" is the top of the list ordered by both the diagram threat's severity and the scanner's severity.
- **Severity differs by scanner**: skill-scanner has a severity per finding (CRITICAL to INFO). mcp-scanner gives an **aggregated severity per analyzer**, not per finding.
- **What "open" counts**: every scanner finding is counted as open (the results have no notion of "resolved" as Veracode's do).

---

## 7. The AITech mapping table

The table is [`data/finding-maps/aitech.yaml`](../data/finding-maps/aitech.yaml) (like the threat knowledge, it lives in YAML, not in code).
It refers only to the code scheme of the Cisco AI Security and Safety Taxonomy (AITech = technique, AISubtech = sub-technique) and does not reproduce the definitions.

- **Lookup**: the finding's AISubtech row if there is one; otherwise the parent AITech row.
- **Older numbers are caught**: mcp-scanner can emit older sub-technique numbers (for example, Tool Shadowing as `AISubtech-12.1.5`; it is 12.1.4 in taxonomy 2.0.0).
  Even if the sub-technique number is off, the parent AITech row (here `AITech-12.1`) catches it.
- **Deliberately not included**: kinds of harmful content (abuse, discrimination, and so on; malware is included), kinds of personal information, sensors, cross-modal, and similar
  codes that rarely apply as threats on a diagram. Findings with codes that are not included appear under "Findings that could not be mapped".
- One code can land on several `canonicalId`s. Which of them is confirmed depends on which appear on the diagram.
- Few `canonicalId`s land on the skill and MCP server types themselves (5 for skills, 3 for MCP servers). Code execution, exfiltration, and the like come from rules on the **agent** that loads the skill.
  That is why the `--node` of §5 looks as far as the calling side.
- The table can be extended or corrected by editing YAML only, without touching code.

---

## 8. Handling of secrets

Scanner results can contain fragments of the scanned code and connection information. The cross-reference handles them as follows.

- **Not read**: `snippet` (a code fragment that may contain an embedded secret as is), `description`, `remediation` (free text), `tool_description`,
  `server_url` (for stdio, the command and arguments, which may contain tokens), `skill_path` (environment information such as absolute paths), and `server_source`.
- **What appears in the output**: only the finding identifier, severity, classification code, short title, and location (a relative path and line inside the skill; the server name and tool name for MCP).
- Tests confirm that values that look like secrets do not appear in the output.
- **Do not handle the result file casually.** It contains items that are not read, so do not put it in a public repository, ticket, or chat.

---

## 9. Use it in CI

Create the scanner result file, then use `findings-report --fail-on` as a severity gate.
Building the CLI is written the same way as in [Integrating with AI-Driven Development CI](ci-integration.md).

```yaml
name: ai-scanners
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4          # Pin to a commit SHA in production
      - uses: actions/checkout@v4
        with:
          repository: takashi-ohmoto-git/CyberRiskScape
          ref: <commit SHA>                 # Pin to a SHA, not a tag
          path: crs
      - run: cd crs && npm ci && npm run build:cli
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install cisco-ai-skill-scanner
      - name: Scan skills (rules only; add --use-llm with a key for better detection)
        run: skill-scanner scan-all ./skills --recursive --format json --output skill-result.json
      - name: Cross-reference with the threat model
        run: node crs/dist-cli/main.js findings-report threat-model/project.json --skill-scanner skill-result.json --fail-on High --out findings-report.md
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: findings-report
          path: findings-report.md
```

- `--fail-on High` exits 1 when there is a **finding that lands on a threat of High or higher on the diagram**. Findings with no counterpart on the diagram and findings that could not be mapped
  do not count toward the gate (they still appear in the report).
- A rules-only scan detects a limited set. Passing the gate does not mean safe (§10). If you use LLM judging, pass the key through `secrets` and only to the step that creates the result file.
- Items whose scan did not complete (mcp-scanner) are counted in the report but are not part of the gate. Check the report.
- If you keep the result file and report as artifacts, be careful about who can read them in a public repository (§8).

---

## 10. Limits

- **Verification was done with fictional samples matched to the official documentation and code. It has not been checked against the output of real scanners.**
  The scanners' output format may change in the future. Items that cannot be read are reported in the counts, so first check that the counts are as expected.
- **Zero findings does not make a threat go away.** The diagram's threats come from the configuration, independently of the scanners. The policy is "unset is treated the same as a bad value";
  even with zero findings, only the real mitigations and inputs reduce the diagram's threats. As the scanner README says, zero findings is not a guarantee of safety.
- **Only the codes in the table are covered.** Classifications that are not in it appear under "Findings that could not be mapped".
- **Operational posture is not filled automatically.** For example, a skill's vetting status (`skillVetting`) is not set to "done" because the skill went through a scanner.
  The diagram is not changed, so a person enters it.
- **Not available from the screen.** Only the CLI reading a file. CyberRiskScape does not call the Cisco AI Defense API or run the scanners.
- **The scanner's severity and the diagram's severity are different things.** They are shown side by side but are not added or adjusted.

---

## Reference links

1. skill-scanner (GitHub) — <https://github.com/cisco-ai-defense/skill-scanner>
   Output formats — <https://github.com/cisco-ai-defense/skill-scanner/blob/main/docs/reference/output-formats.md>
2. mcp-scanner (GitHub) — <https://github.com/cisco-ai-defense/mcp-scanner>
   Output formats — <https://github.com/cisco-ai-defense/mcp-scanner/blob/main/docs/output-formats.md>

---

## What to read next

- How to read threats — [Reading the Threat Panel](reading-threats.md)
- An integration with a similar way of cross-checking — [Fixing Veracode Findings with AI](veracode-remediation.md)
- Putting it in CI — [Integrating with AI-Driven Development CI](ci-integration.md)
- Investigate attack paths from the detected threats — [Attack Path Analysis](attack-paths.md)
- Put cloud scan results on the diagram — [Putting Prowler Findings on the Diagram](prowler.md)
