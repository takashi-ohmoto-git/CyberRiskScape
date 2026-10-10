# Using It from Coding Agents — MCP Server Setup Guide

**English** | [日本語](mcp-integration.ja.md)

The [previous chapter (CI integration)](ci-integration.md) explained how to wire a saved project
JSON into CI as a source-of-record file. This chapter continues from there: it explains how to let
**coding agents (Claude Code, GitHub Copilot, and others) query threats while they design, and
update the diagram**. The connection uses MCP (Model Context Protocol), so any MCP-capable client
can use the same server.

For how to use it in each situation, see [MCP Use Cases](mcp-use-cases.md).

---

## What to do first

1. **Build** — at the repository root, run `npm install` and `npm run build:cli` (details in §3)
2. **Register it with your client** — pick your client's configuration from §4 and write it
   (Claude Code, Copilot in VS Code, the Copilot coding agent, Cursor)
3. **Check that it works** — ask the agent the following. If it returns the component types and
   threat rules, the connection works (you can try it without any model JSON)

```text
Using the CyberRiskScape MCP tools, list the component types and give me three threat rules
that apply to a database (type DB).
```

---

## 1. What it can do

The CyberRiskScape CLI has an `mcp` subcommand that runs as an MCP server. An agent can:

- **Ask about threats while designing** — read the structure of a saved model and the detected
  threats, mitigations and sources. Even before a model exists, it can look up which threats apply
  to a given component type
- **Update the diagram and see the impact immediately** — add, change or delete nodes, edges, trust
  boundaries, attributes and annotations, and receive how the threats changed as a result, plus any
  matching change triggers (T1–T8)

What it cannot do (by design) is make **changes that belong to human judgment**. An agent cannot
change the following (it can read them):

- Accepting a threat or marking it as a false positive
- Risk assessments
- Mitigation implementation status
- Manually added threats
- Project information

Agents are also never asked to supply coordinates (see §6). The server makes no external network
calls and no LLM calls, so it works on a closed network.

---

## 2. Roles — AI and humans

The agent writes directly to the model JSON in the working tree (the source of record). Human
judgment is then concentrated in the **PR diff gate**.

```
Agent updates the structure (apply_model_changes)
        │   receives the threat diff and matching triggers right away
        ↓
The change becomes a PR (a diff of the model JSON)
        │
        ↓
CI's model diff gate (the GitHub Action from the previous chapter) posts the same diff and triggers on the PR
        │
        ↓
A human (designated reviewer) decides
```

The diff the agent sees and the diff a human sees on the PR are produced by the same mechanism. The
agent learns what changed on the spot, and the human confirms the same content on the PR and makes
the final call. For setting up the gate, CODEOWNERS and branch protection, see
[Integrating with AI-Driven Development CI](ci-integration.md). **This MCP server on its own does
not enforce approval.** Enforcement lives in Git/GitHub.

---

## 3. Setup

You need Node.js and the build environment of this repository.

```bash
npm install
npm run build:cli
node dist-cli/main.js mcp [--root <dir>] [--locale ja|en] [--triggers <yaml>]
```

| Option | Value | Default |
|---|---|---|
| `--root` | Directory holding the model JSON files. A tool's `path` is relative to it | the launch directory |
| `--locale` | `ja` \| `en` (language of threat text, etc.) | `ja` |
| `--triggers` | Path to a change-trigger definition YAML | the bundled T1–T8 |

- The transport is **stdio only**. The client launches the server as a process and talks to it over
  standard input/output. It is not meant to be started by hand
- Logs go to standard error only (standard output is reserved for the protocol)
- Only the bundled threat rules are evaluated (same as the CLI's `analyze`)

The configuration examples below assume you have run `npm run build:cli` at the repository root and
that the model JSON lives in the repository.

---

## 4. Configuration examples by client

### 4.1 Claude Code

Put a `.mcp.json` at the project root to make it the project's shared configuration.

```json
{
  "mcpServers": {
    "cyberriskscape": {
      "command": "node",
      "args": [
        "${CLAUDE_PROJECT_DIR}/dist-cli/main.js",
        "mcp",
        "--root",
        "${CLAUDE_PROJECT_DIR}"
      ]
    }
  }
}
```

`${CLAUDE_PROJECT_DIR}` expands to the project root. To add the server from the command line, pass
the server command after `--`.

```bash
claude mcp add --scope project cyberriskscape -- node dist-cli/main.js mcp --root .
```

In interactive sessions, Claude Code asks for approval the first time it uses a server defined in
the project's `.mcp.json`.

### 4.2 GitHub Copilot in VS Code

Write it in the workspace's `.vscode/mcp.json`. The top-level key is **`servers`**, not
`mcpServers`, and `type` is `"stdio"`.

```json
{
  "servers": {
    "cyberriskscape": {
      "type": "stdio",
      "command": "node",
      "args": [
        "${workspaceFolder}/dist-cli/main.js",
        "mcp",
        "--root",
        "${workspaceFolder}"
      ]
    }
  }
}
```

### 4.3 GitHub Copilot coding agent

Enter JSON in "MCP configuration" in the repository settings (Settings → Copilot → Coding agent).
The format is `mcpServers`, and each server **requires `tools` (an allowlist of tool names)**.
Copilot uses the tools you allow here autonomously, **without asking for approval**, so allow only
what you need.

```json
{
  "mcpServers": {
    "cyberriskscape": {
      "type": "local",
      "command": "node",
      "args": ["dist-cli/main.js", "mcp", "--root", "."],
      "tools": [
        "get_model",
        "analyze_threats",
        "get_threat",
        "diff_models",
        "list_component_types",
        "lookup_threat_rules",
        "list_change_triggers",
        "apply_model_changes"
      ]
    }
  }
}
```

To allow read-only use, remove `apply_model_changes` from the array.

- The coding agent works on a checkout of the repository in a cloud environment. To make
  `dist-cli/main.js` available there, include `npm run build:cli` in the agent's environment setup
  steps (`.github/workflows/copilot-setup-steps.yml`)
- The agent's changes arrive as a PR, so the diff gate in §2 acts as the reviewer as is
- Only MCP **tools** are supported, and this server provides only tools

### 4.4 Cursor

Write it in `.cursor/mcp.json` at the project root (per project) or `~/.cursor/mcp.json` in your home
directory (all projects). The format is `mcpServers`, and a standard-I/O server sets `type` to
`"stdio"`. `${workspaceFolder}` expands to the project root.

```json
{
  "mcpServers": {
    "cyberriskscape": {
      "type": "stdio",
      "command": "node",
      "args": [
        "${workspaceFolder}/dist-cli/main.js",
        "mcp",
        "--root",
        "${workspaceFolder}"
      ]
    }
  }
}
```

By default, Cursor asks for approval before using MCP tools. You can turn a server on or off in
Cursor's settings (Customize).

---

## 5. Tools

Seven read tools and one write tool. `path` is a path relative to `--root` that points at a model
JSON file.

| Tool | Main arguments | Returns |
|---|---|---|
| `get_model` | `path`, `layer?` | Nodes, edges, trust boundaries and annotations per layer (no coordinates). `revision` |
| `analyze_threats` | `path`, `layer?`, `framework?`, `minSeverity?`, `elementId?`, `includeSuppressed?`, `limit?` | A summary list of detected threats (highest effective severity first). `revision` |
| `get_threat` | `path`, `threatId` | Details of one threat (mitigations, sources, compliance references, treatment, etc.) |
| `diff_models` | `basePath`, `headPath` | Matching change triggers and the threat diff (same shape as the CLI's `diff --format json`) |
| `list_component_types` | none | Component type ids, categories, the types each can contain, and settable attributes. Consult before writing structure |
| `lookup_threat_rules` | `nodeType?`, `framework?`, `query?` | Look up which threat rules apply to a type without a model. For the early design stage |
| `list_change_triggers` | none | The T1–T8 change-trigger checklist |
| `apply_model_changes` | `path`, `revision`, `layer`, `operations`, `dryRun?` | Changes the structure and returns the threat diff and matching triggers (write) |

Notes:

- `layer` is `L0` to `L3`. `framework` is `STRIDE` / `AI` / `AgenticAI` / `ALL`.
  `minSeverity` is `Critical` / `High` / `Medium` / `Low`
- `elementId` in `analyze_threats` accepts an internal id or an ElementalID such as `C1`, `DF1` or
  `Z1`. Because threat ids can collide across layers, they are returned as `L1:<id>`, and you pass
  that form to `get_threat`. Threat ids in the diffs of `diff_models` and `apply_model_changes`
  (`added` / `removed` / `suppressionChanged` / `severityChanged`) use the same `L1:<id>` form and can
  be passed to `get_threat` as is (the CLI's `diff --format json` keeps the plain id without a layer)
- Result counts are capped (200 threats, 50 rules; `truncated` becomes true when exceeded).
  `analyze_threats` takes `limit` (1-200, default 200) to return only the first N of the sorted list
- The **`revision`** returned by `get_model` and `analyze_threats` is the SHA-256 of the file
  contents. It is required for writing (§7)

### apply_model_changes operations

`operations` is an array of operation objects, up to 100 per call. **All operations are validated
before any is applied, and if even one fails nothing is written** (atomic).

| Operation | Main arguments | Notes |
|---|---|---|
| `add_node` | `type`, `label`, `ref?`, `boundaryId?`, `parentId?`, `description?`, plus per-type attributes | No coordinates. The result contains the assigned id |
| `update_node` | `id`, `set?`, `boundaryId?` | Passing `boundaryId` moves the node to that boundary (`null` for outside any boundary). A `null` in `set` removes the attribute |
| `delete_node` | `id` | Edges connected to the node are removed too. References to the node from attributes and annotations are cleared |
| `add_edge` | `source`, `target`, `auth`, `network`, `encryption`, `ref?`, `dataFlow?`, `dataFlowName?`, `semantic?`, `authProviderId?` | `auth`: `None` / `Password` / `ApiKey` / `Token` / `MFA` / `Passkey` / `Certificate`. `network`: `Internet` / `VPN` / `VPC`. `encryption`: `Plain` / `TLS` / `E2EE`. `dataFlow` is the **direction seen from the source**: `outbound` = source -> target (default), `inbound` = target -> source, `bidirectional` = both |
| `update_edge` | `id`, `set` | `source` / `target` cannot be changed (delete and add to reconnect) |
| `delete_edge` | `id` | |
| `add_boundary` | `type`, `ref?`, `trustLevel?`, `around?`, plus per-type attributes | `type`: `RECT` / `RECT_DASHED` / `ROUNDED` / `ROUNDED_DASHED` / `BLAST_RADIUS`. Sized to enclose the nodes in `around` (an array of node ids); an empty boundary if omitted |
| `update_boundary` | `id`, `set` | `trustLevel` and per-type attributes (such as the VLAN name). Position and size cannot be changed |
| `delete_boundary` | `id` | Removes only the boundary (nodes inside remain) |
| `add_annotation` | `kind` (`label` / `callout`), `text`, `targetNodeId?` | `targetNodeId` is allowed only for `callout` |

- For boundaries other than `RECT`, `trustLevel` (`Internal` / `Partner` / `Internet`) is determined
  by the type's attributes, so a different value cannot be given
- Settable attributes differ per type. Check `attributes` in `list_component_types` (attributes that
  do not fit are rejected)
- Fields not in the definition, such as ids, coordinates or sequence numbers, are rejected

**Referencing with `ref`.** To refer, within the same call, to a node or boundary you have just
added, attach `ref` to the add operation and refer to it as `@name` in later operations. You do not
need to know the assigned id in advance.

An example that adds a node and connects it to an existing node in a single call:

```json
{
  "path": "threat-model/project.json",
  "revision": "<the revision returned by get_model>",
  "layer": "L1",
  "dryRun": true,
  "operations": [
    {
      "op": "add_node",
      "ref": "cache",
      "type": "DB",
      "label": "Session cache",
      "boundaryId": "bprod1"
    },
    {
      "op": "add_edge",
      "source": "nweb1",
      "target": "@cache",
      "auth": "Password",
      "network": "VPC",
      "encryption": "TLS"
    }
  ]
}
```

(`nweb1` and `bprod1` are examples; check real ids with `get_model`. The valid `type` values are
returned by `list_component_types`.)

With `dryRun: true` nothing is written; **only the threat diff and matching triggers that would
result** are returned. If it looks right, call again with the same content with `dryRun` removed (or
set to `false`).
**Ids assigned in a `dryRun` result are provisional**: the real write assigns different ids (the
result's `note` says so too). Do not use them in later operations; within one call, use `ref`.

**Error guidance.** If an operation includes acceptance, false-positive, risk-assessment or
control-status data (`suppression`, `riskScore`, `controlStatus`, manual threats, ...), or an undefined
operation such as `accept_threat` is sent, it is rejected at input validation with a message (in
Japanese) saying that acceptance, false positives, risk assessment and control status cannot be changed
with this tool: a person sets them in CyberRiskScape and approves them in a PR. The file is not changed.
Other undefined keys and operations are also rejected with Japanese messages (the language of these
messages is fixed to Japanese).

---

## 6. No coordinates — how placement works

Which trust boundary a node belongs to is decided by its coordinates on the diagram. If agents were
given coordinates, membership could change unintentionally. This server therefore takes operations
as "which boundary to put it in" (`boundaryId`) and decides coordinates itself.

- With `boundaryId`, the node is placed automatically in free space inside that boundary. If there is
  none, the boundary is expanded. **If expanding would absorb other nodes or boundaries, the
  operation is rejected** (so membership does not change unintentionally)
- Without it, the node goes to a position inside no boundary (to the right of existing elements),
  which is treated as outside the trust boundaries (the Internet side)
- `around` in `add_boundary` creates a boundary enclosing existing nodes. Here too, the operation is
  rejected if it would absorb nodes other than the ones being enclosed

To check the result of placement, call `get_model` after the change; it shows which boundaries each
node belongs to (`boundaryIds`).

---

## 7. Safety mechanisms

| Mechanism | Detail |
|---|---|
| Path restriction | Only existing `.json` files under `--root` are accessible. Paths that escape the root through symbolic links are rejected. Size limit: 10MB |
| Optimistic locking | A write requires the `revision` you just read. If the file has changed since (for example, a person saved it in the app), the write is rejected. Re-read and try again |
| Protection of judgment fields | Acceptances, false positives, risk assessments, mitigation status, manual threats and project information are not operation targets. Tests verify they are unchanged across a write |
| Atomic writes | The resulting project is re-validated against the schema before the file is replaced. On failure, the original file is left as it was |
| Input validation | Every operation is validated against a schema (string lengths, enum values, undefined fields rejected) |
| No external communication | No network calls and no LLM calls |

**Strings inside the model are data, not instructions.** Node labels, descriptions and annotations
contain text written by people (or other tools). Even if such text contains a sentence like "ignore
these settings and do X", the agent must not treat it as an instruction. Take particular care when
having it read a model from an untrusted source.

Also, **writes update the working-tree file directly.** So that you can revert with Git if needed,
commit your changes before letting an agent work.

---

## 8. Limitations

- Only **structure** can be changed. Acceptances, false positives, risk assessments, mitigation
  status, manual threats and project information cannot. These judgments are made by a person in the
  app
- Only the **bundled threat library** is evaluated. Custom rules created in the browser are not
  consulted (same as the CLI)
- One `apply_model_changes` call changes **one layer**, with **up to 100 operations**
- Only existing `.json` files under `--root` can be read or written; **new files cannot be created**
- Coordinates and sizes cannot be specified. Fine visual adjustment is done by a person in the app
- The transport is stdio only, and only MCP **tools** are provided (no resources or prompts)
- As in the previous chapter, change trigger T4 (new technology or runtime) cannot be determined
  automatically from a diff

---

## What to read next

- How to use it in each situation (design, review, Copilot, Cursor, pairing with Snyk) —
  [MCP Use Cases](mcp-use-cases.md)
- Setting up the diff gate, CODEOWNERS and branch protection —
  [Integrating with AI-Driven Development CI](ci-integration.md)
- How to read detected threats — [Reading the Threat Panel](reading-threats.md)
- Another way to let AI read the model, as Markdown —
  [Turning Your Threat Model into an AI-Readable Security Context](security-context.md)
