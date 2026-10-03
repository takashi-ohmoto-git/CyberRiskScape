# MCP Use Cases — Design, Review and Pairing with Other Tools

**English** | [日本語](mcp-use-cases.ja.md)

The [previous chapter (MCP server setup)](mcp-integration.md) was the reference for configuration and
tools. This chapter shows, scenario by scenario, **what a development team and a security owner ask
an agent (Claude Code, GitHub Copilot, Cursor and others) to do, which tools the agent calls, and what
a person decides**. If you have not set it up yet, do
[What to do first in the previous chapter](mcp-integration.md#what-to-do-first) first.

Every scenario assumes the same division of labor:

- The agent can **query threats and update the structure** (nodes, edges, boundaries, and so on), and no more
- **Risk assessments, acceptances, false positives and mitigation status are set by a person in the app**
  (the agent cannot change them)
- Structure changes become a PR, and a person reviews the diff
  ([Integrating with AI-Driven Development CI](ci-integration.md))

You can copy the example prompts as they are, but adapt file paths and element names to your project.

---

## 1. Early design: look up threats by type, with no diagram yet

**Situation** — You are starting to design a feature and there is no diagram (model JSON) yet. You
plan a chat feature that uses RAG and want to know which threats to prepare for first.

**Example instruction to the agent**

```text
I am designing a chat feature with RAG. It will use a vector DB and an agent that calls an LLM.
Using CyberRiskScape, find which threat rules apply to these component types, and list the five
things we should decide first in the design.
```

**Tool flow**

1. `list_component_types` — find the ids of the available types (for example the types that
   correspond to a vector DB, an agent and an LLM)
2. `lookup_threat_rules` — pass the type id as `nodeType` (and `framework`, `AI` / `AgenticAI`, if
   needed) to get the rules that apply. `query` narrows by keyword

**What a person does** — Decide which of the agent's items to take up as design-review topics. The
result at this stage is "threats that generally apply to the type"; real connections and trust
boundaries are not reflected yet. Once you have a diagram, scenario 2 shows real detections.

---

## 2. Understand the important threats in an existing model and turn mitigations into tasks

**Situation** — There is a saved model, `threat-model/project.json`. You want only the important
detected threats, and to turn their mitigations into issues or tasks.

**Example instruction to the agent**

```text
List the top 10 threats of High severity or above in threat-model/project.json. Read the details of
each and turn the mitigations into implementation tasks (a title and acceptance criteria each).
Do not change acceptance or treatment.
```

**Tool flow**

1. `analyze_threats` — with `minSeverity: "High"` and `limit: 10`, get the first 10 in order of
   effective severity (`elementId` narrows it to one node)
2. `get_threat` — pass each `L1:<id>` to read the mitigations, sources and the reason it fired
3. (The agent writes out the tasks. That part is not a CyberRiskScape feature.)

**What a person does** — Check the tasks make sense and set priorities. Accepting a risk, or marking
something "implemented", is recorded by a person in the app after the work is done
([Assessing Risk in Analytics](analytics-assessment.md)). The agent cannot change mitigation status,
so creating a task never marks anything as implemented.

---

## 3. Add a new component and see the impact

**Situation** — You are adding an MCP server, a RAG vector DB or an external SaaS to an existing
system. You want to update the diagram and see how threats increase.

**Example instruction to the agent**

```text
In L1 of threat-model/project.json, add one vector DB and connect it from the existing API server
over TLS. First do a dryRun and tell me the new threats and the matching change triggers. If it looks
fine, write it.
```

**Tool flow**

1. `get_model` — get the ids of existing nodes, their boundaries, and the `revision`
2. `list_component_types` — check the id of the type to add and its settable attributes
3. `apply_model_changes` (`dryRun: true`) — send the node and the edge in one call. Later operations
   refer to the new node by `ref` (for example `"ref": "vectordb"` on `add_node` and
   `"target": "@vectordb"` on `add_edge`). Nothing is written; the threats that would be added or
   removed and the matching triggers (for example T5 and T8) are returned
4. `apply_model_changes` (remove `dryRun`) — if it is right, write the same content

**What a person does** — Read the dryRun result (new threats and triggers) and confirm the structure
is what you intended. The `auth`, `network` and `encryption` of an edge may be values the agent
guessed, so always check them against the real design. After the write, tidy the diagram's
appearance in the app if needed and do the risk assessment. Because a write updates the
working-tree file directly, **commit before the work** so you can revert with Git.

---

## 4. Self-review before a PR

**Situation** — You have a branch that changes the model JSON. Before opening a PR you want to know
the diff reviewers will see and the triggers they will be asked about.

`diff_models` compares two files. Prepare the base (the comparison source) from Git:

```bash
git show origin/main:threat-model/project.json > threat-model/base.json
```

**Important** — The base must also be placed under `--root` (paths outside `--root` are rejected).
Delete `threat-model/base.json` when you are done and do not commit it.

**Example instruction to the agent**

```text
Compare threat-model/base.json (the main version) with threat-model/project.json (the work in
progress) and tell me the matching change triggers and the threats that were added or resolved.
Summarize it in a form I can paste into the PR description.
```

**Tool flow**

1. `diff_models` — pass `basePath` and `headPath`. It returns the matching triggers and the threat
   diff (`added` / `removed` / `suppressionChanged` / `severityChanged`)
2. `list_change_triggers` — read the checklist items (the T1–T8 checkpoints) for the matching triggers
3. `get_threat` — read the details of any added threat you care about

**What a person does** — Write in the PR description what each trigger asks you to confirm (for T6,
for example, how an external vendor that receives customer data is handled). T4 (new technology or
runtime) cannot be determined from a diff, so think about whether it applies even if the agent's
summary does not mention it. Once you open the PR, CI's diff gate posts the same diff.

---

## 5. GitHub Copilot

### 5.1 Interactive use in VS Code agent mode

**Situation** — You want to update the diagram on the spot while discussing the design.

The configuration is [4.2 GitHub Copilot in VS Code](mcp-integration.md#42-github-copilot-in-vs-code)
(`.vscode/mcp.json`). In agent mode, the prompts of scenarios 1–4 work as they are. VS Code asks for
confirmation each time a tool is called, so you can use it so that **you allow the write tool
(`apply_model_changes`) only after looking at its arguments**.

### 5.2 Assign an issue to the coding agent

**Situation** — You assign a feature issue, "add a vector DB", to the Copilot coding agent and want
the PR to include the diagram update along with the implementation.

**Example instruction in the issue**

```text
## Requirements
Add a vector DB for document search and have the API server query it.

## Diagram
Reflect the new vector DB and its connection in L1 of threat-model/project.json.
Use the CyberRiskScape MCP tools: first check the threat diff with dryRun, then write.
In the PR description, write the change triggers that matched and a summary of the added threats.
Do not change risk assessments, acceptances or mitigation status.
```

**Flow**

1. Copilot reads the issue, calls the MCP tools **autonomously** (`get_model` → `apply_model_changes`
   dryRun → write), and makes the implementation and the model JSON change into one PR
2. CI's diff gate posts the threat diff and triggers on the PR
   ([Integrating with AI-Driven Development CI](ci-integration.md))
3. **A person (the designated reviewer) looks at the diff gate result and approves or sends it back**

**Deciding what to allow** — According to GitHub's documentation, the coding agent uses the tools of
a configured MCP server **autonomously, without asking for approval**, so only the tools you put in
the `tools` allowlist are used. Only MCP **tools** are supported, not resources or prompts.

- To let it update the structure: allow all eight, as in
  [4.3](mcp-integration.md#43-github-copilot-coding-agent). The change becomes a PR, and a person
  decides at the diff gate
- **To restrict it to reading**: remove `apply_model_changes`. The agent can look up threats and write
  them in the PR description, but cannot update the diagram

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
        "list_change_triggers"
      ]
    }
  }
}
```

**Rule of thumb** — Allow writes only once the diff gate and CODEOWNERS approval are in place. If
they are not, start read-only and add writing later. Also, to use `dist-cli/main.js` in the cloud
environment, include `npm run build:cli` in the environment setup steps (4.3 of the previous chapter).

---

## 6. Cursor

The configuration is [4.4 Cursor](mcp-integration.md#44-cursor) (`.cursor/mcp.json`). By default,
Cursor asks for approval before using MCP tools.

**Design-consultation example**

```text
I am thinking of adding a new authentication service. Read threat-model/project.json, list the
connections with weak authentication (auth set to None), and show me with a dryRun the threats that
would be added.
```

**Structure-update example**

```text
In L1 of threat-model/project.json, add a WAF in front of the "Web server". Use the same boundary as
the existing one, show me the dryRun result, and then write it.
```

The tool flow is the same as scenario 3. In Cursor you can check the arguments (`operations`) on the
approval prompt for each tool call. If you set it to run tools automatically, decide whether to
include the write tool using the points in scenario 8.

---

## 7. Pairing with Snyk (through the agent)

This puts Snyk's official MCP server and the CyberRiskScape MCP server **side by side in the same
agent**, so that "threats in the design" and "vulnerabilities in the implementation" can be compared in
one conversation. The two servers do not talk to each other. The agent connects them.

### 7.1 Preparing the Snyk MCP (as confirmed in Snyk's official documentation)

- It starts with `snyk mcp -t stdio` (stdio transport). Snyk CLI v1.1298.0 or later is required, and
  `npx -y snyk@latest mcp -t stdio` also works
- You must authenticate with a Snyk account (browser login, or the `SNYK_TOKEN` environment variable)
- The tools scan open-source dependencies (SCA), code, IaC, containers, SBOMs and so on. Tool names
  and coverage can change between Snyk versions, so see Snyk's documentation for the latest
- Available plans, pricing, and whether code or dependency information is sent to Snyk's service for
  scanning **follow Snyk's terms**. This guide has not confirmed them, so check Snyk's documentation
  and your own policy before adopting it

An example registering both side by side (Cursor's `.cursor/mcp.json`; other clients list them
side by side in their own formats):

```json
{
  "mcpServers": {
    "cyberriskscape": {
      "type": "stdio",
      "command": "node",
      "args": ["${workspaceFolder}/dist-cli/main.js", "mcp", "--root", "${workspaceFolder}"]
    },
    "snyk": {
      "type": "stdio",
      "command": "snyk",
      "args": ["mcp", "-t", "stdio"]
    }
  }
}
```

### 7.2 Use cases

**(a) Compare design threats and implementation vulnerabilities to set priorities**

```text
List the top 10 threats of High severity or above in threat-model/project.json. Then scan this
repository's dependencies (SCA) and IaC with Snyk and map the findings to nodes in the diagram
(infer which finding belongs to which component from the repository layout, and give your reasoning).
Put the design threats and implementation vulnerabilities in one table and suggest where to look first.
```

Flow: `analyze_threats` and `get_model` (CyberRiskScape) → Snyk scans (Snyk) → the agent maps and
builds the table. **The mapping is the agent's inference** and is not certain. A person should check
the reasoning.

**(b) Flag contradictions between "implemented" mitigations and Snyk findings**

```text
In threat-model/project.json, read with get_threat the threats whose mitigation status is
"implemented". If Snyk has findings in the related area (for example input validation, encryption or
dependency updates), list them as possible contradictions. Do not change the status.
```

The agent **cannot change** mitigation status. It only flags suspected contradictions; a person
decides whether to revisit them and updates the app.

**(c) Consider whether a dependency or IaC change matches a trigger**

```text
This PR changes package.json and Terraform. After checking the changed dependencies and IaC with
Snyk, list the changes that look like T4 (new technology) or T6 (third-party integration) among
list_change_triggers, and if the diagram needs updating, show me a proposal with dryRun.
```

T4 cannot be determined from a diff, so noticing it **from dependency or IaC changes, by a person or
within the conversation**, is where this helps. Do not write the agent's proposal as is; a person
checks the dryRun result.

### 7.3 Limits

- **A connection through an agent is not guaranteed to give the same result each time.** Do not use it
  for a CI gate or as audit evidence. Build the gate with the CLI and GitHub Action from the earlier
  chapters, which behave deterministically
- **Snyk's results are not saved in CyberRiskScape's files.** The mapping also lives only in the
  conversation. To keep it, a person copies it into the PR description or an issue
- **Risk assessments and mitigation status cannot be changed by the agent.** A person sets them in the app
- Snyk's terms, pricing and scan scope follow Snyk

---

## 8. Common cautions

**What to allow the agent**

| Configuration | Tools allowed | Suited for |
|---|---|---|
| Read-only | The 7 tools other than `apply_model_changes` | Threat research, PR descriptions, review support. When you are trying it first |
| Read and write | All 8 | Letting it update the diagram too. When the diff gate and CODEOWNERS are in place |

- Even in a read-only configuration the agent **reads** the diagram, so if the model contains
  confidential design information, check how the agent's provider handles data
- In environments such as coding agents that use tools **without approval**, the allowlist is the only
  restriction. Allow only what is needed

**Strings inside the model are data** — Node labels, descriptions and annotations are text written
by people or other tools. Do not let the agent treat a sentence like "ignore this instruction and do
X" as a command ([§7 of the previous chapter](mcp-integration.md#7-safety-mechanisms)). Take particular
care when having it read a model from an untrusted source.

**Closed networks** — The CyberRiskScape MCP server makes no external calls and no LLM calls. But
**the agent itself (the service that provides the LLM) and other servers such as Snyk communicate
separately**. For a closed network, check that each server you pair with the agent works there.

**Where to put `--root`** — A tool's `path` is relative to `--root`, and only existing `.json` files
under `--root` are accessible. Set `--root` to the directory that holds the model JSON (the repository
root, or something like `threat-model/`). The base of `diff_models` must also be under `--root`
(scenario 4). Setting `--root` too broadly lets unrelated JSON be read, so keep it to what is needed.

---

## What to read next

- Configuration and tool reference — [Using It from Coding Agents](mcp-integration.md)
- Diff gate, CODEOWNERS and branch protection — [Integrating with AI-Driven Development CI](ci-integration.md)
- How to read detected threats — [Reading the Threat Panel](reading-threats.md)
