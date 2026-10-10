# Integrating with AI-Driven Development CI — Treating the Threat Model as a Source-of-Record File

**English** | [日本語](ci-integration.ja.md)

The earlier chapters walked through drawing, reading, and assessing a threat model by hand in the
browser. This chapter switches perspective: it explains how to wire **a saved project JSON, kept
as a source-of-record file in your repository, into CI/CD** using the headless CLI and a GitHub
Action. The goal is to keep the threat model continuously connected to a development flow where AI
reads and writes code alongside it — sometimes called "AI-driven development."

This chapter stands on its own, but the commands it uses are a second connection point to the
outside world, alongside the export feature covered in
[Turning Your Threat Model into an AI-Readable Security Context](security-context.md).

---

## 1. Why this exists

Human review is struggling to keep pace with how fast AI can write code, and threat modeling is no
exception. "Draw it carefully once, then forget about it" doesn't survive a development flow where
AI adds a new external integration or agent tool every week — the model drifts from reality almost
immediately.

The "AI-driven development" this chapter targets means development that satisfies all four of the
following conditions.

| # | Condition | How this chapter satisfies it |
|---|---|---|
| 1 | AI routinely and procedurally handles **at least two** of requirements/design/testing/review/documentation, beyond implementation | AI routinely handles threat model **updates** (design) and the **review checkpoints** for a diff (review) |
| 2 | The source of record is **a spec, acceptance criteria, tests, or a design constraint** — not a chat log | The saved project JSON (e.g. `threat-model/project.json`) is committed to the repo and treated as **the source of record for a design constraint** |
| 3 | A designated human makes the **final call** on adoption, security, permissions, secrets, and external dependencies — nothing ships unreviewed | `CODEOWNERS` and branch protection **force human review** on model changes and disposition decisions |
| 4 | The process, tools, allowed inputs, and review criteria are **documented**, not left to individual habit | This chapter itself — the setup steps, what information may be input (§6), and the review criteria (T1–T8) |

In short, what this chapter does isn't just "wire the threat model into CI" — it's **documenting the
procedure that puts the threat model, as a source-of-record file, in front of a human's final
decision.**

---

## 2. Roles — AI and humans

| Task | Who |
|---|---|
| Open a code PR / draft a threat model update | AI (or a human) |
| Run the model diff and read the result | AI (CI runs it automatically; the result is readable both as a PR comment and by an AI reviewer) |
| Fill in the trigger (T1–T8) checklist | AI (ticks the applicable items per the PR template) |
| Approve a new Critical/High threat's **change to accepted/false-positive** | **A human (designated reviewer)** — enforced via CODEOWNERS |
| Apply the `threat-model-not-needed` label | **A human (designated reviewer)** — who applied it is recorded on the PR timeline |
| Final call on adoption, security, permissions, secrets, external dependencies | **A human** — this tool only supplies judgment material; it never makes the call |

**The gate (the CI exit code) only enforces "no new unsuppressed Critical/High threats."** A change
to accepted/false-positive, or a label-based skip, **never fails CI** — instead, both are recorded
in a place a human will see on the PR. Enforcement relies on Git/GitHub's own record (CODEOWNERS,
branch protection, the PR timeline).

---

## 3. The two-stage flow

Requiring a model diff gate on every code change would make it meaningless noise for unrelated
PRs. So this chapter's setup runs **two stages**.

```
              A PR is opened
                   │
       ┌───────────┴───────────┐
       │                       │
 the model file changed   the model file did not change
       │                       │
       ↓                       ↓
② Model diff gate       ① Trigger judgement (watch-paths)
   (§4 below)                  │
                     ┌─────────┴─────────┐
                     │                   │
            matches watch-paths     doesn't match
                     │                   │
                     ↓                   ↓
      no label → fail, asking for the checklist   succeed
      label present → succeed (who applied it is recorded)
```

### ① Trigger judgement (code / IaC / dependency PRs)

The model file itself didn't change, but the PR touched a `watch-paths` pattern (e.g.
`infra/**`, `**/auth/**`, `**/package.json`, `**/Dockerfile`). The gate shows the **T1–T8
trigger checklist** as judgment material for whether a model update is needed.

| # | Trigger | Checkpoint | Auto-judged from the model diff |
|---|---|---|---|
| T1 | New trust boundary | Data crosses a new network segment, tenant isolation boundary, or privilege boundary | Yes |
| T2 | New external interface | Internet-facing API, webhook, gRPC endpoint, callback URL, or public SDK | Yes |
| T3 | New authentication / authorization mechanism | New login flow, token type, mTLS, RBAC model, service identity, or certificate management | Yes |
| T4 | New technology or runtime | An unfamiliar language, framework, data store, cloud service, or deployment model | **No** (the diagram carries no tech-stack information) |
| T5 | Sensitive data takes a new path | Customer data, secrets, cryptographic keys, or PII pass through a component that did not previously handle them | Yes |
| T6 | New third-party integration | An external vendor's SDK, API, or service that receives or processes customer data | Yes |
| T7 | Expanded agent capability | A new tool, MCP server, sub-agent delegation, or memory store; increased autonomy or permissions | Yes |
| T8 | Change to the model, training data, or RAG source | A change to the LLM in use, fine-tuning/training data, or RAG reference sources | Yes |

"Auto-judged from the model diff" only applies **once the model file itself has been updated**. At
stage ① the model file hasn't changed yet, so every item is shown as "needs human/AI review" here
(see §8 for why T4 can never be auto-judged even at stage ②).

A PR that touches a watched path without updating the model keeps failing CI until a designated
reviewer looks at it and applies the `threat-model-not-needed` label.

### ② Model diff gate (model-file PRs)

The model file itself changed. The action compares the base (merge target) and head (PR) versions
and reports, as Markdown posted to the PR comment and job summary:

- which triggers matched (with the evidence elements)
- added / removed threats
- disposition changes (**a change to accepted/false-positive is flagged "needs approval"**)
- effective severity changes
- the `fail-on` gate verdict

and **fails CI when a newly added, unsuppressed threat is at or above `fail-on`**. Pre-existing
unaddressed threats never fail it — ongoing remediation is fine.

### How heavy should the threat modeling be — two tracks

Once a trigger matches, pick one of these tracks according to the size of the change.

| | Track A: Diff review | Track B: Full threat model |
|---|---|---|
| When to use | Low-to-medium-risk changes: about one new interface, a narrow scope, 1–3 matching triggers | A new major component, a new authentication mechanism, a regulatory boundary (FedRAMP, ISMAP, etc.), multiple interacting services, or a formal compliance deliverable is required |
| Prerequisite | A baseline model of the system already exists (built with Track B) | None. **The first model of any system always goes here** |
| Duration | 1–2 days | 2–4 weeks |
| Tools | A short model update in Canvas + the diff report from CI | Canvas (diagramming, Analytics, attack path analysis) |
| Deliverable | The diff report on the PR: matching triggers and their evidence, added/removed threats, disposition changes (needs approval), and the gate verdict (the Go/No-Go) | A project file with triaged mitigations (risk ratings, dispositions, and control status recorded) and its report |
| Review | Self-review by the development team's security lead → approval on the PR by the security team | Iterative review meetings with the security team |

**When to move from Track A to Track B**: when the diff report matches T1 (new trust boundary) or
T3 (new authentication/authorization mechanism), or when four or more triggers match.

Current constraints when running Track A:

- **The CLI does not create or update the model.** It reviews diffs of an existing model. Update
  the model in Canvas and include the saved JSON in the PR. You can edit the JSON directly, but
  membership in a trust boundary is decided by node coordinates, so hand edits or direct edits by
  an AI are not recommended.
- **The CLI does not render the diagram and does not narrow threats to a top N.** Open the model
  file in Canvas to see the DFD; the "Entry points & trust boundaries" section of
  `analyze --format md` describes it in text.
- **Risk ratings (impact × likelihood) are not assigned automatically.** A person enters them in
  Canvas's Analytics. The diff report uses the rating when one exists, and the rule's default
  severity otherwise.

---

## 4. Setup

### 4.1 Save the project JSON into the repository

Export the project JSON from the app's **PROJECT** menu and commit it to the repository (e.g.
`threat-model/project.json`). From here on, this setup treats that file as **the source of
record**.

### 4.2 Add the workflow

Copy [`guide/ci/threat-model.yml`](ci/threat-model.yml) to
`.github/workflows/threat-model.yml` and adjust `model` / `fail-on` / `watch-paths` for your
repository.

```yaml
- uses: takashi-ohmoto-git/CyberRiskScape@v0.6.0   # pin to a commit SHA in production
  with:
    model: threat-model/project.json
    fail-on: High
    watch-paths: |
      infra/**
      **/auth/**
      **/package.json
      **/Dockerfile
```

> **Pin to a commit SHA, not a branch, in production.** This action builds and runs arbitrary code
> from whatever ref you reference, via `npm ci && npm run build:cli`. A tag (`@v0.6.0`) can be
> moved later, so in production use the commit SHA that the tag points to.

### 4.3 Set up CODEOWNERS

Following [`guide/ci/CODEOWNERS.example`](ci/CODEOWNERS.example), assign a designated reviewer
(team) to the model file's path. **Also assign the workflow file — and your custom trigger
definitions, if you use them — to the same reviewers.** A workflow triggered by `pull_request`
runs the version from the PR, so a PR that edits the workflow can remove the gate itself.
(The action reads custom trigger definitions from the base branch, so a PR alone cannot swap
them, but assigning them keeps later changes under review too.)

```
threat-model/project.json         @your-org/security-reviewers
.github/workflows/threat-model.yml  @your-org/security-reviewers
```

**CODEOWNERS cannot govern the `threat-model-not-needed` label.** GitHub can only restrict label
application at the granularity of "triage permission or above," so **agree on who may apply the
label as a social/process control** (e.g. by restricting who gets triage/write access).

### 4.4 Set up branch protection

In the branch protection rule for the target branch, require:

- this workflow's status check (as a required check)
- code owner review approval (requiring the CODEOWNERS from §4.3)

This technically enforces §2's "nothing ships unreviewed."

### 4.5 Add a PR template (optional)

[`guide/ci/pull_request_template.md`](ci/pull_request_template.md) is a PR template with a
T1–T8 checklist, based on the output of
`node dist-cli/main.js triggers --format md --locale en`. Copy it to
`.github/pull_request_template.md` to use it. If you have organization-specific trigger
definitions, regenerate it with `--triggers <file>`.

---

## 5. Reading the PR comment

When the model diff gate fails (CI exit 1), the PR comment lays the result out by heading.

- **Triggers** — which T1–T8 matched, with evidence elements. T4 always reads "confirm in PR
  review"
- **Added threats / Removed threats** — a table of severity, asset, and threat name
- **Disposition changes** — rows where "Needs approval" is **Yes are threats newly set to
  accepted or false-positive**. This **never fails CI**, but these rows assume a designated
  reviewer will look them over and approve
- **Effective severity changes**
- **Gate result** — FAIL if a new unsuppressed threat is at or above `fail-on`, PASS otherwise

Note that **"needs approval" does not mean CI stopped the PR.** Treat any PR with a "needs
approval" row as one your reviewers should look at even if the gate passed — folding it into the
CODEOWNERS review checklist is the reliable way to do that.

---

## 6. What information may go in

- **The model file's contents are design information** — asset names, component layout, trust
  boundaries, authentication schemes, and so on. Classify its sensitivity **per your
  organization's own policy**. If it lives in a public repository, be careful not to include
  real hostnames, internal domains, or personal names
- **The CLI itself (`analyze` / `diff` / `triggers`) makes no network calls at all.** It's a pure
  local computation that only uses the bundled threat library
- **Running the Action involves two kinds of outside network access**: fetching dependencies from
  the npm registry at build time (`npm ci`), and calling the GitHub API to post the result comment
  (`gh pr comment`). See the next section for how to avoid both on a closed network
- **There are no LLM calls.** This setup judges everything from fixed rules (the threat library)
  and the model diff alone. Wiring the LLM integration planned for Phase 2 into CI would require a
  separate, explicit opt-in

---

## 7. Closed networks and self-hosted runners

On a self-hosted runner on IaaS, or any environment that can't reach the npm registry, **don't use
the Action as-is** — instead, prebuild the CLI and call it directly.

```bash
# Once, in an environment that can build it
npm run build:cli   # produces dist-cli/main.js — a single file, Node-only

# On the closed network, ship only dist-cli/main.js and call it directly from the workflow
node dist-cli/main.js diff base.json head.json --format md --fail-on High --out result.md
node dist-cli/main.js triggers --format md --out checklist.md
```

`dist-cli/main.js` has no dependency besides Node, so this path needs neither the npm registry
nor general internet access. Only ensure connectivity to the GitHub API if you still want to post
the result as a PR comment.

---

## 8. Limitations

- **Only the bundled threat library is evaluated.** Custom rules stored in IndexedDB (created in
  the browser) are not visible to the CLI and are not part of the file
- **T4 (new technology or runtime) can never be auto-judged from the model diff** — the diagram
  carries no tech-stack information. It always shows as "confirm in PR review," whether in the
  stage ① trigger judgement or the stage ② model diff comment, so a human (or AI reviewer) has to
  make the call
- **A change to the LLM itself is not detected.** T8 catches a new LLM node or a new
  `rag_retrieval` edge, but the current diagram data model has no attribute that represents a
  change to which model an existing LLM node refers to (e.g. a version bump), so that case is out
  of scope

---

## What to read next

- Another way to use the model — export it as Markdown for an AI to read —
  [Turning Your Threat Model into an AI-Readable Security Context](security-context.md)
- Recording risk assessment and disposition — [Assessing Risk in Analytics](analytics-assessment.md)
- How to read a threat — [Reading the Threat Panel](reading-threats.md)
