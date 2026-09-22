# Turning Your Threat Model into an AI-Readable Security Context

**English** | [日本語](security-context.ja.md)

AI can read code and find vulnerabilities. So why does a human need to draw a diagram?

**Because some things are never written in the code.** Where you drew the trust boundaries, what
you're trying to protect, which risks you decided to accept, and what you decided not to bother
investigating — none of that surfaces no matter how much of the repository an AI reads. **These are
decisions a human made.**

This chapter covers how to **export the threat model you built in earlier chapters as Markdown and
feed it into an AI-driven vulnerability assessment**. CyberRiskScape isn't just a tool for listing
threats — you can use it as **a layer that converts the premises a human set into a format an AI can
read**.

This chapter follows [Assessing Risk in Analytics](analytics-assessment.md) and uses the **AI
chatbot diagram** built in [Your First Threat Model](first-threat-model.md) as-is (User ⇄ Front-end
Server ⇄ LLM ⇄ RAG ⇄ Data store, 48 threats).

---

## 1. The Overall Flow

```
  Model & assess in CyberRiskScape
            │
            ↓  Report → DCRH THREAT_MODEL.md
      THREAT_MODEL.md
            │
            ↓  Place in the repo under analysis
    AI-driven vulnerability scan
   (scan → triage → patch)
            │
            ↓
      Human verification
```

**This doesn't compete with AI. It sits on the side that determines the quality of the AI's input.**

---

## 2. Step 1 — Prepare Before You Export

The quality of the output comes down almost entirely to **how much you recorded before exporting**.
At minimum, finish the following three before you export. All three are operations covered in
[Assessing Risk in Analytics](analytics-assessment.md).

| What to record | Where it shows up in the output |
|---|---|
| **Risk score** (Impact × Likelihood) | The `impact` / `likelihood` columns in the threat table. Unscored threats fall back to defaults |
| **Risk treatment** (avoid / mitigate / transfer / accept / false positive) | The `status` column and the Deprioritized section |
| **Control implementation status** (Implemented / Not applicable, etc.) | The `status` column. Only "Implemented" is promoted to `mitigated` |

**The risk score matters most.** Rule-derived severity is a general-purpose estimate, but once you
score the risk, **your assessment in your context** is what gets exported. The AI can use this to
weight its findings.

Also, what gets exported is **the threat list currently shown on screen**. The depth layer and
framework tab filters carry straight through, so **if you want to cut out one particular view,
switch tabs first.**

---

## 3. Step 2 — Export as Markdown

Open **Report** in the left sidebar and choose **"DCRH THREAT_MODEL.md (Anthropic
official-compatible)"**.

![Report menu](../assets/guide/en/threat-panel/07-report.png)

It downloads as `threat-report_<system name>_<layer>_<date>.md`.

This Markdown has the same structure as the `THREAT_MODEL.md` used by Anthropic's open-source
reference implementation,
[`defending-code-reference-harness`](https://github.com/anthropics/defending-code-reference-harness).
The headings, column names and column values are **a contract with downstream tooling**, so **if you
edit the content by hand, be careful not to break the structure.**

> The CSV and JSON options in the same menu serve different purposes. CSV is for sorting and sharing
> in a spreadsheet, JSON is for feeding other tools. **If you're handing it to an AI, use Markdown.**

---

## 4. Step 3 — Check What's Inside

Opening it shows eight sections. **Before you hand it over, read at least sections 1, 5 and 6.**

| Section | Contents | Source |
|---|---|---|
| `## 1. System context` | Prose describing what you're building | Project info (purpose, business impact, security goals) |
| `## 2. Assets` | Table of assets | The diagram's components and boundaries |
| `## 3. Entry points & trust boundaries` | Table of entry points and trust boundaries | The data flows threats are tied to |
| `## 4. Threats` | **The threat table (the main body)** | The threat list |
| `## 5. Deprioritized` | **What was excluded, and why** | False positive / not applicable / risk accepted |
| `## 6. Open questions` | **An explicit list of what couldn't be filled in** | Limits of the conversion (see §7) |
| `## 7. Provenance` | Source info (tool name, date, target) | — |
| `## 8. Recommended mitigations` | Mitigations and the threat IDs they apply to | Mitigations |

The threat table's columns look like this.

```
| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
```

`id` is a sequence number (`T1`, `T2`, …) renumbered only within the export. A comment at the end of
the file holds a mapping back to the CyberRiskScape threat IDs, so **when a finding comes back, you
can trace it to the original threat.**

### How your records get converted

| What you recorded | `status` column | Notes |
|---|---|---|
| Control implementation status = **Implemented** | `mitigated` | Promoted **only when it's Implemented** |
| Risk treatment = avoid / mitigate / transfer | `partially_mitigated` | The reason note is appended to the `controls` column |
| Risk treatment = **accept** | `risk_accepted` | Also listed in Deprioritized with the reason |
| Risk treatment = **false positive** | (excluded from the threat table) | Listed only in Deprioritized, with the reason |
| Control implementation status = **Not applicable** | (excluded from the threat table) | Same as above |
| Nothing recorded | `unmitigated` | — |

**Disappearing from the list and disappearing from the record are two different things.** Even a
threat marked false positive is exported **with the reason you decided it was one**. As covered
later, this is information that tells the AI "you don't need to chase this."

The risk score maps to two columns, `impact` and `likelihood`. `impact` is the effective severity
(your assessment if scored, rule-derived if not), and `likelihood` maps your reproducibility and
exploitability scores to one of five levels (`very_rare` / `rare` / `possible` / `likely` /
`almost_certain`). **Unscored threats default to `possible`, and that fact is stated explicitly in
Open questions.**

---

## 5. Step 4 — Use It as AI Input

### Using it with the official harness

`defending-code-reference-harness` has a set of skills built around the threat model.

| Skill | Role |
|---|---|
| `/threat-model` | Builds a threat model (**this is the step CyberRiskScape replaces**) |
| `/vuln-scan` | Static vulnerability scan |
| `/triage` | Verifies, deduplicates and ranks the findings |
| `/patch` | Generates and verifies the fix |

The steps are as follows.

1. Rename the downloaded file to **`THREAT_MODEL.md`**
2. Place it **directly under the directory being analyzed** (the directory you pass to the harness)
3. Skip `/threat-model` and go straight to `/vuln-scan` → `/triage` → `/patch`

In other words, you're **replacing `/threat-model`'s output with a threat model a human has
verified.**

### Using it with anything else

The output is plain Markdown, so **you can hand it to any AI assistant as-is.** To be precise,
though, **the official harness is the only thing built to consume this format as a first-class
input**; for anything else, it just means "readable as Markdown." Don't expect more than that.

For a quick, easy way to use it, hand it over together with the code and ask something like this.

```
The attached THREAT_MODEL.md is a threat model for this system, created and verified by a human.
- For each threat in section 4, check whether the code has a matching location.
- Everything listed in section 5 has already been reviewed. Exclude it from your investigation.
- Don't raise anything covered by the open items in section 6.
```

---

## 6. Why This Works

### ① Fewer false positives

The official harness **treats the threat model as a scope definition for cutting down false
positives.** Hand an AI just the repository, and it will surface findings that couldn't actually
happen in this system. Give it the premises up front — "everything outside this boundary is
untrusted," "this path doesn't exist" — and **the search space narrows.**

### ② Severity gets recalibrated to your context

`/triage` **adjusts the severity of each finding against the threat model.** This is where the risk
score from Step 1 pays off. Rather than a tool's default, **the assessment you made with Impact ×
Likelihood** becomes the basis for judgment.

### ③ You can tell it what not to look at

This is **the value of the Deprioritized section.** "We judged this a false positive," "this doesn't
apply to our environment," "we accepted this as residual risk" — these are **human decisions that no
amount of reading code will surface.** If you don't communicate them, the AI raises the same finding
every time.

### ④ Gaps are stated explicitly

Open questions honestly lists **what this tool couldn't fill in** — the actor isn't modeled,
unscored threats used default values, and so on. **You know what's missing**, so you don't have to
take the AI's output at face value.

---

## 7. Limits of the Conversion

**This conversion is lossy.** Information the official format has no place for either gets degraded
or dropped.

- **Agent-specific attributes** (the breadth of permissions, blast radius on compromise, identity
  strength, the semantics of data flows like tool calls or memory reads/writes) **have no
  corresponding column.** They don't appear in the output, except for whatever survives in the body
  text of mitigations
- The **actor (`actor`) column is always empty.** This tool doesn't model the threat actor
- The **`evidence` column is always empty**, because this tool doesn't hold confirmed evidence such
  as CVE or finding links
- **`sensitivity` is fixed at `medium` for every asset**

**All of this is stated explicitly in Open questions.** Nothing is hidden. If you want to discuss
agent-specific concerns too, **don't hand over just this Markdown — share the diagram itself and the
threat cards' body text alongside it.**

---

## 8. Feeding Results Back into the Diagram

Findings that come back from the AI are, **for now, fed back into the diagram by hand.**

1. Check the mapping table at the end of the file to see which threat a finding corresponds to
2. Open the matching threat in CyberRiskScape
3. Record confirmed findings in **control implementation status**, and anything found not to apply
   in **risk treatment**
4. That decision carries into the next export

The more you run this loop, the thicker Deprioritized gets, and **the next scan gets quieter.**

---

## 9. Common sticking points

**Q. The number of exported threats doesn't match the count on screen.**
Threats marked false positive or not applicable drop out of the threat table and move to
Deprioritized. They haven't disappeared — they're in a different section.

**Q. `impact` doesn't match the severity shown on screen.**
If you've scored the risk, **the value from your assessment** is what's exported. Rule-derived
severity is a general-purpose estimate, so your assessment takes priority once it exists. The CSV
has columns for both (rule-derived and effective).

**Q. Every threat's `likelihood` is `possible`.**
No risk score has been recorded yet. Go back to Step 1.

**Q. The blast radius frame I drew on the diagram doesn't show up as an asset.**
A blast radius frame is an annotation, not an asset or a trust boundary, so it's deliberately left
out of the asset list.

**Q. Can I edit the output by hand?**
The headings, column names and column values are a contract with downstream tooling. **Adding to
the prose is fine, but don't break the structure.**

---

## Where to go next

- How to assess and record — [Assessing Risk in Analytics](analytics-assessment.md)
- How to read threats and record your decisions — [Reading the Threat Panel](reading-threats.md)
- Deciding where to put controls — [Attack Path Analysis](attack-paths.md)
- Lining threats up against standards — [The Compliance Map](compliance-map.md)
- Why threats belong in the design stage — [An Introduction to Secure by Design](secure-by-design.md)
