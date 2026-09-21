# An Introduction to Secure by Design

**English** | [日本語](secure-by-design.ja.md)

This page is not about operating CyberRiskScape. It explains **why threats need to be considered
while a system is still being designed**, and the idea behind that — "Secure by Design".
If you would rather start with the tool itself, go to [Getting Started](getting-started.md).

The content is based on *Shifting the Balance of Cybersecurity Risk*, joint guidance from CISA
(the US Cybersecurity and Infrastructure Security Agency) and 18 partner organizations.
Full bibliographic details are in [References](#references) at the end.

---

## 1. What Secure by Design means

**Secure by Design** means technology products are built — **from the design stage onward** — in a
way that reasonably protects against malicious actors gaining access. The guidance frames this as an
investment of dedicated resources at every layer of product design and development, something that
**cannot be "bolted on" later**.

Its counterpart is **Secure by Default**: products that are resilient against prevalent exploitation
techniques **straight out of the box**, at no additional charge. The guidance compares this to
seatbelts, which come with every new car.

> Security should not be a luxury option, but should be considered a right customers receive
> without negotiating or paying more.
> — from the guidance

To get there, the guidance sets out three principles:

| # | Principle | What it means |
|---|---|---|
| 1 | **Take ownership of customer security outcomes** | The burden of security should not fall on the customer alone |
| 2 | **Embrace radical transparency and accountability** | Publish complete, accurate vulnerability information and compete on being safe |
| 3 | **Lead from the top** | Treat security as a business priority, not merely a technical feature |

What matters is that these principles bite **before development begins**. A secure by design product
is conceived with customer security as a core business goal before anyone writes code.

---

## 2. Why Secure by Design is being asked for now

### 2.1 The state we are in: "Vulnerable by Design"

The guidance opens with a chapter titled **"Vulnerable by Design."**

The software industry has historically relied on **fixing vulnerabilities after customers have
deployed the product**, leaving customers to apply patches at their own expense and to keep
monitoring, updating and cleaning up indefinitely. The guidance calls this a vicious cycle of
constantly creating and applying fixes — one that **only secure by design practices will break**.

### 2.2 Most vulnerabilities come from a small set of root causes

Products that are secure by design will still have vulnerabilities. But the guidance points out that
**a large set of vulnerabilities stems from a relatively small subset of root causes**.

The implication is that fixing defects one at a time is not the highest-value move: it is better to
**eliminate whole classes of them in the design**. Memory-safe languages, web template frameworks
that escape input automatically, parameterized queries and defense-in-depth all follow from that.

### 2.3 Regulation and the market are moving

- **The EU Cyber Resilience Act (CRA)** requires manufacturers to implement security throughout a
  product's lifecycle, to keep vulnerable products from reaching the market.
- **Secure by demand.** The guidance also gives customers a role: asking hard questions during
  procurement and vendor due diligence creates a demand signal that moves the market.
- **International agreement.** Eighteen organizations co-authored the guidance, Japan's NISC and
  JPCERT/CC among them. This is not one country's local requirement.

### 2.4 AI is not an exception

The guidance states explicitly that it **applies to manufacturers of AI software systems and models
as well**. Individual practices may need adjusting for AI-specific considerations, but
**the three overarching principles apply to all AI systems**.

That is the premise behind CyberRiskScape treating LLMs, AI agents, MCP servers and agent memory as
first-class components. New building blocks appear, but the principle — think about threats while
designing — does not change.

---

## 3. The role of threat modeling

In the guidance, threat modeling is not one security activity among many. It appears repeatedly as
**the foundation that makes Secure by Design work**. It plays four roles.

### 3.1 Enumerating what can go wrong, at design time

The guidance recommends using a **threat model tailored to the product during the product
development stage**, addressing all potential threats to the system and accounting for how each
system is deployed. This is the point at which protections get built into the blueprint, instead of
being found and patched after shipping.

### 3.2 Writing down what you protect, and from whom

Among its recommendations is **"publish high-level threat models"**, and it describes secure by
design products as ones that start with **written threat models describing what the creators are
trying to protect, and from whom**.

It adds that effective threat models are **informed by the way intrusions happen in the wild**, and
should cover the enterprise and development environments as well as how the manufacturer intends the
software to be used in customer environments.

Note what is being asked for: not an understanding in someone's head, but **a written artifact**.

### 3.3 Setting priorities

Threat models are used to **prioritize the most critical and high-impact features during resource
allocation and development**. Because a threat model reflects the product's specific use case, it
lets development teams decide where to fortify.

The same logic applies to adoption: the guidance says the introduction of secure by design practices
should be **prioritized based on tailored threat modeling, criticality, complexity and business
impact**.

### 3.4 Justifying the defaults

Secure by Default forces a decision about which features are on by default and which settings are
needed to be secure. The guidance names **explicit threat modeling as a tactic that helps inform
exactly that decision**.

Anything enabled by default becomes part of the customer's attack surface. The question is whether
you can say "we looked at the threats, and chose this default" rather than "it was convenient".

---

## 4. Where CyberRiskScape fits

Against those four roles, here is what this tool takes on:

| Role of threat modeling | What CyberRiskScape provides |
|---|---|
| What you protect, and from whom | The diagram states it. Attacker components and their Objective put the "from whom" on the canvas |
| Enumerating potential threats | Threats fire from the structure you drew, covering gaps a manual pass would miss |
| Informed by real intrusions | The threat library is built from published sources — OWASP, MITRE ATLAS, NIST, Anthropic and others — with references |
| Setting priorities | Severity plus a DREAD score and a response (mitigate / accept / transfer / avoid) per threat |
| A staged adoption plan | Mitigations are given at three tiers: FOUNDATION / ENTERPRISE / ADVANCED |
| Producing a written artifact | Export the threat list as CSV, JSON or Markdown |

To be clear about the other side: **this tool does not demonstrate conformance with Secure by
Design**. The guidance asks for an organizational commitment; a diagram and a list are only the
starting point.

- The threats you see are those the threat library covers. Completeness is not guaranteed.
- How serious a risk is, and whether to accept it, is your judgment.
- It is not a basis for claiming conformance with SSDF, the CRA or any other framework.

What it does do is carry most of the work of producing **a written threat model** — drawing the
structure, enumerating the threats, keeping the reasoning, and exporting the result.

---

## Where to go next

- The tool in practice — [Getting Started with CyberRiskScape](getting-started.md)
- Build one yourself — [Your First Threat Model](first-threat-model.md)
- Features and how the rules are organized — [README.md](../README.md)

---

## References

This page summarizes and restructures the following document. It is not a verbatim reproduction.

> **Shifting the Balance of Cybersecurity Risk: Principles and Approaches for
> Secure by Design Software** (October 2023 update, TLP:CLEAR)
>
> CISA, NSA, FBI and international partners (ACSC, CCCS, NCSC-UK, BSI, NCSC-NL, NCSC-NO,
> CERT NZ and NCSC-NZ, KISA, INCD, NISC-JP and JPCERT/CC, CSIRT Americas (OAS/CICTE),
> CSA Singapore, NÚKIB)
>
> https://www.cisa.gov/securebydesign

A work of the US Government, not subject to copyright protection in the United States
(17 U.S.C. §105). Referencing it here does not imply endorsement of this project by any of these
organizations.
