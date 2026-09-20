# CyberRiskScape

**Open-source visual threat modeling for AI, LLM, agentic systems, and post-quantum cryptography**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Threat rules](https://img.shields.io/badge/threat%20rules-113-orange.svg)](data/threat-library)
[![Tests](https://img.shields.io/badge/tests-468%20passing-brightgreen.svg)](#development)
[![Demo](https://img.shields.io/badge/demo-live-blueviolet.svg)](https://takashi-ohmoto-git.github.io/CyberRiskScape/)

**English** | [日本語](README.ja.md)

Draw a data flow diagram in your browser, and CyberRiskScape enumerates the threats that
apply to your architecture — including the ones classical threat modeling tools have no
vocabulary for: goal hijacking, tool misuse, privilege carry-over, memory poisoning.

It runs entirely in the browser. No server, no account, no telemetry — your design never
leaves your machine.

**▶ Live demo: https://takashi-ohmoto-git.github.io/CyberRiskScape/** (nothing to install)

> **Interface language.** English and Japanese are both supported — use the JA / EN switch
> in the top bar, and your choice is remembered. The interface and all 113 threat rules
> (name, category, description, mitigations) are translated. Component type labels in the
> palette are still Japanese; that is the last piece — see [Roadmap](#roadmap).
> Help is welcome.

---

## What makes it different

### Agentic AI is a first-class citizen

Alongside classical STRIDE, CyberRiskScape treats **AI agents, LLMs, MCP servers, and
long-term memory** as first-class component types, with a rule set to match.

| Framework | Rules | Covers |
|---|---:|---|
| `STRIDE` | 47 | Spoofing, tampering, repudiation, information disclosure, DoS, elevation of privilege |
| `AI` | 25 | Adversarial ML, model extraction, training data poisoning |
| `AgenticAI` | 41 | Goal hijacking, tool misuse, privilege carry-over, memory poisoning |

This is where the project invests. Most threat modeling tools have zero rules in the third row.

### Features

- **Visual DFD editor** — 38 component types across 6 libraries and 9 categories, trust
  boundaries, and data flows carrying encryption, authentication, and semantic attributes
- **Automatic threat detection** — distinguishes *inherent* threats (a component fires them
  just by existing) from *path-dependent* ones (they need a specific connection to exist)
- **Attack path analysis** — maps routes from attacker to asset and identifies choke points
  where several routes converge on one defensible node
- **Compliance mapping** — maps detected threats to NIST CSF 2.0 (128 items), NIST AI RMF
  (72 items), and Japan's AI Business Operator Guidelines (34 items)
- **Risk assessment** — DREAD scoring and risk treatment decisions (mitigate / accept /
  transfer / avoid)
- **Custom rules** — add your own detection rules from an in-app editor
- **Threat library inspector** — read-only view of every rule and the exact conditions
  that make it fire
- **Export** — threat lists as CSV / JSON, and as Markdown compatible with the
  `THREAT_MODEL.md` schema used by Anthropic's `defending-code-reference-harness`
- **Local persistence** — automatic retention via IndexedDB, plus explicit saves to local
  files through the File System Access API

---

## Screenshot

![CyberRiskScape screenshot](assets/screenshot.png)

Left: component palette and library management. Center: the DFD canvas and its legend.
Right: detected threats, each with its firing conditions, three-tier mitigations,
compliance references, and sources.

See it running in the [live demo](https://takashi-ohmoto-git.github.io/CyberRiskScape/).

---

## Requirements

| | |
|---|---|
| Node.js | 20 or later (for development and builds only) |
| Browser | Chromium-based (Chrome / Edge) recommended |

Saving to local files uses the File System Access API, which is Chromium-only. On Firefox
and Safari that one feature is disabled; everything else works.

---

## Quick start

```bash
git clone https://github.com/takashi-ohmoto-git/CyberRiskScape.git
cd CyberRiskScape
npm install
npm run dev
```

Open the URL it prints (http://localhost:5173 by default).

Production builds are plain static files and can be hosted anywhere:

```bash
npm run build     # outputs to dist/
npm run preview   # serve the build locally
```

---

## How to use it

1. **Place components** — drag DFD elements (users, LLMs, agents, data stores, …) from the
   left sidebar onto the canvas
2. **Connect them** — draw data flows and set encryption, authentication, and semantics
   (tool call, memory write, …)
3. **Draw trust boundaries** — make the crossings explicit
4. **Review threats** — threats appear as you build. Each one opens to show why it fired:
   its conditions, rule ID, and source
5. **Assess and decide** — record DREAD scores and a risk treatment; suppress false positives
6. **Export** — CSV, JSON, or Markdown

---

## Development

```bash
npm run dev          # dev server
npm run build        # production build
npm run preview      # preview the build
npm run test         # run all tests
npm run test:watch   # watch mode
npx tsc --noEmit     # type check (strict)
```

The standard check after a change is `npx tsc --noEmit` plus the test suite. 468 tests
currently pass.

---

## Roadmap

Near-term priorities, in order:

1. **English component library** — translate the component type labels that still render in
   Japanese, using the same overlay approach as the threat library
2. **Structured audit report** — PDF / HTML output fit to serve as audit evidence, with
   detection confidence stated explicitly

Done recently: an English UI with a language switcher, and an English translation overlay
for all 113 threat rules that leaves the existing schema unchanged.

---

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
development workflow, the rules for adding threat rules, and how to help with translation.

---

## Security

Please report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/takashi-ohmoto-git/CyberRiskScape/security/advisories/new),
not through public issues. Details are in [SECURITY.md](SECURITY.md).

Two things to be aware of:

- **Do not load untrusted YAML.** Inline SVG icons in component libraries are not yet
  sanitized, so review any third-party library YAML before using it
- This tool is a **design aid** for threat modeling. It does not guarantee that its findings
  are complete or correct; use it alongside expert judgment, not instead of it

---

## License

[Apache License 2.0](LICENSE)

The threat library and compliance mappings are original work of this project. Attribution
for the external sources they reference (OWASP, MITRE ATLAS, NIST, CISA, Anthropic, and
others) is collected in [NOTICE](NOTICE).
