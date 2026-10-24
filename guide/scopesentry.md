# Turn ScopeSentry Assets, Vulnerabilities, and Takeover Findings into a Diagram — From Your Own ASM to a Threat Model

**English** | [日本語](scopesentry.ja.md)

> ScopeSentry is a name belonging to its respective owners. This page explains how to bring observations from a
> ScopeSentry export or API into a CyberRiskScape diagram. It is not provided, certified, or endorsed by the ScopeSentry
> developers. The use of the name is descriptive. The export format and API calls follow the official source as of the time of
> writing (October 2026); check the official information for the latest.

> **Scan only what you are authorized to test** — Use ScopeSentry only against assets that your organization manages or that you have
> been authorized to assess. Scanning targets without permission may violate laws or contracts. The import on this page only
> reads results that have already been collected; it never scans anything.

---

## 1. What you will learn, and prerequisites

- How to import ScopeSentry **assets, vulnerabilities, and subdomain takeover results (SubdomainTakerResult)** and **generate a draft diagram of the
  services exposed to the internet** (UI and CLI)
- Two ways to import: **from an export file** or **from the API (ScopeSentry's MCP endpoint)**
- Which fields become which types and attributes in the diagram, and **what is not read**
- The **threats that are actually detected** on the imported diagram (with counts confirmed on the sample), and the input that clears the subdomain takeover threat
- How to re-import periodically and **catch newly exposed services with `diff --fail-on`**

**Background: what ScopeSentry is** (according to the official description at the time of writing)

- ScopeSentry is a self-hosted, open-source ASM (attack surface management) and reconnaissance platform. It can enumerate subdomains, scan
  ports, fingerprint services, scan for vulnerabilities, and **detect subdomain takeover**, and it can run on distributed nodes. It uses MongoDB and
  Redis and is deployed with Docker ([source 1](#references)).
- CyberRiskScape only **reads ScopeSentry's export format**. It does not depend on ScopeSentry's code or license.

**Knowledge assumed:** the operations in [Getting Started with CyberRiskScape](getting-started.md) and [Reading the Threat Panel](reading-threats.md).
This works like the Shodan import, so reading §4.4 of [Reducing Internet Exposure](exposure-reduction.md) first helps.

---

## 2. How observations map to CyberRiskScape types

### 2.1 Export from ScopeSentry

In the ScopeSentry UI, use **Export** on the asset list, choose **JSON** (one record per line) as the format, select the fields, and export.

- **XLSX cannot be imported.** Always choose JSON.
- We recommend these 12 fields: `host`, `ip`, `port`, `service`, `type`, `url`, `technologies`, `webServer`, `cdnname`, `tls`, `rootDomain`, `time`
- You can export the vulnerability page and the subdomain takeover page the same way. **Concatenate the three files into one**
  (`cat a.json b.json c.json > all.json`) and import it. The record kind is detected from the field names.

### 2.2 Mapping

One node is created per service (IP and port pair). If the same service appears more than once, the newest observation is used. Rules are checked from the top.

| ScopeSentry information | CyberRiskScape type |
|---|---|
| Product or technology such as Ollama or vLLM; port 11434 | `LLM` (LLM Model) |
| Database ports (3306, 5432, 6379, 9200, 27017, etc.) | `DATA_STORE` (Data Store) |
| Remote administration ports (22, 23, 445, 3389, 5900-5903, 5938, 5985, 5986) | `GATEWAY` (API Gateway) |
| HTTP response present (`type` is http, or `url` present); ports 80, 443, 8080, 8443 | `FRONT_END_SERVER` (Front-End Server) |
| None of the above | `PROCESS` (Process) |
| **Subdomain takeover report** | One `DNS_ZONE` (**DNS (authoritative DNS / zone)**) per root domain (`rootDomain`) |

![DNS (authoritative DNS / zone) in the palette](../assets/guide/scopesentry/05-palette.png)

`DNS (authoritative DNS / zone)` is in **Network & Edge** in the left palette. It is a new type that represents a zone holding your domain's
records (A, CNAME, NS, MX, and so on).

- **Edges:** from the attacker (Internet) to each service. **TLS** if TLS is confirmed, otherwise **Plain**. Authentication cannot be verified from outside, so it is set to **Password**
  (correct it to match reality). No edge is drawn to DNS (it is a naming problem, not a connection).
- **Attack Surface Attribute:** for front-end servers and API gateways, "Global IP assignment" is set to **yes**. Other items are left unset and are evaluated as the unsafe value.
- **Description:** IP, port, product, observation date, detected technologies, CDN, and the IDs of vulnerabilities ScopeSentry reported (**unverified**).
  A vulnerability is linked to the service whose URL host and port match; those that cannot be linked are only counted. Vulnerabilities are not treated as threats.
  Use them as a prompt to check patches and scan results.
- **Takeover reports:** the DNS node's description lists the host and CNAME as "reported as takeover-able (**unverified**)".
- **Not read:** page bodies, headers, banners, requests/responses, screenshots, titles, and matched snippets.
  URLs are used only to link a vulnerability to a node and are not shown in the diagram (URL userinfo and query strings are discarded before matching).
- The limit is 300 services. Anything beyond that is not imported, and the count is shown.

---

## 3. Example diagram

The sample is built from fictional data (documentation addresses `192.0.2.0/24`, `203.0.113.0/24`, `198.51.100.0/24`, and `example.com` / `example.net`).

| File | Contents |
|---|---|
| [`templates/scopesentry-sample.jsonl`](templates/scopesentry-sample.jsonl) | A sample in the shape of a ScopeSentry export (5 assets, 2 vulnerabilities, 1 takeover) |
| [`templates/scopesentry-sample.en.json`](templates/scopesentry-sample.en.json) ([Japanese](templates/scopesentry-sample.ja.json)) | The diagram imported from the above (template) |

The assets are a public web site (443, TLS), an admin panel (8443), SSH (22), Redis (6379), and Ollama (11434). See [Creating and Using Templates](templates.md) for how to load it.

### Import from the UI

Go to **Template → Import tab → "Select ScopeSentry export"** and choose the exported JSON (or the sample above).

![ScopeSentry import on the Import tab](../assets/guide/scopesentry/01-import.png)

After loading, the counts are shown (for the sample: services 5 / hosts 4 / vulnerabilities 2 / takeover reports 1). **Replace and apply** turns it into a diagram.

![The imported diagram](../assets/guide/scopesentry/02-diagram.png)

Contents: 7 components (1 attacker, 5 services, 1 DNS), 5 data flows, 2 trust boundaries. The attacker is placed in the external boundary (Internet), and the exposed services in a
Public Area boundary. (The screenshots show the Japanese UI.)

### Import from the CLI

```bash
npm run build:cli
node dist-cli/main.js import-scopesentry guide/templates/scopesentry-sample.jsonl --out scopesentry.json
node dist-cli/main.js analyze scopesentry.json
```

---

## 4. Threats to focus on

Importing the sample detects **73 threats** (14 Critical, 38 High, 21 Medium) as of this writing.

### 4.1 Subdomain takeover (DNS)

| Threat | Severity | Fires when |
|---|---|---|
| No or irregular review of DNS record targets (`posture-dns-dangling-record-001`) | High | The DNS node's operational posture "DNS record target review" is **unset, not performed, or irregular** |

If a record that points to a decommissioned cloud resource (storage, PaaS, CDN, SaaS) remains, an attacker can create a resource with the same name and take over the subdomain.
A ScopeSentry takeover report suggests that this may be the case.

![Threat card on the DNS node](../assets/guide/scopesentry/03-takeover-threat.png)

The card says the operational posture is unset and is evaluated as no control (unset is treated the same as a bad value). There are two ways to **clear the threat**.

1. Actually fix the reported issue (remove the lingering record, verify its target).
2. Then select the DNS node and enter "**DNS record target review**" under **Operational posture** to match reality.
   Choosing **Periodic** clears the threat (confirmed on the sample: 73 to 72 threats).

![Operational posture of the DNS node](../assets/guide/scopesentry/04-dns-posture.png)

"Irregular" and "Not performed" do not clear it. You can also record the last review date and a note. **Do not enter "Periodic" if you do not actually review the records.**

### 4.2 Exposed services

Main threats detected on the sample (the IDs are the threat rule IDs).

| Target | Main threats (rule ID) | Severity |
|---|---|---|
| Public web, admin panel, SSH | Remote management exposed (`stride-web-remote-mgmt-exposed-001`), anonymous access on public (`stride-web-anonymous-on-public-001`) | Critical |
| Same | Direct global IP exposure (`stride-web-global-ip-exposure-001`), no source IP restriction (`stride-web-no-source-ip-restriction-001`), no application-layer protection (`stride-web-no-waf-001`) | High |
| Same | Missing patches for known vulnerabilities (`posture-patch-missing-001`) | Critical |
| Public web, admin panel | Web shell implanted by exploiting a public app (`webserver-webshell-implant-001`) | Critical |
| Redis (6379) | Information disclosure (`stride-data-store-info-disclosure-001`), tampering (`stride-data-store-tampering-001`), short log retention (`posture-log-retention-short-001`) | High |
| Ollama (11434) | Direct prompt injection (`owasp-llm01-prompt-injection-001`), full model access (`atlas-aml-t0044-full-model-access-001`) | Critical |
| Edges (plaintext, password only) | Eavesdropping (`stride-edge-plain-encryption-001`), password/API-key-only authentication over a public network (`stride-edge-password-internet-001`) | High |

> **Note** — Vulnerabilities reported by ScopeSentry (2 in the sample) only appear in the node description as "unverified"; they do not change the threat count.
> Treat a report such as a default login on an admin panel as **a prompt to verify and re-enter the diagram's attributes (authentication, source IP restriction)**.
> Enter only what you have confirmed. Entering "yes" by guess merely makes threats look as if they disappeared.

---

## 5. Attack path analysis

Open [Attack Path Analysis](attack-paths.md) on the imported diagram to compare the paths from an internet attacker to each service.
An imported diagram alone does not show how services relate (for example, which service uses Redis). Once you add the internal structure, you can see the paths from an
exposed entry point to critical assets, and the choke points.

---

## 6. Use cases

### 6.1 Import from an export file

Load the JSON exported in §2.1 from the UI or the CLI (§3). It does not connect to ScopeSentry and **works with the file alone**.

### 6.2 Import from the API (ScopeSentry's MCP)

To skip the export step, the CLI can fetch directly. It connects to the MCP endpoint that ScopeSentry officially provides (`<base-url>/mcp`) and retrieves
assets, vulnerabilities, and subdomain takeover results using **only the read-only `list_assets`** (100 per page, up to 3,000 in total).
The REST API requires a UI login (JWT), and API keys only work on `/mcp`, which is why this approach is used.

```bash
# Create the API key on ScopeSentry's API Key page and pass it in an environment variable (it is not kept on the command line or in the diagram)
export SCOPESENTRY_API_KEY=ssk_xxxxxxxx
node dist-cli/main.js import-scopesentry --api https://scopesentry.example.internal --out scopesentry.json
# Narrow down by project or search expression
node dist-cli/main.js import-scopesentry --api https://scopesentry.example.internal \
  --project <project ObjectID> --search "<ScopeSentry search expression>" --out scopesentry.json
```

**Security notes**

- **Pass the API key only through an environment variable.** It is never written to files, diagrams, logs, or error messages. Do not leave it in shell history or CI logs either.
- **ScopeSentry's default deployment uses plain HTTP** (as of this writing). The API key would travel over the wire, so use a URL that is **HTTPS (terminated at a reverse proxy)** or on a
  **closed local network** for `--api`. Do not use it over the internet in plaintext.
- The tool calls **only `list_assets`**, and write-type calls are rejected by an allow list. For the account that holds the key, restrict it to **the minimum, read-only scope**
  if ScopeSentry lets you choose permissions (check the official information for how permissions are chosen).
- When the limit (3,000 records) is reached, the tool says so and stops. Narrow down with `--project` or `--search`.
- Use it only for results within the authorized scope (see the note at the top).

### 6.3 Re-import periodically and catch new exposure

Element IDs in an imported diagram are **derived from IP and port (and the DNS root domain)**, so you can `diff` the previous and current imports directly.
Only threats from newly opened ports or newly reported takeovers show up as "added".

```bash
node dist-cli/main.js import-scopesentry 2026-10.json --out 2026-10.model.json
node dist-cli/main.js import-scopesentry 2026-11.json --out 2026-11.model.json
node dist-cli/main.js diff 2026-10.model.json 2026-11.model.json --fail-on High
```

Adding one RDP (3389) asset to the sample and comparing gives 16 added, 0 resolved, and 12 new threats at High or above, so the command stops with exit code 1 (as of this writing).
The diff report also lists **execution triggers** that a person should review, such as a new external interface (T2). For CI, see
[Integrating with AI-Driven Development CI](ci-integration.md).

> Attributes you enter by hand on an imported diagram (such as DNS "Periodic") are not in a freshly re-imported diagram.
> If you use a hand-edited diagram as the baseline, the same threat shows up as "added". **Compare imports against imports.**

---

## 7. Limits

- **At the time of writing this was verified not against a real instance but against mocks based on the format in the official source.** If field names or formats in a real
  ScopeSentry export or API response differ, rows that cannot be imported are counted as "skipped". Check the counts.
- **The diagram is a copy of observations.** Assets that ScopeSentry did not find are not drawn. A scan reflects the moment it ran and may be out of date.
- **Authentication, source IP restrictions, WAF, and logging cannot be seen from outside.** Enter only items you have confirmed.
- **Vulnerabilities (CVEs, etc.) are not judged.** ScopeSentry's reports are only written to the description as "unverified".
- **Takeover reports are not represented as edges to DNS.** The reported host is written in the DNS node's description, and you decide which services are affected and add them to the diagram.
- **XLSX exports cannot be imported.** The root domain uses the `rootDomain` field, or falls back to the last two labels of the host (multi-level TLDs such as `co.jp` may be split incorrectly).
- OT / ICS devices (industrial protocols) cannot be represented.

---

## References

1. ScopeSentry (GitHub) — <https://github.com/Autumn-27/ScopeSentry>

---

## What to read next

- The full exposure-reduction process — [Reducing Internet Exposure](exposure-reduction.md)
- How to read threats — [Reading the Threat Panel](reading-threats.md)
- Put periodic assessment into CI — [Integrating with AI-Driven Development CI](ci-integration.md)
- Investigate paths from the attacker's view — [Attack Path Analysis](attack-paths.md)
- Build a test plan — [Creating a Penetration Test Plan from the Threat Model](pentest-plan.md)
