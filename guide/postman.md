# Verifying Threats with Postman — Export Check Requests from Detected Threats

**English** | [日本語](postman.ja.md)

> Postman is a trademark of Postman, Inc. This page explains how to verify threats detected in CyberRiskScape with
> Postman; it is not provided, certified, or endorsed by Postman, Inc. The collection format and the state of the
> runner tools follow the official information at the time of writing (October 2026). Check the linked sources for
> the latest.

---

## 1. What this page covers and prerequisites

- How to export check requests, as a Postman Collection, for the detected threats **that can be verified with an
  HTTP request** (UI and CLI)
- Which check is created for which threat, and what it verifies
- Running the checks in Postman, the Postman CLI or Newman, and wiring them into CI
- The **limitations** of the export (what it cannot verify)

Threat modeling tells you "there is no authentication here" or "another user's records may be readable", but
whether the implementation really behaves that way has to be checked separately. This export turns **identifying a
threat → confirming the countermeasure** into a single flow.

**Assumed knowledge**: [Reading the Threat Panel](reading-threats.md). For the CLI and CI, see
[Integrating with AI-Driven Development CI](ci-integration.md).

> **What to run it against** — Run the exported requests **only against systems you own or are authorized to test**.
> The requests are limited to harmless checks of whether a control holds (sending without authentication, asking for
> another user's ID, using a canary string, and so on). They contain no attack payloads.

---

## 2. How to export

### 2.1 From the UI

Open **Report** in the left sidebar and press **"Postman Collection (verification requests)"**. The threats detected
in the current layer and framework are used, and a `*.postman_collection.json` file is downloaded.

![Postman Collection in the Report menu](../assets/guide/postman/01-report-menu.png)

### 2.2 From the CLI

```bash
npm ci && npm run build:cli
node dist-cli/main.js export-postman model.json --out checks.postman_collection.json
```

You can pass `--layer` (default: the first layer with nodes), `--framework` and `--locale`. For a
[diagram built from a Kong configuration](kong-ai-gateway.md), pass the output of `import-kong` as is.

---

## 3. The check requests created

A check request is created per detected threat's canonicalId (the ID that groups equivalent threats). The request
targets the threat's node, or the receiving node when the threat is on a connection. When several threats lead to
the same check on the same node, they are merged into one request.

| Check | Threats (canonicalId) | Pass condition |
|---|---|---|
| Is an unauthenticated request rejected? | Unauthenticated public-network path, unauthenticated exposure, etc. | 401 / 403 |
| Is plain HTTP refused? | Plaintext communication | Redirect to https, 400 / 403 / 426, or unable to connect |
| Can another user's record be read? (BOLA) | `api-object-level-authorization` | 403 / 404 |
| Can a regular user call an admin function? (BFLA) | `gateway-authorization-gap` | 401 / 403 |
| Is rate limiting applied? | `gateway-resource-exhaustion`, `llm-resource-exhaustion` | Rate-limit headers present (no load is applied) |
| Is the management plane unreachable from outside? | `web-remote-management-exposure` | 401 / 403, or unable to connect |
| Does it resist instruction override? (canary string) | `direct-prompt-injection` | The canary string is not in the response |
| Does it withhold the system prompt? | `system-prompt-leakage` | The marker string is not in the response |
| Are MCP tool descriptors free of hidden instructions? | `tool-descriptor-poisoning` | `tools/list` descriptions contain no instruction-override wording |

Other threats (training-data poisoning, credentials exposed from a workspace, and so on) cannot be verified with an
HTTP request, so no tests are created for them. Their count appears in the collection's description.

The mapping lives in `data/test-templates/postman.yaml`. It is data, not code, so to add a check you add a template
to that YAML.

### 3.1 Example of an exported request

```json
{
  "name": "他人のレコードを参照できないか（BOLA）",
  "request": {
    "method": "GET",
    "header": [{ "key": "Authorization", "value": "Bearer {{token_user_a}}" }],
    "url": "https://{{C2_host}}{{C2_object_path}}"
  },
  "event": [{
    "listen": "test",
    "script": {
      "type": "text/javascript",
      "exec": [
        "pm.test(\"Another user's object is not accessible (403/404)\", function () {",
        "  pm.expect(pm.response.code).to.be.oneOf([403, 404]);",
        "});"
      ]
    }
  }]
}
```

(Request names follow the display language; this example was exported in Japanese. Test names inside the scripts are
always in English.) Requests are placed in one folder per node (ElementalID and name, such as `C2 orders-api`), and
the description lists the names and IDs of the threats being checked.

---

## 4. Fill in the variables before running

The diagram has no host names or tokens, so they are exported as collection variables. Set them to your test
environment through a Postman environment or the CLI's `--env-var`.

| Variable | Value to set |
|---|---|
| `C7_host` etc. (`<ElementalID>_host`) | Host name of the entry point that reaches the node (e.g. `api.example.com`; a port is fine) |
| `C7_path` etc. | Path used for the check (default `/`) |
| `C2_object_path` | Path to a record owned by user B (default `/resources/{{object_id_user_b}}`) |
| `C3_admin_function_path` | Path of a function only administrators may call |
| `C3_admin_url` | Management URL (Admin API or console) |
| `C4_chat_path` | Path of the chat entry point that reaches the LLM. For an LLM node, set `_host` to **the app or gateway entry point that reaches that LLM** |
| `C6_mcp_path` | Path of the MCP (Streamable HTTP) endpoint |
| `token_user_a` | A regular user's (user A's) access token |
| `object_id_user_b` | ID of a record owned by user B |
| `canary` | Canary string that must not appear in responses (has a default) |
| `system_prompt_marker` | Marker string placed in the test environment's system prompt (has a default) |

The ElementalID (`C7` and so on) is the number shown at the bottom left of each node on the diagram.

---

## 5. Run

### 5.1 In Postman

Choose **Import** in Postman and load the exported JSON. Postman v12 and later can still import this format (v2.1).
If you want to manage it with v12's Git integration (collection v3 YAML), convert it with the Postman CLI's
`postman collection migrate` ([source 2](#references)).

### 5.2 From the CLI (in CI)

```bash
# Postman CLI (local collections run without signing in)
postman collection run checks.postman_collection.json -e test-env.json

# Newman (works because the format is v2.1)
npx newman run checks.postman_collection.json -e test-env.json --env-var token_user_a=$TOKEN
```

If any test fails, the exit code is non-zero, so you can fail the CI job. Pass tokens from CI secrets; do not write
them into the environment file.

> **About Newman** — The official documentation recommends moving to the Postman CLI, and Newman does not support the
> collection v3 format ([source 3](#references)). This export uses v2.1, so either runner works.

### 5.3 Reading the results

- A **failure** means the threat flagged on the diagram is likely real in the implementation. Keep "Control status"
  on the threat card at "Required" and work on the countermeasure
- A **pass** means the control holds within the scope of that check. It does not mean the threat is gone (for example,
  ignoring one canary string does not mean every phrasing is ignored). Use it as evidence when recording control status
- When the plaintext or management-plane checks **cannot connect**, the test passes and the run also shows a request error

---

## 6. Limitations

- **Only some threats — those verifiable over HTTP — are checked.** Threats without a mapping get no test
- **Each check is a single request.** It is not a thorough assessment of prompt-injection resistance or BOLA. For
  thorough testing, use dedicated scanners or manual testing as well
- **Request shapes are generic.** The chat body uses the OpenAI-compatible format, and MCP sends `tools/list` directly.
  Adjust bodies and headers to your actual API (some MCP servers require `initialize` first)
- Targets are derived from the diagram's structure. If the diagram's connections differ from reality, so do the
  checked locations
- One layer — the one currently shown — is exported

---

## References

1. Postman Collection Format v2.1.0 (JSON Schema) — <https://schema.getpostman.com/json/collection/v2.1.0/collection.json>
2. Postman CLI collection commands (`collection run`, `collection migrate`) — <https://learning.postman.com/docs/postman-cli/postman-cli-collections>
3. Running with Newman and migrating to the Postman CLI — <https://learning.postman.com/docs/collections/using-newman-cli/command-line-integration-with-newman/>
4. OWASP API Security Top 10 2023 — <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
5. OWASP Top 10 for LLM Applications 2025 — <https://genai.owasp.org/llm-top-10/>

---

## What to read next

- Recording control status — [Assessing Risk in Analytics](analytics-assessment.md)
- Gating threat differences in PRs — [Integrating with AI-Driven Development CI](ci-integration.md)
- Building the diagram from configuration — [Threat Modeling Kong AI Gateway](kong-ai-gateway.md)
