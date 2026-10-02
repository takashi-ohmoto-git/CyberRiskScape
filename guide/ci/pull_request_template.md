<!--
  This PR template is based on the output of
  `node dist-cli/main.js triggers --format md --locale en`
  (see guide/ci-integration.md). To use it in your own repository, copy it to
  `.github/pull_request_template.md` (GitHub auto-applies templates placed directly under
  `.github/` or under `.github/PULL_REQUEST_TEMPLATE/`).
-->

## What changed

<!-- What this PR changes -->

## Threat modeling trigger checklist

Check whether this PR needs a threat model update. Tick the items that apply and update the threat model if needed.

### Auto-detected from the model diff

- [ ] **T1 New trust boundary** — Data crosses a new network segment, tenant isolation boundary, or privilege boundary
- [ ] **T2 New external interface** — Internet-facing API, webhook, gRPC endpoint, callback URL, or public SDK
- [ ] **T3 New authentication / authorization mechanism** — New login flow, token type, mTLS, RBAC model, service identity, or certificate management
- [ ] **T5 Sensitive data takes a new path** — Customer data, secrets, cryptographic keys, or PII pass through a component that did not previously handle them
- [ ] **T6 New third-party integration** — An external vendor's SDK, API, or service that receives or processes customer data
- [ ] **T7 Expanded agent capability** — A new tool, MCP server, sub-agent delegation, or memory store; increased autonomy or permissions
- [ ] **T8 Change to the model, training data, or RAG source** — A change to the LLM in use, fine-tuning/training data, or RAG reference sources

### Needs human (or AI reviewer) review (cannot be auto-judged from the model diff)

- [ ] **T4 New technology or runtime** — An unfamiliar language, framework, data store, cloud service, or deployment model

### Did you update the threat model?

- [ ] One of the above applies, so I updated the threat model (e.g. `threat-model/project.json`)
- [ ] None of the above applies, or a reviewer is expected to apply the `threat-model-not-needed` label
