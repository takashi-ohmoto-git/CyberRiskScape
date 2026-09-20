import type { TranslationKey } from '../ja';

/** Zero Trust for AI Agents panel (English). Missing keys fall back to Japanese. */
export const enZeroTrust: Partial<Record<TranslationKey, string>> = {
  'zeroTrust.header.subtitle':
    'A security framework for deploying autonomous AI agents in the enterprise',
  'zeroTrust.header.quote': '"Trust nothing. Verify everything. Assume breach."',
  'zeroTrust.header.source': 'Source: Anthropic, "Zero Trust for AI Agents" eBook (2026)',

  'zeroTrust.principles.sectionTitle': 'Principles',
  'zeroTrust.principles.neverTrust.title': 'Never trust, always verify',
  'zeroTrust.principles.neverTrust.body':
    'Every request is authenticated and authorized regardless of origin — being inside the network is not a free pass.',
  'zeroTrust.principles.assumeBreach.title': 'Assume breach',
  'zeroTrust.principles.assumeBreach.body':
    'Design for containment, not just prevention. Segment by identity and contain the blast radius.',
  'zeroTrust.principles.leastAgency.title': 'Least privilege → least agency',
  'zeroTrust.principles.leastAgency.body':
    'Constrain not only what an agent can access, but what each tool can do, how often, and where.',
  'zeroTrust.principles.designTest.title': 'Design test: "Impossible, not tedious"',
  'zeroTrust.principles.designTest.body':
    'Agentic attackers have infinite patience and near-zero cost per attempt, so controls that only add friction (rate limiting, SMS-based MFA) will be defeated. Prefer controls that remove a capability over ones that merely throttle it.',

  'zeroTrust.whyNow.sectionTitle': 'Why now',
  'zeroTrust.whyNow.speedOfExploit.stat': 'Months → hours',
  'zeroTrust.whyNow.speedOfExploit.body':
    'AI compresses the time from vulnerability to exploitation at negligible cost.',
  'zeroTrust.whyNow.backdoorDocs.stat': '250 documents',
  'zeroTrust.whyNow.backdoorDocs.body':
    'Enough to implant a persistent backdoor in an LLM (600M-13B parameters) that survives safety training.',
  'zeroTrust.whyNow.spotlighting.stat': '50% → <2%',
  'zeroTrust.whyNow.spotlighting.body':
    'Spotlighting untrusted content lowers the success rate of indirect prompt injection.',
  'zeroTrust.whyNow.jailbreakBlockRate.stat': '95%',
  'zeroTrust.whyNow.jailbreakBlockRate.body':
    'Share of jailbreak attempts blocked by constitutional classifiers.',

  'zeroTrust.matrix.sectionTitle': 'Capability matrix — 3 tiers × 7 domains',
  'zeroTrust.matrix.domainHeader': 'Domain',
  'zeroTrust.matrix.tier.foundation.label': 'FOUNDATION',
  'zeroTrust.matrix.tier.foundation.tagline': 'Minimum implementation level — a raised baseline',
  'zeroTrust.matrix.tier.enterprise.label': 'ENTERPRISE',
  'zeroTrust.matrix.tier.enterprise.tagline':
    'The maturity level most organizations should target',
  'zeroTrust.matrix.tier.advanced.label': 'ADVANCED',
  'zeroTrust.matrix.tier.advanced.tagline': 'For regulated or high-impact environments',

  'zeroTrust.matrix.domain.identityAuth.name': 'Identity & authentication',
  'zeroTrust.matrix.domain.identityAuth.foundation':
    'Per-agent cryptographic identity, short-lived IdP tokens — no static API keys',
  'zeroTrust.matrix.domain.identityAuth.enterprise':
    'X.509 certificates with lifecycle management, mutual TLS + certificate pinning',
  'zeroTrust.matrix.domain.identityAuth.advanced':
    'Hardware-backed identity via HSM/TPM with remote attestation',

  'zeroTrust.matrix.domain.accessControl.name': 'Access control & permissions',
  'zeroTrust.matrix.domain.accessControl.foundation':
    'RBAC, default-deny, identity-based workload isolation',
  'zeroTrust.matrix.domain.accessControl.enterprise':
    'Context-aware ABAC, per-agent sandboxed execution',
  'zeroTrust.matrix.domain.accessControl.advanced':
    'Continuous authorization, JIT/JEA, confidential computing',

  'zeroTrust.matrix.domain.observability.name': 'Observability & audit',
  'zeroTrust.matrix.domain.observability.foundation':
    'Comprehensive action logging, request IDs linking actions to their trigger',
  'zeroTrust.matrix.domain.observability.enterprise':
    'Tamper-evident audit trails, distributed tracing (OpenTelemetry)',
  'zeroTrust.matrix.domain.observability.advanced':
    'Real-time SIEM streaming, full input-to-output provenance chain',

  'zeroTrust.matrix.domain.behaviorMonitoring.name': 'Behavioral monitoring',
  'zeroTrust.matrix.domain.behaviorMonitoring.foundation':
    'Manual baselines, alerts with model-drafted initial triage',
  'zeroTrust.matrix.domain.behaviorMonitoring.enterprise':
    'Learned baselines, automated containment and access revocation',
  'zeroTrust.matrix.domain.behaviorMonitoring.advanced':
    'Continuous drift detection, automated SOAR playbooks',

  'zeroTrust.matrix.domain.ioControl.name': 'Input/output control',
  'zeroTrust.matrix.domain.ioControl.foundation':
    'Input validation and length limits, PII/credential output filtering',
  'zeroTrust.matrix.domain.ioControl.enterprise':
    'Content filtering for attack patterns, semantic output analysis',
  'zeroTrust.matrix.domain.ioControl.advanced':
    'Constitutional classifiers + spotlighting, human approval for high-risk actions',

  'zeroTrust.matrix.domain.integrityRecovery.name': 'Integrity & recovery',
  'zeroTrust.matrix.domain.integrityRecovery.foundation':
    'Version-controlled configuration, documented and tested rollback',
  'zeroTrust.matrix.domain.integrityRecovery.enterprise':
    'Signed configuration, automated rollback with health checks',
  'zeroTrust.matrix.domain.integrityRecovery.advanced':
    'Immutable infrastructure, self-healing automated remediation',

  'zeroTrust.matrix.domain.aiGovernance.name': 'AI governance',
  'zeroTrust.matrix.domain.aiGovernance.foundation':
    'Documented usage policy and incident response plan, addressing shadow AI',
  'zeroTrust.matrix.domain.aiGovernance.enterprise':
    'Formal framework with cross-functional stakeholder oversight',
  'zeroTrust.matrix.domain.aiGovernance.advanced':
    'Automated compliance checks enforced in the deployment pipeline',

  'zeroTrust.matrix.footnote.lead': 'Each tier builds on the one before it.',
  'zeroTrust.matrix.footnote.emphasis':
    '"Skip even one capability, and attackers will find the gap."',

  'zeroTrust.threats.sectionTitle': 'Threats (OWASP)',
  'zeroTrust.threats.promptInjection.title': 'Prompt injection',
  'zeroTrust.threats.promptInjection.body':
    'Direct and indirect — LLMs cannot reliably distinguish contextual information from instructions to execute.',
  'zeroTrust.threats.toolAbuse.title': 'Tool & resource abuse',
  'zeroTrust.threats.toolAbuse.body':
    'MCP tool poisoning, rug-pull tool substitution, data exfiltration via tool chaining, resource exhaustion.',
  'zeroTrust.threats.identityAbuse.title': 'Identity & privilege abuse',
  'zeroTrust.threats.identityAbuse.body':
    'Out-of-scope permission inheritance, confused deputy relaying, privilege retention via memory.',
  'zeroTrust.threats.supplyChain.title': 'Supply chain risk',
  'zeroTrust.threats.supplyChain.body':
    'Poisoned model weights, malicious MCP servers, dependency confusion attacks.',
  'zeroTrust.threats.memoryPoisoning.title': 'Memory & context poisoning',
  'zeroTrust.threats.memoryPoisoning.body':
    'RAG/vector DB poisoning, attacks on shared context, gradual drift of long-term memory.',
  'zeroTrust.threats.baselineRising.label': 'The baseline keeps rising:',
  'zeroTrust.threats.baselineRising.body':
    'Today\'s "Advanced" becomes tomorrow\'s "Enterprise," and "Enterprise" becomes "Foundation."',

  'zeroTrust.workflow.sectionTitle': 'Implementation workflow — 8 phases',
  'zeroTrust.workflow.phase.identifyRequirements.title': 'Identify requirements',
  'zeroTrust.workflow.phase.identifyRequirements.body':
    'Align regulatory, operational, and stakeholder needs',
  'zeroTrust.workflow.phase.protectSupplyChain.title': 'Protect the supply chain',
  'zeroTrust.workflow.phase.protectSupplyChain.body': 'AI-BOM, scorecards, AI vendoring, signing',
  'zeroTrust.workflow.phase.defineAgentBoundaries.title': 'Define agent boundaries',
  'zeroTrust.workflow.phase.defineAgentBoundaries.body':
    'Unique identity, least agency, blast radius',
  'zeroTrust.workflow.phase.defendPromptInjection.title': 'Defend against prompt injection',
  'zeroTrust.workflow.phase.defendPromptInjection.body':
    'Input separation, classifiers, limiting attack surface',
  'zeroTrust.workflow.phase.secureToolAccess.title': 'Secure tool access',
  'zeroTrust.workflow.phase.secureToolAccess.body':
    'Allowlists, parameter validation, sandboxing',
  'zeroTrust.workflow.phase.protectCredentials.title': 'Protect credentials',
  'zeroTrust.workflow.phase.protectCredentials.body':
    'Short-lived, hardware-bound, JIT, per-agent',
  'zeroTrust.workflow.phase.protectMemory.title': 'Protect memory',
  'zeroTrust.workflow.phase.protectMemory.body': 'Isolation, integrity checks on retrieval, TTL',
  'zeroTrust.workflow.phase.measureMetrics.title': 'Measure key metrics',
  'zeroTrust.workflow.phase.measureMetrics.body': 'Dwell time, coverage, explainability',
};
