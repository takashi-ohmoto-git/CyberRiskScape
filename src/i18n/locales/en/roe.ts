import type { TranslationKey } from '../ja';

/** English translation for the rules of engagement (RoE) / scope declaration (Markdown). */
export const enRoe: Partial<Record<TranslationKey, string>> = {
  'roe.title': 'Rules of engagement (RoE) / scope declaration: {system}',
  'roe.h.overview': '1. Overview and premises',
  'roe.h.inScope': '2. Authorized targets (permitted to test)',
  'roe.h.outOfScope': '3. Out-of-scope targets (must not test)',
  'roe.h.approval': '4. Approval policy',
  'roe.h.sourceSide': '5. Items to copy to the source side (operator checklist)',
  'roe.h.limits': '6. Limits',

  'roe.overview.system': 'System: {system}',
  'roe.overview.layer': 'Layer: {layer}',
  'roe.overview.generated': 'Generated: {date} (produced from the threat model by {product})',
  'roe.overview.purpose':
    'This document is the rules of engagement (RoE) for running an agentic penetration-testing tool yourself. It declares the authorized targets, the out-of-scope targets, and the approval policy, to be copied to the tool’s deny rules and to the source-side firewall/proxy and reconciled against them.',
  'roe.overview.note':
    'This is a draft generated automatically from the threat model. Addresses (domains, IP addresses) cannot be determined from the diagram, so the "address hints" below must be confirmed by a human. Enforce the target on the source-side firewall/proxy, not through in-tool settings (prompts, deny rules).',

  'roe.inScope.none': 'No authorized targets (no owned assets are drawn on the diagram).',
  'roe.inScope.rule':
    'The owned assets on the diagram, excluding external and third-party ones. Confirm each target’s address and register it in the source-side allowlist.',
  'roe.outOfScope.rule':
    'The following must not be tested (getting the target wrong means attacking a third party).',
  'roe.outOfScope.everythingElse':
    '**Anything not drawn on this diagram is out of scope.** Test only the targets you have explicitly authorized.',

  'roe.zone.internal': 'Internal',
  'roe.zone.partner': 'Partner',
  'roe.zone.internet': 'Internet',
  'roe.zone.undeclared': 'zone undeclared',

  'roe.inScope.undeclared': '⚠ Not placed in a trust boundary. Confirm it is an owned asset (not a third party).',

  'roe.reason.thirdParty': 'service owned by a third party',
  'roe.reason.partnerZone': 'target in the partner boundary',
  'roe.reason.internetZone': 'target on the public network / external',

  'roe.addressHint': 'address hint: {hint} (confirm)',
  'roe.addressNone': 'no address hint (confirm manually)',

  'roe.approval.intro':
    'Govern the tool’s tool execution with the following policy. Copy each item to the tool’s deny rules (intercept) and policy.',
  'roe.approval.backed': '(a matching threat also fires on this diagram)',
  'approval.defaultDeny':
    'Set the default decision to deny (deny by default) and list the permitted tools and actions in an allowlist.',
  'approval.reviewAllTools':
    'Put every tool call under review, including MCP tools and custom tools.',
  'approval.enforceScopeAtSource':
    'Enforce the permitted target on the source-side firewall/proxy, not by a prompt instruction.',
  'approval.gateSelfExtension':
    'Prevent the agent from registering or changing its own tools, MCP, skills, or approval rules; limit changes to human approval and signed distribution.',
  'approval.humanApprovalHighImpact':
    'For high-impact actions, show the summary and diff for human approval, and monitor the count and time of approvals to detect rubber-stamping.',
  'approval.rulesNotDisableable':
    'Remove the ability to disable or delete deny rules from the agent and user, and attach an audit log to changes.',

  'roe.sourceSide.intro':
    'Copy the declaration above to outside the runtime, not to in-tool settings. Check off each item once done.',
  'roe.sourceSide.item1':
    'Confirmed the addresses in "2. Authorized targets" and registered them in the source-side firewall/proxy allowlist.',
  'roe.sourceSide.item2':
    'Configured blocking of any traffic outside the allowlist before it runs (deny by default).',
  'roe.sourceSide.item3':
    'Copied the approval policy (section 4) to the tool’s deny rules and policy, and made it non-disableable by the agent.',
  'roe.sourceSide.item4':
    'Isolated the tool’s runtime from production, with no route to production credentials or management surfaces.',

  'roe.limits.item1':
    'Addresses (domains, IP addresses) cannot be determined from the diagram. Confirm the address hints by hand.',
  'roe.limits.item2':
    'Targets not drawn on this diagram are not evaluated. The quality of the scope is the quality of the diagram.',
  'roe.limits.item3':
    'This document is a declaration, not live enforcement. Confirm in the runtime that blocking actually happens.',
};
