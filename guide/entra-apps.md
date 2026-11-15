# Putting Entra ID External App and Consent Inventory on the Diagram — Finding External Apps with Powerful Permissions via Microsoft Graph

**English** | [日本語](entra-apps.ja.md)

> Product names on this page are names of their respective owners. This page explains how to import the inventory of external apps and consents
> of Entra ID, read from Microsoft Graph, into CyberRiskScape. It is not provided, certified, or endorsed by Microsoft; the use of the names is descriptive.
> Response formats and permission names follow the official documentation as of the time of writing (November 2026). Check the official information for the latest.

> **Scope** — Connect to Microsoft Graph only for **a tenant that you manage or are authorized to assess**.
> Only read-only GET requests are made. Tenant settings are not changed.

---

## 1. What this page covers and prerequisites

In an Entra ID tenant, apps built by other organizations (SaaS, business partners' integration apps, and so on) get in through the consent of users or administrators.
CyberRiskScape reads service principals, delegated consents, and the app-only permissions of Microsoft Graph from Microsoft Graph (v1.0), turns the **external apps**
(apps whose owning tenant is neither your own organization nor a Microsoft service) that hold powerful permissions into **findings**, and attaches them to the **IdP** on the diagram.
**The diagram is not changed.** Findings are only added.

This differs in viewpoint from the Entra ID part of the BloodHound CE integration ([Putting BloodHound CE Results on the Diagram](bloodhound.md)).
That one imports the results of BloodHound's analysis of attack paths and chains of permissions; this one reads the **inventory of external apps and consents** (which app holds which permissions and consents) directly from Graph.

**Prerequisites**

- A CyberRiskScape project JSON to attach findings to, with an **IdP** node on the diagram (without one, findings are left unattached).
- Node.js. Build the CLI first (`npm ci && npm run build:cli`).
- There are two entry points (section 4). To read through the API, register an app in Entra ID and grant admin consent to the application permissions **Application.Read.All** and **Directory.Read.All** (both read-only).
- **CLI only.** The output project JSON can be loaded on screen with **Template** → **Import**.

**Background for this page**: the operations in [Getting Started](getting-started.md) and [Reading the Threat Panel](reading-threats.md).

---

## 2. What it can do

From the inventory it reads, it makes these four findings (one per observation).

| Observation | Corresponding threat | Severity |
|---|---|---|
| External apps holding powerful app-only permissions (Microsoft Graph) | Tenant-wide privileges held by apps on their own (app-only) | Critical |
| External apps given **tenant-wide** consent to powerful permissions | Delegated consent to external apps (including illicit consent grants) | High |
| External apps that **individual users** consented to for powerful permissions | Same as above | Medium |
| Microsoft service apps with credentials configured | Taking over registered apps by adding credentials | High |

- "Powerful permissions" are judged by the bundled list (`data/finding-maps/graph-permissions.yaml`): 24 permissions covering tenant administration (granting roles, apps, permissions), changing users, groups, and authentication methods, mail and calendars, files and sites, and chat.
- For delegated consent, **only consent to Microsoft Graph** is examined.
- Whether an app is external is judged by the owning tenant of its service principal. Your own tenant ID and Microsoft's service tenant are excluded from external apps.

### Matching against the diagram

The display names of external apps are matched against the labels of app-type nodes on the diagram (SaaS, OAuth client, other apps, and the like).
Only an **exact match of the display name** counts (case and leading or trailing spaces are ignored). Apps that do not match get a "**Not on the diagram**" mark in the report.
This is a **candidate for a missed drawing**, not a verdict.

---

## 3. Preparing the diagram

Findings are attached to the **IdP** (Identity & Access) on the diagram: to the one IdP if there is exactly one, otherwise left unattached. If there are several, specify it with `--idp-node` (section 4.3).

The IdP comes with these three threat rules, written as threats of IdPs that hold app registrations in general (not only Entra ID).

- Tenant-wide privileges held by apps on their own (app-only)
- Delegated consent to external apps (including illicit consent grants)
- Taking over registered apps by adding credentials

For matching, draw the external apps on the diagram as labeled nodes (SaaS, OAuth client, other apps, and the like); this reveals missed drawings.

---

## 4. Importing

There are two entry points. Either one is enough.

### 4.1 Import through the API (CLI only)

Pass the details of the app you registered in Entra ID in environment variables. The values are neither saved nor printed.

```bash
export MSGRAPH_TENANT_ID=<your tenant ID>
export MSGRAPH_CLIENT_ID=<application (client) ID>
export MSGRAPH_CLIENT_SECRET=<client secret>
node dist-cli/main.js import-entra-apps my-project.json --graph -o out.json
```

- It obtains a token with the client credentials flow and sends **only GET requests** to `graph.microsoft.com`. Read-only.
- The application permissions required are **Application.Read.All** and **Directory.Read.All** (Directory.Read.All is used for the list of delegated consents).
- It follows next-page URLs only if they are on `graph.microsoft.com`. Redirects are not followed. There is an upper limit on the pages followed for one list; beyond it, the list is cut off.

### 4.2 Import from files

Obtain the Graph response JSON yourself and place it in a folder under these names (one page or an array of pages both work). Pass your tenant ID with `--tenant-id`.

| File name | Graph request to obtain it (GET) |
|---|---|
| `servicePrincipals.json` (required) | `/v1.0/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,accountEnabled,verifiedPublisher,passwordCredentials,keyCredentials&$top=999` |
| `graphServicePrincipal.json` | `/v1.0/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')?$select=id,appId,displayName,appRoles` |
| `graphAppRoleAssignedTo.json` | `/v1.0/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')/appRoleAssignedTo?$top=999` |
| `oauth2PermissionGrants.json` | `/v1.0/oauth2PermissionGrants` |

```bash
node dist-cli/main.js import-entra-apps my-project.json --in ./graph-responses --tenant-id <your tenant ID> -o out.json
```

**Without `graphServicePrincipal.json`, app-only permissions cannot be judged** (the report says so).

### 4.3 Which node the findings go to, and options

| Option | Meaning |
|---|---|
| `--idp-node <C number or ID>` | The IdP to attach findings to. The one IdP if the diagram has exactly one (default). Specify it when there are several. If there is none, findings are left unattached |
| `--scope <name>` | Scope of replacement (default `default`). Use it to separate tenants. **Re-importing replaces the findings of the same scope.** Findings of other scopes remain |
| `--report <md or json>` | Report format (default `md`, to standard output) |
| `-o <file>` | Where to write the project JSON with findings saved (nothing is saved if omitted) |

---

## 5. Reading the results

- **Report**: the number of external apps, the count per observation, and a list of the external apps with powerful permissions or consents (app name, whether the publisher is verified, app-only permissions, tenant-wide consents, the number of per-user consents, and the match against the diagram).
- **Threat cards**: the cards of the corresponding threats show a "**Confirmed in Entra settings**" mark. It is a pointer to confirm the actual settings in the Entra ID admin center.
- **Reports**: the findings also appear in `findings-report` and `findings-priority`, and in the SARIF export.
- The "Not on the diagram" mark is a candidate for a missed drawing. If the app really exists, add it to the diagram; if the consent is unnecessary, consider revoking it.

---

## 6. What is stored about secrets and people

| Kind | Handling |
|---|---|
| Client secret and token | Neither saved nor printed (used only for the token request) |
| App credentials (passwords, certificates) | Only the count of expiry dates is read. **Values and hints are not stored** |
| Per-user consents | **Count only.** Users are not identified |
| App display names and publishers | Kept as asset information |

---

## 7. Limits

- Sign-in logs (judging apps that are no longer used) are not examined, because they are in the beta API.
- Consent to APIs other than Microsoft Graph is not judged.
- Matching against the diagram is an exact name match only. An app that merely has a different name is reported as "Not on the diagram".
- **It has not been verified with a real tenant.** It was checked against the response shapes in the official documentation and with tests using fictitious data (2026-11-15).

---

## 8. References

- Microsoft Graph permissions reference: https://learn.microsoft.com/en-us/graph/permissions-reference

---

## 9. What to read next

- [Putting BloodHound CE Results on the Diagram](bloodhound.md) — backing chains of permissions in AD, Entra ID, and Azure with BloodHound results
- [Reading the Threat Panel](reading-threats.md) — how to read the marks and rationale on a threat card
- [Threat Modeling NHIs and Identity Platforms](nhi-identity.md) — how to draw directory and IdP threats
