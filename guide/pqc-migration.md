# Supporting PQC Migration — Finding Where Encryption Changes Along a Path

**English** | [日本語](pqc-migration.ja.md)

> The verdicts on this page are **estimates drawn from your design diagram**. They are not the result of checking
> device configurations or vendor answers. The report it produces is a simple version and does not replace a proper
> cryptographic inventory (a register of where your organization uses cryptography); see §7.

Migrating to PQC (Post-Quantum Cryptography) starts with knowing which cryptography is used where.
In practice, the places that get overlooked are those where **a connection is decrypted partway and re-established with
different cryptography** — load balancers, CDNs, proxies. This page shows how to find those places on a diagram and
produce candidate rows for a cryptographic inventory.

It is written for **infrastructure operations staff who have just been assigned PQC migration**. No cryptography
background is assumed, and each technical term is explained briefly where it first appears.

**Prerequisite**: the operations in [Getting Started](getting-started.md) (placing and connecting components).

---

## 1. What it does

For PQC migration you examine the cryptography in use **for each stretch (segment) over which encryption continues
unbroken between a sender and a destination**. Take this setup:

> User's browser →(TLS)→ load balancer →(plaintext)→ web server

TLS is terminated (decrypted) at the load balancer, so this path is **two segments**: segment 1 is "browser to load
balancer" over TLS, and segment 2 is "load balancer to web server" in plaintext. Each segment has a different
exposure to quantum computers, so you need to check them **one row per segment**.

CyberRiskScape's PQC migration mode does the following.

- It **splits the path from sender to destination into segments** at each node that terminates or decrypts the encryption
- For each segment it gives a **termination verdict**, a **likelihood** (is this a place that is easily attacked?), and a
  **PQC verdict** (is it quantum-safe?)
- It turns the result into a **simple report (CSV)** you can use as candidate rows for a cryptographic inventory

> **Terms**:
> **Termination** means encryption is removed at that node, and a different connection (or plaintext) continues onward.
> A **cryptographic inventory** is a register of where and how your organization uses cryptography.
> **Key exchange** is the procedure by which two parties safely agree on an encryption key; it is the part
> quantum computers threaten most.

---

## 2. Draw on the PQC layer

CyberRiskScape has a **PQC layer**, separate from the depth layers (L0–L3).
The PQC layer is a dedicated diagram for drawing where encryption terminates and the routes between those points.

1. Open **Project** in the left sidebar and click the row that reads something like "Depth layer (L1)" to expand it.
2. Choose **PQC** near the bottom of the list. It sits below a divider, showing that it is separate from the depth layers.
   The row's label changes to "PQC layer".

The cryptography fields appear in the node and edge panels **only while the PQC layer is selected** (§4).

### 2.1 Copy an existing diagram as a draft

If you have already drawn a diagram on L1 or another layer, you can **copy it instead of redrawing it**.

1. Select the layer to copy from (for example L1).
2. Click **Copy this layer…** at the end of the layer list.
3. Choose the target (PQC) and press **Copy**.

How copying behaves:

- The target's contents are **replaced entirely**. If the target already has elements, the dialog shows a warning
- **Component numbers (ElementalIDs such as C3) are kept.** C3 on a depth layer is still C3 on the PQC layer
- **Manual threats, suppressions (accepted / false positive), risk scores and control statuses are not copied.**
  Only the diagram's structure and the attributes on each element are copied
- You can undo a copy afterwards

**The reverse (PQC layer → depth layer) works the same way**: select the PQC layer and pick a depth layer as the target.
It is handy when you want a diagram to which you added devices on the PQC layer to feed the depth layers' threat analysis as well.

> A copy is a **draft**. After copying, continue on the PQC layer by adding devices (§3) and entering cryptography
> details (§4).

---

## 3. Use the device stencils

The devices that handle encryption along a path are available as types in `LIBRARY` in the left sidebar.

| Type | Category | How it handles encryption (default) |
|---|---|---|
| L2 switch | Network & Edge | Pass-through |
| Router / L3 switch | Network & Edge | Pass-through |
| Load balancer | Network & Edge | Terminate (pass-through when run at L4) |
| CDN | Network & Edge | Terminate |
| VPN gateway | Network & Edge | Tunnel |
| Service mesh | Network & Edge | Terminate |
| Firewall | Security Controls | Pass-through |
| WAF | Security Controls | Terminate |
| IDS / IPS | Security Controls | Pass-through |
| Proxy / SWG | Security Controls | Decrypt & inspect |
| SASE / SSE | Security Controls | Decrypt & inspect |
| ZTNA / identity-aware proxy | Security Controls | Terminate |
| Bastion | Servers | Terminate |
| HSM | Crypto & Keys | Not on the path (stores keys and performs operations) |

There are others too, such as the wireless access point (tunnel), email gateway (terminate) and private endpoint
(pass-through). Browse `LIBRARY` for the categories and the full list.

### 3.1 The five termination values

Each type has a **default** for how it handles encryption. There are five values.

| Verdict | Meaning | Splits the segment? |
|---|---|---|
| **Pass-through** | Does not touch the encryption; passes it along as is | No |
| **Terminate** | Ends TLS (or similar) at the node and opens a separate connection onward | **Yes** |
| **Decrypt & inspect** | Decrypts to inspect the contents, then re-issues the certificate with your internal CA (your own certificate authority) and sends it on | **Yes** |
| **Tunnel** | Carries traffic in an outer tunnel without changing the inner encryption | No (raises a warning) |
| **Passive decrypt** | Takes in the server's private key and decrypts traffic from the side to inspect it | No (raises a warning) |

A node whose verdict is "Unknown" **splits the segment, erring on the safe side**.

> **Exception**: when the edges before and after a node are both E2EE (end-to-end encrypted), the inner encryption does
> not change, so the segment is not split.

### 3.2 Passive decryption stops working with PQC

**Passive decryption** happens when a WAF or IDS / IPS is deployed out of band (outside the traffic path).
The server's private key is loaded into the device, which decrypts the traffic it sees from the side.

This method depends on **static RSA key exchange** (a scheme in which a fixed server key is used to agree on keys).
TLS 1.3 removed static RSA in favor of creating a new key for every connection, and PQC key exchange works the same
way. So **once you move to TLS 1.3 or PQC, passively decrypting devices can no longer see the contents.**
When a node on the path is a passive decryptor, the segment gets a "Passive decryption" warning. It is an obstacle to
PQC migration, and you will need to rethink how inspection is done.

### 3.3 Cloud equivalents are drawn with the same types

Cloud services can be drawn with the type that matches their function. The type descriptions also list the matching
services as examples.

| Cloud service | Type to draw |
|---|---|
| AWS ALB / Azure Application Gateway / Google Cloud Load Balancing | Load balancer |
| Amazon CloudFront / Azure Front Door / Google Cloud CDN | CDN |
| AWS Transit Gateway, NAT gateway / Azure Virtual WAN | Router / L3 switch |
| AWS Site-to-Site VPN / Azure VPN Gateway | VPN gateway |
| AWS PrivateLink / Azure Private Link | Private endpoint |
| AWS CloudHSM / Azure Managed HSM / Google Cloud HSM | HSM |

**Dedicated-line services** (AWS Direct Connect, Azure ExpressRoute, Google Cloud Interconnect and so on) are not a
device type. You represent them by **setting the edge's network to "Leased line (VPN)"**.
A dedicated line passes through a carrier's equipment, so the cryptography between cloud and on-premises needs thought
for that stretch too.

> With cloud devices, the provider sometimes decides the cryptographic settings (such as the key exchange method).
> In that case set the node's **Managed by** to "Cloud provider" (§4.1).

---

## 4. Enter cryptography details on nodes and edges

With the PQC layer selected, choosing a node or an edge shows cryptography fields in its panel.
**They do not appear on depth layers.** Everything is optional, and analysis works with fields left blank (blank items
are treated as "Needs review").

### 4.1 Nodes: Crypto (PQC)

| Field | What it holds |
|---|---|
| **Termination** | Overrides the type's default. Leave it at "Default (…)" to use the type's default. Choose a value once you know the real device configuration |
| **Managed by** | In-house / Cloud provider. Choosing Cloud provider marks segments that have this node at an end as provider-dependent (segments where you cannot change the algorithm yourself) |
| **Signature algorithm** | The signature (certificate, code signing and so on) algorithm the node uses. For example `ML-DSA-65` / `ECDSA P-256` |
| **Key storage** | HSM / KMS / Software / Unknown |
| **Algorithm can be changed** | Whether the device or service lets you change the algorithm (Yes / No / Unknown). Devices that cannot be changed need replacing during migration |

In the termination drop-down, the alternative configurations that the type can have (for a load balancer, "Pass-through",
for example) are listed first. A **checkpoint** note for the type is shown below it.

### 4.2 Edges: Crypto details (PQC)

| Field | Example |
|---|---|
| **Protocol** | TLS / IPsec / SSH |
| **Version** | 1.3 / IKEv2 |
| **Key exchange** | `X25519MLKEM768` / `ECDHE P-256` |
| **Signature (certificate)** | `ML-DSA-65` / `RSA 2048` |

Entering a **key exchange** or **signature** shows a **quantum-resistance badge** next to it.

| Badge | Meaning | Example |
|---|---|---|
| Quantum-safe | A method that quantum computers are not expected to break | `X25519MLKEM768` (a hybrid that combines a classical method with ML-KEM) |
| Transitional | An interim method, such as a pre-standardization name | `Kyber` |
| Quantum-vulnerable | Public-key cryptography that quantum computers can break | `ECDHE` / `RSA` / `X25519` |

The verdict comes from whether your text contains a **partial match for an algorithm name**.
A hybrid method matches several classes, so quantum-safe takes priority.
A name that matches no class shows no badge (and counts as "Needs review").

> The edge's encryption setting (Plain / TLS / E2EE) feeds the verdict directly. **If it is Plain, the verdict is
> "Plaintext" even when key exchange is blank.**

---

## 5. Analyze a path

You run the analysis from the **sender node's** panel.

1. On the PQC layer, select the node you want as the sender (for example the user).
2. In the panel's **Crypto path (PQC)**, pick the **destination**.
3. Press **Analyze path**.

The screen shows a **route diagram** from sender to destination and a **segment table**. When there are several routes,
switch between them with the **Route 1, Route 2…** tabs.

### 5.1 Reading the segments

In the route diagram, a node that terminates or decrypts the encryption and so becomes a **segment break** carries a
scissors mark. In the segment table, each row is one segment.

| Column | What it shows |
|---|---|
| Sender → destination | The nodes at the two ends of the segment |
| Via | Nodes the segment passes through without touching encryption (pass-through, tunnel, passive decrypt) |
| Termination (basis) | The verdict for the segment's **start** node, and the basis for it |
| Protocol / key exchange / signature | The values entered on the edges in the segment |
| Likelihood | High, Medium or Low |
| PQC verdict | The verdict for the segment's key exchange |
| Signature verdict | The verdict for the segment's signatures |
| Provider-dependent | A segment where one of its two end nodes is managed by the cloud provider |
| Warnings | Points that need attention (§5.4) |

There are three kinds of **basis for the termination verdict**.

| Basis | Meaning |
|---|---|
| **Confirmed** | A person explicitly chose the node's termination verdict |
| **Default** | The type's default was used (an estimate) |
| **Needs review** | The type has no default, so no verdict can be made |

Where a segment end is the sender or destination itself, it is shown as "Endpoint".

### 5.2 Likelihood: is it an easily attacked place?

Likelihood judges, from the trust boundaries, whether a segment lies **close to attackers** — High, Medium or Low.
It is a simple verdict modeled on the approach in the PQC migration guide for Japanese financial institutions (September 2025 edition)
published by the Fintech Security WG of the financial-sector information-sharing organization (the Financial ISAC Japan):
High = exposed to attack by an unspecified large number of parties, Medium = attackable from outside over some network,
Low = inside the organization. It therefore assumes **you have drawn the trust boundaries first**.

| Verdict | Condition |
|---|---|
| **High** | An end node of the segment is on the Internet side, or an edge in the segment has network "Public network (Internet)". **A node that belongs to no trust boundary is treated as being on the Internet side** |
| **Medium** | An end node of the segment is inside a Partner trust boundary |
| **Low** | Neither of the above (for example, internal) |

An attack that **collects traffic now and breaks it later with a quantum computer** is more realistic the easier the
traffic is to collect. Fixing the segments that have both high likelihood and a poor PQC verdict first is the most
effective order.

### 5.3 PQC verdict: the worst value in the segment

When a segment has several edges, the **worst value** becomes the segment's verdict. From worst to best:

**Plaintext → Quantum-vulnerable → Transitional → Needs review → Quantum-safe**

The signature verdict is likewise the worst value among the signatures on the segment's edges and the **signature
algorithm of the segment's destination node**. A segment with no key exchange or signature entered shows "Needs review".

### 5.4 Warnings

| Warning | When it appears | What to look at |
|---|---|---|
| Passive decryption | A passive-decrypt node lies inside the segment | Inspection stops working with TLS 1.3 / PQC (§3.2) |
| Re-signing | The segment's start node decrypts and inspects | Certificates are re-issued by an internal CA, so the internal CA's signature algorithm must migrate too |
| Outer tunnel | A tunnel node lies inside the segment | The outer tunnel's encryption wraps the inner encryption. Check the outer key exchange method |
| Mixed encryption | Edges in the segment have mixed encryption settings | Check whether plaintext and TLS are mixed within the segment |

### 5.5 When no route is found along the edge directions

Routes are first searched **following the direction of the edges**. If none is found, the search is **repeated ignoring
direction**, and the screen says "No path follows the edge directions, so the search ignored directions".
When the sender and destination are not connected by edges at all, it shows "No path from source to destination". Check that no edge is missing.
When there are too many routes, a notice says only some are shown.

---

## 6. Add to the report and export a CSV

You can **add the paths you analyze to the report** and export them together as a CSV.

1. On the path analysis screen, enter a **label for the report** if you wish (optional) and press **Add to report**.
   If you leave the label empty, the "sender→destination" node names are used.
2. Added flows appear under **Registered flows** in the sender node's panel. You can reopen or delete them.
3. With the PQC layer selected, open **Report** in the left sidebar and press **PQC migration report (CSV)**.

The button is disabled while no flow has been added. **The CSV can be exported only while the PQC layer is selected.**
The file is named `pqc-migration-report-….csv` and is UTF-8 with a BOM, so spreadsheet software opens it directly.

### 6.1 Structure of the CSV

The top holds the schema version, project name, system name, flow count, segment count and a note, followed by a blank
line and then the table. The table has **one row per segment**.

| Column | What it holds |
|---|---|
| Flow | The label given when it was added |
| Route No | The route number (Route 1, 2… on screen) |
| Segment No | The segment's number within that route (same as the on-screen table) |
| Segment sender / Segment destination | Component number and label (for example `C3 Load balancer`) |
| Via nodes | Nodes in the middle of the segment |
| Termination | The verdict for the segment's start node |
| Basis | Confirmed / Default / Needs review (with a note when provider-dependent) |
| Protocol | Protocols in the segment (the edge's encryption class if not entered) |
| Key exchange | The segment's key exchange. "Needs review" if not entered |
| Signature | The segment's signatures. "Needs review" if not entered |
| Likelihood | High / Medium / Low |
| PQC verdict | The verdict for the segment's key exchange |
| Signature verdict | The verdict for the segment's signatures |
| Warnings | The warnings in §5.4, plus notes for direction-ignoring searches and missing routes |

When the same segment appears on several routes, it is listed **only for the first route**. A flow for which no route was
found becomes a single row with empty segment columns and just a warning.

### 6.2 It is a simple version — and how to use "Needs review"

This CSV is a **simple version estimated from the design diagram**. The file itself carries this note near the top:

> This is a simplified report inferred from the design diagram. Confirm the formal crypto inventory against device configurations and vendor responses.

Use the CSV as **candidate rows when you build the cryptographic inventory**. From there:

- Rows whose "Basis", "Key exchange" or "Signature" say **Needs review** require you to check the device configuration
  or **ask the vendor**. **The count of "Needs review" is a rough guide to how many questions to put to vendors**
- As the count falls, the diagram holds more information. Confirm and enter node termination verdicts and edge key
  exchanges, then export again

---

## 7. Limits and cautions

- **It estimates from the design diagram.** It does not read real device configurations. If the diagram differs from
  reality, so will the verdicts
- **Type defaults are estimates.** A load balancer defaults to "Terminate", for example, but if it runs at L4 it is
  really pass-through. Choosing the node's termination verdict overrides the default, and the segment's basis then
  becomes "Confirmed"
- **Signatures and key wrapping are issues outside the path.** Path analysis mainly looks at the **key exchange** of
  a connection. The following two cannot be expressed as segments of a path:
  - **Forged signatures** (Trust Now, Forge Later: a signature trusted today is forged in the future): this concerns
    the signatures of long-lived devices and firmware. Check it by entering the node's **signature algorithm**; the
    related threat rule (non-PQC signature verification on long-lived devices) covers it
  - **Key wrapping** (storing an encryption key wrapped inside another key): this concerns data kept for a long time.
    It is covered by the backup types in Storage & Databases and the related threat rules (quantum-vulnerable key
    wrapping of backups, HSMs without PQC key support)
- **A node has a single termination verdict.** If the same device treats traffic differently depending on its type,
  draw separate nodes for each type of traffic

---

## 8. Sources

The reference table behind the PQC verdicts is this project's own arrangement built on the following publicly available
documents. It is not a reproduction of their text.

1. CRYPTREC Cryptographic Algorithm List (LS-0001-2022R2), Table 2, PQC list — <https://www.cryptrec.go.jp/list.html>
2. NIST FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM) — <https://csrc.nist.gov/pubs/fips/203/final>
3. NIST FIPS 204, Module-Lattice-Based Digital Signature Standard (ML-DSA) — <https://csrc.nist.gov/pubs/fips/204/final>
4. NIST FIPS 205, Stateless Hash-Based Digital Signature Standard (SLH-DSA) — <https://csrc.nist.gov/pubs/fips/205/final>
5. NIST SP 800-208, Recommendation for Stateful Hash-Based Signature Schemes (LMS / XMSS) — <https://csrc.nist.gov/pubs/sp/800/208/final>
6. NIST IR 8547, Transition to Post-Quantum Cryptography Standards — <https://csrc.nist.gov/pubs/ir/8547/ipd>

---

## Where to go next

- Assess and record the threats related to PQC migration — [Assessing Risk in Analytics](analytics-assessment.md)
- Other report outputs — [Exporting PDF Reports and Diagram Images](report-export.md)
- How to read the threat panel — [Reading the Threat Panel](reading-threats.md)
- Decide where to start mitigating — [Attack Path Analysis](attack-paths.md)
