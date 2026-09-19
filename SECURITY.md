# Security Policy

**English** | [日本語](SECURITY.ja.md)

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/takashi-ohmoto-git/CyberRiskScape/security/advisories/new),
**not** through public issues. Private vulnerability reporting is enabled on this repository.

We will review the report and respond with a fix plan and a timeline.

## Supported versions

This project has not made a formal release yet. Only the latest `main` is supported.

## Known caveats

- **Do not load untrusted YAML.** Inline SVG icons in component libraries are not sanitized
  yet, so review any third-party library YAML before using it
- This tool is a **design aid** for threat modeling. It does not guarantee that its findings
  are complete or correct; use it alongside expert judgment, not instead of it

## Security properties by design

CyberRiskScape runs **entirely client-side**. It makes no requests to any server, and the
designs you create exist only in your browser's IndexedDB and in files you explicitly save.
Nothing you model is transmitted anywhere.
