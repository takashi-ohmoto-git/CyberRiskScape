# Contributing

**English** | [日本語](CONTRIBUTING.ja.md)

Issues and pull requests are welcome.

## Ground rules

- **Never hardcode threat rules.** They belong in YAML under `data/threat-library/`
- **Cite the source** of every new rule, and summarize rather than reproducing text verbatim
- Changes to logic come with tests
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)

## Development workflow

```bash
npm install
npm run dev          # dev server
npx tsc --noEmit     # type check (strict)
npm test             # run all tests
npm run build        # production build
```

Please confirm that the type check and the tests pass before opening a pull request. CI
(`.github/workflows/ci.yml`) runs both as well.

## Adding a threat rule

Threat rules live in YAML under `data/threat-library/`. See
[`data/threat-library/`](data/threat-library) for the existing files and their structure.

In the pull request description, please state:

- **which external source** (framework or guideline) the rule is based on, and where in it
- if the rule overlaps an existing one, why it should stand as a separate rule rather than
  sharing a `canonicalId`

## Translation

This is currently the most useful place to help.

UI strings are managed through a small in-house i18n layer in `src/i18n/` — no external
dependency. `src/i18n/locales/ja.ts` is the source of truth; `src/i18n/locales/en.ts`
partially overrides it, and any key missing from `en.ts` falls back to Japanese. Two things
are open:

- **Filling in `en.ts`.** Add keys as you translate them; partial coverage is fine and safe
- **A language switcher.** The locale store exists (`useLocale`), but nothing in the UI sets
  it yet, so the app always starts in Japanese. Note that persistence must use IndexedDB —
  this project does not use `localStorage` or `sessionStorage`

Threat rule text (`name`, `description`, `mitigation`) is Japanese. The plan is a
translation overlay under `data/threat-library/i18n/en/` keyed by rule ID, so the existing
schema stays unchanged and untranslated rules fall back to the original text. Please open an
issue before starting on this so we can agree on the format first.

## Documentation language

**English is canonical.** `README.md`, `CONTRIBUTING.md`, and `SECURITY.md` are the versions
to update when something changes. Their Japanese counterparts (`*.ja.md`) are kept in sync as
summaries and may lag in detail — that is intentional. A pull request that updates only the
Japanese file will be asked to update the English one too; the reverse is not required.

## License

Contributions are distributed under this project's license,
[Apache License 2.0](LICENSE).
