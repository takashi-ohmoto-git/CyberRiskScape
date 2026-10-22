# Offline log triage

**English** | [日本語](README.ja.md)

`crs_triage.py` is a first-pass, offline triage of log files when a compromise is suspected. It scans a copy of
your logs for crash / out-of-memory patterns, correlates them with `POST` + 5xx lines in the access log, and lists
recently changed files under a web root. Python 3.8+, standard library only, no network access.

> **It does not decide whether a compromise happened. Finding nothing is not proof of safety:** a problem that
> occurs before the application logs anything may leave no trace, and logs can be missing or tampered with. Use the
> hits to decide where to look first.

## Before you start

- Work on a **copy** of the logs (and of the web root), and treat the copy as read-only. The tool only reads its
  inputs and writes the report files you name.
- The detection patterns are not built in. You pass them as a JSON file (`--patterns`), which keeps the tool generic.

## Prerequisites

| Item | Prerequisite |
|---|---|
| Runtime | Python 3.8 or later (standard library only; nothing else to install). Runs on Linux, macOS and Windows |
| Network | Not needed. The tool makes no external connections at all, including name resolution (DNS). You can run it on an isolated analysis machine |
| Host name | The string you pass with `--host` is written to the results as is. If omitted, it is **the OS host name of the machine running the tool** (no DNS lookup). **When you examine copies on another machine, always pass the original host name with `--host`.** The investigation report (`investigation-report`) matches this name as a string against `host` in the map (`hosts.json`) |
| Read permission | You need permission to read the logs. Much of `/var/log` is readable only by root or the adm group. Files and directories that cannot be read are recorded in `skipped`, and the run continues |
| Writes | Only to the `--output` and `--json` destinations. Inputs are only read |
| Log formats | Text logs and `.gz` are read. Systemd journals, binary files and compression other than `.gz` must be exported to text or extracted first (see "Limits") |
| Start of `--days` | Counted back from **the time you run the tool**. If you run it days after taking the copy, add those days |
| Web root timestamps | Recent changes are judged by the newer of a file's mtime and ctime. **Copying sets ctime to the copy time on every OS**, so in a copied web root every file appears "recent". In that case, read the mtime column in the report (copy with `cp -a`, `tar -p` or `rsync -a` to keep mtime). To use ctime as well, run the tool read-only on the original server, or on a disk image mounted read-only |
| Time zone | Log timestamps are handled as written in the logs. File times (mtime and ctime) are shown in **the time zone of the machine running the tool** |

**There are two ways to run it.**

- **Examine copies on another machine** (recommended): copy the logs (and the web root) from the original server, and run the tool on an analysis machine with `--logs`, `--webroot` and `--host`
- **Run it directly on the original server**: `--logs` defaults to `/var/log` and `--host` to that server's host name. Reading the logs often needs root, and you will be running a script in the
  environment under investigation. Do this only if your organization's evidence-handling procedures allow it

## Usage

```bash
# 1. Write the patterns (from the bundled investigation templates; no model needed)
node dist-cli/main.js export-triage-patterns --out patterns.json     # after `npm run build:cli`

# 2. Run the triage against a copy of the logs
python3 tools/triage/crs_triage.py --patterns patterns.json \
  --logs ./logs_copy --webroot ./www_copy --days 3 --host web01 \
  --output report.md --json report.json

# 3. Overlay report.json (and/or a Velociraptor collection) on the threat model
node dist-cli/main.js investigation-report model.json \
  --evidence report.json --evidence ./velociraptor_collections \
  --hosts hosts.json --out investigation-report.md
#    hosts.json: {"hosts":[{"host":"web01","node":"C3"}]}  (case-insensitive; the FQDN's first label also matches)
```

`tools/triage/patterns.example.json` is a convenience copy of what step 1 writes. The CLI is the source of truth
(the YAML `tools.triage` section of `data/investigation-templates/compromise.yaml`); regenerate rather than edit
the sample.

## Options

| Option | Default | Meaning |
|---|---|---|
| `--patterns <file>` | (required) | Pattern file (JSON, see below) |
| `--logs <dir>` | `/var/log` | Log directory. Every file is scanned recursively; `.gz` is read directly |
| `--webroot <dir>` | none | Web root to check for recently changed files |
| `--days <n>` | 3 | Look-back period for the web root |
| `--window <min>` | 5 | Correlation window (minutes) around each `POST` + 5xx line |
| `--output <file>` | `crs_triage_report.md` | Markdown report |
| `--json <file>` | none | JSON report |
| `--host <name>` | this machine | Name of the original host (use it when you triage a copy elsewhere) |
| `--client-ip-regex <re>` | first field of the line | Regex with a named group `(?P<ip>...)` to extract the client IP, e.g. from `X-Forwarded-For` |

## Pattern file

```json
{
  "format": "cyberriskscape-triage-patterns",
  "version": 1,
  "id": "my-patterns",
  "logPatterns": [
    { "id": "kernel-oom-killed-process", "category": "kernel-oom", "regex": "Out of memory: Killed process", "priority": 10 }
  ],
  "accessLog": { "method": "POST", "statuses": [500, 502, 503, 504] },
  "webroot": { "extensions": [".php"], "filenames": [".user.ini"] },
  "notes": ["Free text appended to the report's Notes."]
}
```

- `logPatterns`: `regex` is matched case-insensitively. Patterns are tried in ascending `priority`; a line is counted
  only for the first pattern that matches. `category` is free text (`post-5xx` and `recent-file` are reserved).
  Every category in `logPatterns` counts as a crash / OOM signal for the correlation.
- `accessLog` (optional): lines containing `method` followed by one of `statuses` right after the request line.
- `webroot` (optional): extensions and exact file names (case-insensitive) that count as web files.
- Keep regexes to the syntax common to Python and JavaScript.

## Output JSON

`format` (`cyberriskscape-triage`), `version` (1), `host`, `collectedAt`, `parameters` (`logs`, `webroot`, `days`,
`window`, `patterns: {id, version}`), `scanned` (path, size, lines, first/last time), `skipped` (path, reason),
`hits` (`category`, `pattern`, `path`, `line`, `time`, `content`, `ip`) and `correlations` (`ip`, `post5xx`,
`nearbyOomOrCrash`, `score`). `skipped` lists everything that was **not** examined (binary files, systemd journals,
unreadable files): read it before trusting an empty result.

## Limits

- Time formats: access log, Apache error log, PHP-FPM, ISO 8601 and syslog. Lines in other formats have no time and
  are not used for correlation. Syslog lines carry no year, so the file's mtime year is used.
- Correlation compares wall-clock times and ignores time zone offsets. Lines without an offset are assumed to be in
  the server's local time.
- The client IP is the first field of the line unless `--client-ip-regex` says otherwise. Behind a reverse proxy,
  WAF or CDN the IPs may all be internal (the report warns about this).
- Binary files and systemd journals are skipped (export them first, e.g. `journalctl -k -o short-iso > kernel.log`);
  `.xz` / `.bz2` / `.zst` / `.zip` must be decompressed first.
- Only the first 300 characters of a line are kept in the table, and at most 50 `POST` + 5xx lines per IP are listed
  (counts and correlation use all lines).
- File times can be forged. mtime can be set with `touch`; ctime (inode change time on Linux) is harder to fake, but
  neither is reliable for copied or extracted files. **On Windows, ctime is the creation time.**

## Tests

```bash
python -I -m unittest discover -s tools/triage/tests
```

License: Apache-2.0.
