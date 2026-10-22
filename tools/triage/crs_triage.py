#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TAKASHI OMOTO
"""
Offline log triage (first-pass) for suspected compromise.

Scans a COPY of log files (plain or .gz) for patterns supplied in a JSON pattern file, correlates
POST + 5xx access-log lines with nearby crash / OOM events, and lists recently changed files under a web root.
It does NOT decide whether a compromise happened, and finding nothing does not prove safety.
Python 3.8+ / standard library only. No network access. Inputs are only read.

Usage:
    python3 crs_triage.py --patterns patterns.json --logs ./logs_copy --webroot ./www_copy --days 3
    python3 crs_triage.py --patterns patterns.json --logs ./logs_copy --host web01 --json report.json
    python3 crs_triage.py --patterns patterns.json --logs ./logs_copy --client-ip-regex 'X-Forwarded-For: (?P<ip>[0-9a-fA-F.:]+)'
"""

import argparse
import bisect
import gzip
import ipaddress
import os
import re
import socket
import sys
import zlib
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ========== Detection patterns (loaded from a JSON pattern file) ==========
PATTERN_FORMAT = 'cyberriskscape-triage-patterns'
PATTERN_VERSION = 1


class PatternError(Exception):
    pass


class Patterns:
    """パターンファイルの内容。検索パターン・POST+5xx のステータス・Web ルートの対象・注記はすべてここから来る。"""

    def __init__(self, doc):
        if not isinstance(doc, dict) or doc.get('format') != PATTERN_FORMAT:
            raise PatternError('format が "%s" ではない' % PATTERN_FORMAT)
        if doc.get('version') != PATTERN_VERSION:
            raise PatternError('version %s には未対応（対応: %d）' % (doc.get('version'), PATTERN_VERSION))
        self.id = _req_str(doc, 'id', 'patterns')
        self.version = doc['version']
        raw = doc.get('logPatterns', [])
        if not isinstance(raw, list):
            raise PatternError('logPatterns は配列にする')
        items = []
        for i, p in enumerate(raw):
            where = 'logPatterns[%d]' % i
            if not isinstance(p, dict):
                raise PatternError('%s はオブジェクトにする' % where)
            pid = _req_str(p, 'id', where)
            cat = _req_str(p, 'category', where)
            rx = _req_str(p, 'regex', where)
            prio = p.get('priority', 100)
            if isinstance(prio, bool) or not isinstance(prio, (int, float)):
                raise PatternError('%s.priority は数値にする' % where)
            try:
                compiled = re.compile(rx, re.I)
            except re.error as e:
                raise PatternError('%s.regex が不正: %s' % (where, e))
            items.append((prio, i, pid, cat, compiled))
        # priority の小さいものを先に試し、1 行は最初に当たった 1 件にだけ数える
        items.sort(key=lambda t: (t[0], t[1]))
        self.log_patterns = [(pid, cat, rx) for _, _, pid, cat, rx in items]
        self.categories = []
        for _, cat, _ in self.log_patterns:
            if cat not in self.categories:
                self.categories.append(cat)
        if 'post-5xx' in self.categories or 'recent-file' in self.categories:
            raise PatternError('category "post-5xx" / "recent-file" は予約語')

        ac = doc.get('accessLog')
        self.access_method = None
        self.access_re = None
        if ac is not None:
            if not isinstance(ac, dict):
                raise PatternError('accessLog はオブジェクトにする')
            method = _req_str(ac, 'method', 'accessLog')
            statuses = ac.get('statuses')
            if (not isinstance(statuses, list) or not statuses
                    or not all(isinstance(s, int) and not isinstance(s, bool) and 100 <= s <= 599 for s in statuses)):
                raise PatternError('accessLog.statuses は 100〜599 の整数の配列にする')
            st = '|'.join(str(s) for s in statuses)
            m = re.escape(method)
            self.access_method = method
            # ステータスはリクエスト行の直後。行末でも拾う。
            self.access_re = re.compile(
                r'"%s\s[^"]*"\s+(?:%s)(?:\s|$)' % (m, st)
                + r'|%s\s+\S+\s+HTTP/[\d.]+"?\s+(?:%s)(?:\s|$)' % (m, st), re.I)

        wr = doc.get('webroot') or {}
        if not isinstance(wr, dict):
            raise PatternError('webroot はオブジェクトにする')
        self.web_exts = set(_str_list(wr, 'extensions'))
        self.web_names = set(_str_list(wr, 'filenames'))
        self.notes = _str_list(doc, 'notes', keep_case=True)


def _req_str(d, key, where):
    v = d.get(key)
    if not isinstance(v, str) or not v:
        raise PatternError('%s.%s は空でない文字列にする' % (where, key))
    return v


def _str_list(d, key, keep_case=False):
    v = d.get(key, [])
    if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
        raise PatternError('%s は文字列の配列にする' % key)
    return list(v) if keep_case else [x.lower() for x in v]


def load_patterns(path):
    import json
    try:
        doc = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    except (OSError, ValueError) as e:
        raise PatternError('パターンファイルを読めない: %s' % e)
    return Patterns(doc)


COMPRESSED_EXTS = {'.xz', '.bz2', '.zst', '.zip', '.lz4', '.7z'}

CONTENT_MAX = 500
POST_HITS_PER_IP = 50      # JSON/Markdown に載せる POST+5xx 行の IP ごとの上限（集計・相関は全件）
MD_CONTENT_MAX = 300

# ========== Time parsing ==========
MON = {m: i for i, m in enumerate(
    ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'], 1)}

RX_ACCESS = re.compile(r'\[(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})\]')
RX_APACHE_ERR = re.compile(r'\[[A-Za-z]{3} ([A-Za-z]{3}) (\d{1,2}) (\d{2}):(\d{2}):(\d{2})(?:\.\d+)? (\d{4})\]')
RX_FPM = re.compile(r'\[(\d{1,2})-([A-Za-z]{3})-(\d{4}) (\d{2}):(\d{2}):(\d{2})(?: [^\]]+)?\]')
RX_ISO = re.compile(r'(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,]\d+)?(Z|[+-]\d{2}:?\d{2})?')
RX_SYSLOG = re.compile(r'^(?:<\d+>)?([A-Za-z]{3})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})\b')


def _mk(y, mon, d, h, mi, s):
    try:
        return datetime(int(y), mon, int(d), int(h), int(mi), int(s))
    except (ValueError, TypeError):
        return None


def _p_access(line, ref):
    m = RX_ACCESS.search(line)
    if not m:
        return None
    dt = _mk(m.group(3), MON.get(m.group(2).lower()), m.group(1), m.group(4), m.group(5), m.group(6))
    if not dt:
        return None
    tz = m.group(7)
    return m.start(), dt, dt.isoformat() + tz[:3] + ':' + tz[3:]


def _p_apache_err(line, ref):
    m = RX_APACHE_ERR.search(line)
    if not m:
        return None
    dt = _mk(m.group(6), MON.get(m.group(1).lower()), m.group(2), m.group(3), m.group(4), m.group(5))
    return (m.start(), dt, dt.isoformat()) if dt else None


def _p_fpm(line, ref):
    m = RX_FPM.search(line)
    if not m:
        return None
    dt = _mk(m.group(3), MON.get(m.group(2).lower()), m.group(1), m.group(4), m.group(5), m.group(6))
    return (m.start(), dt, dt.isoformat()) if dt else None


def _p_iso(line, ref):
    m = RX_ISO.search(line)
    if not m:
        return None
    dt = _mk(m.group(1), int(m.group(2)), m.group(3), m.group(4), m.group(5), m.group(6))
    if not dt:
        return None
    tz = m.group(7) or ''
    if tz == 'Z':
        tz = '+00:00'
    elif tz and ':' not in tz:
        tz = tz[:3] + ':' + tz[3:]
    return m.start(), dt, dt.isoformat() + tz


def _p_syslog(line, ref):
    m = RX_SYSLOG.match(line)
    if not m:
        return None
    mon = MON.get(m.group(1).lower())
    if not mon:
        return None
    dt = _mk(ref.year, mon, m.group(2), m.group(3), m.group(4), m.group(5))
    if dt and dt > ref + timedelta(days=1):       # 年またぎ（12 月のログを 1 月に回収した等）
        dt = _mk(ref.year - 1, mon, m.group(2), m.group(3), m.group(4), m.group(5))
    # 2/29 など年の補正で不正になる場合は None
    return (0, dt, dt.isoformat()) if dt else None


PARSERS = [_p_access, _p_apache_err, _p_fpm, _p_iso, _p_syslog]


def parse_time(line, ref, prefer):
    """(dt_naive, iso, parser_index) か (None, None, prefer)。
    前回成功した形式を先に試し、外れたら全形式のうち行内で最も左に出る時刻を採る。"""
    if prefer is not None:
        r = PARSERS[prefer](line, ref)
        if r:
            return r[1], r[2], prefer
    best = None
    for i, p in enumerate(PARSERS):
        r = p(line, ref)
        if r and (best is None or r[0] < best[0]):
            best = (r[0], r[1], r[2], i)
    if best:
        return best[1], best[2], best[3]
    return None, None, prefer


# ========== Helpers ==========
def clean(s: str, n: int) -> str:
    s = ''.join(' ' if (ord(c) < 32 or ord(c) == 127) else c for c in s.strip())
    return s[:n]


def md(s) -> str:
    """Markdown の表のセル用。コードスパンに入れる前提で、バッククォート・パイプ・改行を無害化する。"""
    s = clean(str(s), MD_CONTENT_MAX).replace('`', "'").replace('|', '\\|')
    return '`' + s + '`'


def local_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts).astimezone().isoformat(timespec='seconds')


def is_nonpublic(ip: str) -> bool:
    try:
        return not ipaddress.ip_address(ip.strip('[]')).is_global
    except ValueError:
        return False


def secs(dt: datetime) -> float:
    return (dt - datetime(1970, 1, 1)).total_seconds()


class Ctx:
    def __init__(self, client_ip_rx, patterns):
        self.patterns = patterns
        self.hits = []                    # dict
        self.scanned = []
        self.skipped = []
        self.client_ip_rx = client_ip_rx
        self.post_count = defaultdict(int)
        self.post_samples = {}
        self.post_times = defaultdict(list)   # ip -> [secs]
        self.post_stored = defaultdict(int)
        self.post_total_lines = 0


def extract_ip(line, rx) -> str:
    if rx:
        m = rx.search(line)
        if m and m.group('ip'):
            return m.group('ip')
        return 'unknown'
    parts = line.split(None, 1)
    return parts[0] if parts else 'unknown'


def probe(path: Path):
    """(is_gzip, error_or_None, is_binary)。先頭 4KB だけ見る。"""
    with open(path, 'rb') as f:
        head = f.read(4096)
    if head[:2] == b'\x1f\x8b':
        try:
            with gzip.open(path, 'rb') as g:
                head = g.read(4096)
        except (OSError, EOFError, zlib.error) as e:
            return True, 'gzip を読めない: %s' % e, False
        return True, None, b'\0' in head
    return False, None, b'\0' in head


def scan_file(path: Path, ctx: Ctx, out_paths):
    pats = ctx.patterns
    name = path.name.lower()
    spath = str(path)
    if name.endswith(('.journal', '.journal~')):
        ctx.skipped.append({'path': spath, 'reason': 'systemd journal（バイナリ）。'
                            '`journalctl -k -o short-iso > kernel.log` 等でテキストに書き出してから渡す'})
        return
    try:
        st = path.stat()
        if any(os.path.samefile(spath, o) for o in out_paths if os.path.exists(o)):
            return  # 自分の出力ファイルは調べない
        is_gz, err, binary = probe(path)
    except OSError as e:
        ctx.skipped.append({'path': spath, 'reason': '権限または読み込みエラー: %s' % e.__class__.__name__ + ' ' + str(e.strerror or e)})
        return
    if err:
        ctx.skipped.append({'path': spath, 'reason': err})
        return
    if binary:
        reason = 'バイナリ（先頭 4KB に NUL を含む）のため読まない'
        if path.suffix.lower() in COMPRESSED_EXTS:
            reason += '。未対応の圧縮形式なので展開してから渡す'
        ctx.skipped.append({'path': spath, 'reason': reason})
        return

    ref = datetime.fromtimestamp(st.st_mtime)
    lineno = 0
    first = last = None   # (dt, iso)
    prefer = None
    partial_err = None
    try:
        f = gzip.open(path, 'rb') if is_gz else open(path, 'rb')
        with f:
            for raw in f:
                lineno += 1
                line = raw.decode('utf-8', errors='replace').rstrip('\r\n')
                dt, iso, prefer = parse_time(line, ref, prefer)
                if dt:
                    if first is None or dt < first[0]:
                        first = (dt, iso)
                    if last is None or dt > last[0]:
                        last = (dt, iso)
                if pats.access_re and pats.access_method in line and pats.access_re.search(line):
                    ip = extract_ip(line, ctx.client_ip_rx)
                    ctx.post_total_lines += 1
                    ctx.post_count[ip] += 1
                    if ip not in ctx.post_samples:
                        ctx.post_samples[ip] = clean(line, 300)
                    if dt:
                        ctx.post_times[ip].append(secs(dt))
                    if ctx.post_stored[ip] < POST_HITS_PER_IP:
                        ctx.post_stored[ip] += 1
                        ctx.hits.append({'category': 'post-5xx', 'pattern': 'access-post-5xx', 'path': spath,
                                         'line': lineno, 'time': iso, 'content': clean(line, CONTENT_MAX),
                                         'ip': ip, '_dt': dt})
                    continue
                for pname, cat, rx in pats.log_patterns:
                    if rx.search(line):
                        ctx.hits.append({'category': cat, 'pattern': pname, 'path': spath, 'line': lineno,
                                         'time': iso, 'content': clean(line, CONTENT_MAX), 'ip': None, '_dt': dt})
                        break
    except (OSError, EOFError, zlib.error) as e:
        partial_err = e
    ctx.scanned.append({'path': spath, 'size': st.st_size, 'lines': lineno,
                        'firstTime': first[1] if first else None, 'lastTime': last[1] if last else None})
    if partial_err:
        ctx.skipped.append({'path': spath, 'reason': '読み込み途中で失敗（%d 行目まで調べた）: %s' % (lineno, partial_err)})


def scan_logs(log_dir: Path, ctx: Ctx, out_paths):
    print('[*] Scanning logs in %s ...' % log_dir)

    def onerr(e):
        ctx.skipped.append({'path': str(e.filename), 'reason': 'ディレクトリを開けない: %s' % (e.strerror or e)})

    for root, _, files in os.walk(log_dir, onerror=onerr):
        for fname in sorted(files):
            p = Path(root) / fname
            if not os.path.isfile(p):
                ctx.skipped.append({'path': str(p), 'reason': '通常ファイルではない（壊れたリンク・デバイス等）'})
                continue
            scan_file(p, ctx, out_paths)


def correlate(ctx: Ctx, window_min: int):
    sig = sorted(secs(h['_dt']) for h in ctx.hits
                 if h['category'] in ctx.patterns.categories and h['_dt'])
    w = window_min * 60
    result = []
    if not sig:
        return result
    for ip, times in ctx.post_times.items():
        near = set()
        events = 0
        for s in times:
            lo = bisect.bisect_left(sig, s - w)
            hi = bisect.bisect_right(sig, s + w)
            if hi > lo:
                events += 1
                near.update(range(lo, hi))
        if near:
            result.append({'ip': ip, 'post5xx': ctx.post_count[ip], 'nearbyOomOrCrash': len(near),
                           'score': events + len(near)})
    result.sort(key=lambda r: (-r['score'], r['ip']))
    return result


def find_recent_web(webroot: Path, days: int, ctx: Ctx):
    if not webroot.exists():
        ctx.skipped.append({'path': str(webroot), 'reason': 'webroot が見つからない'})
        return []
    cutoff = datetime.now().timestamp() - days * 86400
    recent = []
    print('[*] Looking for web files changed in last %d days under %s ...' % (days, webroot))

    def onerr(e):
        ctx.skipped.append({'path': str(e.filename), 'reason': 'ディレクトリを開けない: %s' % (e.strerror or e)})

    for root, _, files in os.walk(webroot, onerror=onerr):
        for fname in files:
            low = fname.lower()
            ext = os.path.splitext(low)[1]
            if ext in ctx.patterns.web_exts:
                pat = 'ext:' + ext
            elif low in ctx.patterns.web_names:
                pat = 'name:' + low
            else:
                continue
            fpath = os.path.join(root, fname)
            try:
                st = os.stat(fpath)
            except OSError as e:
                ctx.skipped.append({'path': fpath, 'reason': 'stat できない: %s' % (e.strerror or e)})
                continue
            newer = max(st.st_mtime, st.st_ctime)
            if newer > cutoff:
                recent.append({'path': fpath, 'pattern': pat, 'newer': newer,
                               'mtime': local_iso(st.st_mtime), 'ctime': local_iso(st.st_ctime)})
    recent.sort(key=lambda r: r['newer'], reverse=True)
    return recent


def build_report(args, ctx, correlations, recent, top_ips, proxy_warn, host, collected, counts):
    L = []
    L.append('# Offline Triage Report')
    L.append('Generated: %s' % collected)
    L.append('Host: %s' % md(host))
    L.append('')
    L.append('## Summary')
    L.append('- Logs: %s / Webroot: %s / days=%d / window=%d min' % (md(args.logs), md(args.webroot) if args.webroot else 'なし', args.days, args.window))
    L.append('- 調べたファイル: %d / 読めなかったファイル: %d' % (len(ctx.scanned), len(ctx.skipped)))
    L.append('- 検索パターン: %s / ' % md(ctx.patterns.id) + ' / '.join('%s: %d' % (c, counts[c]) for c in ctx.patterns.categories))
    L.append('- POST+5xx の行: %d（IP %d 件）' % (ctx.post_total_lines, len(ctx.post_count)))
    L.append('- 相関のある IP（前後 %d 分以内に検索パターンのヒット）: %d' % (args.window, len(correlations)))
    L.append('- 最近変更された Web ファイル: %d' % len(recent))
    if ctx.skipped:
        L.append('- **注意：読めなかったファイルがある。「## 読めなかったファイル」を確認すること**')
    if proxy_warn:
        L.append('- **警告：** ' + proxy_warn)
    L.append('')

    if correlations:
        L.append('## 相関の上位 IP（POST+5xx の前後に検索パターンのヒット）')
        L.append('スコア = 近傍に検索パターンのヒットがあった POST+5xx の件数 + 近傍のヒット数（重複なし）')
        L.append('')
        L.append('| IP | POST+5xx | 近傍のヒット | スコア |')
        L.append('|----|---------:|-------------:|-------:|')
        for r in correlations[:20]:
            L.append('| %s | %d | %d | %d |' % (md(r['ip']), r['post5xx'], r['nearbyOomOrCrash'], r['score']))
        L.append('')

    oomhits = [h for h in ctx.hits if h['category'] in ctx.patterns.categories]
    if oomhits:
        oomhits.sort(key=lambda h: (h['_dt'] is None, h['_dt'] or datetime.min))
        L.append('## 検索パターンのヒット（時刻順、先頭 100 件／全 %d 件）' % len(oomhits))
        L.append('| 時刻 | 分類 | パターン | File | Line | Content |')
        L.append('|------|------|----------|------|-----:|---------|')
        for h in oomhits[:100]:
            L.append('| %s | %s | %s | %s | %s | %s |' % (h['time'] or '-', h['category'], h['pattern'],
                                                         md(h['path']), h['line'], md(h['content'])))
        L.append('')

    if top_ips:
        L.append('## POST + 5xx の上位 IP')
        if proxy_warn:
            L.append('> **警告：** ' + proxy_warn)
            L.append('')
        L.append('| IP | Count | Sample |')
        L.append('|----|------:|--------|')
        for ip, cnt in top_ips:
            L.append('| %s | %d | %s |' % (md(ip), cnt, md(ctx.post_samples.get(ip, ''))))
        L.append('')
        L.append('（JSON/ヒット一覧に載せる POST+5xx の行は IP ごとに最大 %d 行。集計と相関は全件を使用）' % POST_HITS_PER_IP)
        L.append('')

    if recent:
        L.append('## 最近変更された Web ファイル（mtime と ctime の新しいほうで判定）')
        L.append('| File | 判定 | mtime | ctime |')
        L.append('|------|------|-------|-------|')
        for r in recent[:50]:
            L.append('| %s | %s | %s | %s |' % (md(r['path']), r['pattern'], r['mtime'], r['ctime']))
        if len(recent) > 50:
            L.append('')
            L.append('（ほか %d 件。全件は JSON を参照）' % (len(recent) - 50))
        L.append('')

    L.append('## 調べたファイル')
    L.append('| File | Size | Lines | 最初の時刻 | 最後の時刻 |')
    L.append('|------|-----:|------:|------------|------------|')
    for s in ctx.scanned:
        L.append('| %s | %d | %d | %s | %s |' % (md(s['path']), s['size'], s['lines'], s['firstTime'] or '-', s['lastTime'] or '-'))
    if not ctx.scanned:
        L.append('| （なし） | | | | |')
    L.append('')

    L.append('## 読めなかったファイル')
    if ctx.skipped:
        L.append('| File | 理由 |')
        L.append('|------|------|')
        for s in ctx.skipped:
            L.append('| %s | %s |' % (md(s['path']), md(s['reason'])))
    else:
        L.append('なし')
    L.append('')

    L.append('## Notes')
    L.append('- 該当なし = 安全ではありません。アプリケーションコード実行前に発生する問題は、ログに残らない場合があります。')
    L.append('- 相関（同一 IP で検索パターンのヒット + 5xx のバースト）がある場合は優先的に調査してください。')
    for n in ctx.patterns.notes:
        L.append('- ' + clean(n, 1000))
    L.append('- mtime は攻撃者が書き換え（touch 等）できる。ctime（Linux では inode 変更時刻）のほうが偽装しにくいが、'
             'コピーや展開を経たファイルでは両方とも信頼できない。Windows の ctime は作成時刻。')
    L.append('- 時刻はログ内の表記のまま（オフセットなしの形式はサーバーのローカル時刻と仮定）。相関は表記上の時刻（オフセットを無視した壁時計）で比べる。'
             'syslog 形式は年がないためファイルの mtime の年で補っている。時刻が取れなかった行は相関に使えない。')
    L.append('- 「読めなかったファイル」のバイナリ（journal 等）は調べていない。テキストに書き出してから再実行すること。')
    return '\n'.join(L) + '\n'


def main():
    try:
        sys.stdout.reconfigure(errors='replace')
        sys.stderr.reconfigure(errors='replace')
    except Exception:
        pass
    parser = argparse.ArgumentParser(description='Offline log triage for suspected compromise (does not decide whether a compromise happened)')
    parser.add_argument('--patterns', type=Path, required=True, help='Pattern file (JSON, format cyberriskscape-triage-patterns)')
    parser.add_argument('--logs', type=Path, default=Path('/var/log'), help='Log directory to scan')
    parser.add_argument('--webroot', type=Path, default=None, help='Web root to check for recently changed web files')
    parser.add_argument('--days', type=int, default=3, help='Days to look back for recent web files')
    parser.add_argument('--window', type=int, default=5, help='Correlation window in minutes (default 5)')
    parser.add_argument('--output', type=Path, default=Path('crs_triage_report.md'), help='Output Markdown report')
    parser.add_argument('--json', type=Path, default=None, help='Output JSON report (optional)')
    parser.add_argument('--host', default=None, help='Original host name (default: this machine)')
    parser.add_argument('--client-ip-regex', default=None,
                        help='Regex with named group "ip" to extract the client IP from access log lines')
    args = parser.parse_args()

    if not args.logs.is_dir():
        print('[!] Log directory not found: %s' % args.logs, file=sys.stderr)
        sys.exit(1)
    rx = None
    if args.client_ip_regex:
        try:
            rx = re.compile(args.client_ip_regex)
        except re.error as e:
            print('[!] Invalid --client-ip-regex: %s' % e, file=sys.stderr)
            sys.exit(2)
        if 'ip' not in rx.groupindex:
            print('[!] --client-ip-regex needs a named group (?P<ip>...)', file=sys.stderr)
            sys.exit(2)

    try:
        patterns = load_patterns(args.patterns)
    except PatternError as e:
        print('[!] Invalid --patterns: %s' % e, file=sys.stderr)
        sys.exit(2)

    ctx = Ctx(rx, patterns)
    out_paths = [str(args.output)] + ([str(args.json)] if args.json else [])
    scan_logs(args.logs, ctx, out_paths)

    recent = find_recent_web(args.webroot, args.days, ctx) if args.webroot else []
    for r in recent:
        ctx.hits.append({'category': 'recent-file', 'pattern': r['pattern'], 'path': r['path'], 'line': None,
                         'time': local_iso(r['newer']), 'content': 'mtime=%s; ctime=%s' % (r['mtime'], r['ctime']),
                         'ip': None, '_dt': None})

    correlations = correlate(ctx, args.window)
    top_ips = sorted(ctx.post_count.items(), key=lambda x: (-x[1], x[0]))[:20]
    proxy_warn = ''
    top_head = [ip for ip, _ in top_ips[:10]]
    if top_head and all(is_nonpublic(ip) for ip in top_head):
        proxy_warn = ('上位の IP がすべてプライベート・ループバック等。前段にリバースプロキシ・WAF・CDN がある可能性。'
                      '実際の送信元は X-Forwarded-For 等の記録で確認（--client-ip-regex で抽出方法を差し替え可能）')

    counts = {c: sum(1 for h in ctx.hits if h['category'] == c) for c in patterns.categories}
    host = args.host or socket.gethostname()
    collected = datetime.now().astimezone().isoformat(timespec='seconds')

    report = build_report(args, ctx, correlations, recent, top_ips, proxy_warn, host, collected, counts)
    args.output.write_text(report, encoding='utf-8')
    print('\n[+] Report written to: %s' % args.output)

    if args.json:
        import json
        hits = [{k: v for k, v in h.items() if k != '_dt'} for h in ctx.hits]
        doc = {
            'format': 'cyberriskscape-triage', 'version': 1, 'host': host, 'collectedAt': collected,
            'parameters': {'logs': str(args.logs), 'webroot': str(args.webroot) if args.webroot else None,
                           'days': args.days, 'window': args.window,
                           'patterns': {'id': patterns.id, 'version': patterns.version}},
            'scanned': ctx.scanned, 'skipped': ctx.skipped, 'hits': hits, 'correlations': correlations,
        }
        args.json.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding='utf-8')
        print('[+] JSON written to: %s' % args.json)

    print('\n=== Quick Summary ===')
    print('Scanned: %d files, skipped: %d' % (len(ctx.scanned), len(ctx.skipped)))
    print('  '.join('%s: %d' % (c, counts[c]) for c in patterns.categories))
    print('POST+5xx lines: %d (IPs: %d)' % (ctx.post_total_lines, len(ctx.post_count)))
    if correlations:
        print('Correlated IPs (top 5):')
        for r in correlations[:5]:
            print('  %s: score %d' % (r['ip'], r['score']))
    if proxy_warn:
        print('[!] ' + proxy_warn)
    if recent:
        print('Recent web files: %d' % len(recent))


if __name__ == '__main__':
    main()
