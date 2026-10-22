# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TAKASHI OMOTO
import gzip
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent / 'crs_triage.py'
EXAMPLE = HERE.parent / 'patterns.example.json'

# 検索パターンはテスト用の合成（ツール本体にも同梱サンプルにも依存しない）
PATTERNS = {
    'format': 'cyberriskscape-triage-patterns', 'version': 1, 'id': 'test-patterns',
    'logPatterns': [
        {'id': 'k-oom', 'category': 'kernel-oom', 'regex': 'Out of memory: Killed process', 'priority': 10},
        {'id': 'k-inv', 'category': 'kernel-oom', 'regex': 'invoked oom-killer', 'priority': 11},
        {'id': 'k-kill', 'category': 'kernel-oom', 'regex': 'oom-kill', 'priority': 12},
        {'id': 'segv', 'category': 'crash', 'regex': r'SIGSEGV|Segmentation fault|exited on signal 11', 'priority': 20},
        {'id': 'mem', 'category': 'oom', 'regex': r'Allowed memory size of \d+ bytes exhausted', 'priority': 30},
        {'id': 'generic-oom', 'category': 'oom', 'regex': 'Out of memory', 'priority': 31},
    ],
    'accessLog': {'method': 'POST', 'statuses': [500, 502, 503, 504]},
    'webroot': {'extensions': ['.php', '.phtml'], 'filenames': ['.user.ini']},
    'notes': ['custom-note-marker'],
}


def run_tool(*args):
    return subprocess.run([sys.executable, '-I', str(TOOL), *args], capture_output=True, text=True,
                          encoding='utf-8', errors='replace')


class TriageTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.logs = self.tmp / 'logs'
        self.web = self.tmp / 'web'
        for d in (self.logs / 'apache2', self.logs / 'rot', self.web / 'sub'):
            d.mkdir(parents=True)
        self.patterns = self.tmp / 'patterns.json'
        self.patterns.write_text(json.dumps(PATTERNS), encoding='utf-8')
        (self.logs / 'apache2' / 'access.log').write_text(
            '45.33.32.156 - - [21/Oct/2026:12:34:50 +0900] "POST /u HTTP/1.1" 502 120 "-" "x"\n'
            '45.33.32.156 - - [21/Oct/2026:12:35:10 +0900] "POST /u HTTP/1.1" 504\n'
            '8.8.4.4 - - [21/Oct/2026:15:00:00 +0900] "POST /a HTTP/1.1" 200 5\n'
            '8.8.4.4 - - [21/Oct/2026:15:00:01 +0900] "GET /a HTTP/1.1" 500 5\n', encoding='utf-8')
        (self.logs / 'apache2' / 'error.log').write_text(
            '[Wed Oct 21 12:35:00.789012 2026] [php:error] PHP Fatal error: Allowed memory size of 1 bytes exhausted\n'
            '[Wed Oct 21 12:35:20.000000 2026] [core:notice] child exit signal Segmentation fault (11)\n',
            encoding='utf-8')
        (self.logs / 'messages').write_text(
            'Oct 21 12:35:05 web01 kernel: Out of memory: Killed process 1 (x)\n', encoding='utf-8')
        with gzip.open(self.logs / 'rot' / 'messages-1.gz', 'wt') as f:
            f.write('2026-10-20T03:00:00+09:00 web01 kernel: oom-kill:constraint=NONE\n')
        (self.logs / 'sys@a.journal').write_bytes(b'LPKSHHRH\0\0')
        (self.logs / 'wtmp').write_bytes(b'\0\0abc\0' * 50)
        (self.web / 'shell.php').write_text('<?php', encoding='utf-8')
        (self.web / 'sub' / '.user.ini').write_text('x', encoding='utf-8')
        (self.web / 'readme.txt').write_text('x', encoding='utf-8')

    def run_json(self, *extra, webroot=True):
        out = self.tmp / 'r.json'
        args = ['--patterns', str(self.patterns), '--logs', str(self.logs), '--output', str(self.tmp / 'r.md'),
                '--json', str(out), '--host', 'h1', *extra]
        if webroot:
            args += ['--webroot', str(self.web)]
        r = run_tool(*args)
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        return json.loads(out.read_text(encoding='utf-8')), (self.tmp / 'r.md').read_text(encoding='utf-8')

    def test_output_shape_and_counts(self):
        doc, _ = self.run_json()
        self.assertEqual(doc['format'], 'cyberriskscape-triage')
        self.assertEqual(doc['version'], 1)
        self.assertEqual(doc['host'], 'h1')
        for k in ('collectedAt', 'parameters', 'scanned', 'skipped', 'hits', 'correlations'):
            self.assertIn(k, doc)
        self.assertEqual(doc['parameters']['patterns'], {'id': 'test-patterns', 'version': 1})
        for k in ('logs', 'webroot', 'days', 'window'):
            self.assertIn(k, doc['parameters'])
        cats = {}
        for h in doc['hits']:
            cats[h['category']] = cats.get(h['category'], 0) + 1
        self.assertEqual(cats, {'kernel-oom': 2, 'crash': 1, 'oom': 1, 'post-5xx': 2, 'recent-file': 2})

    def test_skipped_binary_and_journal(self):
        doc, md = self.run_json()
        names = {os.path.basename(s['path']) for s in doc['skipped']}
        self.assertEqual(names, {'sys@a.journal', 'wtmp'})
        self.assertIn('読めなかったファイル', md)

    def test_correlation_and_non_post_not_counted(self):
        doc, _ = self.run_json()
        self.assertEqual([c['ip'] for c in doc['correlations']], ['45.33.32.156'])
        self.assertEqual(doc['correlations'][0]['post5xx'], 2)
        self.assertGreater(doc['correlations'][0]['score'], 0)

    def test_gzip_is_scanned(self):
        doc, _ = self.run_json()
        self.assertTrue(any(s['path'].endswith('messages-1.gz') for s in doc['scanned']))
        self.assertTrue(any(h['pattern'] == 'k-kill' for h in doc['hits']))

    def test_proxy_warning_and_client_ip_regex(self):
        (self.logs / 'apache2' / 'access.log').write_text(
            '10.0.0.5 - - [21/Oct/2026:12:34:50 +0900] "POST /u HTTP/1.1" 502 1 xff=93.184.216.34\n',
            encoding='utf-8')
        doc, md = self.run_json(webroot=False)
        self.assertIn('リバースプロキシ', md)
        doc, md = self.run_json('--client-ip-regex', r'xff=(?P<ip>[0-9.]+)', webroot=False)
        self.assertNotIn('リバースプロキシ', md)
        self.assertEqual(doc['correlations'][0]['ip'], '93.184.216.34')

    def test_patterns_drive_detection(self):
        custom = dict(PATTERNS, logPatterns=[
            {'id': 'only-segv', 'category': 'custom', 'regex': 'segmentation fault', 'priority': 1}],
            accessLog={'method': 'POST', 'statuses': [502]}, webroot={'extensions': ['.txt'], 'filenames': []})
        self.patterns.write_text(json.dumps(custom), encoding='utf-8')
        doc, md = self.run_json()
        cats = sorted({h['category'] for h in doc['hits']})
        self.assertEqual(cats, ['custom', 'post-5xx', 'recent-file'])
        self.assertEqual(sum(1 for h in doc['hits'] if h['category'] == 'post-5xx'), 1)
        self.assertIn('readme.txt', json.dumps(doc))
        self.assertIn('custom-note-marker', md)

    def test_priority_first_match_wins(self):
        (self.logs / 'one.log').write_text('Out of memory: Killed process 9\n', encoding='utf-8')
        doc, _ = self.run_json(webroot=False)
        hits = [h for h in doc['hits'] if h['path'].endswith('one.log')]
        self.assertEqual([(h['category'], h['pattern']) for h in hits], [('kernel-oom', 'k-oom')])

    def test_markdown_escaping(self):
        (self.logs / 'esc.log').write_text('Out of memory: Killed process `a|b`\n', encoding='utf-8')
        _, md = self.run_json(webroot=False)
        self.assertIn("'a\\|b'", md)

    def test_bad_patterns_rejected(self):
        bad_regex = dict(PATTERNS, logPatterns=[{'id': 'a', 'category': 'c', 'regex': '(', 'priority': 1}])
        for bad in ({'format': 'x', 'version': 1, 'id': 'a'}, bad_regex, dict(PATTERNS, version=2)):
            self.patterns.write_text(json.dumps(bad), encoding='utf-8')
            r = run_tool('--patterns', str(self.patterns), '--logs', str(self.logs),
                         '--output', str(self.tmp / 'x.md'))
            self.assertEqual(r.returncode, 2, r.stderr)
        r = run_tool('--logs', str(self.logs))
        self.assertNotEqual(r.returncode, 0)

    @unittest.skipUnless(EXAMPLE.exists(), 'sample patterns not present')
    def test_bundled_example_loads(self):
        r = run_tool('--patterns', str(EXAMPLE), '--logs', str(self.logs), '--output', str(self.tmp / 'e.md'))
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == '__main__':
    unittest.main()
