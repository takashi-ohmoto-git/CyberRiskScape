// MITRE Fight Fraud Framework (F3) の公式 JSON（f3-vX.json）から、マトリクス表示に要る最小限
// （戦術・テクニック・サブテクニックの ID・名前・所属・並び順）だけを抜き出し、
// data/attack-matrix/f3.yaml を生成する。説明文は取り込まない。
//
// 使い方（リポジトリ直下で実行。JSON は事前にダウンロードしておく）:
//   curl -L -o <tmp>/f3-v1.2.json \
//     https://raw.githubusercontent.com/center-for-threat-informed-defense/fight-fraud-framework/main/public/f3-v1.2.json
//   node tools/attack-matrix/build-f3-matrix.mjs <tmp>/f3-v1.2.json
//
// 新版が出たら同じ手順で再生成し、src/features/attack-matrix の件数テストを更新する。
//
// SPDX-License-Identifier: Apache-2.0

import { readFileSync, writeFileSync } from 'node:fs';
import { stringify } from 'yaml';

const OUT = 'data/attack-matrix/f3.yaml';

const src = process.argv[2];
if (!src) {
  console.error('usage: node tools/attack-matrix/build-f3-matrix.mjs <f3-vX.json>');
  process.exit(1);
}

const items = JSON.parse(readFileSync(src, 'utf8'));
const isSub = (o) => o.id.includes('.');
const tactics = items.filter((o) => o.tactic);
const parents = items.filter((o) => !o.tactic && !isSub(o));
const subs = items.filter((o) => !o.tactic && isSub(o));

const version = parents[0].version;
const modified = items
  .map((o) => o.lastModified)
  .sort()
  .at(-1)
  .slice(0, 10);

const doc = {
  version,
  modified,
  tactics: tactics.map((t) => ({
    id: t.id,
    name: t.name,
    techniques: parents.filter((p) => (p.tactics ?? []).includes(t.id)).map((p) => p.id),
  })),
  techniques: parents.map((p) => {
    // サブテクニック名は "親: 子" 形式なので子の部分だけにする（ATT&CK 側と同じ形）。
    const children = subs
      .filter((s) => s.id.startsWith(`${p.id}.`))
      .map((s) => ({ id: s.id, name: s.name.includes(': ') ? s.name.slice(s.name.indexOf(': ') + 2) : s.name }))
      .sort((a, b) => a.id.localeCompare(b.id));
    return { id: p.id, name: p.name, ...(children.length > 0 ? { subtechniques: children } : {}) };
  }),
};

// 取りこぼし検知：どの戦術にも属さないテクニック・親の無いサブテクニックがあれば止める。
const placed = new Set(doc.tactics.flatMap((t) => t.techniques));
const orphanTech = doc.techniques.filter((t) => !placed.has(t.id)).map((t) => t.id);
const subCount = doc.techniques.reduce((n, t) => n + (t.subtechniques?.length ?? 0), 0);
if (orphanTech.length > 0 || subCount !== subs.length) {
  console.error('unplaced techniques:', orphanTech, 'subtechniques', subCount, '/', subs.length);
  process.exit(1);
}

const header = `# MITRE Fight Fraud Framework™ (F3™) マトリクス（v${doc.version}、${doc.modified} 更新）
# 出典: https://ctid.mitre.org/fightfraud/ ／ https://github.com/center-for-threat-informed-defense/fight-fraud-framework
# © 2026 MITRE. Licensed under Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0). PR_25-02691-6
# 戦術・テクニック・サブテクニックの ID と名前だけを抜き出したもの（説明文は含まない）。
# F3 は ATT&CK の ID（T で始まる）を一部そのまま再利用している。
# 生成: node tools/attack-matrix/build-f3-matrix.mjs <f3-vX.json> — 手で編集しない。
#
# SPDX-License-Identifier: Apache-2.0

`;
writeFileSync(OUT, header + stringify(doc, { lineWidth: 0 }));
console.log(
  `wrote ${OUT}: v${doc.version}, ${doc.tactics.length} tactics, ${doc.techniques.length} techniques, ${subCount} subtechniques`,
);
