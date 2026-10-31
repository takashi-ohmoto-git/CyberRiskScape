// MITRE ATT&CK Enterprise の STIX 2.1 バンドルから、マトリクス表示に要る最小限
// （戦術・テクニック・サブテクニックの ID・名前・所属・並び順）だけを抜き出し、
// data/attack-matrix/enterprise-attack.yaml を生成する。説明文は取り込まない。
//
// 使い方（リポジトリ直下で実行。STIX は事前にダウンロードしておく）:
//   curl -L -o <tmp>/enterprise-attack-20.0.json \
//     https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.0.json
//   node tools/attack-matrix/build-attack-matrix.mjs <tmp>/enterprise-attack-20.0.json
//
// 新版が出たら同じ手順で再生成し、src/features/attack-matrix の件数テストと
// data/attack-matrix/i18n/ja/enterprise-attack.yaml の訳を更新する。
//
// SPDX-License-Identifier: Apache-2.0

import { readFileSync, writeFileSync } from 'node:fs';
import { stringify } from 'yaml';

const OUT = 'data/attack-matrix/enterprise-attack.yaml';

const src = process.argv[2];
if (!src) {
  console.error('usage: node tools/attack-matrix/build-attack-matrix.mjs <enterprise-attack.json>');
  process.exit(1);
}

const objects = JSON.parse(readFileSync(src, 'utf8')).objects;
const live = (o) => !o.revoked && !o.x_mitre_deprecated;
const extId = (o) => o.external_references.find((r) => r.source_name === 'mitre-attack').external_id;
const byName = (a, b) => a.name.localeCompare(b.name, 'en', { sensitivity: 'base' });

const collection = objects.find((o) => o.type === 'x-mitre-collection');
const matrix = objects.find((o) => o.type === 'x-mitre-matrix' && live(o));
const byStixId = new Map(objects.map((o) => [o.id, o]));
const tactics = matrix.tactic_refs.map((ref) => byStixId.get(ref));

const patterns = objects.filter(
  (o) => o.type === 'attack-pattern' && live(o) && (o.x_mitre_domains ?? []).includes('enterprise-attack'),
);
const parents = patterns.filter((o) => !o.x_mitre_is_subtechnique).sort(byName);
const subs = patterns.filter((o) => o.x_mitre_is_subtechnique);

const phasesOf = (o) =>
  (o.kill_chain_phases ?? []).filter((k) => k.kill_chain_name === 'mitre-attack').map((k) => k.phase_name);

const doc = {
  version: collection.x_mitre_version,
  modified: collection.modified.slice(0, 10),
  tactics: tactics.map((t) => ({
    id: extId(t),
    name: t.name,
    techniques: parents.filter((p) => phasesOf(p).includes(t.x_mitre_shortname)).map(extId),
  })),
  techniques: parents.map((p) => {
    const id = extId(p);
    const children = subs
      .filter((s) => extId(s).startsWith(`${id}.`))
      .map((s) => ({ id: extId(s), name: s.name }))
      .sort((a, b) => a.id.localeCompare(b.id));
    return { id, name: p.name, ...(children.length > 0 ? { subtechniques: children } : {}) };
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

const header = `# MITRE ATT&CK® Enterprise マトリクス（v${doc.version}、${doc.modified} 公開）
# 出典: https://attack.mitre.org/ ／ https://github.com/mitre-attack/attack-stix-data
# © The MITRE Corporation. Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).
# 戦術・テクニック・サブテクニックの ID と名前だけを抜き出したもの（説明文は含まない）。
# 生成: node tools/attack-matrix/build-attack-matrix.mjs <enterprise-attack.json> — 手で編集しない。
#
# SPDX-License-Identifier: CC-BY-4.0

`;
writeFileSync(OUT, header + stringify(doc, { lineWidth: 0 }));
console.log(
  `wrote ${OUT}: v${doc.version}, ${doc.tactics.length} tactics, ${doc.techniques.length} techniques, ${subCount} subtechniques`,
);
