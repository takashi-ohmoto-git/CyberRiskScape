import { stringify } from 'yaml';
import { translate, type TranslationKey } from '../../i18n';
import type { DetectionRequirements } from './buildDetectionRequirements';
import { getDetectionRequirements, type DetectionRequirement } from './requirements';

/**
 * 検知要件を Sigma ルール（Sigma Rules Specification 2.1.0）の下書きにする（plan §2.150）。
 * - 要件ごとに 1 本。当たるノード・脅威・必要なログは説明と `threat_model`（独自の項目）に載せる
 * - logsource は要件の `sigma`（data/detection-requirements/detection.yaml）。無ければ `category: application`
 * - 検知の条件は推測で作らない：`expand` 修飾子のプレースホルダーにし、status は unsupported（そのままでは動かない）。
 *   プレースホルダーを解決できない変換ツールはルールを拒否する（仕様）ので、誤って配備されない
 * - id は製品・システム名・レイヤー・要件から決まる UUID（RFC 9562 の version 8）。書き出し直しても同じになる
 * DOM にも Node にも依存しない純粋関数。
 */

export const SIGMA_DETECTION_PLACEHOLDER = '%define_detection_logic%';

/** 文字列から決まる UUID（version 8・variant 10）。4 本の FNV-1a（32 ビット）を種を変えてつなぐ。 */
export function deterministicUuid(text: string): string {
  const words = [0x811c9dc5, 0x01000193, 0x9e3779b9, 0x85ebca6b].map((seed) => {
    let h = seed >>> 0;
    for (let i = 0; i < text.length; i++) {
      h ^= text.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h.toString(16).padStart(8, '0');
  });
  const hex = words.join('').split('');
  hex[12] = '8';
  hex[16] = ((parseInt(hex[16], 16) & 0x3) | 0x8).toString(16);
  const h = hex.join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

interface Aggregated {
  req: DetectionRequirement;
  title: string;
  watch: string[];
  logs: string[];
  attack: string[];
  nodes: string[];
  threats: Set<string>;
}

export function detectionRequirementsToSigma(d: DetectionRequirements): string {
  const t = (key: TranslationKey, params?: Record<string, string | number>) => translate(key, d.locale, params);
  const byId = new Map(getDetectionRequirements(d.locale).map((r) => [r.id, r]));
  const agg = new Map<string, Aggregated>();
  for (const n of d.nodes) {
    for (const r of n.requirements) {
      const req = byId.get(r.id);
      if (!req) continue;
      const a = agg.get(r.id) ?? { req, title: r.title, watch: r.watch, logs: r.logs, attack: r.attack, nodes: [], threats: new Set<string>() };
      a.nodes.push(`${n.id} ${n.label}`.trim());
      for (const name of r.threatNames) a.threats.add(name);
      agg.set(r.id, a);
    }
  }

  const docs = [...agg.values()].map((a) => {
    const description = [
      t('detection.sigma.draft', { product: d.product, system: d.system, layer: d.layer }),
      t('detection.watch'),
      ...a.watch.map((w) => `- ${w}`),
      t('detection.sigma.nodes'),
      ...a.nodes.map((n) => `- ${n}`),
      t('detection.logs'),
      ...a.logs.map((l) => `- ${l}`),
    ].join('\n');
    return {
      title: a.title,
      id: deterministicUuid(`${d.product}|${d.system}|${d.layer}|${a.req.id}`),
      status: 'unsupported',
      description,
      author: t('detection.sigma.author', { product: d.product }),
      date: d.generatedAt,
      ...(a.attack.length > 0 ? { tags: a.attack.map((x) => `attack.${x.toLowerCase()}`) } : {}),
      logsource: {
        ...(a.req.sigma ?? { category: 'application' }),
        definition: a.logs.join(' / '),
      },
      detection: {
        selection: { 'field_to_define|expand': SIGMA_DETECTION_PLACEHOLDER },
        condition: 'selection',
      },
      falsepositives: [t('detection.sigma.falsepositive')],
      threat_model: {
        system: d.system,
        layer: d.layer,
        requirement: a.req.id,
        nodes: a.nodes,
        threats: [...a.threats],
      },
    };
  });
  return docs.map((doc) => stringify(doc, { indent: 4, lineWidth: 0, blockQuote: 'literal' })).join('---\n');
}
