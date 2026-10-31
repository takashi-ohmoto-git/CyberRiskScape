import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import type { Locale } from '../../i18n';

/**
 * MITRE ATT&CK Enterprise マトリクス（戦術・テクニック・サブテクニックの ID と名前）のローダー。
 *
 * 本体は `data/attack-matrix/enterprise-attack.yaml`（tools/attack-matrix で生成）。
 * 日本語名は `data/attack-matrix/i18n/ja/enterprise-attack.yaml`（非公式訳。ID 鍵）。
 * 訳が無い ID は英語名にフォールバックする。
 */

const SubtechniqueSchema = z.object({ id: z.string(), name: z.string() });
const TechniqueSchema = z.object({
  id: z.string(),
  name: z.string(),
  subtechniques: z.array(SubtechniqueSchema).optional(),
});
const TacticSchema = z.object({
  id: z.string(),
  name: z.string(),
  techniques: z.array(z.string()),
});
const MatrixFileSchema = z.object({
  version: z.string(),
  modified: z.union([z.string(), z.date()]),
  tactics: z.array(TacticSchema),
  techniques: z.array(TechniqueSchema),
});
const NamesOverlaySchema = z.object({
  schemaVersion: z.literal(1),
  locale: z.string(),
  version: z.string().optional(),
  names: z.record(z.string(), z.string()),
});

export interface AttackSubtechnique {
  id: string;
  name: string;
}
export interface AttackTechnique {
  id: string;
  name: string;
  subtechniques: AttackSubtechnique[];
}
export interface AttackTactic {
  id: string;
  name: string;
  /** 表示順のテクニック（親のみ）。 */
  techniques: AttackTechnique[];
}
export interface AttackMatrix {
  version: string;
  tactics: AttackTactic[];
  /** 親テクニック ID → テクニック。 */
  techniques: Map<string, AttackTechnique>;
  /** サブテクニック ID → 親テクニック ID。 */
  subToParent: Map<string, string>;
}

const matrixModules = import.meta.glob<string>('../../../data/attack-matrix/enterprise-attack.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});
const jaModules = import.meta.glob<string>('../../../data/attack-matrix/i18n/ja/enterprise-attack.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

function firstText(mods: Record<string, string>): string | undefined {
  return Object.values(mods)[0];
}

export function parseAttackMatrix(text: string): AttackMatrix {
  const file = MatrixFileSchema.parse(parseYaml(text));
  const techniques = new Map<string, AttackTechnique>();
  const subToParent = new Map<string, string>();
  for (const t of file.techniques) {
    techniques.set(t.id, { id: t.id, name: t.name, subtechniques: t.subtechniques ?? [] });
    for (const s of t.subtechniques ?? []) subToParent.set(s.id, t.id);
  }
  const tactics: AttackTactic[] = file.tactics.map((ta) => ({
    id: ta.id,
    name: ta.name,
    techniques: ta.techniques.flatMap((id) => {
      const t = techniques.get(id);
      return t ? [t] : [];
    }),
  }));
  return { version: file.version, tactics, techniques, subToParent };
}

export function parseNamesOverlay(text: string): Map<string, string> {
  const file = NamesOverlaySchema.parse(parseYaml(text));
  return new Map(Object.entries(file.names));
}

const matrixText = firstText(matrixModules);
if (!matrixText) throw new Error('data/attack-matrix/enterprise-attack.yaml が見つかりません');

export const ATTACK_MATRIX: AttackMatrix = parseAttackMatrix(matrixText);

const jaText = firstText(jaModules);
/** 日本語名（ID 鍵）。訳ファイルが無い場合は空。 */
export const ATTACK_NAMES_JA: Map<string, string> = jaText ? parseNamesOverlay(jaText) : new Map();

/** マトリクス内のすべての ID（戦術・テクニック・サブ）の英語名。 */
export function englishName(id: string): string | undefined {
  const m = ATTACK_MATRIX;
  const tactic = m.tactics.find((t) => t.id === id);
  if (tactic) return tactic.name;
  const tech = m.techniques.get(id);
  if (tech) return tech.name;
  const parent = m.subToParent.get(id);
  return parent ? m.techniques.get(parent)?.subtechniques.find((s) => s.id === id)?.name : undefined;
}

/** 表示名。ja は訳、なければ英語。en は英語。ID が不明なら ID をそのまま返す。 */
export function localizedName(id: string, locale: Locale): string {
  if (locale === 'ja') {
    const ja = ATTACK_NAMES_JA.get(id);
    if (ja) return ja;
  }
  return englishName(id) ?? id;
}
