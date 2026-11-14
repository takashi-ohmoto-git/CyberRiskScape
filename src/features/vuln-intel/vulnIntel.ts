import { identifierValues } from '../../core/model/identifierSchemes';
import {
  MAX_VULN_INTEL,
  type Finding,
  type FindingEpss,
  type FindingKev,
  type VulnIntel,
  type VulnIntelEntry,
} from '../../core/model/types';

/**
 * CVE ごとの付加情報（KEV・EPSS）の保持と、指摘への付け直し（docs/common-data-model.md §7.2 D）。
 *
 * KEV・EPSS は指摘（`kev`・`epss`）に付けて使うが、指摘は取り込み直すと製品×範囲の単位で丸ごと置き換わる
 * ので、そこにしか無いと印が消える。照合した結果を CVE をキーにプロジェクト直下（`vulnIntel`）にも持ち、
 * 保存データを読み込むときに指摘へ付け直す。持つのはプロジェクトの指摘に当たった CVE の分だけ
 * （カタログ全体は持たない）。
 */

type IntelKind = keyof VulnIntelEntry;

/** `kind` の情報を入れ替える。ほかの種類の情報は残し、空になった CVE は除く。上限を超えた分は入れない。 */
function replaceKind<K extends IntelKind>(
  prev: VulnIntel | undefined,
  kind: K,
  hits: ReadonlyMap<string, NonNullable<VulnIntelEntry[K]>>,
): VulnIntel | undefined {
  const next: VulnIntel = {};
  for (const [cve, entry] of Object.entries(prev ?? {})) {
    const { [kind]: _dropped, ...rest } = entry;
    if (Object.keys(rest).length > 0) next[cve] = rest;
  }
  for (const [cve, value] of hits) {
    if (!(cve in next) && Object.keys(next).length >= MAX_VULN_INTEL) continue;
    next[cve] = { ...next[cve], [kind]: value };
  }
  return Object.keys(next).length > 0 ? next : undefined;
}

/** 指摘が持つ CVE のうち、`lookup` に載っているものを集める。 */
function hitsOf<T>(findings: readonly Finding[], lookup: (cve: string) => T | undefined): Map<string, T> {
  const hits = new Map<string, T>();
  for (const f of findings) {
    for (const cve of identifierValues(f.identifiers, 'cve')) {
      if (hits.has(cve)) continue;
      const hit = lookup(cve);
      if (hit !== undefined) hits.set(cve, hit);
    }
  }
  return hits;
}

/** KEV の照合結果を記録する。前回の KEV の記録は今回の結果で入れ替える（カタログから外れた CVE は消える）。 */
export function recordKev(
  prev: VulnIntel | undefined,
  findings: readonly Finding[],
  entries: ReadonlyMap<string, FindingKev>,
): VulnIntel | undefined {
  return replaceKind(prev, 'kev', hitsOf(findings, (cve) => entries.get(cve)));
}

/** EPSS の照合結果を記録する。前回の EPSS の記録は今回の結果で入れ替える。 */
export function recordEpss(
  prev: VulnIntel | undefined,
  findings: readonly Finding[],
  scores: ReadonlyMap<string, { score: number; percentile?: number }>,
  date?: string,
): VulnIntel | undefined {
  const hits = hitsOf(findings, (cve): FindingEpss | undefined => {
    const s = scores.get(cve);
    return s ? { score: s.score, ...(s.percentile !== undefined ? { percentile: s.percentile } : {}), ...(date ? { date } : {}) } : undefined;
  });
  return replaceKind(prev, 'epss', hits);
}

/**
 * 記録してある KEV・EPSS を指摘へ付け直す。記録に載っている CVE を持つ指摘だけを触り、記録の値を優先する
 * （CVE が複数なら、KEV は最初に当たったもの、EPSS は最大の score）。記録に無い CVE の指摘はそのまま
 * （診断ツールが自分で付けた EPSS などは消さない）。何も変わらなければ同じ配列を返す。
 */
export function applyVulnIntel<F extends Finding>(findings: readonly F[], intel: VulnIntel | undefined): readonly F[] {
  if (!intel) return findings;
  let changed = false;
  const out = findings.map((f) => {
    let kev: FindingKev | undefined;
    let epss: FindingEpss | undefined;
    for (const cve of identifierValues(f.identifiers, 'cve')) {
      const entry = Object.hasOwn(intel, cve) ? intel[cve] : undefined;
      if (!entry) continue;
      kev ??= entry.kev;
      if (entry.epss && (!epss || entry.epss.score > epss.score)) epss = entry.epss;
    }
    if (!kev && !epss) return f;
    changed = true;
    return { ...f, ...(kev ? { kev } : {}), ...(epss ? { epss } : {}) };
  });
  return changed ? out : findings;
}
