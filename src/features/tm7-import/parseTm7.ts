import { XMLParser } from 'fast-xml-parser';

/**
 * Microsoft Threat Modeling Tool の .tm7（XML。DataContractSerializer の出力）を、
 * 図への変換に使う中間の形に読む。読み替えはしない（値は元の文字列のまま）。
 *
 * 公開仕様は無いため、形は TMT 7.3 で作成したファイル（形式 4.3）から確定した（docs §2.132）。
 * 要素の属性は、候補の値の一覧と選ばれた添字が要素ごとに埋め込まれているので、
 * 埋め込みのテンプレート（KnowledgeBase）は引かない。
 */

export interface Tm7Attribute {
  /** 画面での項目名（例: 'Provides Confidentiality'）。 */
  displayName: string;
  /** 内部名（例: 'providesConfidentiality'。GUID のこともある）。無ければ ''。 */
  name: string;
  /** 値の種類（'ListDisplayAttribute' 等。名前空間の接頭辞は外す）。 */
  kind: string;
  /** 解決した値。リストは選ばれた値。値なし（見出し）は undefined。 */
  value?: string;
  /** リストの場合の選ばれた添字（0 は既定の選択）。 */
  selectedIndex?: number;
}

export interface Tm7Element {
  guid: string;
  /** 'StencilEllipse' / 'StencilRectangle' / 'StencilParallelLines' / 'BorderBoundary' / 'Connector' / 'LineBoundary' 等。 */
  shape: string;
  genericTypeId: string;
  typeId: string;
  attributes: Tm7Attribute[];
  /** Borders 側（枠・図形）。 */
  left?: number;
  top?: number;
  width?: number;
  height?: number;
  /** Lines 側（線・線の形の境界）。 */
  sourceGuid?: string;
  targetGuid?: string;
  sourceX?: number;
  sourceY?: number;
  targetX?: number;
  targetY?: number;
  handleX?: number;
  handleY?: number;
}

export interface Tm7Surface {
  guid: string;
  header: string;
  borders: Tm7Element[];
  lines: Tm7Element[];
}

export interface Tm7Note {
  id: string;
  addedBy: string;
  date: string;
  message: string;
}

export interface Tm7Threat {
  /** 脅威の値の項目（Properties の中身も含めて平らにしたもの）。空の値は持たない。 */
  fields: Record<string, string>;
}

export interface Tm7Model {
  version: string;
  meta: Record<string, string>;
  surfaces: Tm7Surface[];
  notes: Tm7Note[];
  threats: Tm7Threat[];
}

export type ParseTm7Result = { ok: true; model: Tm7Model } | { ok: false; error: 'parse' | 'notTm7' };

/** 入力の上限（外部入力の防御）。 */
export const TM7_MAX_BYTES = 50 * 1024 * 1024;
const ELEMENTS_MAX = 20000;
const THREATS_MAX = 50000;

const REPEATED = new Set([
  'DrawingSurfaceModel',
  'KeyValueOfguidanyType',
  'anyType',
  'string',
  'Note',
  'KeyValueOfstringstring',
]);

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  removeNSPrefix: true,
  processEntities: false,
  htmlEntities: false,
  ignoreDeclaration: true,
  ignorePiTags: true,
  parseTagValue: false,
  parseAttributeValue: false,
  trimValues: false,
  isArray: (name) => REPEATED.has(name) || /^KeyValueOfstringThreat/.test(name),
});

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const arr = (v: unknown): unknown[] => (v === undefined || v === null ? [] : Array.isArray(v) ? v : [v]);

/** テキストを取り出す（`<x>a</x>` は 'a'、`<x i:type=".."">a</x>` は '#text'、空・nil は ''）。 */
function text(v: unknown): string {
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  if (isObj(v) && typeof v['#text'] === 'string') return v['#text'];
  if (isObj(v) && (typeof v['#text'] === 'number')) return String(v['#text']);
  return '';
}

function num(v: unknown): number | undefined {
  const s = text(v).trim();
  if (s === '') return undefined;
  const n = Number(s);
  return Number.isFinite(n) ? n : undefined;
}

const stripPrefix = (s: string): string => s.slice(s.indexOf(':') + 1);

function parseAttribute(raw: unknown): Tm7Attribute | undefined {
  if (!isObj(raw)) return undefined;
  const kind = stripPrefix(String(raw['@_type'] ?? ''));
  const displayName = text(raw.DisplayName);
  const name = text(raw.Name);
  const v = raw.Value;
  if (isObj(v) && 'string' in v) {
    const values = arr(v.string).map(text);
    const idx = num(raw.SelectedIndex) ?? 0;
    return { displayName, name, kind, value: values[idx], selectedIndex: idx };
  }
  if (isObj(v) && v['@_nil'] === 'true') return { displayName, name, kind };
  return { displayName, name, kind, value: text(v) };
}

function parseElement(raw: unknown): Tm7Element | undefined {
  if (!isObj(raw)) return undefined;
  const v = raw.Value;
  if (!isObj(v)) return undefined;
  const guid = text(v.Guid) || text(raw.Key);
  if (!guid) return undefined;
  const props = isObj(v.Properties) ? v.Properties : {};
  return {
    guid,
    shape: String(v['@_type'] ?? ''),
    genericTypeId: text(v.GenericTypeId),
    typeId: text(v.TypeId),
    attributes: arr(props.anyType).map(parseAttribute).filter((a): a is Tm7Attribute => !!a),
    left: num(v.Left),
    top: num(v.Top),
    width: num(v.Width),
    height: num(v.Height),
    sourceGuid: text(v.SourceGuid) || undefined,
    targetGuid: text(v.TargetGuid) || undefined,
    sourceX: num(v.SourceX),
    sourceY: num(v.SourceY),
    targetX: num(v.TargetX),
    targetY: num(v.TargetY),
    handleX: num(v.HandleX),
    handleY: num(v.HandleY),
  };
}

function parseThreat(raw: unknown): Tm7Threat | undefined {
  if (!isObj(raw) || !isObj(raw.Value)) return undefined;
  const fields: Record<string, string> = {};
  for (const [k, val] of Object.entries(raw.Value)) {
    if (k.startsWith('@_') || k === 'Properties') continue;
    const s = text(val);
    if (s !== '') fields[k] = s;
  }
  // Properties（Title・説明・独自テンプレートの項目）を後から重ねる。値の側が空のとき本体の項目が使われる。
  const props = isObj(raw.Value.Properties) ? raw.Value.Properties : {};
  for (const kv of arr(props.KeyValueOfstringstring)) {
    if (!isObj(kv)) continue;
    const key = text(kv.Key);
    const s = text(kv.Value);
    if (key && s !== '') fields[key] = s;
  }
  return { fields };
}

export function parseTm7(xml: string): ParseTm7Result {
  let doc: unknown;
  try {
    doc = parser.parse(xml);
  } catch {
    return { ok: false, error: 'parse' };
  }
  const root = isObj(doc) ? doc.ThreatModel : undefined;
  if (!isObj(root) || !isObj(root.DrawingSurfaceList)) return { ok: false, error: 'notTm7' };

  const surfaces: Tm7Surface[] = [];
  let elements = 0;
  for (const s of arr(root.DrawingSurfaceList.DrawingSurfaceModel)) {
    if (!isObj(s)) continue;
    const borders = arr(isObj(s.Borders) ? s.Borders.KeyValueOfguidanyType : undefined)
      .map(parseElement)
      .filter((e): e is Tm7Element => !!e);
    const lines = arr(isObj(s.Lines) ? s.Lines.KeyValueOfguidanyType : undefined)
      .map(parseElement)
      .filter((e): e is Tm7Element => !!e);
    elements += borders.length + lines.length;
    if (elements > ELEMENTS_MAX) return { ok: false, error: 'parse' };
    surfaces.push({ guid: text(s.Guid), header: text(s.Header), borders, lines });
  }

  const meta: Record<string, string> = {};
  if (isObj(root.MetaInformation)) {
    for (const [k, v] of Object.entries(root.MetaInformation)) {
      if (!k.startsWith('@_')) meta[k] = text(v);
    }
  }

  const notes: Tm7Note[] = arr(isObj(root.Notes) ? root.Notes.Note : undefined)
    .filter(isObj)
    .map((n) => ({ id: text(n.Id), addedBy: text(n.AddedBy), date: text(n.Date), message: text(n.Message) }));

  const threatsRoot = isObj(root.ThreatInstances) ? root.ThreatInstances : {};
  const threatEntries = Object.entries(threatsRoot)
    .filter(([k]) => /^KeyValueOfstringThreat/.test(k))
    .flatMap(([, v]) => arr(v));
  if (threatEntries.length > THREATS_MAX) return { ok: false, error: 'parse' };
  const threats = threatEntries.map(parseThreat).filter((t): t is Tm7Threat => !!t);

  return { ok: true, model: { version: text(root.Version), meta, surfaces, notes, threats } };
}
