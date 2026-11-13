import { csvRow } from '../export/threatReport';
import { OBJECT_TYPE, type EventLog } from './buildEventLog';

/**
 * 脅威を案件（case）とする平らなイベントログ CSV。脅威に関連するイベントだけを 1 行ずつ出す
 * （指摘・構成要素だけのイベントは対象外。それらは OCEL 側）。UTF-8・CRLF。BOM は呼び出し側で付ける。
 */

export const EVENT_CSV_COLUMNS = [
  'case_id',
  'activity',
  'timestamp',
  'resource',
  'severity',
  'rule_id',
  'canonical_id',
  'threat_name',
  'element',
  'element_label',
  'element_type',
  'layer',
  'status',
  'note',
  'commit',
  'commit_message',
] as const;

/** 表計算ソフトが式として解釈する先頭文字（CSV インジェクション）を無害にする。 */
function guard(v: string): string {
  return /^[=+\-@\t\r]/.test(v) ? `'${v}` : v;
}

export function toEventCsv(log: EventLog): string {
  const threats = new Map(
    log.objects
      .filter((o) => o.type === OBJECT_TYPE.threat)
      .map((o) => [o.id, new Map(o.attributes.map((a) => [a.name, String(a.value)] as const))] as const),
  );
  const rows: string[] = [csvRow([...EVENT_CSV_COLUMNS])];
  for (const e of log.events) {
    const a = (k: string) => String(e.attributes[k] ?? '');
    for (const rel of e.relations) {
      const t = threats.get(rel.objectId);
      if (!t) continue;
      const o = (k: string) => t.get(k) ?? '';
      rows.push(
        csvRow(
          [
            rel.objectId,
            e.activity,
            e.time,
            a('resource'),
            a('severity'),
            o('rule_id'),
            o('canonical_id'),
            o('name'),
            o('element_id'),
            o('element_label'),
            o('element_type'),
            o('layer'),
            a('status'),
            a('note'),
            a('commit'),
            a('commit_message'),
          ].map(guard),
        ),
      );
    }
  }
  return rows.join('\r\n') + '\r\n';
}
