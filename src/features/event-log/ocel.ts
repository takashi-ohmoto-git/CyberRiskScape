import { z } from 'zod';
import type { EventLog } from './buildEventLog';

/**
 * OCEL 2.0 JSON（https://www.ocel-standard.org/specification/formats/json/ 、2026-11-13 確認）への書き出し。
 * 公式の JSON Schema が見つからなかったため、仕様の構造（objectTypes・eventTypes・objects・events）と
 * 参照の整合（型の宣言・オブジェクトの存在・ID の一意・イベントは 1 件以上のオブジェクトに関連）を
 * この Zod スキーマで確かめる。
 */

const AttrTypeSchema = z.enum(['string', 'time', 'integer', 'float', 'boolean']);
const AttrDefSchema = z.object({ name: z.string().min(1), type: AttrTypeSchema });
const TypeDefSchema = z.object({ name: z.string().min(1), attributes: z.array(AttrDefSchema) });
const ValueSchema = z.union([z.string(), z.number(), z.boolean()]);
const RelationSchema = z.object({ objectId: z.string().min(1), qualifier: z.string() });
const TimeSchema = z.string().refine((v) => !Number.isNaN(Date.parse(v)), '時刻が不正です');

export const OcelLogSchema = z
  .object({
    objectTypes: z.array(TypeDefSchema),
    eventTypes: z.array(TypeDefSchema),
    objects: z.array(
      z.object({
        id: z.string().min(1),
        type: z.string(),
        attributes: z.array(z.object({ name: z.string(), time: TimeSchema, value: ValueSchema })),
        relationships: z.array(RelationSchema),
      }),
    ),
    events: z.array(
      z.object({
        id: z.string().min(1),
        type: z.string(),
        time: TimeSchema,
        attributes: z.array(z.object({ name: z.string(), value: ValueSchema })),
        relationships: z.array(RelationSchema),
      }),
    ),
  })
  .superRefine((log, ctx) => {
    const issue = (message: string) => ctx.addIssue({ code: 'custom', message });
    const objectTypes = new Map(log.objectTypes.map((t) => [t.name, new Set(t.attributes.map((a) => a.name))]));
    const eventTypes = new Map(log.eventTypes.map((t) => [t.name, new Set(t.attributes.map((a) => a.name))]));
    const objectIds = new Set<string>();
    for (const o of log.objects) {
      if (objectIds.has(o.id)) issue(`オブジェクト ID が重複しています: ${o.id}`);
      objectIds.add(o.id);
      const declared = objectTypes.get(o.type);
      if (!declared) issue(`宣言されていないオブジェクト型です: ${o.type}`);
      else for (const a of o.attributes) if (!declared.has(a.name)) issue(`宣言されていない属性です: ${o.type}.${a.name}`);
    }
    const eventIds = new Set<string>();
    for (const e of log.events) {
      if (eventIds.has(e.id)) issue(`イベント ID が重複しています: ${e.id}`);
      eventIds.add(e.id);
      const declared = eventTypes.get(e.type);
      if (!declared) issue(`宣言されていないイベント型です: ${e.type}`);
      else for (const a of e.attributes) if (!declared.has(a.name)) issue(`宣言されていない属性です: ${e.type}.${a.name}`);
      if (e.relationships.length === 0) issue(`オブジェクトに関連しないイベントです: ${e.id}`);
      for (const r of e.relationships) if (!objectIds.has(r.objectId)) issue(`存在しないオブジェクトを参照しています: ${e.id} → ${r.objectId}`);
    }
    for (const o of log.objects) {
      for (const r of o.relationships) if (!objectIds.has(r.objectId)) issue(`存在しないオブジェクトを参照しています: ${o.id} → ${r.objectId}`);
    }
  });

export type OcelLog = z.infer<typeof OcelLogSchema>;

export function toOcelJson(log: EventLog): OcelLog {
  return {
    objectTypes: log.objectTypes,
    eventTypes: log.eventTypes,
    objects: log.objects.map((o) => ({
      id: o.id,
      type: o.type,
      attributes: o.attributes,
      relationships: o.relations,
    })),
    events: log.events.map((e) => ({
      id: e.id,
      type: e.activity,
      time: e.time,
      attributes: Object.entries(e.attributes).map(([name, value]) => ({ name, value })),
      relationships: e.relations,
    })),
  };
}
