import { LAYER_KEYS, type BusinessCriticality } from '../core/model/types';
import { resolveLayers } from '../features/persistence/serialize';
import type { PersistedProject } from '../features/persistence/schema';
import type { ApplyBusinessContextSummary } from '../features/business-context/applyBusinessContext';
import {
  BUSINESS_CONTEXT_KIND,
  parseBusinessContextTable,
} from '../features/business-context/parseBusinessContextTable';
import { importBusinessContext } from '../cli/importBusinessContext';

/**
 * MCP の `apply_business_context` の純粋部分。業務の文脈の共通の表（行の配列）を受け、
 * CLI の import-business-context と同じ処理でノードの businessContext を置き換える。
 * 検証は表の取り込みと同じ（JSON の表として parseBusinessContextTable に通す）。
 * 書き込み前に「businessContext 以外は何も変わっていない」ことを検査する（多層防御）。
 */

/** 1 回の呼び出しで受け付ける行の上限（エージェントの入力として十分な数に絞る）。 */
export const MCP_MAX_BUSINESS_CONTEXT_ROWS = 1000;

/** source.product の既定（エージェントが申告しないとき）。 */
export const MCP_BUSINESS_CONTEXT_PRODUCT = 'mcp-agent';

export class BusinessContextToolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BusinessContextToolError';
  }
}

export interface CriticalityChange {
  nodeId: string;
  layer: string;
  elementalId?: string;
  label?: string;
  before?: BusinessCriticality;
  after: BusinessCriticality;
}

export interface ApplyBusinessContextToolResult {
  project: PersistedProject;
  summary: ApplyBusinessContextSummary;
  changes: CriticalityChange[];
}

type AnyNode = { id: string; seq?: number; label?: string; businessContext?: { criticality: BusinessCriticality } };

const withoutContext = (layers: ReturnType<typeof resolveLayers>['layers']): string =>
  JSON.stringify(
    LAYER_KEYS.map((k) => {
      const l = layers[k];
      return {
        ...l,
        nodes: l.nodes.map((n) => {
          const { businessContext: _ignored, ...rest } = n;
          return rest;
        }),
      };
    }),
  );

/** businessContext 以外（判断系・ノードの他の項目・線・境界・注釈）が変わっていないことを確かめる。 */
export function assertOnlyBusinessContextChanged(before: PersistedProject, after: PersistedProject): void {
  const { layers: _b, ...restBefore } = before;
  const { layers: _a, ...restAfter } = after;
  if (JSON.stringify(restBefore) !== JSON.stringify(restAfter)) {
    throw new BusinessContextToolError('内部検査エラー：業務の文脈以外の項目が変化したため書き込みを中止しました。');
  }
  if (withoutContext(resolveLayers(before).layers) !== withoutContext(resolveLayers(after).layers)) {
    throw new BusinessContextToolError('内部検査エラー：ノードの業務の文脈以外が変化したため書き込みを中止しました。');
  }
}

export function applyBusinessContextTool(
  raw: unknown,
  input: { rows: unknown[]; source?: { product?: string; ref?: string } },
  now: Date = new Date(),
): ApplyBusinessContextToolResult {
  if (input.rows.length === 0) throw new BusinessContextToolError('rows を 1 行以上指定してください。');
  if (input.rows.length > MCP_MAX_BUSINESS_CONTEXT_ROWS) {
    throw new BusinessContextToolError(`rows は ${MCP_MAX_BUSINESS_CONTEXT_ROWS} 行までです。`);
  }
  const source = { product: input.source?.product ?? MCP_BUSINESS_CONTEXT_PRODUCT, ...(input.source?.ref ? { ref: input.source.ref } : {}) };
  const parsed = parseBusinessContextTable(
    JSON.stringify({ kind: BUSINESS_CONTEXT_KIND, schemaVersion: 1, source, rows: input.rows }),
    'rows.json',
  );
  if (!parsed.ok) throw new BusinessContextToolError(parsed.error);

  let out;
  try {
    out = importBusinessContext(raw, parsed, now);
  } catch (e) {
    throw new BusinessContextToolError(e instanceof Error ? e.message : String(e));
  }

  const beforeLayers = resolveLayers(raw as PersistedProject).layers;
  const changes: CriticalityChange[] = out.summary.applied.map((a) => {
    const prev = (beforeLayers[a.layer].nodes as AnyNode[]).find((n) => n.id === a.nodeId)?.businessContext?.criticality;
    return {
      nodeId: a.nodeId,
      layer: a.layer,
      ...(a.seq !== undefined ? { elementalId: `C${a.seq}` } : {}),
      ...(a.label ? { label: a.label } : {}),
      ...(prev ? { before: prev } : {}),
      after: a.criticality,
    };
  });
  return { project: out.project, summary: out.summary, changes };
}
