import { describe, expect, it } from 'vitest';
import { deserializeProject } from '../features/persistence/serialize';
import type { PersistedProject } from '../features/persistence/schema';
import { applyBusinessContextTool, assertOnlyBusinessContextChanged, MCP_MAX_BUSINESS_CONTEXT_ROWS } from './businessContext';

const empty = { nodes: [], edges: [], boundaries: [] };
const project = (): PersistedProject =>
  deserializeProject({
    schemaVersion: 1,
    activeLayer: 'L1',
    idCounters: { L0: { node: 0, edge: 0, boundary: 0 }, L1: { node: 2, edge: 1, boundary: 0 }, L2: { node: 0, edge: 0, boundary: 0 }, L3: { node: 0, edge: 0, boundary: 0 } },
    activeFramework: 'ALL',
    projectMeta: { name: 't', systemName: 's', purpose: '', businessImpact: '', securityObjectives: '' },
    updatedAt: 0,
    layers: {
      L0: empty,
      L1: {
        nodes: [
          { id: 'n-erp', seq: 1, type: 'BACKEND_API', x: 0, y: 0, label: '基幹' },
          { id: 'n-crm', seq: 2, type: 'CRM', x: 100, y: 0, label: 'CRM' },
        ],
        edges: [{ id: 'e1', seq: 1, source: 'n-erp', target: 'n-crm', auth: 'Token', network: 'Internet', encryption: 'TLS' }],
        boundaries: [],
      },
      L2: empty,
      L3: empty,
    },
  })!;

describe('applyBusinessContextTool', () => {
  it('行から業務の文脈を置き換え、重要度の前後を changes に返す', () => {
    const r = applyBusinessContextTool(project(), {
      rows: [{ node: 'C1', process: 'P2P', criticality: 'High' }],
      source: { product: 'Celonis via MCP' },
    });
    expect(r.changes).toEqual([{ nodeId: 'n-erp', layer: 'L1', elementalId: 'C1', label: '基幹', after: 'High' }]);
    const erp = r.project.layers!.L1.nodes.find((n) => n.id === 'n-erp')!;
    expect(erp.businessContext?.source?.product).toBe('Celonis via MCP');
    expect(() => assertOnlyBusinessContextChanged(project(), r.project)).not.toThrow();
  });

  it('source の申告が無ければ product は mcp-agent', () => {
    const r = applyBusinessContextTool(project(), { rows: [{ node: 'n-crm', process: 'O2C', criticality: 'Low' }] });
    expect(r.project.layers!.L1.nodes.find((n) => n.id === 'n-crm')!.businessContext?.source?.product).toBe('mcp-agent');
  });

  it('行が 0 件・上限超え・不正な値は失敗する', () => {
    expect(() => applyBusinessContextTool(project(), { rows: [] })).toThrow();
    const many = Array.from({ length: MCP_MAX_BUSINESS_CONTEXT_ROWS + 1 }, () => ({ node: 'C1', process: 'x', cases: 1 }));
    expect(() => applyBusinessContextTool(project(), { rows: many })).toThrow();
    expect(() => applyBusinessContextTool(project(), { rows: [{ node: 'C1', process: 'x', cases: 'many' }] })).toThrow();
  });
});

describe('assertOnlyBusinessContextChanged', () => {
  it('業務の文脈以外（ノードのラベル・線・判断系）が変わったら止める', () => {
    const base = project();
    const label = structuredClone(base);
    label.layers!.L1.nodes[0].label = '別名';
    expect(() => assertOnlyBusinessContextChanged(base, label)).toThrow();
    const edge = structuredClone(base);
    edge.layers!.L1.edges[0].auth = 'None';
    expect(() => assertOnlyBusinessContextChanged(base, edge)).toThrow();
    const meta = structuredClone(base);
    meta.projectMeta = { ...meta.projectMeta!, name: '変更' };
    expect(() => assertOnlyBusinessContextChanged(base, meta)).toThrow();
  });
});
