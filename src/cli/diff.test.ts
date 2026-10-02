import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { diffProjects, diffToJson, diffToMarkdown, evaluateDiffGate } from './diff';
import { analyzeProject } from './analyze';
import { serializeProject } from '../features/persistence/serialize';
import { EMPTY_LAYER, type LayerData, type LayerKey } from '../core/model/types';
import type { ChangeTrigger } from '../change-triggers/schema/trigger';
import { setLocale } from '../i18n';
import { BUNDLED_CHANGE_TRIGGERS } from '../change-triggers/loader/bundledChangeTriggers';

const BASE_FIXTURE_PATH = new URL('./__fixtures__/sample-project.json', import.meta.url);
const CHANGED_FIXTURE_PATH = new URL('./__fixtures__/sample-project-changed.json', import.meta.url);

function layers(l1: LayerData): Record<LayerKey, LayerData> {
  return { L0: EMPTY_LAYER, L1: l1, L2: EMPTY_LAYER, L3: EMPTY_LAYER };
}

/** LLM → DB の最小プロジェクト（base）。 */
function baseLayers(): Record<LayerKey, LayerData> {
  return layers({
    nodes: [
      { id: 'n1', seq: 1, type: 'LLM', x: 0, y: 0, label: 'GPT' },
      { id: 'n2', seq: 2, type: 'DB', x: 100, y: 0, label: 'Store' },
    ],
    edges: [
      { id: 'e1', seq: 1, source: 'n1', target: 'n2', auth: 'None', network: 'Internet', encryption: 'Plain' },
    ],
    boundaries: [],
    annotations: [],
  });
}

function rawFrom(l: Record<LayerKey, LayerData>, extra: Partial<Parameters<typeof serializeProject>[0]> = {}): unknown {
  return serializeProject({ layers: l, activeLayer: 'L1', activeFramework: 'ALL', ...extra });
}

const NO_TRIGGERS: ChangeTrigger[] = [];

describe('diffProjects', () => {
  it('変更がなければ added/removed/suppressionChanged/severityChanged は空', () => {
    const raw = rawFrom(baseLayers());
    const diff = diffProjects(raw, raw, { triggers: NO_TRIGGERS });
    expect(diff.added).toEqual([]);
    expect(diff.removed).toEqual([]);
    expect(diff.suppressionChanged).toEqual([]);
    expect(diff.severityChanged).toEqual([]);
  });

  it('ノード追加で新規に成立した脅威を added に含める', () => {
    const base = baseLayers();
    const head = layers({
      ...base.L1,
      nodes: [...base.L1.nodes, { id: 'n3', seq: 3, type: 'AGENT', x: 200, y: 0, label: 'Agent' }],
    });
    const diff = diffProjects(rawFrom(base), rawFrom(head), { triggers: NO_TRIGGERS });
    expect(diff.added.length).toBeGreaterThan(0);
    expect(diff.added.every((a) => a.layer === 'L1')).toBe(true);
    expect(diff.removed).toEqual([]);
  });

  it('ノード削除で脅威が消えると removed に含める', () => {
    const base = baseLayers();
    const head = layers({ ...base.L1, nodes: [base.L1.nodes[0]], edges: [] });
    const diff = diffProjects(rawFrom(base), rawFrom(head), { triggers: NO_TRIGGERS });
    expect(diff.removed.length).toBeGreaterThan(0);
  });

  it('追加と同時に受容された脅威も「要承認」に載せる（ゲート素通りを防ぐ）', () => {
    const base = baseLayers();
    const head = layers({
      ...base.L1,
      nodes: [...base.L1.nodes, { id: 'n3', seq: 3, type: 'AGENT', x: 200, y: 0, label: 'Agent' }],
    });
    const newId = diffProjects(rawFrom(base), rawFrom(head), { triggers: NO_TRIGGERS }).added[0].threat.id;
    const headRaw = rawFrom(head, { suppressions: { [newId]: { status: 'accepted', at: 0 } } });

    const diff = diffProjects(rawFrom(base), headRaw, { triggers: NO_TRIGGERS });
    const change = diff.suppressionChanged.find((c) => c.threat.id === newId);
    expect(change).toMatchObject({ before: undefined, after: 'accepted', needsApproval: true });
    expect(evaluateDiffGate(diff, 'Low').some((o) => o.threat.id === newId)).toBe(false);
  });

  it('suppressions の変更を検出し、受容/誤検知への変更は needsApproval=true にする', () => {
    const raw = rawFrom(baseLayers());
    // 共通の脅威 1 件を特定して、head 側だけ suppression を付与する。
    const threats = analyzeProject(raw, { layer: 'L1' })[0].threats;
    expect(threats.length).toBeGreaterThan(0);
    const targetId = threats[0].id;

    const headRaw = rawFrom(baseLayers(), {
      suppressions: { [targetId]: { status: 'accepted', at: 0 } },
    });

    const diff = diffProjects(raw, headRaw, { triggers: NO_TRIGGERS });
    const change = diff.suppressionChanged.find((c) => c.threat.id === targetId);
    expect(change).toBeDefined();
    expect(change?.before).toBeUndefined();
    expect(change?.after).toBe('accepted');
    expect(change?.needsApproval).toBe(true);
  });

  it('リスク評価による実効 severity の変化を検出する', () => {
    const raw = rawFrom(baseLayers());
    const threats = analyzeProject(raw, { layer: 'L1' })[0].threats;
    const target = threats.find((t) => t.severity !== 'Critical');
    expect(target).toBeDefined();

    const headRaw = rawFrom(baseLayers(), {
      riskScores: {
        [target!.id]: { damage: 3, affectedUsers: 3, reproducibility: 3, exploitability: 3, at: 0 },
      },
    });

    const diff = diffProjects(raw, headRaw, { triggers: NO_TRIGGERS });
    const change = diff.severityChanged.find((c) => c.threat.id === target!.id);
    expect(change).toBeDefined();
    expect(change?.after).toBe('Critical');
  });

  it('トリガーを渡すと triggerHits に根拠付きで反映される', () => {
    const base = baseLayers();
    const head = layers({
      ...base.L1,
      nodes: [...base.L1.nodes, { id: 'n3', seq: 3, type: 'AGENT', x: 200, y: 0, label: 'Agent' }],
    });
    const trigger: ChangeTrigger = {
      id: 'T7',
      title: 'エージェントの能力拡大',
      checkpoint: 'checkpoint',
      detect: [{ kind: 'node-added', nodeTypes: ['AGENT'] }],
    };
    const diff = diffProjects(rawFrom(base), rawFrom(head), { triggers: [trigger] });
    expect(diff.triggerHits).toHaveLength(1);
    expect(diff.triggerHits[0].triggerId).toBe('T7');
  });

  it('detect: [] のトリガーは常に manualCheckTriggers に含まれる', () => {
    const raw = rawFrom(baseLayers());
    const t4: ChangeTrigger = { id: 'T4', title: '新しい技術またはランタイム', checkpoint: 'checkpoint', detect: [] };
    const diff = diffProjects(raw, raw, { triggers: [t4] });
    expect(diff.manualCheckTriggers).toEqual([t4]);
    expect(diff.triggerHits).toEqual([]);
  });
});

describe('evaluateDiffGate', () => {
  it('新規・未抑制・しきい値以上の脅威のみを offender とする', () => {
    const base = baseLayers();
    const head = layers({
      ...base.L1,
      nodes: [...base.L1.nodes, { id: 'n3', seq: 3, type: 'AGENT', x: 200, y: 0, label: 'Agent' }],
    });
    const diff = diffProjects(rawFrom(base), rawFrom(head), { triggers: NO_TRIGGERS });
    const offendersLow = evaluateDiffGate(diff, 'Low');
    expect(offendersLow.length).toBe(diff.added.length);
  });

  it('既存の未対応脅威（removed/unchanged）はゲート対象にしない', () => {
    const raw = rawFrom(baseLayers());
    const diff = diffProjects(raw, raw, { triggers: NO_TRIGGERS });
    expect(evaluateDiffGate(diff, 'Low')).toEqual([]);
  });

  it('受容済みへの変更はゲートを落とさない（added ではないため対象外）', () => {
    const raw = rawFrom(baseLayers());
    const threats = analyzeProject(raw, { layer: 'L1' })[0].threats;
    const targetId = threats[0].id;
    const headRaw = rawFrom(baseLayers(), { suppressions: { [targetId]: { status: 'accepted', at: 0 } } });
    const diff = diffProjects(raw, headRaw, { triggers: NO_TRIGGERS });
    expect(evaluateDiffGate(diff, 'Low')).toEqual([]);
  });
});

describe('CI スモーク用フィクスチャ（sample-project-changed.json）', () => {
  it('base/head とも妥当で、T2・T3・T7 が検出され、受容済みへの対応方針変更を 1 件含む', () => {
    const baseRaw = JSON.parse(readFileSync(BASE_FIXTURE_PATH, 'utf-8'));
    const headRaw = JSON.parse(readFileSync(CHANGED_FIXTURE_PATH, 'utf-8'));
    const diff = diffProjects(baseRaw, headRaw, { triggers: BUNDLED_CHANGE_TRIGGERS.triggers });

    const hitIds = diff.triggerHits.map((h) => h.triggerId).sort();
    expect(hitIds).toEqual(['T2', 'T3', 'T7']);
    expect(diff.manualCheckTriggers.map((t) => t.id)).toEqual(['T4']);

    expect(diff.suppressionChanged).toHaveLength(1);
    expect(diff.suppressionChanged[0].after).toBe('accepted');
    expect(diff.suppressionChanged[0].needsApproval).toBe(true);

    expect(diff.added.length).toBeGreaterThan(0);
  });
});

describe('diffToMarkdown / diffToJson', () => {
  it('md は主要セクションの見出しを含む', () => {
    setLocale('ja');
    const raw = rawFrom(baseLayers());
    const diff = diffProjects(raw, raw, { triggers: NO_TRIGGERS });
    const md = diffToMarkdown(diff);
    expect(md).toContain('## 実行トリガー');
    expect(md).toContain('## 追加された脅威');
    expect(md).toContain('## 解消された脅威');
    expect(md).toContain('## 対応方針の変更');
    expect(md).toContain('## 実効severityの変化');
    expect(md).toContain('## ゲート判定');
    expect(md).toContain('未設定（--fail-on 省略）');
  });

  it('ゲート結果を渡すと PASS/FAIL を出す', () => {
    setLocale('ja');
    const raw = rawFrom(baseLayers());
    const diff = diffProjects(raw, raw, { triggers: NO_TRIGGERS });
    const md = diffToMarkdown(diff, { failOn: 'Critical', offenders: [] });
    expect(md).toContain('PASS');
  });

  it('json は gate / triggers / added 等のキーを持つ', () => {
    const raw = rawFrom(baseLayers());
    const diff = diffProjects(raw, raw, { triggers: NO_TRIGGERS });
    const json = JSON.parse(diffToJson(diff)) as Record<string, unknown>;
    expect(json.kind).toBe('cyberriskscape-model-diff');
    expect(json.gate).toBeNull();
    expect(Array.isArray(json.added)).toBe(true);
    expect(Array.isArray(json.triggers)).toBe(true);
  });
});
