import { describe, expect, it } from 'vitest';
import { fillPatchStatus } from './fillPatchStatus';
import { deserializeProject } from '../persistence/serialize';
import { cveFinding, makeProject } from '../../cli/__fixtures__/findingsPriorityProject';

function load(raw: object) {
  const p = deserializeProject(JSON.parse(JSON.stringify(raw)));
  if (!p) throw new Error('fixture invalid');
  return p;
}
const nodeOf = (p: ReturnType<typeof load>, id: string) => p.layers!.L1.nodes.find((n) => n.id === id)!;

describe('fillPatchStatus', () => {
  it('CVE 付きの指摘がある patch 対応ノードの未入力 → Missing にし、根拠の CVE を返す', () => {
    const r = fillPatchStatus(load(makeProject([cveFinding('f1', 'web', 'High', 'cve-2099-0002'), cveFinding('f2', 'web', 'Low', 'CVE-2099-0001')])));
    expect(nodeOf(r.project, 'web').posture?.patchStatus).toBe('Missing');
    expect(r.filled).toMatchObject([{ layer: 'L1', nodeId: 'web', cves: ['CVE-2099-0001', 'CVE-2099-0002'] }]);
  });

  it('入力済みの patchStatus → 上書きせず alreadySet に数える（UpToDate も保つ）', () => {
    const raw = makeProject([cveFinding('f1', 'web', 'High', 'CVE-2099-0001')]) as { layers: { L1: { nodes: { id: string; posture?: object }[] } } };
    raw.layers.L1.nodes.find((n) => n.id === 'web')!.posture = { patchStatus: 'UpToDate' };
    const r = fillPatchStatus(load(raw));
    expect(nodeOf(r.project, 'web').posture?.patchStatus).toBe('UpToDate');
    expect(r.filled).toEqual([]);
    expect(r.skipped.alreadySet).toBe(1);
  });

  it('patch グループを持たない型 → 書かず noPatchGroup に数える', () => {
    const r = fillPatchStatus(load(makeProject([cveFinding('f1', 'pii', 'High', 'CVE-2099-0001')])));
    expect(nodeOf(r.project, 'pii').posture).toBeUndefined();
    expect(r.skipped.noPatchGroup).toBe(1);
  });

  it('試行のみ・CVE なし・ノード未結合の指摘 → 根拠にしない（未結合は数える）', () => {
    const unbound = { ...cveFinding('f3', 'web', 'High', 'CVE-2099-0003'), subject: undefined };
    const noCve = { ...cveFinding('f4', 'web', 'High', 'x'), identifiers: [{ scheme: 'cwe', value: 'CWE-79' }] };
    const r = fillPatchStatus(load(makeProject([cveFinding('f1', 'web', 'High', 'CVE-2099-0001', { outcome: 'attempted' }), unbound, noCve])));
    expect(r.filled).toEqual([]);
    expect(r.skipped.unboundFindings).toBe(1);
    expect(nodeOf(r.project, 'web').posture?.patchStatus).toBeUndefined();
  });

  it('補完以外は変わらない → 指摘・他ノード・辺はそのまま', () => {
    const before = load(makeProject([cveFinding('f1', 'web', 'High', 'CVE-2099-0001')]));
    const r = fillPatchStatus(before);
    expect(r.project.findings).toEqual(before.findings);
    expect(nodeOf(r.project, 'mid')).toEqual(nodeOf(before, 'mid'));
    expect(r.project.layers!.L1.edges).toEqual(before.layers!.L1.edges);
  });
});
