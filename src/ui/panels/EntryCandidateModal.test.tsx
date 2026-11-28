import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { EntryCandidateModalBody } from './EntryCandidateModal';
import type { EntryCandidate } from '../../features/attack-tree/findEntryPoints';
import type { EntrySurfaceDetail } from '../../features/attack-tree/entrySurfaces';

const candidate = (over: Partial<EntryCandidate> = {}): EntryCandidate => ({
  nodeId: 'n1',
  rank: 1,
  reasons: ['publicSurface'],
  weaknesses: ['noWaf'],
  assumed: false,
  threatCount: 2,
  maxSeverity: 'High',
  surfaces: [{ id: 'fileUpload', threatIds: ['t1'], canonicalIds: ['c1'] }],
  outcomes: ['rce'],
  ...over,
});

const details: EntrySurfaceDetail[] = [
  {
    id: 'fileUpload',
    outcomes: ['rce'],
    threats: [{ id: 't1', name: '架空のアップロード脅威', severity: 'High' }],
  },
];

const render = (c: EntryCandidate, d: EntrySurfaceDetail[]) =>
  renderToStaticMarkup(<EntryCandidateModalBody title="C6 受注 API" candidate={c} details={d} />);

describe('EntryCandidateModalBody', () => {
  it('面がある候補 → 題名・順位・弱点・面・届き得る先・根拠の脅威と重大度を表示する', () => {
    const html = render(candidate(), details);
    expect(html).toContain('C6 受注 API');
    expect(html).toContain('#1');
    expect(html).toContain('WAF');
    expect(html).toContain('ファイルアップロード');
    expect(html).toContain('架空のアップロード脅威');
    expect(html).toContain('High');
    expect(html).toContain('<table');
  });

  it('assumed の候補 → 順位に * が付き、仮定の注記を表示する', () => {
    const html = render(candidate({ assumed: true }), details);
    expect(html).toContain('#1*');
    expect(html).toContain('未入力の属性を悪い値と仮定した判定を含みます');
  });

  it('assumed でない候補 → 仮定の注記を出さない', () => {
    const html = render(candidate(), details);
    expect(html).not.toContain('#1*');
    expect(html).not.toContain('未入力の属性を悪い値と仮定した判定を含みます');
  });

  it('面が無い候補 → 当たる脅威が無い旨を表示し、表を出さない', () => {
    const html = render(candidate({ surfaces: [], outcomes: [] }), []);
    expect(html).toContain('高価値の面に当たる脅威はありません。');
    expect(html).not.toContain('<table');
  });
});
