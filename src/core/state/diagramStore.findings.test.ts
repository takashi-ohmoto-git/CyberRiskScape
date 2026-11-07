import { beforeEach, describe, expect, it } from 'vitest';
import { useDiagramStore } from './diagramStore';
import type { Finding } from '../model/types';

const F: Finding = {
  id: 'p:1',
  source: { product: 'p', format: 'security-audit' },
  externalId: '1',
  identifiers: [],
  severity: 'High',
  canonicalIds: [],
} as unknown as Finding;

beforeEach(() => {
  useDiagramStore.setState({ findings: [], past: [], future: [] });
});

describe('setFindings', () => {
  it('指摘を差し替え、Undo 履歴には積まない', () => {
    useDiagramStore.getState().setFindings([F]);
    expect(useDiagramStore.getState().findings).toEqual([F]);
    expect(useDiagramStore.getState().past).toHaveLength(0);
    useDiagramStore.getState().setFindings([]);
    expect(useDiagramStore.getState().findings).toEqual([]);
  });
});
