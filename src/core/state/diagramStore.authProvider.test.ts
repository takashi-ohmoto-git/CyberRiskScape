import { beforeEach, describe, expect, it } from 'vitest';
import { selectActiveEdges, selectActiveNodes, useDiagramStore } from './diagramStore';
import { EMPTY_LAYER, type DiagramEdge, type DiagramNode, type LayerData } from '../model/types';

/** 各テスト前に空レイヤー + カウンタ 0 の既知状態へリセット（module singleton 対策）。 */
beforeEach(() => {
  useDiagramStore.setState({
    layers: {
      L0: EMPTY_LAYER,
      L1: { nodes: [], edges: [], boundaries: [], annotations: [] },
      L2: EMPTY_LAYER,
      L3: EMPTY_LAYER,
    },
    activeLayer: 'L1',
    idCounters: {
      L0: { node: 0, edge: 0, boundary: 0 },
      L1: { node: 0, edge: 0, boundary: 0 },
      L2: { node: 0, edge: 0, boundary: 0 },
      L3: { node: 0, edge: 0, boundary: 0 },
    },
    selectedNodeIds: [],
    selectedEdgeId: null,
    selectedBoundaryIds: [],
    linkingFromId: null,
    past: [],
    future: [],
    _dragArmed: false,
    _commitTag: null,
  });
});

const nodes = () => selectActiveNodes(useDiagramStore.getState());
const edges = () => selectActiveEdges(useDiagramStore.getState());

/** app → api のエッジ 1 本と IdP ノードを置いた既知のレイヤーを組む。 */
function seedLayer(authProviderId?: string): { app: DiagramNode; idp: DiagramNode } {
  const app: DiagramNode = { id: 'n-app', type: 'PROCESS', x: 0, y: 0 };
  const api: DiagramNode = { id: 'n-api', type: 'PROCESS', x: 200, y: 0 };
  const idp: DiagramNode = { id: 'n-idp', type: 'IDENTITY_PROVIDER', x: 0, y: 200 };
  const edge: DiagramEdge = {
    id: 'e1',
    source: app.id,
    target: api.id,
    auth: 'MFA',
    network: 'VPC',
    encryption: 'TLS',
    ...(authProviderId ? { authProviderId } : {}),
  };
  useDiagramStore.setState((s) => ({
    layers: { ...s.layers, L1: { nodes: [app, api, idp], edges: [edge], boundaries: [], annotations: [] } },
  }));
  return { app, idp };
}

describe('authProviderId の参照整合性', () => {
  it('発行元の IdP ノードを削除するとエッジの authProviderId が解除される', () => {
    const { idp } = seedLayer('n-idp');
    expect(edges()[0].authProviderId).toBe('n-idp');

    useDiagramStore.getState().deleteNode(idp.id);
    expect(nodes()).toHaveLength(2);
    expect(edges()).toHaveLength(1);
    expect(edges()[0].authProviderId).toBeUndefined();
  });

  it('無関係なノードの削除では authProviderId を保持する', () => {
    const { app } = seedLayer('n-idp');
    useDiagramStore.getState().deleteNode(app.id);
    expect(edges()[0].authProviderId).toBe('n-idp');
  });

  it('テンプレート取込時に authProviderId を新 ID へ付け替える', () => {
    const template: LayerData = {
      nodes: [
        { id: 'old-app', type: 'PROCESS', x: 0, y: 0 },
        { id: 'old-api', type: 'PROCESS', x: 200, y: 0 },
        { id: 'old-idp', type: 'IDENTITY_PROVIDER', x: 0, y: 200 },
      ],
      edges: [
        {
          id: 'old-e1',
          source: 'old-app',
          target: 'old-api',
          auth: 'MFA',
          network: 'VPC',
          encryption: 'TLS',
          authProviderId: 'old-idp',
        },
      ],
      boundaries: [], annotations: [],
    };
    useDiagramStore.getState().importTemplateToActiveLayer(template);
    const idp = nodes().find((n) => n.type === 'IDENTITY_PROVIDER');
    expect(edges()[0].authProviderId).toBe(idp?.id);
    expect(edges()[0].authProviderId).not.toBe('old-idp');
  });

  it('テンプレート外を指す authProviderId は取込時に解除される', () => {
    const template: LayerData = {
      nodes: [
        { id: 'old-app', type: 'PROCESS', x: 0, y: 0 },
        { id: 'old-api', type: 'PROCESS', x: 200, y: 0 },
      ],
      edges: [
        {
          id: 'old-e1',
          source: 'old-app',
          target: 'old-api',
          auth: 'MFA',
          network: 'VPC',
          encryption: 'TLS',
          authProviderId: 'not-in-template',
        },
      ],
      boundaries: [], annotations: [],
    };
    useDiagramStore.getState().importTemplateToActiveLayer(template);
    expect(edges()[0].authProviderId).toBeUndefined();
  });
});

describe('ノード側 authProviderId の参照整合性（[[plan]] §2.42）', () => {
  /** ドメイン参加サーバ（エッジを持たない）と IdP を置く。 */
  function seedNodeDeclaration(): { srv: DiagramNode; idp: DiagramNode } {
    const srv: DiagramNode = {
      id: 'n-srv',
      type: 'FRONT_END_SERVER',
      x: 0,
      y: 0,
      authProviderId: 'n-idp',
    };
    const idp: DiagramNode = { id: 'n-idp', type: 'IDENTITY_PROVIDER', x: 200, y: 0 };
    useDiagramStore.setState((s) => ({
      layers: { ...s.layers, L1: { nodes: [srv, idp], edges: [], boundaries: [], annotations: [] } },
    }));
    return { srv, idp };
  }

  it('発行元ノードを削除するとノードの authProviderId が解除される', () => {
    const { idp } = seedNodeDeclaration();
    useDiagramStore.getState().deleteNode(idp.id);
    expect(nodes()).toHaveLength(1);
    expect(nodes()[0].authProviderId).toBeUndefined();
  });

  it('無関係なノードの削除では保持する', () => {
    seedNodeDeclaration();
    useDiagramStore.setState((s) => ({
      layers: {
        ...s.layers,
        L1: {
          ...s.layers.L1,
          nodes: [...s.layers.L1.nodes, { id: 'n-other', type: 'PROCESS', x: 400, y: 0 }],
        },
      },
    }));
    useDiagramStore.getState().deleteNode('n-other');
    expect(nodes().find((n) => n.id === 'n-srv')?.authProviderId).toBe('n-idp');
  });

  it('テンプレート取込で新しい ID へ付け替えられる', () => {
    const template: LayerData = {
      nodes: [
        { id: 'old-srv', type: 'FRONT_END_SERVER', x: 0, y: 0, authProviderId: 'old-idp' },
        { id: 'old-idp', type: 'IDENTITY_PROVIDER', x: 200, y: 0 },
      ],
      edges: [],
      boundaries: [], annotations: [],
    };
    useDiagramStore.getState().importTemplateToActiveLayer(template);
    const idp = nodes().find((n) => n.type === 'IDENTITY_PROVIDER');
    const srv = nodes().find((n) => n.type === 'FRONT_END_SERVER');
    expect(srv?.authProviderId).toBe(idp?.id);
    expect(srv?.authProviderId).not.toBe('old-idp');
  });

  it('テンプレート外を指す authProviderId は取込時に解除される', () => {
    const template: LayerData = {
      nodes: [{ id: 'old-srv', type: 'FRONT_END_SERVER', x: 0, y: 0, authProviderId: 'nope' }],
      edges: [],
      boundaries: [], annotations: [],
    };
    useDiagramStore.getState().importTemplateToActiveLayer(template);
    expect(nodes()[0].authProviderId).toBeUndefined();
  });
});
