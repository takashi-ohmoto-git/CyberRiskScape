import { describe, expect, it } from 'vitest';
import { BUNDLED_CHANGE_TRIGGERS, getChangeTriggers } from './bundledChangeTriggers';
import { componentRegistry } from '../../component-library/defaultRegistry';

/**
 * 同梱トリガー（`data/change-triggers/triggers.yaml`）の不変条件を検証する。
 *
 * - `fields`（node-changed / edge-changed / boundary-changed）が指す先は実在のフィールド名か。
 *   型定義（`src/core/model/types.ts`）から読み手が検証できる小さな allowlist をここに持つ
 *   （型そのものを import して keyof で縛ると、無関係な型変更でこのテストが落ちて
 *   トリガーの意図が埋もれるため、意図的に文字列リテラルで複製する）。
 * - `nodeTypes` / `categories`（node-added / node-changed）が指す先は ComponentRegistry に
 *   実在するか（`bundledChangeTriggers.ts` の起動時 warn と同じ検証を、テストでは fail させる）。
 */

const NODE_FIELDS = new Set([
  'id',
  'seq',
  'type',
  'x',
  'y',
  'parentId',
  'label',
  'description',
  'managedState',
  'userTrustAttribute',
  'attackSurface',
  'cloudSanction',
  'cloudOwnership',
  'agentAttributes',
  'threatActorType',
  'attackObjectiveId',
  'identityProviderKind',
  'authProviderId',
]);

const EDGE_FIELDS = new Set([
  'id',
  'seq',
  'source',
  'target',
  'auth',
  'network',
  'encryption',
  'dataFlow',
  'dataFlowName',
  'semantic',
  'authProviderId',
]);

const BOUNDARY_FIELDS = new Set([
  'id',
  'seq',
  'type',
  'x',
  'y',
  'width',
  'height',
  'trustLevel',
  'macroTrust',
  'vlanName',
  'vlanId',
  'networkAddress',
  'microTrust',
  'microSegmentationStatus',
  'sensitiveData',
  'blastRadiusLabel',
]);

describe('同梱トリガー（triggers.yaml）', () => {
  it('T1〜T8 が同梱されている', () => {
    expect(BUNDLED_CHANGE_TRIGGERS.triggers.map((t) => t.id).sort()).toEqual([
      'T1',
      'T2',
      'T3',
      'T4',
      'T5',
      'T6',
      'T7',
      'T8',
    ]);
  });

  it('node-changed / edge-changed / boundary-changed の fields は実在するフィールド名のみ', () => {
    const broken: string[] = [];
    for (const trigger of BUNDLED_CHANGE_TRIGGERS.triggers) {
      for (const detector of trigger.detect) {
        let allowlist: Set<string> | undefined;
        let fields: readonly string[] | undefined;
        if (detector.kind === 'node-changed') {
          allowlist = NODE_FIELDS;
          fields = detector.fields;
        } else if (detector.kind === 'edge-changed') {
          allowlist = EDGE_FIELDS;
          fields = detector.fields;
        } else if (detector.kind === 'boundary-changed') {
          allowlist = BOUNDARY_FIELDS;
          fields = detector.fields;
        }
        if (!allowlist || !fields) continue;
        for (const field of fields) {
          if (!allowlist.has(field)) broken.push(`${trigger.id}.${detector.kind}.fields: ${field}`);
        }
      }
    }
    expect(broken).toEqual([]);
  });

  it('node-added / node-changed の nodeTypes は ComponentRegistry に実在する', () => {
    const broken: string[] = [];
    for (const trigger of BUNDLED_CHANGE_TRIGGERS.triggers) {
      for (const detector of trigger.detect) {
        if (detector.kind !== 'node-added' && detector.kind !== 'node-changed') continue;
        for (const nodeType of detector.nodeTypes ?? []) {
          if (!componentRegistry.has(nodeType)) broken.push(`${trigger.id}: ${nodeType}`);
        }
      }
    }
    expect(broken).toEqual([]);
  });

  it('node-added / node-changed の categories は ComponentRegistry に実在する', () => {
    const categoryIds = new Set(componentRegistry.getCategories().map((c) => c.id));
    const broken: string[] = [];
    for (const trigger of BUNDLED_CHANGE_TRIGGERS.triggers) {
      for (const detector of trigger.detect) {
        if (detector.kind !== 'node-added' && detector.kind !== 'node-changed') continue;
        for (const category of detector.categories ?? []) {
          if (!categoryIds.has(category)) broken.push(`${trigger.id}: ${category}`);
        }
      }
    }
    expect(broken).toEqual([]);
  });

  it('getChangeTriggers("ja") は同梱データをそのまま返す', () => {
    expect(getChangeTriggers('ja')).toBe(BUNDLED_CHANGE_TRIGGERS);
  });

  it('getChangeTriggers("en") は同じ id 集合を保つ', () => {
    const en = getChangeTriggers('en');
    expect(en.triggers.map((t) => t.id).sort()).toEqual(
      BUNDLED_CHANGE_TRIGGERS.triggers.map((t) => t.id).sort(),
    );
  });
});
