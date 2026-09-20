import { describe, expect, it } from 'vitest';
import {
  findOrphanOverlayIds,
  findUntranslatedRuleIds,
  loadThreatLibraryOverlay,
  localizeRules,
  parseThreatLibraryOverlayFile,
} from './localizeThreatLibrary';
import { ThreatLibraryLoadError } from './loadThreatLibrary';
import type { ThreatRule } from '../schema/threatRule';

const nodeRule: ThreatRule = {
  id: 'sample-node-001',
  framework: 'AI',
  category: '情報漏えい',
  name: 'プロンプト経由の情報漏えい',
  severity: 'High',
  description: '{{nodeLabel}} から機密が漏れる。',
  mitigation: '[Foundation] 出力をフィルタする。 [Enterprise] 監査ログを取る。',
  mitigationTiers: {
    foundation: '出力をフィルタする。',
    enterprise: '監査ログを取る。',
  },
  appliesTo: { kind: 'node', nodeType: 'LLM' },
};

const edgeRule: ThreatRule = {
  id: 'sample-edge-001',
  framework: 'STRIDE',
  category: '改ざん',
  severity: 'Medium',
  description: '経路が保護されていない。',
  appliesTo: {
    kind: 'edge',
    when: { encryption: ['Plain'] },
    conditions: [
      { when: { auth: ['None'] }, severity: 'High', description: '未認証のため深刻度を上げる。' },
      { when: { auth: ['MFA'] }, severity: 'Low', description: 'MFA のため深刻度を下げる。' },
    ],
  },
};

const overlayYaml = `
schemaVersion: 1
locale: en
rules:
  sample-node-001:
    name: Information disclosure through prompts
    category: Information Disclosure
    description: Secrets can leak from {{nodeLabel}}.
    mitigation: |
      [Foundation] Filter model output.
      [Enterprise] Keep an audit log.
`;

describe('parseThreatLibraryOverlayFile', () => {
  it('ルール id をキーに訳文を返す', () => {
    const overlay = parseThreatLibraryOverlayFile(overlayYaml, 'en/sample.yaml');
    expect(Object.keys(overlay)).toEqual(['sample-node-001']);
    expect(overlay['sample-node-001']?.name).toBe('Information disclosure through prompts');
  });

  it('未知のフィールドはスキーマ違反として落とす', () => {
    const bad = `
schemaVersion: 1
locale: en
rules:
  sample-node-001:
    titel: typo
`;
    expect(() => parseThreatLibraryOverlayFile(bad, 'en/bad.yaml')).toThrow(ThreatLibraryLoadError);
  });

  it('YAML 構文エラーはソース名付きで落とす', () => {
    expect(() => parseThreatLibraryOverlayFile('rules: [unclosed', 'en/broken.yaml')).toThrow(
      /broken\.yaml/,
    );
  });
});

describe('loadThreatLibraryOverlay', () => {
  it('複数ファイルを 1 つのマップへ統合する', () => {
    const other = `
schemaVersion: 1
locale: en
rules:
  sample-edge-001:
    category: Tampering
`;
    const merged = loadThreatLibraryOverlay([
      { source: 'en/a.yaml', text: overlayYaml },
      { source: 'en/b.yaml', text: other },
    ]);
    expect(Object.keys(merged).sort()).toEqual(['sample-edge-001', 'sample-node-001']);
  });

  it('同じルール id が複数ファイルにあれば落とす', () => {
    expect(() =>
      loadThreatLibraryOverlay([
        { source: 'en/a.yaml', text: overlayYaml },
        { source: 'en/b.yaml', text: overlayYaml },
      ]),
    ).toThrow(/Duplicate overlay entry/);
  });
});

describe('localizeRules', () => {
  const overlay = parseThreatLibraryOverlayFile(overlayYaml, 'en/sample.yaml');

  it('指定されたフィールドだけを差し替える', () => {
    const [localized] = localizeRules([nodeRule], overlay);
    expect(localized?.name).toBe('Information disclosure through prompts');
    expect(localized?.category).toBe('Information Disclosure');
    expect(localized?.description).toBe('Secrets can leak from {{nodeLabel}}.');
    // 訳の無いフィールドは原文のまま
    expect(localized?.severity).toBe('High');
    expect(localized?.appliesTo).toEqual(nodeRule.appliesTo);
  });

  it('原文を破壊しない（新しいオブジェクトを返す）', () => {
    localizeRules([nodeRule], overlay);
    expect(nodeRule.name).toBe('プロンプト経由の情報漏えい');
  });

  it('mitigation の差し替え時に mitigationTiers を訳文から再計算する', () => {
    const [localized] = localizeRules([nodeRule], overlay);
    expect(localized?.mitigationTiers).toEqual({
      foundation: 'Filter model output.',
      enterprise: 'Keep an audit log.',
    });
  });

  it('tier markup の無い訳文では mitigationTiers を落とす', () => {
    const flat = parseThreatLibraryOverlayFile(
      `
schemaVersion: 1
locale: en
rules:
  sample-node-001:
    mitigation: Filter model output.
`,
      'en/flat.yaml',
    );
    const [localized] = localizeRules([nodeRule], flat);
    expect(localized?.mitigation).toBe('Filter model output.');
    expect(localized?.mitigationTiers).toBeUndefined();
  });

  it('訳の無いルールはそのまま返す', () => {
    const [localized] = localizeRules([edgeRule], overlay);
    expect(localized).toBe(edgeRule);
  });

  it('conditions の説明を並び順で差し替える', () => {
    const conditionOverlay = parseThreatLibraryOverlayFile(
      `
schemaVersion: 1
locale: en
rules:
  sample-edge-001:
    conditions:
      - description: Unauthenticated, so severity is raised.
      - description: MFA is in place, so severity is lowered.
`,
      'en/conditions.yaml',
    );
    const [localized] = localizeRules([edgeRule], conditionOverlay);
    const appliesTo = localized?.appliesTo;
    expect(appliesTo?.kind).toBe('edge');
    if (appliesTo?.kind !== 'edge') throw new Error('expected an edge rule');
    expect(appliesTo.conditions?.[0]?.description).toBe('Unauthenticated, so severity is raised.');
    expect(appliesTo.conditions?.[1]?.description).toBe('MFA is in place, so severity is lowered.');
    // 条件の判定部分は変えない
    expect(appliesTo.conditions?.[0]?.when).toEqual({ auth: ['None'] });
  });

  it('conditions の訳が足りない場合は残りを原文のままにする', () => {
    const partial = parseThreatLibraryOverlayFile(
      `
schemaVersion: 1
locale: en
rules:
  sample-edge-001:
    conditions:
      - description: Unauthenticated, so severity is raised.
`,
      'en/partial.yaml',
    );
    const [localized] = localizeRules([edgeRule], partial);
    const appliesTo = localized?.appliesTo;
    if (appliesTo?.kind !== 'edge') throw new Error('expected an edge rule');
    expect(appliesTo.conditions?.[1]?.description).toBe('MFA のため深刻度を下げる。');
  });
});

describe('診断', () => {
  const overlay = parseThreatLibraryOverlayFile(overlayYaml, 'en/sample.yaml');

  it('原本に無いルール id を検出する', () => {
    expect(findOrphanOverlayIds([edgeRule], overlay)).toEqual(['sample-node-001']);
    expect(findOrphanOverlayIds([nodeRule], overlay)).toEqual([]);
  });

  it('未翻訳のルール id を検出する', () => {
    expect(findUntranslatedRuleIds([nodeRule, edgeRule], overlay)).toEqual(['sample-edge-001']);
  });
});

describe('references', () => {
  const ruleWithRefs: ThreatRule = {
    ...nodeRule,
    references: [
      { title: 'NIST SP 800-207 - Zero Trust Architecture（暗黙信頼の排除）', url: 'https://x.test/a' },
      { title: 'NCSC (UK) - Shadow IT guidance' },
    ],
  };

  const overlay = parseThreatLibraryOverlayFile(
    `
schemaVersion: 1
locale: en
rules:
  sample-node-001:
    references:
      "0":
        title: NIST SP 800-207 - Zero Trust Architecture (removing implicit trust)
`,
    'en/refs.yaml',
  );

  it('添字で指定された出典だけを差し替え、url は保つ', () => {
    const [localized] = localizeRules([ruleWithRefs], overlay);
    expect(localized?.references?.[0]?.title).toBe(
      'NIST SP 800-207 - Zero Trust Architecture (removing implicit trust)',
    );
    expect(localized?.references?.[0]?.url).toBe('https://x.test/a');
  });

  it('指定の無い添字は原文のまま残す', () => {
    const [localized] = localizeRules([ruleWithRefs], overlay);
    expect(localized?.references?.[1]?.title).toBe('NCSC (UK) - Shadow IT guidance');
  });

  it('原本に無い添字は無視する', () => {
    const outOfRange = parseThreatLibraryOverlayFile(
      `
schemaVersion: 1
locale: en
rules:
  sample-node-001:
    references:
      "9":
        title: Never applied
`,
      'en/out-of-range.yaml',
    );
    const [localized] = localizeRules([ruleWithRefs], outOfRange);
    expect(localized?.references).toHaveLength(2);
    expect(localized?.references?.map((r) => r.title)).toEqual(
      ruleWithRefs.references?.map((r) => r.title),
    );
  });

  it('出典を持たないルールには何もしない', () => {
    const [localized] = localizeRules([nodeRule], overlay);
    expect(localized?.references).toBeUndefined();
  });

  it('添字でないキーを拒否する', () => {
    expect(() =>
      parseThreatLibraryOverlayFile(
        `
schemaVersion: 1
locale: en
rules:
  sample-node-001:
    references:
      first:
        title: Bad key
`,
        'en/bad-key.yaml',
      ),
    ).toThrow(ThreatLibraryLoadError);
  });
});
