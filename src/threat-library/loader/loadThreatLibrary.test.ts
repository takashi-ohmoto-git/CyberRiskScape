import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  loadThreatLibrary,
  parseThreatLibraryFile,
  ThreatLibraryLoadError,
  type RawYamlFile,
} from './loadThreatLibrary';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const DATA_DIR = resolve(__dirname, '../../../data/threat-library');

function loadAllYamlFiles(): RawYamlFile[] {
  const files = readdirSync(DATA_DIR).filter(
    (f) => f.endsWith('.yaml') || f.endsWith('.yml'),
  );
  return files.map((name) => ({
    source: name,
    text: readFileSync(join(DATA_DIR, name), 'utf-8'),
  }));
}

describe('loadThreatLibrary - 同梱データ', () => {
  it('data/threat-library 配下の YAML をすべてロードできる', () => {
    const result = loadThreatLibrary(loadAllYamlFiles());
    expect(result.rules.length).toBeGreaterThan(0);
    expect(result.sources).toContain('stride-ai.yaml');
    expect(result.sources).toContain('maestro.yaml');
  });

  it('全ルールの id がライブラリ全体で一意である', () => {
    const result = loadThreatLibrary(loadAllYamlFiles());
    const ids = result.rules.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('STRIDE / AI / AgenticAI の 3 フレームワークが少なくとも 1 件ずつ含まれる', () => {
    const result = loadThreatLibrary(loadAllYamlFiles());
    expect(result.rules.some((r) => r.framework === 'STRIDE')).toBe(true);
    expect(result.rules.some((r) => r.framework === 'AI')).toBe(true);
    expect(result.rules.some((r) => r.framework === 'AgenticAI')).toBe(true);
  });

  it('edge ルールには when / allOf / anyOf のいずれかが必ず存在する', () => {
    const result = loadThreatLibrary(loadAllYamlFiles());
    const edgeRules = result.rules.filter((r) => r.appliesTo.kind === 'edge');
    expect(edgeRules.length).toBeGreaterThan(0);
    for (const rule of edgeRules) {
      if (rule.appliesTo.kind !== 'edge') continue;
      const { when, allOf, anyOf } = rule.appliesTo;
      const variants = [when, allOf, anyOf].filter((v) => v !== undefined);
      expect(variants).toHaveLength(1);
    }
  });

  it('ruleSources が各ルールの定義元ファイル名を正しく保持する', () => {
    const result = loadThreatLibrary(loadAllYamlFiles());
    for (const rule of result.rules) {
      expect(result.ruleSources[rule.id]).toBeDefined();
      expect(result.sources).toContain(result.ruleSources[rule.id]);
    }
  });

  it('anthropic-zt-agents.yaml の各ルールは mitigationTiers が markup から自動 populate される', () => {
    const result = loadThreatLibrary(loadAllYamlFiles());
    const ztRules = result.rules.filter((r) => r.id.startsWith('anthropic-zt-'));
    expect(ztRules.length).toBeGreaterThan(0);
    for (const rule of ztRules) {
      // anthropic-zt-agents.yaml の全ルールは 3 段すべての markup を含む設計
      expect(rule.mitigationTiers, `${rule.id} should have mitigationTiers`).toBeDefined();
      expect(rule.mitigationTiers?.foundation).toBeDefined();
      expect(rule.mitigationTiers?.enterprise).toBeDefined();
      expect(rule.mitigationTiers?.advanced).toBeDefined();
    }
  });

  it('markup を含まない既存ルールには mitigationTiers が設定されない', () => {
    const result = loadThreatLibrary(loadAllYamlFiles());
    // stride-ai-* の既存ルールは markup を持たない設計
    const noMarkupRule = result.rules.find((r) => r.id === 'stride-ai-llm-evasion-001');
    expect(noMarkupRule).toBeDefined();
    expect(noMarkupRule?.mitigationTiers).toBeUndefined();
    expect(noMarkupRule?.mitigation).toBeDefined();
  });
});

describe('parseThreatLibraryFile - バリデーション', () => {
  it('正常な最小 YAML をパースできる', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: test-001
    framework: STRIDE
    category: x
    severity: Low
    description: y
    appliesTo:
      kind: node
      nodeType: LLM
`;
    const rules = parseThreatLibraryFile(yaml, 'inline');
    expect(rules).toHaveLength(1);
    expect(rules[0].id).toBe('test-001');
  });

  it('未知の severity を拒否する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: test-002
    framework: STRIDE
    category: x
    severity: TOTALLY_BAD
    description: y
    appliesTo:
      kind: node
      nodeType: LLM
`;
    expect(() => parseThreatLibraryFile(yaml, 'inline')).toThrow(ThreatLibraryLoadError);
  });

  it('nodeType は open string ID を受理する（実在性はレジストリ側で別途検証）', () => {
    // §2.16 で closed enum → open string に変更。
    // 「実在する型か」は ComponentRegistry 経由で起動時に warn ログで通知する（fail させない）。
    const yaml = `
schemaVersion: 1
rules:
  - id: test-003
    framework: STRIDE
    category: x
    severity: Low
    description: y
    appliesTo:
      kind: node
      nodeType: MCP_SERVER
`;
    const rules = parseThreatLibraryFile(yaml, 'inline');
    expect(rules).toHaveLength(1);
    if (rules[0].appliesTo.kind !== 'node') throw new Error('expected node');
    expect(rules[0].appliesTo.nodeType).toBe('MCP_SERVER');
  });

  it('nodeType: 形式違反（小文字始まり）は拒否する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: test-003b
    framework: STRIDE
    category: x
    severity: Low
    description: y
    appliesTo:
      kind: node
      nodeType: invalid_lowercase
`;
    expect(() => parseThreatLibraryFile(yaml, 'inline')).toThrow(ThreatLibraryLoadError);
  });

  it('edge ルールで when が空オブジェクトの場合は拒否する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: test-004
    framework: STRIDE
    category: x
    severity: Low
    description: y
    appliesTo:
      kind: edge
      when: {}
`;
    expect(() => parseThreatLibraryFile(yaml, 'inline')).toThrow(ThreatLibraryLoadError);
  });

  it('不正な id 形式（大文字含む）を拒否する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: Test_005
    framework: STRIDE
    category: x
    severity: Low
    description: y
    appliesTo:
      kind: node
      nodeType: LLM
`;
    expect(() => parseThreatLibraryFile(yaml, 'inline')).toThrow(ThreatLibraryLoadError);
  });

  it('conditions の when が空オブジェクトの場合は拒否する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: cond-001
    framework: AgenticAI
    category: x
    severity: High
    description: y
    appliesTo:
      kind: edge
      when:
        targetType: [TOOL]
      conditions:
        - when: {}
          severity: Low
`;
    expect(() => parseThreatLibraryFile(yaml, 'inline')).toThrow(ThreatLibraryLoadError);
  });

  it('conditions ケースに severity も description も無い場合は拒否する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: cond-002
    framework: AgenticAI
    category: x
    severity: High
    description: y
    appliesTo:
      kind: edge
      when:
        targetType: [TOOL]
      conditions:
        - when:
            auth: [MFA]
`;
    expect(() => parseThreatLibraryFile(yaml, 'inline')).toThrow(ThreatLibraryLoadError);
  });

  it('conditions 配列が空の場合は拒否する（nonempty）', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: cond-003
    framework: AgenticAI
    category: x
    severity: High
    description: y
    appliesTo:
      kind: edge
      when:
        targetType: [TOOL]
      conditions: []
`;
    expect(() => parseThreatLibraryFile(yaml, 'inline')).toThrow(ThreatLibraryLoadError);
  });

  it('正常な conditions 付きルールを受理する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: cond-ok-001
    framework: AgenticAI
    category: x
    severity: High
    description: y
    appliesTo:
      kind: edge
      when:
        targetType: [TOOL]
      conditions:
        - when:
            auth: [MFA]
          severity: Low
          description: ok
`;
    const rules = parseThreatLibraryFile(yaml, 'inline');
    expect(rules).toHaveLength(1);
    const at = rules[0].appliesTo;
    if (at.kind !== 'edge') throw new Error('expected edge');
    expect(at.conditions).toHaveLength(1);
    expect(at.conditions?.[0].severity).toBe('Low');
  });

  // ── 組合せ条件: allOf / anyOf ──────────────────────────────
  it('edge ルールで when / allOf / anyOf をすべて省略した場合は拒否する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: combo-001
    framework: STRIDE
    category: x
    severity: Low
    description: y
    appliesTo:
      kind: edge
`;
    expect(() => parseThreatLibraryFile(yaml, 'inline')).toThrow(ThreatLibraryLoadError);
  });

  it('edge ルールで when と allOf を同時指定した場合は拒否する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: combo-002
    framework: STRIDE
    category: x
    severity: Low
    description: y
    appliesTo:
      kind: edge
      when:
        encryption: [Plain]
      allOf:
        - encryption: [Plain]
        - auth: [None]
`;
    expect(() => parseThreatLibraryFile(yaml, 'inline')).toThrow(ThreatLibraryLoadError);
  });

  it('edge ルールの allOf が要素 1 件未満の場合は拒否する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: combo-003
    framework: STRIDE
    category: x
    severity: Low
    description: y
    appliesTo:
      kind: edge
      allOf:
        - encryption: [Plain]
`;
    expect(() => parseThreatLibraryFile(yaml, 'inline')).toThrow(ThreatLibraryLoadError);
  });

  it('edge ルールの anyOf 内に空オブジェクトリーフが混入したら拒否する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: combo-004
    framework: STRIDE
    category: x
    severity: Low
    description: y
    appliesTo:
      kind: edge
      anyOf:
        - encryption: [Plain]
        - {}
`;
    expect(() => parseThreatLibraryFile(yaml, 'inline')).toThrow(ThreatLibraryLoadError);
  });

  it('正常な edge allOf を受理する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: combo-allof-001
    framework: STRIDE
    category: x
    severity: High
    description: y
    appliesTo:
      kind: edge
      allOf:
        - sourceType: [AGENT]
        - encryption: [Plain]
          auth: [None]
`;
    const rules = parseThreatLibraryFile(yaml, 'inline');
    expect(rules).toHaveLength(1);
    const at = rules[0].appliesTo;
    if (at.kind !== 'edge') throw new Error('expected edge');
    expect(at.allOf).toHaveLength(2);
    expect(at.when).toBeUndefined();
    expect(at.anyOf).toBeUndefined();
  });

  it('正常な edge anyOf を受理する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: combo-anyof-001
    framework: STRIDE
    category: x
    severity: High
    description: y
    appliesTo:
      kind: edge
      anyOf:
        - encryption: [Plain]
        - network: [Internet]
          auth: [None]
`;
    const rules = parseThreatLibraryFile(yaml, 'inline');
    expect(rules).toHaveLength(1);
    const at = rules[0].appliesTo;
    if (at.kind !== 'edge') throw new Error('expected edge');
    expect(at.anyOf).toHaveLength(2);
  });

  it('node ルールで nodeType と anyOf を同時指定した場合は拒否する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: node-combo-001
    framework: STRIDE
    category: x
    severity: Low
    description: y
    appliesTo:
      kind: node
      nodeType: LLM
      anyOf:
        - nodeType: LLM
        - nodeType: AGENT
`;
    expect(() => parseThreatLibraryFile(yaml, 'inline')).toThrow(ThreatLibraryLoadError);
  });

  it('node ルールで nodeType も anyOf も無い場合は拒否する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: node-combo-002
    framework: STRIDE
    category: x
    severity: Low
    description: y
    appliesTo:
      kind: node
`;
    expect(() => parseThreatLibraryFile(yaml, 'inline')).toThrow(ThreatLibraryLoadError);
  });

  it('正常な node anyOf を受理する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: node-combo-003
    framework: STRIDE
    category: x
    severity: Low
    description: y
    appliesTo:
      kind: node
      anyOf:
        - nodeType: LLM
        - nodeType: AGENT
`;
    const rules = parseThreatLibraryFile(yaml, 'inline');
    const at = rules[0].appliesTo;
    if (at.kind !== 'node') throw new Error('expected node');
    expect(at.anyOf).toHaveLength(2);
    expect(at.nodeType).toBeUndefined();
  });

  // ── Node 接続要件: connection ────────────────────────────────
  it('node connection: required:false と direction の併用を拒否する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: conn-bad-001
    framework: STRIDE
    category: x
    severity: Low
    description: y
    appliesTo:
      kind: node
      nodeType: LLM
      connection:
        required: false
        direction: inbound
`;
    expect(() => parseThreatLibraryFile(yaml, 'inline')).toThrow(ThreatLibraryLoadError);
  });

  it('node connection: required:false と peerType の併用を拒否する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: conn-bad-002
    framework: STRIDE
    category: x
    severity: Low
    description: y
    appliesTo:
      kind: node
      nodeType: LLM
      connection:
        required: false
        peerType: [USER]
`;
    expect(() => parseThreatLibraryFile(yaml, 'inline')).toThrow(ThreatLibraryLoadError);
  });

  it('node connection: 不正な direction を拒否する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: conn-bad-003
    framework: STRIDE
    category: x
    severity: Low
    description: y
    appliesTo:
      kind: node
      nodeType: LLM
      connection:
        direction: sideways
`;
    expect(() => parseThreatLibraryFile(yaml, 'inline')).toThrow(ThreatLibraryLoadError);
  });

  it('node connection: 空の peerType 配列を拒否する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: conn-bad-004
    framework: STRIDE
    category: x
    severity: Low
    description: y
    appliesTo:
      kind: node
      nodeType: LLM
      connection:
        peerType: []
`;
    expect(() => parseThreatLibraryFile(yaml, 'inline')).toThrow(ThreatLibraryLoadError);
  });

  it('node connection: intrinsic（required:false）の最小形を受理する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: conn-ok-001
    framework: STRIDE
    category: x
    severity: Low
    description: y
    appliesTo:
      kind: node
      nodeType: LLM
      connection:
        required: false
`;
    const rules = parseThreatLibraryFile(yaml, 'inline');
    expect(rules).toHaveLength(1);
    const at = rules[0].appliesTo;
    if (at.kind !== 'node') throw new Error('expected node');
    expect(at.connection?.required).toBe(false);
  });

  it('node connection: direction + peerType を受理する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: conn-ok-002
    framework: STRIDE
    category: x
    severity: Low
    description: y
    appliesTo:
      kind: node
      nodeType: LLM
      connection:
        direction: inbound
        peerType: [USER, EXTERNAL_ENTITY]
`;
    const rules = parseThreatLibraryFile(yaml, 'inline');
    const at = rules[0].appliesTo;
    if (at.kind !== 'node') throw new Error('expected node');
    expect(at.connection?.direction).toBe('inbound');
    expect(at.connection?.peerType).toEqual(['USER', 'EXTERNAL_ENTITY']);
  });

  it('node connection: peerType + peerAttackSurface を受理する（ピア属性条件）', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: conn-peer-surface-001
    framework: AgenticAI
    category: x
    severity: High
    description: y
    appliesTo:
      kind: node
      nodeType: AGENT
      connection:
        direction: outbound
        peerType: [GATEWAY]
        peerAttackSurface:
          hasGlobalIp: true
`;
    const rules = parseThreatLibraryFile(yaml, 'inline');
    const at = rules[0].appliesTo;
    if (at.kind !== 'node') throw new Error('expected node');
    expect(at.connection?.peerAttackSurface?.hasGlobalIp).toBe(true);
  });

  it('node connection: required:false と peerAttackSurface の併用を拒否する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: conn-bad-peer-surface-001
    framework: AgenticAI
    category: x
    severity: High
    description: y
    appliesTo:
      kind: node
      nodeType: AGENT
      connection:
        required: false
        peerAttackSurface:
          hasGlobalIp: true
`;
    expect(() => parseThreatLibraryFile(yaml, 'inline')).toThrow(ThreatLibraryLoadError);
  });

  it('node connection: 空の peerAttackSurface を拒否する', () => {
    const yaml = `
schemaVersion: 1
rules:
  - id: conn-bad-empty-surface-001
    framework: AgenticAI
    category: x
    severity: High
    description: y
    appliesTo:
      kind: node
      nodeType: AGENT
      connection:
        peerType: [GATEWAY]
        peerAttackSurface: {}
`;
    expect(() => parseThreatLibraryFile(yaml, 'inline')).toThrow(ThreatLibraryLoadError);
  });

  it('schemaVersion 不一致を拒否する', () => {
    const yaml = `
schemaVersion: 2
rules: []
`;
    expect(() => parseThreatLibraryFile(yaml, 'inline')).toThrow(ThreatLibraryLoadError);
  });

  it('YAML パースエラーは ThreatLibraryLoadError として throw される', () => {
    const broken = 'schemaVersion: 1\nrules:\n  - id: a\n   bad: indent';
    expect(() => parseThreatLibraryFile(broken, 'broken.yaml')).toThrow(ThreatLibraryLoadError);
  });
});

describe('loadThreatLibrary - 重複検知', () => {
  it('同一 id が複数ファイルにまたがる場合は拒否する', () => {
    const dup = `
schemaVersion: 1
rules:
  - id: dup-1
    framework: STRIDE
    category: a
    severity: Low
    description: a
    appliesTo:
      kind: node
      nodeType: LLM
`;
    expect(() =>
      loadThreatLibrary([
        { source: 'a.yaml', text: dup },
        { source: 'b.yaml', text: dup },
      ]),
    ).toThrow(/Duplicate rule id/);
  });

  it('同一ファイル内の id 重複も拒否する', () => {
    const dup = `
schemaVersion: 1
rules:
  - id: dup-2
    framework: STRIDE
    category: a
    severity: Low
    description: a
    appliesTo:
      kind: node
      nodeType: LLM
  - id: dup-2
    framework: STRIDE
    category: b
    severity: Low
    description: b
    appliesTo:
      kind: node
      nodeType: AGENT
`;
    expect(() => loadThreatLibrary([{ source: 'x.yaml', text: dup }])).toThrow(
      /Duplicate rule id/,
    );
  });
});
