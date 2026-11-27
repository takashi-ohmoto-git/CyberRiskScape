/**
 * 書き出し系のサブコマンド（export-*）の実装。
 */
import { writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { analyzeProject, analyzeResolvedProject, resolveProject, type LayerAnalysisResult } from '../analyze';
import { diffProjects } from '../diff';
import { readModelHistory } from '../gitHistory';
import { buildEventLog } from '../../features/event-log/buildEventLog';
import { toOcelJson } from '../../features/event-log/ocel';
import { toEventCsv } from '../../features/event-log/eventCsv';
import { exportScope, exportScopeToText } from '../exportScope';
import { detectionRequirementsToSigma } from '../../features/detection-requirements/detectionRequirementsSigma';
import { SERVICE_SCOPE_KINDS } from '../../core/model/serviceScope';
import { deserializeProject } from '../../features/persistence/serialize';
import { version as APP_VERSION } from '../../../package.json';
import { buildSpdx } from '../../features/bom-import/buildSpdx';
import { listBomComponents } from '../../features/bom-import/listBomComponents';
import { setLocale } from '../../i18n';
import { ATTACK_OBJECTIVE_APPLICABLE, LAYER_KEYS, type Asset } from '../../core/model/types';
import { formatElementalId } from '../../core/model/elementalId';
import { getChangeTriggers } from '../../change-triggers/loader/bundledChangeTriggers';
import { toPostmanCollection } from '../../features/postman-export/toPostmanCollection';
import { buildSbomForAi } from '../../features/sbom-ai/buildSbomForAi';
import { VarsFileSchema, applyVariableValues, filterByBaseUrl } from '../../features/postman-export/dastOptions';
import { buildTestPlan } from '../../features/test-plan/buildTestPlan';
import { computeRetestScope } from '../../features/test-plan/retestScope';
import { detectTriggers } from '../../change-triggers/detectTriggers';
import { testPlanToJson, testPlanToMarkdown } from '../../features/test-plan/testPlanOutput';
import { buildRoe } from '../../features/roe-export/buildRoe';
import { roeToJson, roeToMarkdown } from '../../features/roe-export/roeOutput';
import { buildNavigatorLayer, navigatorLayerToJson } from '../../features/attack-navigator/buildNavigatorLayer';
import { buildInvestigationPlan } from '../../features/investigation-plan/buildInvestigationPlan';
import { buildDetectionRequirements } from '../../features/detection-requirements/buildDetectionRequirements';
import {
  detectionRequirementsToJson,
  detectionRequirementsToMarkdown,
} from '../../features/detection-requirements/detectionRequirementsOutput';
import { buildContractorPaths } from '../../features/contractor-paths/buildContractorPaths';
import {
  contractorPathsToCsv,
  contractorPathsToJson,
  contractorPathsToMarkdown,
} from '../../features/contractor-paths/contractorPathsOutput';
import { buildRequirements } from '../../features/requirements-export/buildRequirements';
import {
  requirementsToCsv,
  requirementsToJson,
  requirementsToMarkdown,
} from '../../features/requirements-export/requirementsOutput';
import { buildTriagePatterns } from '../../features/investigation-plan/triagePatterns';
import { getInvestigationViewpoints } from '../../features/investigation-plan/viewpoints';
import {
  investigationPlanToJson,
  investigationPlanToMarkdown,
} from '../../features/investigation-plan/investigationPlanOutput';
import {
  TEST_PLAN_FORMATS,
  FRAMEWORKS,
  LOCALES,
  fail,
  parseEnum,
  readJsonFile,
  resolveTriggers,
  writeOutput,
} from '../cliShared';
import { USAGE } from '../usage';
import type { CliValues } from '../cliArgs';

const DETECTION_FORMATS = ['md', 'json', 'sigma'] as const;

const REQUIREMENTS_FORMATS = ['md', 'csv', 'json'] as const;

const INVESTIGATION_TOOLS = ['velociraptor'] as const;

const EXPORT_SCOPE_FORMATS = ['text', 'json'] as const;

/** `export-scope`：サービスの担当範囲を探索の起点として書き出す。 */
export function runExportScope(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const kind = parseEnum(values.kind, SERVICE_SCOPE_KINDS, 'kind');
  const format = parseEnum(values.format, EXPORT_SCOPE_FORMATS, 'format') ?? 'text';
  let result: ReturnType<typeof exportScope>;
  try {
    result = exportScope(readJsonFile(file), kind);
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  if (result.invalid.length > 0) {
    console.error(`解釈できない担当範囲 ${result.invalid.length} 件を出しませんでした: ${result.invalid.map((e) => `${e.kind} ${e.value}`).join(', ')}`);
  }
  writeOutput(format === 'json' ? JSON.stringify(result, null, 2) : exportScopeToText(result, kind), values.out);
}

/** `export-spdx`：部品を SPDX 2.3 JSON で出力する（docs/architecture.md §8.8）。 */
export function runExportSpdx(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) fail(`入力ファイルを指定してください。\n\n${USAGE}`);
  const raw = readJsonFile(file);
  const loaded = deserializeProject(raw);
  if (!loaded) fail('プロジェクト JSON の形式が不正です。');
  const resolved = resolveProject(raw);
  const parts = listBomComponents(
    loaded.bomComponents ?? [],
    LAYER_KEYS.flatMap((layer) => resolved.layers[layer].nodes.map((node) => ({ node, layer }))),
  );
  const meta = loaded.projectMeta;
  const out = buildSpdx(parts, {
    name: meta?.systemName.trim() || meta?.name.trim() || 'unknown',
    created: new Date().toISOString(),
    documentNamespace: `urn:uuid:${randomUUID()}`,
    toolVersion: APP_VERSION,
  });
  writeOutput(JSON.stringify(out.document, null, 2), values.out);
  process.stderr.write(`SPDX 2.3 を出力しました（パッケージ ${out.packages} / SPDX に載らず除外した暗号資産 ${out.omittedCrypto}）\n`);
}

/**
 * `export-postman`：検出した脅威のうち HTTP で確かめられるものについて、確認リクエストの
 * Postman Collection（v2.1 JSON）を出力する。ホスト名・トークンは変数のまま出す。
 */
export function runExportPostman(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  const framework = parseEnum(values.framework, FRAMEWORKS, 'framework');
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  const raw = readJsonFile(file);
  let results: LayerAnalysisResult[];
  try {
    results = analyzeProject(raw, { layer, framework, locale });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const target = results[0];
  if (!target) fail('ノードのあるレイヤーがありません。');

  const generated = toPostmanCollection(target.input);
  const summary = generated.summary;
  let collection = generated.collection;
  if (values.vars) {
    const parsed = VarsFileSchema.safeParse(readJsonFile(values.vars));
    if (!parsed.success) {
      fail(`--vars は文字列だけを値に持つ JSON オブジェクトにしてください（例: {"C7_host": "api.example.com"}）: ${values.vars}`);
    }
    const applied = applyVariableValues(collection, parsed.data);
    collection = applied.collection;
    if (applied.unknownKeys.length > 0) {
      process.stderr.write(`コレクションに無い変数は無視しました: ${applied.unknownKeys.join(', ')}
`);
    }
    if (applied.filledTokenKeys.length > 0) {
      process.stderr.write(
        '注意: 出力ファイルに認証情報（token_ 変数）が含まれます。取り扱いに注意し、DAST ツール側で認証を設定することを推奨します。\n',
      );
    }
  }
  let kept = summary.requests;
  if (values['base-url']) {
    const filtered = filterByBaseUrl(collection, values['base-url']);
    collection = filtered.collection;
    kept = filtered.kept;
    if (kept === 0) {
      process.stderr.write(
        '警告: --base-url 配下のリクエストが 0 件です。--vars でホスト変数（*_host）を埋めたか、URL を確認してください。\n',
      );
    }
  }
  writeOutput(JSON.stringify(collection, null, 2), values.out);
  const keptNote = values['base-url'] ? `・base URL 配下のリクエスト ${kept} / ${summary.requests} 件` : '';
  process.stderr.write(
    `Postman Collection を出力しました（${target.layer}・リクエスト ${summary.requests} 件${keptNote}・対象の脅威 ${summary.coveredThreats} 件・対象外 ${summary.uncoveredThreats} 件）
`,
  );
}

/**
 * `export-sbom-ai`：脅威モデルから SBOM for AI を CycloneDX 1.7 JSON で出力する。
 * 既定は実装済みの対策だけ。`--include-threats` で未抑制の脅威も vulnerabilities に載せる。
 */
export function runExportSbomAi(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let results: LayerAnalysisResult[];
  try {
    results = analyzeProject(readJsonFile(file), { layer, locale });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const target = results[0];
  if (!target) fail('ノードのあるレイヤーがありません。');

  const bom = buildSbomForAi(target.input, {
    includeThreats: values['include-threats'] ?? false,
    author: values.author,
    timestamp: new Date().toISOString(),
    serialNumber: `urn:uuid:${randomUUID()}`,
    locale,
    importedComponents: deserializeProject(readJsonFile(file))?.bomComponents,
  });
  writeOutput(JSON.stringify(bom, null, 2), values.out);
  const count = (k: string) => (Array.isArray(bom[k]) ? (bom[k] as unknown[]).length : 0);
  process.stderr.write(
    `SBOM for AI（CycloneDX 1.7）を出力しました（${target.layer}・components ${count('components')} 件・services ${count('services')} 件・vulnerabilities ${count('vulnerabilities')} 件）
`,
  );
}

/**
 * `export-detection-requirements`：脅威モデルから、攻撃経路上のノードごとの「監視すべき振る舞い」「必要なログ」と
 * ログが監視先に届かない区間を Markdown または JSON で出力する。検知できることは示さない。
 */
export function runExportDetectionRequirements(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const format = parseEnum(values.format, DETECTION_FORMATS, 'format') ?? 'md';
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let results: LayerAnalysisResult[];
  try {
    results = analyzeProject(readJsonFile(file), { layer, locale });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const target = results[0];
  if (!target) fail('ノードのあるレイヤーがありません。');

  const d = buildDetectionRequirements(target.input, new Date(), locale);
  writeOutput(
    format === 'json' ? detectionRequirementsToJson(d) : format === 'sigma' ? detectionRequirementsToSigma(d) : detectionRequirementsToMarkdown(d),
    values.out,
  );
  const reqs = d.nodes.reduce((n, x) => n + x.requirements.length, 0);
  process.stderr.write(
    `検知要件を出力しました（${target.layer}・対象ノード ${d.nodes.length} 件・監視要件 ${reqs} 件・経路 ${d.routes.length} 本${d.pathBased ? '' : '・攻撃経路なし＝全ノード'}）
`,
  );
}

/**
 * `export-investigation-plan`：脅威モデルから、侵害の疑いがあるときの調査計画（対象ノード・調査観点・
 * 調べられない恐れ）を Markdown または JSON で出力する。
 */
export function runExportInvestigationPlan(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const format = parseEnum(values.format, TEST_PLAN_FORMATS, 'format') ?? 'md';
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  const tool = parseEnum(values.tool, INVESTIGATION_TOOLS, 'tool') ?? null;
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let results: LayerAnalysisResult[];
  try {
    results = analyzeProject(readJsonFile(file), { layer, locale });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const target = results[0];
  if (!target) fail('ノードのあるレイヤーがありません。');

  const plan = buildInvestigationPlan(
    { ...target.input, findings: resolveProject(readJsonFile(file)).findings },
    new Date(),
    locale,
    tool,
  );
  writeOutput(format === 'json' ? investigationPlanToJson(plan) : investigationPlanToMarkdown(plan), values.out);
  const viewpoints = plan.nodes.reduce((n, x) => n + x.viewpoints.length, 0);
  process.stderr.write(
    `調査計画を出力しました（${target.layer}・対象ノード ${plan.nodes.length} 件・調査観点 ${viewpoints} 件${plan.pathBased ? '' : '・攻撃経路なし＝全ノード'}）
`,
  );
}

/**
 * `export-contractor-paths`：委託先の接続経路を MFA 切り替えの優先順に Markdown / CSV / JSON で出力する。
 */
export function runExportContractorPaths(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const format = parseEnum(values.format, REQUIREMENTS_FORMATS, 'format') ?? 'md';
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let results: LayerAnalysisResult[];
  try {
    results = analyzeProject(readJsonFile(file), { layer, locale });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const target = results[0];
  if (!target) fail('ノードのあるレイヤーがありません。');

  const paths = buildContractorPaths(target.input, new Date(), locale);
  writeOutput(
    format === 'json'
      ? contractorPathsToJson(paths)
      : format === 'csv'
        ? contractorPathsToCsv(paths)
        : contractorPathsToMarkdown(paths),
    values.out,
  );
  process.stderr.write(`委託先の接続経路を出力しました（${target.layer}・${paths.rows.length} 件）
`);
}

/**
 * `export-event-log`：git の履歴から脅威・指摘への対応のイベントログ（OCEL 2.0 JSON / CSV）を出力する。
 */
export function runExportEventLog(values: CliValues): void {
  if (!values.repo) fail('--repo <dir> を指定してください。');
  if (!values.path) fail('--path <model.json> を指定してください。');
  const format = parseEnum(values.format, ['ocel', 'csv'] as const, 'format') ?? 'ocel';
  let maxCommits: number | undefined;
  if (values['max-commits'] !== undefined) {
    if (!/^\d{1,5}$/.test(values['max-commits'])) fail('--max-commits は整数で指定してください。');
    maxCommits = Number(values['max-commits']);
  }
  const triggers = getChangeTriggers('ja').triggers;
  let history: ReturnType<typeof readModelHistory>;
  let log: ReturnType<typeof buildEventLog>;
  try {
    history = readModelHistory(values.repo, values.path, { since: values.since, maxCommits });
    log = buildEventLog(history.snapshots, {
      resolve: resolveProject,
      analyze: (m) => analyzeResolvedProject(m, { framework: 'ALL', locale: 'ja' }),
      triggerIds: (base, head) => diffProjects(base, head, { locale: 'ja', triggers }).triggerHits.map((h) => h.triggerId),
      appVersion: APP_VERSION,
    });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const text = format === 'csv' ? toEventCsv(log) : JSON.stringify(toOcelJson(log), null, 2);
  if (format === 'csv' && values.out) writeFileSync(values.out, '﻿' + text, 'utf-8');
  else if (format === 'csv') process.stdout.write(text);
  else writeOutput(text, values.out);
  for (const w of [...history.warnings, ...log.skipped, ...log.notes]) process.stderr.write(`注意: ${w}
`);
  process.stderr.write(`イベントログを出力しました（版 ${log.versions} 件・イベント ${log.events.length} 件・オブジェクト ${log.objects.length} 件・解析に使った版 ${log.appVersion}）
`);
}

/**
 * `export-requirements`：脅威モデルから、セキュリティ要件の一覧（たたき台）を Markdown / CSV / JSON で出力する。
 */
export function runExportRequirements(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const format = parseEnum(values.format, REQUIREMENTS_FORMATS, 'format') ?? 'md';
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let results: LayerAnalysisResult[];
  try {
    results = analyzeProject(readJsonFile(file), { layer, locale });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const target = results[0];
  if (!target) fail('ノードのあるレイヤーがありません。');

  const list = buildRequirements(target.input, new Date(), locale);
  writeOutput(
    format === 'json' ? requirementsToJson(list) : format === 'csv' ? requirementsToCsv(list) : requirementsToMarkdown(list),
    values.out,
  );
  process.stderr.write(
    `セキュリティ要件一覧を出力しました（${target.layer}・要件 ${list.requirements.length} 件・委託先への要件 ${list.contractorRequirements.length} 件）
`,
  );
}

/**
 * `export-triage-patterns`：調査観点の `tools.triage` を、オフラインのログトリアージ
 * （`tools/triage/crs_triage.py --patterns`）に渡す JSON として書き出す。モデルは不要。
 */
export function runExportTriagePatterns(values: CliValues): void {
  const patterns = buildTriagePatterns(getInvestigationViewpoints('ja'));
  writeOutput(JSON.stringify(patterns, null, 2), values.out);
  process.stderr.write(`トリアージのパターンを出力しました（検索パターン ${patterns.logPatterns.length} 件）
`);
}

/**
 * `export-test-plan`：脅威モデルから、ペネトレーションテスト計画書（入口・攻撃シナリオ・重点テスト項目）を
 * Markdown または JSON で出力する。
 */
export function runExportTestPlan(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const format = parseEnum(values.format, TEST_PLAN_FORMATS, 'format') ?? 'md';
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  const framework = parseEnum(values.framework, FRAMEWORKS, 'framework');
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let results: LayerAnalysisResult[];
  try {
    results = analyzeProject(readJsonFile(file), { layer, framework, locale });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const target = results[0];
  if (!target) fail('ノードのあるレイヤーがありません。');

  let retest: ReturnType<typeof computeRetestScope> | undefined;
  if (values['changed-from']) {
    try {
      const base = resolveProject(readJsonFile(values['changed-from']));
      const head = resolveProject(readJsonFile(file));
      const hits = detectTriggers(base.layers, head.layers, resolveTriggers(values, locale));
      retest = computeRetestScope(target.layer, base.layers[target.layer], head.layers[target.layer], hits);
    } catch (e) {
      fail(e instanceof Error ? e.message : String(e));
    }
  }

  const plan = buildTestPlan(target.input, new Date(), locale, retest);
  writeOutput(format === 'json' ? testPlanToJson(plan) : testPlanToMarkdown(plan), values.out);
  const focusThreats = plan.focusGroups.reduce((n, g) => n + g.threats.length, 0);
  process.stderr.write(
    `テスト計画書を出力しました（${target.layer}・入口 ${plan.entryPoints.length} 件・攻撃シナリオ ${plan.scenarios.length} 件・重点テスト項目 ${focusThreats} 件・対象外 ${plan.suppressed.length} 件）
`,
  );
}

/**
 * `export-roe`：脅威モデルから、交戦規定（RoE）／スコープ宣言（許可対象・スコープ外・承認方針）を
 * Markdown または JSON で出力する。エージェント型ペンテストツールの自社運用向け（ベンダー中立）。
 */
export function runExportRoe(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const format = parseEnum(values.format, TEST_PLAN_FORMATS, 'format') ?? 'md';
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  const framework = parseEnum(values.framework, FRAMEWORKS, 'framework');
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let results: LayerAnalysisResult[];
  let assets: Asset[] | undefined;
  try {
    const raw = readJsonFile(file);
    results = analyzeProject(raw, { layer, framework, locale });
    // ノードに結びついた資産（取り込み・手入力）をアドレスの手がかりに使う
    assets = resolveProject(raw).assets;
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const target = results[0];
  if (!target) fail('ノードのあるレイヤーがありません。');

  const doc = buildRoe({ ...target.input, assets }, new Date(), locale);
  writeOutput(format === 'json' ? roeToJson(doc) : roeToMarkdown(doc), values.out);
  process.stderr.write(
    `交戦規定（RoE）／スコープ宣言を出力しました（${target.layer}・許可対象 ${doc.inScope.length} 件・スコープ外 ${doc.outOfScope.length} 件）
`,
  );
}

/**
 * `export-attack-navigator`：検出脅威の references から ATT&CK Enterprise の technique を集め、
 * MITRE ATT&CK Navigator レイヤー（JSON）として出力する。CTEM / BAS / SOC での取り込み用（ベンダー中立）。
 */
export function runExportNavigator(values: CliValues, positionals: string[]): void {
  const file = positionals[1];
  if (!file) {
    fail(`入力ファイルを指定してください。

${USAGE}`);
  }
  const layer = parseEnum(values.layer, LAYER_KEYS, 'layer');
  const framework = parseEnum(values.framework, FRAMEWORKS, 'framework');
  const locale = parseEnum(values.locale, LOCALES, 'locale') ?? 'ja';
  setLocale(locale);

  let results: LayerAnalysisResult[];
  try {
    results = analyzeProject(readJsonFile(file), { layer, framework, locale });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const target = results[0];
  if (!target) fail('ノードのあるレイヤーがありません。');

  let attackerNodeId: string | undefined;
  if (values.node) {
    const ref = values.node.toLowerCase();
    const attacker = target.input.nodes.find(
      (n) => (n.seq != null ? formatElementalId('node', n.seq) : n.id).toLowerCase() === ref,
    );
    if (!attacker) fail(`ノード ${values.node} が見つかりません（${target.layer}）。`);
    if (!ATTACK_OBJECTIVE_APPLICABLE.has(attacker.type) || !attacker.attackObjectiveId) {
      fail(`ノード ${values.node} は攻撃目標（OBJECTIVE）を持つ攻撃者ではありません。`);
    }
    attackerNodeId = attacker.id;
  }

  const layerDoc = buildNavigatorLayer(target.input, new Date(), locale, { attackerNodeId });
  writeOutput(navigatorLayerToJson(layerDoc), values.out);
  process.stderr.write(
    `ATT&CK Navigator レイヤーを出力しました（${target.layer}・technique ${layerDoc.techniques.length} 件・ATLAS ${layerDoc.atlasTechniques.length} 件・攻撃シナリオ ${layerDoc.scenarioCount} 件${attackerNodeId ? `のうち ${values.node} のみ` : ''}）
`,
  );
}
