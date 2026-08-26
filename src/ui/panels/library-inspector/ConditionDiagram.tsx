import { componentRegistry } from '../../../component-library/defaultRegistry';
import { renderIcon } from '../../../component-library/iconRegistry';
import type { AppliesTo } from '../../../threat-library/schema/threatRule';
import { resolveFieldLabel } from '../appliesToSummary';
import { useLocale, useT } from '../../../i18n';

/** 型アイコン + ラベルの小さなチップ。`type` 未指定なら `label` をそのまま表示する。 */
function TypeChip({ type, label }: { type?: string; label?: string }) {
  const cfg = type ? componentRegistry.get(type) : undefined;
  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-lg border border-slate-700 bg-slate-800 text-xs font-bold text-slate-200 whitespace-nowrap">
      <span className={`${cfg?.color ?? 'bg-slate-500'} p-1 rounded text-white shrink-0`}>
        {renderIcon(cfg?.icon ?? { kind: 'builtin', name: 'box' }, { size: 10 })}
      </span>
      {cfg?.label ?? label ?? type}
    </span>
  );
}

/** boolean/配列マップを `ラベル=値` チップの列にする（attackSurface / agentAttributes / peerAttackSurface 共用）。 */
function toChipEntries(
  match: Record<string, unknown> | undefined,
  locale: ReturnType<typeof useLocale>[0],
): [string, string][] {
  if (!match) return [];
  return Object.entries(match)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => [
      resolveFieldLabel(k, locale),
      Array.isArray(v) ? v.join('/') : String(v),
    ]);
}

interface ConditionDiagramProps {
  appliesTo: AppliesTo;
  /** node kind の場合、どの型を中心に描くか（`anyOf` は複数あるため呼び出し側の選択型を渡す）。 */
  centerType?: string;
}

/**
 * ルールの発火条件を簡易な図解にする（キャンバスの再現ではなく、条件の可視化）。
 * SVG は使わず flex + 矢印記号のみ。中心の型と、接続先ピア型・方向を示し、
 * 攻撃面／エージェント属性条件は下部にチップで添える。
 */
export function ConditionDiagram({ appliesTo, centerType }: ConditionDiagramProps) {
  const [locale] = useLocale();
  const t = useT();

  if (appliesTo.kind === 'node') {
    const conn = appliesTo.connection;
    const peerTypes = conn?.peerType;
    const direction = conn?.direction ?? 'any';
    const center = centerType ?? appliesTo.nodeType ?? appliesTo.anyOf?.[0]?.nodeType;

    const chipEntries: [string, string][] = [
      ...toChipEntries(appliesTo.attackSurface, locale),
      ...toChipEntries(
        appliesTo.agentAttributes as unknown as Record<string, unknown> | undefined,
        locale,
      ),
      ...toChipEntries(conn?.peerAttackSurface, locale),
    ];

    return (
      <div>
        <div className="flex items-center gap-2 flex-wrap">
          {peerTypes && direction === 'inbound' && (
            <>
              <div className="flex gap-1 flex-wrap">
                {peerTypes.map((p) => (
                  <TypeChip key={p} type={p} />
                ))}
              </div>
              <span className="text-slate-600">→</span>
            </>
          )}
          <TypeChip type={center} />
          {peerTypes && direction === 'outbound' && (
            <>
              <span className="text-slate-600">→</span>
              <div className="flex gap-1 flex-wrap">
                {peerTypes.map((p) => (
                  <TypeChip key={p} type={p} />
                ))}
              </div>
            </>
          )}
          {peerTypes && direction === 'any' && (
            <>
              <span className="text-slate-600">↔</span>
              <div className="flex gap-1 flex-wrap">
                {peerTypes.map((p) => (
                  <TypeChip key={p} type={p} />
                ))}
              </div>
            </>
          )}
        </div>
        {chipEntries.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-1.5">
            {chipEntries.map(([k, v]) => (
              <span
                key={k}
                className="border border-slate-700 rounded px-1.5 py-0.5 text-xs text-slate-400"
              >
                {k}={v}
              </span>
            ))}
          </div>
        )}
      </div>
    );
  }

  // kind === 'edge'
  const leaf = appliesTo.when ?? appliesTo.allOf?.[0] ?? appliesTo.anyOf?.[0];
  const sourceTypes = leaf?.sourceType;
  const targetTypes = leaf?.targetType;
  const anyLabel = t('libraryInspector.diagram.anyType');

  return (
    <div className="flex items-center gap-2 flex-wrap">
      {sourceTypes && sourceTypes.length > 0 ? (
        <div className="flex gap-1 flex-wrap">
          {sourceTypes.map((s) => (
            <TypeChip key={s} type={s} />
          ))}
        </div>
      ) : (
        <TypeChip label={anyLabel} />
      )}
      <span className="text-slate-600">→</span>
      {targetTypes && targetTypes.length > 0 ? (
        <div className="flex gap-1 flex-wrap">
          {targetTypes.map((tp) => (
            <TypeChip key={tp} type={tp} />
          ))}
        </div>
      ) : (
        <TypeChip label={anyLabel} />
      )}
    </div>
  );
}
