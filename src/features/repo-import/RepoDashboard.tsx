import type { TranslationKey } from '../../i18n';
import type { RepoDashboardData } from './buildRepoDashboard';

/**
 * import-repo のエージェント ダッシュボードの描画。フック・ストアを使わない純粋な描画で、
 * 画面（モーダル）と CLI の単体 HTML（renderToStaticMarkup）で共有する。CSS は repoDashboardCss.ts。
 */

type T = (key: TranslationKey, params?: Record<string, string | number>) => string;

function Chips({ items }: { items: string[] }) {
  return (
    <div className="rd-chips">
      {items.map((s, i) => (
        <span key={`${i}:${s}`} className="rd-chip">
          {s}
        </span>
      ))}
    </div>
  );
}

export function RepoDashboard({ data, t }: { data: RepoDashboardData; t: T }) {
  const yn = (v: boolean | undefined) =>
    v === undefined ? t('repoDashboard.unknown') : v ? t('repoDashboard.yes') : t('repoDashboard.no');
  const totalPackages = data.manifests.reduce((n, m) => n + m.packages.length, 0);
  const lockedCount = data.manifests.filter((m) => m.posture?.dependencyLockfile === 'Locked').length;
  const scriptCount = data.manifests.reduce((n, m) => n + m.packages.filter((p) => p.hasInstallScript).length, 0);

  return (
    <div className="rd-root">
      <div className="rd-header">
        <h1 className="rd-title">
          {t('repoDashboard.title')}
          {data.repoName ? `: ${data.repoName}` : ''}
        </h1>
        <span className="rd-meta">{data.agent.label}</span>
        {data.collectedAt && <span className="rd-meta">{t('repoDashboard.collectedAt', { at: data.collectedAt })}</span>}
      </div>

      <h2 className="rd-section">{t('repoDashboard.alerts.title')}</h2>
      {data.alerts.length === 0 ? (
        <p className="rd-noalerts">{t('repoDashboard.alerts.none')}</p>
      ) : (
        <ul className="rd-alerts">
          {data.alerts.map((a, i) => (
            <li key={i} className={`rd-alert rd-alert-${a.level}`}>
              {t(a.key, a.params)}
            </li>
          ))}
        </ul>
      )}

      <div className="rd-kpis">
        <div className="rd-kpi">
          <div className="rd-kpi-label">{t('repoDashboard.kpi.packages')}</div>
          <div className="rd-kpi-value">{totalPackages}</div>
          <div className="rd-kpi-sub">
            {t('repoDashboard.kpi.packagesSub', { locked: lockedCount, manifests: data.manifests.length })}
          </div>
        </div>
        <div className="rd-kpi">
          <div className="rd-kpi-label">{t('repoDashboard.kpi.permissions')}</div>
          <div className="rd-kpi-value">
            {data.agent.allowCount} / {data.agent.denyCount}
          </div>
          <div className="rd-kpi-sub">
            {t('repoDashboard.kpi.permissionsSub', {
              tools: data.agent.tools.length > 0 ? data.agent.tools.join(', ') : t('repoDashboard.none'),
            })}
          </div>
        </div>
        <div className="rd-kpi">
          <div className="rd-kpi-label">{t('repoDashboard.kpi.assets')}</div>
          <div className="rd-kpi-value">
            {data.skills.length} / {data.commands.length} / {data.mcpServers.length}
          </div>
          <div className="rd-kpi-sub">
            {t('repoDashboard.kpi.assetsSub', {
              skills: data.skills.length,
              commands: data.commands.length,
              mcp: data.mcpServers.length,
            })}
          </div>
        </div>
        <div className="rd-kpi">
          <div className="rd-kpi-label">{t('repoDashboard.kpi.installScripts')}</div>
          <div className={`rd-kpi-value${scriptCount > 0 ? ' rd-kpi-value-warn' : ''}`}>{scriptCount}</div>
          <div className="rd-kpi-sub">{t('repoDashboard.kpi.installScriptsSub')}</div>
        </div>
      </div>

      {data.skills.length > 0 && (
        <details className="rd-details" open>
          <summary>{t('repoDashboard.skills', { count: data.skills.length })}</summary>
          <Chips items={data.skills} />
        </details>
      )}
      {data.commands.length > 0 && (
        <details className="rd-details" open>
          <summary>{t('repoDashboard.commands', { count: data.commands.length })}</summary>
          <Chips items={data.commands} />
        </details>
      )}

      {data.mcpServers.length > 0 && (
        <>
          <h2 className="rd-section">{t('repoDashboard.mcp.title', { count: data.mcpServers.length })}</h2>
          <div className="rd-table-wrap">
            <table className="rd-table">
              <thead>
                <tr>
                  <th>{t('repoDashboard.mcp.name')}</th>
                  <th>{t('repoDashboard.mcp.where')}</th>
                  <th>{t('repoDashboard.mcp.auth')}</th>
                  <th>{t('repoDashboard.mcp.encryption')}</th>
                  <th>{t('repoDashboard.mcp.description')}</th>
                </tr>
              </thead>
              <tbody>
                {data.mcpServers.map((m) => (
                  <tr key={m.id}>
                    <td>{m.label}</td>
                    <td className={m.internet ? 'rd-warn' : undefined}>
                      {m.internet ? t('repoDashboard.mcp.internet') : t('repoDashboard.mcp.local')}
                    </td>
                    <td className={m.auth === 'None' ? 'rd-bad' : undefined}>{m.auth ?? '-'}</td>
                    <td className={m.encryption === 'Plain' ? 'rd-bad' : undefined}>{m.encryption ?? '-'}</td>
                    <td className="rd-wrap">{m.description ?? ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {data.external.length > 0 && (
        <>
          <h2 className="rd-section">{t('repoDashboard.external.title', { count: data.external.length })}</h2>
          <ul className="rd-list">
            {data.external.map((e) => (
              <li key={e.id}>
                {e.label} <span className="rd-muted">({e.type})</span>{' '}
                <span className={e.encryption === 'Plain' ? 'rd-bad' : 'rd-muted'}>{e.encryption}</span>
              </li>
            ))}
          </ul>
        </>
      )}

      {data.manifests.map((m) => {
        // インストールスクリプトありを先頭へ（安定ソート）
        const pkgs = [...m.packages].sort((a, b) => Number(!!b.hasInstallScript) - Number(!!a.hasInstallScript));
        const scripts = m.packages.filter((p) => p.hasInstallScript).length;
        return (
          <details key={m.id} className="rd-details">
            <summary>
              {t('repoDashboard.manifest.summary', {
                label: m.label,
                kind: m.kind,
                count: m.packages.length,
                lockfile: m.posture?.dependencyLockfile ?? t('repoDashboard.unknown'),
                scripts: m.posture?.installScripts ?? (scripts > 0 ? scripts : t('repoDashboard.none')),
              })}
            </summary>
            <div className="rd-table-wrap">
              <table className="rd-table">
                <thead>
                  <tr>
                    <th>{t('repoDashboard.manifest.name')}</th>
                    <th>{t('repoDashboard.manifest.version')}</th>
                    <th>{t('repoDashboard.manifest.scope')}</th>
                    <th>{t('repoDashboard.manifest.script')}</th>
                    <th>{t('repoDashboard.manifest.registry')}</th>
                    <th>{t('repoDashboard.manifest.integrity')}</th>
                    <th>{t('repoDashboard.manifest.pinned')}</th>
                  </tr>
                </thead>
                <tbody>
                  {pkgs.map((p, i) => (
                    <tr key={`${i}:${p.name}`}>
                      <td>{p.name}</td>
                      <td>{p.version ?? ''}</td>
                      <td>
                        {p.dev
                          ? t('repoDashboard.scope.dev')
                          : p.optional
                            ? t('repoDashboard.scope.optional')
                            : t('repoDashboard.scope.prod')}
                      </td>
                      <td className={p.hasInstallScript ? 'rd-warn' : undefined}>
                        {p.hasInstallScript ? t('repoDashboard.yes') : ''}
                      </td>
                      <td>{p.resolvedHost ?? ''}</td>
                      <td>{yn(p.hasIntegrity)}</td>
                      <td>{yn(p.pinned)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </details>
        );
      })}

      {data.envFiles.length > 0 && (
        <>
          <h2 className="rd-section">{t('repoDashboard.env.title', { count: data.envFiles.length })}</h2>
          <p className="rd-note">{t('repoDashboard.env.note')}</p>
          <div className="rd-table-wrap">
            <table className="rd-table">
              <thead>
                <tr>
                  <th>{t('repoDashboard.env.file')}</th>
                  <th>{t('repoDashboard.env.template')}</th>
                  <th>{t('repoDashboard.env.gitIgnored')}</th>
                  <th>{t('repoDashboard.env.name')}</th>
                  <th>{t('repoDashboard.env.kind')}</th>
                  <th>{t('repoDashboard.env.length')}</th>
                </tr>
              </thead>
              <tbody>
                {data.envFiles.flatMap((f) =>
                  (f.items.length > 0 ? f.items : [undefined]).map((it, i) => (
                    <tr key={`${f.id}:${i}`}>
                      <td>{f.label}</td>
                      <td>{yn(f.template)}</td>
                      <td className={!f.template && f.gitIgnored === false ? 'rd-bad' : undefined}>
                        {yn(f.gitIgnored)}
                      </td>
                      <td>{it?.name ?? ''}</td>
                      <td>{it?.valueKind ?? ''}</td>
                      <td>{it?.length ?? ''}</td>
                    </tr>
                  )),
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
