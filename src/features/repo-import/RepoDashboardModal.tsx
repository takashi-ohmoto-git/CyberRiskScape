import { useEffect, useMemo } from 'react';
import { X } from 'lucide-react';
import type { LayerData } from '../../core/model/types';
import { useT } from '../../i18n';
import { buildRepoDashboard } from './buildRepoDashboard';
import { RepoDashboard } from './RepoDashboard';
import { REPO_DASHBOARD_CSS } from './repoDashboardCss';

interface RepoDashboardModalProps {
  layer: LayerData;
  agentId: string;
  onClose: () => void;
}

/** エージェントのダッシュボードを開くモーダル。中身は CLI の単体 HTML と同じ RepoDashboard。 */
export function RepoDashboardModal({ layer, agentId, onClose }: RepoDashboardModalProps) {
  const t = useT();
  const data = useMemo(() => buildRepoDashboard(layer, agentId), [layer, agentId]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onMouseDown={onClose}
    >
      <div
        className="w-[96vw] h-[92vh] overflow-hidden bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-5 flex flex-col gap-3"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-end">
          <button
            onClick={onClose}
            className="text-slate-500 hover:text-slate-200 transition-colors"
            aria-label={t('panels.common.close')}
          >
            <X size={16} />
          </button>
        </div>
        <div className="flex-1 min-h-0 overflow-auto">
          {data ? (
            <>
              <style>{REPO_DASHBOARD_CSS}</style>
              <RepoDashboard data={data} t={t} />
            </>
          ) : (
            <p className="text-xs text-slate-400">{t('repoDashboard.unavailable')}</p>
          )}
        </div>
      </div>
    </div>
  );
}
