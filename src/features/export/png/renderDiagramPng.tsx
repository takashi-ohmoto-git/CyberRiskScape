import { flushSync } from 'react-dom';
import { createRoot } from 'react-dom/client';
import { toBlob } from 'html-to-image';
import type { LayerData, ThreatView } from '../../../core/model/types';
import { computeContentBounds } from './contentBounds';
import { DiagramSnapshot, snapshotSize } from './DiagramSnapshot';

const nextFrame = () => new Promise<void>((r) => requestAnimationFrame(() => r()));

/**
 * レイヤーを画面外に静的描画して PNG（バイト列）にする。ストア・アクティブレイヤー・
 * ビューポートには一切触れない。空レイヤーは null。
 */
export async function renderDiagramPng(
  layer: LayerData,
  threats: ThreatView[],
  opts?: { pixelRatio?: number },
): Promise<Uint8Array | null> {
  const bounds = computeContentBounds(layer);
  if (!bounds) return null;
  const { width, height } = snapshotSize(bounds);

  const container = document.createElement('div');
  container.style.cssText = `position:fixed;left:-100000px;top:0;width:${width}px;height:${height}px;pointer-events:none;`;
  container.setAttribute('aria-hidden', 'true');
  document.body.appendChild(container);
  const root = createRoot(container);
  try {
    flushSync(() => root.render(<DiagramSnapshot layer={layer} threats={threats} bounds={bounds} />));
    // フォント・レイアウト確定待ち（EdgeLayer 等の effect 反映を含む）。
    await nextFrame();
    await nextFrame();
    if (document.fonts?.ready) await document.fonts.ready;
    const blob = await toBlob(container.firstElementChild as HTMLElement, {
      width,
      height,
      pixelRatio: opts?.pixelRatio ?? 2,
    });
    if (!blob) return null;
    return new Uint8Array(await blob.arrayBuffer());
  } finally {
    root.unmount();
    container.remove();
  }
}
