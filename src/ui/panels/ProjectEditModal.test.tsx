import { afterEach, describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { ProjectEditModal } from './ProjectEditModal';
import { useDiagramStore } from '../../core/state/diagramStore';
import { EMPTY_PROJECT_META, type ProjectMeta } from '../../core/model/types';

// サーバー描画（renderToStaticMarkup）は zustand の初期状態スナップショットを読むため、
// setState に加えて初期状態にも同じ値を入れる。
function openModal(projectMeta: ProjectMeta) {
  const patch = { isProjectEditOpen: true, projectMeta };
  useDiagramStore.setState(patch);
  Object.assign(useDiagramStore.getInitialState(), patch);
}

describe('ProjectEditModal', () => {
  afterEach(() => {
    const reset = { isProjectEditOpen: false, projectMeta: EMPTY_PROJECT_META };
    useDiagramStore.setState(reset);
    Object.assign(useDiagramStore.getInitialState(), reset);
  });

  it('開いた状態では「組織と運用」の見出し・6 項目のラベル・プロジェクト ID を描画する', () => {
    openModal({ ...EMPTY_PROJECT_META, lifecycle: 'legacy' });
    const { projectId } = useDiagramStore.getState();
    const html = renderToStaticMarkup(<ProjectEditModal />);
    for (const text of [
      '基本情報',
      '体制',
      '組織と運用',
      '目的と目標',
      '前提と依存',
      '所属組織',
      '組織コード',
      '部門',
      '外部台帳の ID',
      'システムの重要度',
      '運用段階',
      projectId,
      '稼働中だが、保守終了・更改予定などで更新が難しく、稼働を継続させているもの。',
    ]) {
      expect(html).toContain(text);
    }
  });

  it('閉じた状態では何も描画しない', () => {
    useDiagramStore.setState({ isProjectEditOpen: false });
    Object.assign(useDiagramStore.getInitialState(), { isProjectEditOpen: false });
    expect(renderToStaticMarkup(<ProjectEditModal />)).toBe('');
  });
});
