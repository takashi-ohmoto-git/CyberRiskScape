import { describe, expect, it } from 'vitest';
import { renderNodeTemplate } from './renderTemplate';
import type { DiagramNode } from '../model/types';

/** 影響範囲トークン（[[plan]] §2.40 ①）の展開。 */
const idp: DiagramNode = { id: 'idp', type: 'IDENTITY_PROVIDER', x: 0, y: 0, label: 'Entra ID' };
const appA: DiagramNode = { id: 'a', type: 'PROCESS', x: 0, y: 0, label: '業務アプリ A' };
const appB: DiagramNode = { id: 'b', type: 'PROCESS', x: 0, y: 0, label: '業務アプリ B' };

describe('{{dependentCount}} / {{dependentNames}}', () => {
  it('依存コンポーネントの件数と名前を展開する', () => {
    const out = renderNodeTemplate('{{nodeName}}: {{dependentCount}} 件（{{dependentNames}}）', idp, [
      appA,
      appB,
    ]);
    expect(out).toBe('Entra ID: 2 件（業務アプリ A、業務アプリ B）');
  });

  it('依存ゼロでも文が壊れない（0 と明示的な語を返す）', () => {
    const out = renderNodeTemplate('{{dependentCount}} 件（{{dependentNames}}）', idp, []);
    expect(out).toBe('0 件（この図では宣言なし）');
  });

  it('dependents を渡さない呼び出しは依存ゼロ扱い', () => {
    expect(renderNodeTemplate('{{dependentCount}}', idp)).toBe('0');
  });

  it('未知トークンは原文のまま残す（typo 検知の既存方針を壊さない）', () => {
    expect(renderNodeTemplate('{{dependentTotal}}', idp, [appA])).toBe('{{dependentTotal}}');
  });

  it('既存トークンの挙動は変わらない', () => {
    expect(renderNodeTemplate('{{nodeName}}', idp, [appA])).toBe('Entra ID');
  });
});
