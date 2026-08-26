import { describe, expect, it } from 'vitest';
import { findDropTargetParent } from './parenting';
import type { DiagramNode } from '../model/types';
import { SHAPE_DIMENSIONS } from '../canvas/nodeGeometry';

/**
 * 内包可否を制御する最小限のレジストリ・モック。
 * `findDropTargetParent` は `canContain` と `get` しか触らないのでこれで十分。
 */
function makeRegistry(rules: Record<string, string[]>) {
  return {
    canContain: (parentType: string, childType: string) =>
      (rules[parentType] ?? []).includes(childType),
    get: () => undefined,
  };
}

// SHAPE_DIMENSIONS['rounded'] = { w: 128, h: 96 } を基準にテストを作る。
// 実 YAML を読まずに任意の type 名で書けるよう、未登録 type はフォールバックで rounded 扱い。

function node(id: string, type: string, x: number, y: number, parentId?: string): DiagramNode {
  return { id, type, x, y, ...(parentId ? { parentId } : {}) };
}

const D = SHAPE_DIMENSIONS.rounded; // { w: 128, h: 96 }

describe('findDropTargetParent', () => {
  it('対象ノードの中心が canContain 許可ノード内ならその ID を返す', () => {
    const target = node('container', 'PC', 0, 0);
    // dragged の中心 = (10+64, 10+48) = (74, 58)。container 領域 (0,0)-(128,96) 内。
    const dragged = node('doc', 'LOG', 10, 10);
    const parent = findDropTargetParent(dragged, [target, dragged], makeRegistry({ PC: ['LOG'] }));
    expect(parent).toBe('container');
  });

  it('canContain にない子型なら undefined を返す', () => {
    const target = node('container', 'PC', 0, 0);
    const dragged = node('doc', 'LOG', 10, 10);
    const parent = findDropTargetParent(dragged, [target, dragged], makeRegistry({ PC: [] }));
    expect(parent).toBeUndefined();
  });

  it('どのノードにも重なっていなければ undefined を返す（親解除）', () => {
    const target = node('container', 'PC', 0, 0);
    // dragged の中心 = (500+64, 500+48) = (564, 548)。container 領域外。
    const dragged = node('doc', 'LOG', 500, 500, 'container');
    const parent = findDropTargetParent(dragged, [target, dragged], makeRegistry({ PC: ['LOG'] }));
    expect(parent).toBeUndefined();
  });

  it('複数の候補が重なる場合は配列末尾（最前面）を優先', () => {
    const back = node('back', 'PC', 0, 0);
    const front = node('front', 'PC', 0, 0);
    const dragged = node('doc', 'LOG', 10, 10);
    const parent = findDropTargetParent(
      dragged,
      [back, front, dragged],
      makeRegistry({ PC: ['LOG'] }),
    );
    expect(parent).toBe('front');
  });

  it('自身を親候補にしない（自己ループ防止）', () => {
    const dragged = node('self', 'PC', 0, 0);
    const parent = findDropTargetParent(dragged, [dragged], makeRegistry({ PC: ['PC'] }));
    expect(parent).toBeUndefined();
  });

  it('子孫を親候補にしない（サイクル防止）', () => {
    // 構造：dragged(USER) > child(PC) > grandchild(LOG)
    // dragged を grandchild に重ねたら、grandchild は dragged の子孫なので除外
    const dragged = node('user', 'USER', 0, 0);
    const child = node('pc', 'PC', 0, 0, 'user');
    const grandchild = node('log', 'LOG', 10, 10, 'pc');
    // dragged の中心は grandchild の領域内（両方とも 0,0 基準で 128x96）
    const parent = findDropTargetParent(
      dragged,
      [dragged, child, grandchild],
      makeRegistry({ LOG: ['USER'] }), // 仮に LOG が USER を内包できるとしても
    );
    expect(parent).toBeUndefined();
  });

  it('境界線上（中心がちょうど右下角）は内側として扱う', () => {
    const target = node('container', 'PC', 0, 0);
    // 中心が (D.w, D.h) になるように配置
    const dragged = node('doc', 'LOG', D.w - D.w / 2, D.h - D.h / 2);
    const parent = findDropTargetParent(dragged, [target, dragged], makeRegistry({ PC: ['LOG'] }));
    expect(parent).toBe('container');
  });
});
