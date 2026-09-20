/**
 * キャンバス（凡例・ノード描画・リンク作成）と描画定数の文言（日本語 = 真実）。
 * 集約は ../ja.ts。
 */
export const jaCanvas = {
  'canvas.legend.open': '凡例を開く',
  'canvas.legend.close': '凡例を閉じる',
  'canvas.legend.title': '凡例',
  'canvas.legend.components': 'コンポーネント',
  'canvas.legend.dataFlow': 'データフロー',
  'canvas.legend.trustBoundary': 'トラスト境界',

  'canvas.node.overflowCount': '他 {count} 件',

  'canvas.linking.inProgress': 'リンク作成中... 別のコンポーネントをクリックしてください',
  'canvas.linking.cancel': 'キャンセル',

  'canvas.boundaryType.rect': '外部境界',
  'canvas.boundaryType.dmz': 'DMZ',
  'canvas.boundaryType.macro': 'マクロセグメンテーション',
  'canvas.boundaryType.micro': 'マイクロセグメンテーション',

  'canvas.edgeNotation.plain': '平文（暗号化なし）',
  'canvas.edgeNotation.encrypted': '暗号化あり（TLS / E2EE）',
  'canvas.edgeNotation.highRisk': '高リスク経路（未認証 × Internet）',
} as const;
