# セキュリティポリシー

## 脆弱性の報告

脆弱性を発見した場合は、**公開の Issue ではなく** GitHub の
[Security Advisory](https://github.com/takashi-ohmoto-git/CyberRiskScape/security/advisories/new)
から非公開でご報告ください（本リポジトリでは Private vulnerability reporting を
有効にしています）。

内容を確認のうえ、修正方針と対応時期をご連絡します。

> **English**: Please report vulnerabilities privately via
> [GitHub Security Advisories](https://github.com/takashi-ohmoto-git/CyberRiskScape/security/advisories/new),
> not through public issues.

## 対象バージョン

本プロジェクトはまだ正式リリース前です。サポート対象は `main` ブランチの最新版のみです。

## 既知の注意点

- **信頼できない YAML を読み込まないでください。** コンポーネントライブラリの
  インライン SVG アイコンは現在サニタイズされていないため、第三者が配布する
  ライブラリ YAML は内容を確認してから使用してください
- 本ツールは脅威モデリングの**設計支援**を目的としており、検出結果の網羅性や
  正確性を保証するものではありません。実際のリスク評価は専門家の判断と併用してください

## 設計上のセキュリティ特性

本ツールは**完全にクライアントサイドで動作**します。サーバへの通信はなく、
作成した設計データはブラウザの IndexedDB とユーザーが明示的に保存したファイルに
のみ残ります。設計内容が外部に送信されることはありません。
