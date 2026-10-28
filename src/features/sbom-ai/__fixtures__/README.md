# CycloneDX 1.7 公式スキーマ（テスト用）

出力が CycloneDX 1.7 のスキーマに適合することを `ajv` で検証するための、公式スキーマの写し。
JSON はファイル冒頭にコメントを書けないため、出典と取得日はここに記す。

- 出典：https://github.com/CycloneDX/specification （`master` ブランチの `schema/`）
  - `bom-1.7.schema.json`・`spdx.schema.json`・`jsf-0.82.schema.json`・`cryptography-defs.schema.json`
  - 取得元 URL の例：https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.7.schema.json
- 取得日：2026-10-29
- ライセンス：Apache License 2.0（CycloneDX Specification）
- 無改変。`bom-1.7.schema.json` が `$ref` する 3 ファイル（spdx・jsf・cryptography-defs）も同梱している。
