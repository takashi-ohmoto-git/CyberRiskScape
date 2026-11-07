# SPDX 2.3 公式スキーマ（テスト用）

出力が SPDX 2.3 のスキーマに適合することを `ajv` で検証するための、公式スキーマの写し。
JSON はファイル冒頭にコメントを書けないため、出典と取得日はここに記す。

- 出典：https://github.com/spdx/spdx-spec （`support/2.3` ブランチの `schemas/spdx-schema.json`）
- 取得日：2026-11-05
- ライセンス：Creative Commons Attribution 3.0 Unported（SPDX specification）
- 無改変。ファイル名だけ `spdx-2.3.schema.json` に変えた。

# 他のフィクスチャ

- `trivy.cdx.json`：Trivy の `--format cyclonedx` を模した架空の CycloneDX 1.6（部品 2・脆弱性 2）。すべて架空のデータ。
- `syft.cdx.json`：Syft の `-o cyclonedx-json` を模した架空の CycloneDX 1.7（部品 3、OS 部品を含む、脆弱性なし）。すべて架空のデータ。
- `grype.cdx.json`：Grype の `-o cyclonedx-json` を模した架空の CycloneDX 1.7（部品 3・脆弱性 2。部品は bom-ref で解決される）。すべて架空のデータ。
