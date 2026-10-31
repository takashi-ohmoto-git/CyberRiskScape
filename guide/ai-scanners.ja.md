# エージェントスキル・MCP サーバーの検査結果を脅威モデルと突き合わせる（Cisco AI Defense skill-scanner / mcp-scanner）

[English](ai-scanners.md) | **日本語**

> Cisco、skill-scanner、mcp-scanner は各権利者の名称です。Cisco は Cisco Systems, Inc. の商標です。このページは「Cisco AI Defense の
> skill-scanner / mcp-scanner が出力した検査結果を、CyberRiskScape の脅威モデルと突き合わせる方法」を説明するもので、各スキャナーの開発者が提供・認定・推奨するものではなく、
> 提携を意味しません。記述的な使用です。スキャナーの出力の形式は、執筆時点（2026 年 10 月）の公式のソースによります。最新は公式の情報で確かめてください。

> **検査してよい範囲** — スキャナーで検査するのは、**自組織が管理する、または検査を許可されたスキルと MCP サーバーだけ**にしてください。
> このページの突き合わせは、検査済みの結果ファイルを読むだけです。スキャナーにも Cisco AI Defense の API にも接続せず、新しく検査はしません。

---

## 1. このページで分かること・前提

- エージェントスキルの検査ツール（skill-scanner）と MCP サーバーの検査ツール（mcp-scanner）の**結果ファイルを、構成図から検出した脅威と突き合わせる**方法
  （`findings-report --skill-scanner` / `--mcp-scanner`）。「指摘が、図のどの脅威と同じことを言っているか」「図に無い（描き漏れの）指摘はどれか」が分かります
- 突き合わせる範囲を 1 つのスキル・MCP サーバーに絞る方法（`--node`）
- CI で重大度のゲートにする方法（`--fail-on`）
- 読み込まないもの（秘密情報の扱い）と、**限界**

**前提**

- 構成図（CyberRiskScape のプロジェクト JSON）に、スキルや MCP サーバーのノードがある。
- スキャナーの結果ファイル（JSON）がある。スキャナーは Python 製です（§3）。**どちらか片方だけでも使えます。**
- Node.js が動くこと。CLI をビルドしておきます（`npm ci && npm run build:cli`）。
- **CLI 専用です。** 画面から結果ファイルを読み込むことはできません（§10）。

**手段の選び方（どれか一つで足りる）**：このページの手順は、次の**どれか一つ**から始められます。全部を揃える必要はありません。

| 手段 | 向いている場合 | 前提条件 |
|---|---|---|
| skill-scanner だけ | 社内で使うスキルを増やしている | Python 3.11 以上（公式の記載は CPython 3.11–3.14）。スキャナーのインストール |
| mcp-scanner だけ | MCP サーバー（自作・導入）を増やしている | Python 3.11 以上。サーバーに接続できること、または設定ファイルがあること |
| 両方 | スキルも MCP サーバーも使っている | 上の両方。突き合わせはスキャナーごとに 1 回ずつ実行する |

**このページの前提となる知識**：[はじめに](getting-started.ja.md)の操作と、[脅威パネルの読み方](reading-threats.ja.md)。

---

## 2. なぜ組み合わせるか

| | スキャナー（skill-scanner / mcp-scanner） | CyberRiskScape |
|---|---|---|
| 見る単位 | **部品**（1 つのスキル、1 つの MCP サーバーとそのツール） | **全体**（エージェント・データ・権限・経路のつながり） |
| 答える問い | この部品に**悪いものが入っていないか** | その部品が悪用されたら、**どこまで届くか** |

指摘が 1 件でもあれば直す価値はありますが、**その指摘が図のどこに響くか**（エージェントが持つ権限・つながっているデータ）は、スキャナーだけでは分かりません。
逆に、指摘が 0 件でも安全とは限りません。skill-scanner の README 自身が、指摘が無くても脅威が無いことの保証にはならないこと、重要な用途ではスキャナーの結果に
手作業のレビューや脅威モデリングを組み合わせるべきことを述べています（出典：公式 README の「Scope and Limitations」。参考リンク 1）。

このページの突き合わせは、その組み合わせを機械的に行うものです。

1. スキャナーの指摘に付いた AITech / AISubtech の分類コードを、**対応表**で脅威ライブラリの `canonicalId` に変える（§7）
2. 構成図から検出した脅威のうち、同じ `canonicalId` のものを探す
3. 見つかれば「図の脅威がコードで確認された」、見つからなければ「図に該当する脅威が無い（描き漏れ候補）」

---

## 3. スキャナーを実行する

### 3.1 skill-scanner

```bash
pip install cisco-ai-skill-scanner
skill-scanner scan ./my-skill --use-llm --format json --output skill-result.json
skill-scanner scan-all ./skills --recursive --use-llm --format json --output skill-result.json
```

- `--format json` の出力を読みます。1 つのスキルなら単体、`scan-all` なら複数スキルをまとめた形です。どちらも読めます。
- **LLM による判定（`--use-llm`）は任意で、LLM プロバイダの API キー（有償のことがあります）が要ります。** Cisco AI Defense の API を使う選択肢（`--use-aidefense`）も同様です。
- **ルールだけの検査（`--use-llm` なし）は、検出が限られます。** 公式は、推奨設定のすべてで LLM の判定を使うこと、ルールだけでは悪意のあるスキルの一部しか捉えられないことを書いています。
  設定の選び方は公式の README を見てください（参考リンク 1）。
- 結果に出る分類コード（`AITech-…` / `AISubtech-…`）が、突き合わせの鍵です。

### 3.2 mcp-scanner

```bash
uv tool install --python 3.13 cisco-ai-mcp-scanner
# 1 つのサーバー
mcp-scanner --analyzers yara --format raw --server-url https://mcp.example.com/mcp > mcp-result.json
# 結果の配列だけを出す（--raw）
mcp-scanner --analyzers yara --raw --server-url https://mcp.example.com/mcp > mcp-result.json
# 手元の設定ファイルに書かれたサーバーをまとめて
mcp-scanner --analyzers yara --raw known-configs > mcp-known-configs.json
```

- 読めるのは `--format raw`、`--raw`、`known-configs --raw` の 3 種類です。`summary` や `table` など、人向けの表示は読めません。
- `--analyzers yara` はルールだけの検査で、API キーは要りません。**LLM の解析器（`llm`）や Cisco AI Defense の解析器（`api`）は任意で、キー（有償のことがあります）が要ります。**
  ルールだけでは検出が限られます。解析器の選び方は公式の README を見てください（参考リンク 2）。
- **stdio のサーバーを検査すると、そのサーバーのプロセスが起動します。** 信頼できないものは、隔離した環境で実行してください。
- 結果には、検査が完了しなかった項目（`status` が `completed` 以外）も入ります。§6 の「検査が完了していない項目」に数えます。

> CyberRiskScape が行うのは、**これらの結果ファイルを読むことだけ**です。スキャナーの実行・Cisco AI Defense や LLM の API の呼び出しはしません。

---

## 4. 突き合わせる

### 4.1 コマンド

```bash
npm run build:cli
node dist-cli/main.js findings-report my-project.json --skill-scanner skill-result.json
node dist-cli/main.js findings-report my-project.json --mcp-scanner mcp-result.json --node C3
```

| オプション | 意味 |
|---|---|
| `<project.json>` | 突き合わせる図のプロジェクト JSON（必須） |
| `--skill-scanner <file>` / `--mcp-scanner <file>` | スキャナーの結果。`--veracode` と合わせて**ちょうど 1 つ**を指定する |
| `--node <C番号>` | 対象のノード（任意）。§5 |
| `--format <md\|json>` | 出力形式。既定は `md` |
| `--fail-on <Critical\|High\|Medium\|Low>` | 図で指定の重大度以上の脅威に当たる指摘があれば exit 1（§9） |
| `--layer`・`--framework`・`--locale`・`--out` | 対象レイヤー・フレームワーク・表示言語・出力先（他の `findings-report` と同じ） |

- 入力のプロジェクト JSON も結果ファイルも書き換えません。
- 標準エラー出力に、未解決・一致・構成図に無い・対応づけできない件数が 1 行で出ます。
- 表示言語は `--locale en` で英語にできます。

### 4.2 実行例（同梱の架空サンプル）

次の出力は、リポジトリ同梱の**架空の**サンプルで実行したものです（図は業務エージェント・請求書スキル・社内検索 MCP の 3 ノード。スキャナーの結果も架空）。

```bash
node dist-cli/main.js findings-report \
  src/features/findings-report/__fixtures__/cisco-sample-project.json \
  --skill-scanner src/features/findings-report/__fixtures__/skill-scanner-single.json
```

```text
突き合わせました（未解決 4 件・一致 2 件・構成図に無い 0 件・対応づけできない 2 件・除外 SCA 0 件／解決済み 0 件）
```

```text
# 脆弱性スキャン結果と脅威モデルの突き合わせ

skill-scanner の指摘を、AITech 分類の対応表を介して構成図から検出した脅威と突き合わせた結果です。対応表にない分類の指摘は「対応づけできない指摘」に出ます。

- 未解決の指摘: 4 件
- 構成図の脅威と一致: 2 件（脅威 5 件）
- 構成図に該当する脅威がない: 0 件
- 対応づけできない: 2 件

## 構成図の脅威がコードで確認されたもの

### direct-prompt-injection

構成図の脅威:
- [L1] Critical 直接プロンプトインジェクション — C1 業務エージェント (owasp-llm01-prompt-injection-001)

- 指摘: 1 件（重大度の最大 HIGH）
  - #sk-001 [HIGH] AISubtech-1.1.1 Prompt injection: override of prior instructions (invoice-helper/SKILL.md:12)

（以降、tool-descriptor-poisoning・excessive-agency が同じ形で続く）

## 対応づけできない指摘

- **AISubtech-15.1.9 Hate Speech** — 指摘: 1 件（重大度の最大 LOW）
  - #sk-003 [LOW] AISubtech-15.1.9 Hate speech in reference file (invoice-helper/reference/notes.md:3)
- **分類なし** — 指摘: 1 件（重大度の最大 INFO）
  - #sk-004 [INFO] Unclassified note (invoice-helper/SKILL.md)
```

（「優先して確認する指摘」「構成図に該当する脅威がない指摘」「ゲート判定」の節は省略しています。）

MCP サーバーの結果を、`C3`（社内検索 MCP）に絞って `--fail-on High` を付けた例です。

```bash
node dist-cli/main.js findings-report \
  src/features/findings-report/__fixtures__/cisco-sample-project.json \
  --mcp-scanner src/features/findings-report/__fixtures__/mcp-scanner-envelope.json \
  --node C3 --fail-on High
```

```text
対象ノード: C3（このノード・接する線・線の先のノード・内包の親子の脅威とだけ突き合わせています）

- 未解決の指摘: 3 件
- 構成図の脅威と一致: 2 件（脅威 3 件）
- 構成図に該当する脅威がない: 0 件
- 対応づけできない: 1 件
- 検査が完了していない項目: 1 件（検査できていない項目は安全とは限りません）

## ゲート判定

FAIL（High 以上の未抑制の脅威に当たる指摘が 2 件）
```

このとき終了コードは 1 です。機械処理には `--format json` を使います（キー名は英語固定。`summary`・`confirmed`・`notInModel`・`unmapped` などを含みます）。

---

## 5. `--node` — 突き合わせる範囲を絞る

`--node C3` のように指定すると、図の脅威のうち次のものとだけ突き合わせます。指定しなければ図全体です。

- そのノード自身の脅威
- そのノードに**接する線**の脅威
- 線の**先のノード**の脅威
- そのノードを**内包する親・内包される子**の脅威

**なぜノード自身より広いのか**：スキルや MCP サーバーの悪意あるコードは、**それを呼び出す側のエージェントの上で動きます**。
そのため、指摘が響く先は、スキル自身だけでなく、つながっているエージェントやデータにも及びます。
（クラウドの検査を載せる [Prowler](prowler.ja.md) は資源そのものの設定を見るので「ノード自身だけ」です。ここは 1 段広げています。）

`--node` に指定した C 番号が対象のレイヤーに無い場合はエラー（終了コード 2）になり、指定できる ID が表示されます。

---

## 6. 結果の読み方

| 見出し | 意味 | することの例 |
|---|---|---|
| 構成図の脅威がコードで確認されたもの | 指摘の分類が、図で検出されている脅威と同じ `canonicalId` に当たる | 図の脅威の重大度と、指摘の重大度の両方を見て直す順序を決める。図の脅威カードの対策も確認する |
| 構成図に該当する脅威がない指摘（描き漏れ候補） | 分類は対応表にあるが、図にその脅威が出ていない | その部品が図に描かれていない、または属性・線が足りない可能性。**図に描き足す** |
| 対応づけできない指摘 | 分類が対応表に無い、または分類が付いていない | スキャナーの指摘として別途扱う。対応表を足す価値があるかを検討する |
| 検査が完了していない項目 | mcp-scanner の `status` が `completed` 以外（`partial`・`failed`・`skipped`） | **検査できていない項目は安全とは限りません。** 原因（接続・キー・タイムアウト）を直して再実行する |

- 「優先して確認する指摘」は、図の脅威の重大度とスキャナーの重大度の両方から並べた上位の指摘です。
- **重大度の違い**：skill-scanner は指摘ごとに重大度（CRITICAL〜INFO）を持ちます。mcp-scanner は**解析器ごとの集約の重大度**で、指摘ごとの重大度はありません。
- **「未解決」が出す件数**：スキャナーの指摘はすべて未解決として数えます（Veracode のような「解決済み」の概念が結果に無いため）。

---

## 7. AITech 対応表

対応表は [`data/finding-maps/aitech.yaml`](../data/finding-maps/aitech.yaml) です（脅威の知識と同じく、コードではなく YAML にあります）。
分類は Cisco AI Security and Safety Taxonomy（AITech = 技術、AISubtech = サブ技術）のコード体系だけを参照し、定義文は転載していません。

- **引き方**：指摘の AISubtech の行があればそれ、無ければ親の AITech の行。
- **古い番号を受け止める**：mcp-scanner は古いサブ技術の番号を出すことがあります（例：Tool Shadowing が `AISubtech-12.1.5`。分類の 2.0.0 では 12.1.4）。
  サブ技術の番号がずれていても、親の AITech（この例なら `AITech-12.1`）の行で受け止めます。
- **意図的に載せないもの**：有害コンテンツの種別（暴言・差別など。マルウェアは載せています）、個人情報の種別、センサー、クロスモーダルなど、
  構成図の脅威としては当てはまりにくいもの。載せないコードの指摘は「対応づけできない指摘」に出ます。
- 1 つのコードが複数の `canonicalId` に当たることがあります。図の側にどれが出ているかで、確認される脅威が決まります。
- スキルや MCP サーバーに当たる `canonicalId` は少数です（スキル 5・MCP サーバー 3）。コード実行や持ち出しなどは、スキルを読み込む**エージェント**側のルールで出ます。
  だからこそ §5 の `--node` が呼び出し側まで見ます。
- 対応表の追加・修正は、コードを触らずに YAML だけでできます。

---

## 8. 秘密情報の扱い

スキャナーの結果には、検査したコードの断片や接続情報が入ることがあります。取り込みは次のように扱います。

- **読まないもの**：`snippet`（コードの断片。埋め込まれた秘密をそのまま含みうる）・`description`・`remediation`（自由記述）・`tool_description`・
  `server_url`（stdio ではコマンドと引数。トークンを含みうる）・`skill_path`（絶対パスなど環境の情報）・`server_source`。
- **出力に出るのは**：指摘の識別子・重大度・分類コード・短い題名・場所（スキル内の相対パスと行、MCP のサーバー名とツール名）だけです。
- テストで、秘密に見える値が出力に含まれないことを確かめています。
- **結果ファイルは、そのまま扱わない**でください。上記のうち読まない項目を含むため、公開のリポジトリ・チケット・チャットに置かないでください。

---

## 9. CI で使う

スキャナーの結果ファイルを作ってから、`findings-report --fail-on` で重大度のゲートにします。
CLI のビルドは [CI に組み込む](ci-integration.ja.md)と同じ書き方です。

```yaml
name: ai-scanners
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4          # 本番では commit SHA に固定する
      - uses: actions/checkout@v4
        with:
          repository: takashi-ohmoto-git/CyberRiskScape
          ref: <commit SHA>                 # タグではなく SHA に固定する
          path: crs
      - run: cd crs && npm ci && npm run build:cli
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install cisco-ai-skill-scanner
      - name: Scan skills (rules only; add --use-llm with a key for better detection)
        run: skill-scanner scan-all ./skills --recursive --format json --output skill-result.json
      - name: Cross-reference with the threat model
        run: node crs/dist-cli/main.js findings-report threat-model/project.json --skill-scanner skill-result.json --fail-on High --out findings-report.md
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: findings-report
          path: findings-report.md
```

- `--fail-on High` は、**図で High 以上の脅威に当たる指摘**があるときに exit 1 にします。図に該当が無い指摘・対応づけできない指摘は、ゲートに数えません
  （レポートには出ます）。
- ルールだけの検査は検出が限られます。ゲートが通っても「安全」とは言えません（§10）。LLM の判定を使うなら、キーは `secrets` で渡し、結果ファイルを作る手順のステップにだけ渡してください。
- 検査が完了していない項目（mcp-scanner）は、件数がレポートに出ますが、ゲートの対象ではありません。レポートを確認してください。
- 結果ファイルとレポートは、アーティファクトに残す場合も、公開リポジトリでは取り扱いに注意してください（§8）。

---

## 10. 限界

- **動作確認は、公式のドキュメントとコードに合わせた架空のサンプルで行っています。実環境のスキャナーの出力では確かめていません。**
  スキャナーの出力の形式は将来変わりえます。読めない項目は件数に出るので、最初は件数が想定どおりかを確かめてください。
- **指摘が無くても、脅威は消えません。** 図の脅威は、スキャナーとは無関係に、構成から出ています。大方針は「未入力は悪い値と同じ扱い」で、
  指摘が 0 件でも、図の脅威を減らすのは対策と入力の実態だけです。スキャナーの README が述べるとおり、指摘が 0 件は安全の保証ではありません。
- **対応するのは対応表にあるコードだけです。** 載っていない分類は「対応づけできない指摘」に出ます。
- **運用状況は自動で埋めません。** たとえばスキルの審査状況（`skillVetting`）を、スキャナーを通したからといって「実施済み」にはしません。
  図は変えないので、入力は人が行います。
- **画面からは使えません。** CLI でファイルを読む方式だけです。Cisco AI Defense の API・スキャナーの実行は CyberRiskScape からはしません。
- **スキャナーの重大度と図の重大度は別物です。** 並べて示しますが、合算や補正はしません。

---

## 参考リンク

1. skill-scanner（GitHub） — <https://github.com/cisco-ai-defense/skill-scanner>
   出力形式 — <https://github.com/cisco-ai-defense/skill-scanner/blob/main/docs/reference/output-formats.md>
2. mcp-scanner（GitHub） — <https://github.com/cisco-ai-defense/mcp-scanner>
   出力形式 — <https://github.com/cisco-ai-defense/mcp-scanner/blob/main/docs/output-formats.md>

---

## 次に読むもの

- 脅威の読み方 — [脅威パネルの読み方](reading-threats.ja.md)
- 突き合わせの考え方が近い連携 — [Veracode の指摘を AI で直す](veracode-remediation.ja.md)
- CI への組み込み — [AI駆動開発のCIに組み込む](ci-integration.ja.md)
- 検出した脅威から攻撃経路を調べる — [攻撃経路分析](attack-paths.ja.md)
- クラウドの検査結果を図に載せる — [Prowler の検査結果を構成図に載せる](prowler.ja.md)
