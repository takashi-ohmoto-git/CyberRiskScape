# オフライン・ログトリアージ

[English](README.md) | **日本語**

`crs_triage.py` は、侵害の疑いがあるときに、ログを一次トリアージするオフラインのツールです。ログのコピーから
クラッシュ・メモリ不足のパターンを探し、アクセスログの `POST` + 5xx と時刻で突き合わせ、Web ルートで最近変更された
ファイルを一覧にします。Python 3.8 以上、標準ライブラリのみで、外部通信はしません。

> **侵害の有無は判定しません。痕跡が見つからなくても、安全の証明にはなりません。** アプリがログを書く前に起きる問題は
> 痕跡が残らないことがあり、ログが欠けたり改ざんされたりしている場合もあります。ヒットは「どこから見るか」の優先度付けに
> 使ってください。

## 始める前に

- ログ（と Web ルート）は**コピー**を使い、コピーを読み取り専用で扱ってください。このツールは入力を読むだけで、
  書くのは指定したレポートファイルだけです。
- 検索パターンはツールに組み込まれていません。JSON ファイル（`--patterns`）で渡します。これでツール自体は特定の
  脆弱性に依存しません。

## 実行の前提条件

| 項目 | 前提 |
|---|---|
| 実行環境 | Python 3.8 以上（標準ライブラリのみ。追加のインストールは不要）。Linux・macOS・Windows で動きます |
| ネットワーク | 不要です。名前解決（DNS）も含め、外部とは一切通信しません。閉じた調査用の端末で実行できます |
| ホスト名 | `--host` に指定した文字列を、そのまま結果に書きます。省略すると、**実行したマシンの OS のホスト名**（DNS には問い合わせません）になります。**別のマシンでコピーを調べるときは、元のホスト名を `--host` で必ず指定してください。** 調査報告（`investigation-report`）は、この名前を対応表（`hosts.json`）の `host` と文字列で照合します |
| 読み取り権限 | ログを読める権限が要ります。`/var/log` の多くは root や adm グループしか読めません。読めなかったファイルやディレクトリは、止まらずに `skipped` に記録されます |
| 書き込み | `--output`・`--json` の書き出し先だけに書きます。入力は読むだけです |
| ログの形式 | テキストのログと `.gz` を読みます。systemd journal・バイナリ・`.gz` 以外の圧縮は、先にテキストへの書き出しや展開が要ります（「限界」参照） |
| `--days` の起点 | **実行した時点**から数えます。コピーを取ってから日が経ってから実行する場合は、その日数を足してください |
| Web ルートの時刻 | 最近の変更は、ファイルの mtime と ctime の新しい方で判定します。**コピーするとどの OS でも ctime はコピーした時刻になる**ため、コピーした Web ルートでは全ファイルが「最近」に出ます。その場合はレポートの mtime の列で見てください（`cp -a`・`tar -p`・`rsync -a` で mtime を保ってコピーする）。ctime も使うなら、元のサーバー上で読むだけで実行するか、ディスクイメージを読み取り専用でマウントして実行します |
| タイムゾーン | ログの時刻は、ログに書かれた表記のまま扱います。ファイルの時刻（mtime・ctime）は、**実行したマシンのタイムゾーン**で表示されます |

**実行のしかたは 2 通りあります。**

- **別のマシンでコピーを調べる**（推奨）：元のサーバーからログ（と Web ルート）をコピーし、調査用の端末で `--logs`・`--webroot`・`--host` を指定して実行します
- **元のサーバーで直接実行する**：`--logs` の既定は `/var/log`、`--host` の既定はそのサーバーのホスト名です。ログを読むために root 権限が要ることが多く、調査対象の環境で
  スクリプトを動かすことになります。組織の証拠保全の手順で許される場合だけにしてください

## 使い方

```bash
# 1. パターンを書き出す（同梱の調査テンプレートから。モデルは不要）
node dist-cli/main.js export-triage-patterns --out patterns.json     # 事前に `npm run build:cli`

# 2. ログのコピーに対して実行する
python3 tools/triage/crs_triage.py --patterns patterns.json \
  --logs ./logs_copy --webroot ./www_copy --days 3 --host web01 \
  --output report.md --json report.json

# 3. report.json（や Velociraptor の収集結果）を脅威モデルに重ねて報告する
node dist-cli/main.js investigation-report model.json \
  --evidence report.json --evidence ./velociraptor_collections \
  --hosts hosts.json --out investigation-report.md
#    hosts.json: {"hosts":[{"host":"web01","node":"C3"}]}（大文字小文字は無視。FQDN の先頭ラベルでも一致）
```

`tools/triage/patterns.example.json` は、手順 1 の出力の便宜上のコピーです。正本は CLI
（`data/investigation-templates/compromise.yaml` の `tools.triage` 節）なので、サンプルを直接編集せず、書き出し直してください。

## オプション

| オプション | 既定値 | 意味 |
|---|---|---|
| `--patterns <file>` | （必須） | パターンファイル（JSON。下記） |
| `--logs <dir>` | `/var/log` | ログのディレクトリ。配下の全ファイルを走査し、`.gz` はそのまま読みます |
| `--webroot <dir>` | なし | 最近変更されたファイルを調べる Web ルート |
| `--days <n>` | 3 | Web ルートをさかのぼる日数 |
| `--window <min>` | 5 | `POST` + 5xx の前後で相関を見る幅（分） |
| `--output <file>` | `crs_triage_report.md` | Markdown のレポート |
| `--json <file>` | なし | JSON のレポート |
| `--host <name>` | このマシン | 元のホスト名（別の場所でコピーを調べるときに指定） |
| `--client-ip-regex <re>` | 行の先頭のフィールド | クライアント IP を取り出す正規表現。名前付きグループ `(?P<ip>...)` が必要（例：`X-Forwarded-For`） |

## パターンファイル

```json
{
  "format": "cyberriskscape-triage-patterns",
  "version": 1,
  "id": "my-patterns",
  "logPatterns": [
    { "id": "kernel-oom-killed-process", "category": "kernel-oom", "regex": "Out of memory: Killed process", "priority": 10 }
  ],
  "accessLog": { "method": "POST", "statuses": [500, 502, 503, 504] },
  "webroot": { "extensions": [".php"], "filenames": [".user.ini"] },
  "notes": ["レポートの Notes に追記する自由記述。"]
}
```

- `logPatterns`：`regex` は大文字小文字を区別せずに照合します。`priority` の小さいものから試し、1 行は最初に当たった
  パターンにだけ数えます。`category` は自由な文字列です（`post-5xx` と `recent-file` は予約語）。`logPatterns` の
  すべてのカテゴリが、相関では「クラッシュ・メモリ不足の信号」として扱われます。
- `accessLog`（任意）：リクエスト行の直後に `statuses` のいずれかが続く、`method` の行を拾います。
- `webroot`（任意）：Web ファイルとみなす拡張子と、完全一致のファイル名（大文字小文字は区別しません）。
- 正規表現は、Python と JavaScript で共通の構文にとどめてください。

## 出力 JSON

`format`（`cyberriskscape-triage`）、`version`（1）、`host`、`collectedAt`、`parameters`（`logs`・`webroot`・`days`・
`window`・`patterns: {id, version}`）、`scanned`（パス・サイズ・行数・最初と最後の時刻）、`skipped`（パス・理由）、
`hits`（`category`・`pattern`・`path`・`line`・`time`・`content`・`ip`）、`correlations`（`ip`・`post5xx`・
`nearbyOomOrCrash`・`score`）です。`skipped` は**調べられなかった**もの（バイナリ・systemd journal・読めないファイル）の
一覧です。ヒットが 0 件のときは、信じる前に必ず確認してください。

## 限界

- 解析できる時刻の形式は、アクセスログ・Apache のエラーログ・PHP-FPM・ISO 8601・syslog です。ほかの形式の行は時刻が
  取れず、相関に使えません。syslog 形式は年がないため、ファイルの mtime の年で補います。
- 相関は表記上の時刻（壁時計）で比べ、タイムゾーンのオフセットを無視します。オフセットのない形式は、サーバーの
  ローカル時刻と仮定します。
- クライアント IP は、`--client-ip-regex` がなければ行の先頭のフィールドです。リバースプロキシ・WAF・CDN の背後では
  すべて内部 IP になることがあります（レポートに警告を出します）。
- バイナリと systemd journal は読みません（`journalctl -k -o short-iso > kernel.log` 等でテキストに書き出してください）。
  `.xz`・`.bz2`・`.zst`・`.zip` は先に展開してください。
- 表に載せる行は先頭 300 文字までで、`POST` + 5xx の行は IP ごとに最大 50 行です（件数と相関は全行を使います）。
- ファイルの時刻は偽装できます。mtime は `touch` で書き換えられ、ctime（Linux では inode の変更時刻）は偽装しにくいものの、
  コピーや展開を経たファイルではどちらも信頼できません。**Windows の ctime は作成時刻です。**

## テスト

```bash
python -I -m unittest discover -s tools/triage/tests
```

ライセンス：Apache-2.0。
