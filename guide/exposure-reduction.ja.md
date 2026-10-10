# インターネット露出を減らす — CISA の 4 ステップを Shodan・Censys と CyberRiskScape で回す

[English](exposure-reduction.md) | **日本語**

> このページは、米国 CISA（Cybersecurity and Infrastructure Security Agency）の
> 「Internet Exposure Reduction Guidance」（2026 年 8 月改訂）の進め方を、CyberRiskScape の作業に当てはめたものです。
> CISA が作成・認定・推奨するものではありません。ガイダンスの内容は日本語で要約したもので、原文の転載ではありません。
> Shodan・Censys は、それぞれの所有者の商標です。各サービスの仕様と検索の書き方は執筆時点（2026 年 10 月）のものです。

---

## 1. このページで分かること・前提

- CISA が示す**インターネット露出を減らす 4 ステップ**（把握 → 必要性の判断 → リスクの低減 → 定期評価）
- Shodan・Censys で見つけた露出を、**構成図に描いて脅威として評価する**方法
- **Shodan の書き出し（.json.gz）から図の下書きを自動で作る**方法
- 「要らない露出を消す」「要る露出を守る」の効果を、**対応前と対応後の脅威の差**で示す方法
- 定期評価で、**消したはずの露出が戻ってきたこと**を CLI で検知する方法

**CISA のガイダンスについて**

インターネットから到達できる機器やサービスは、攻撃者が Shodan などの検索サービスで探し、設定の誤り・既定の
パスワード・古いソフトウェアを突いて侵入する入口になります。CISA はこれを受けて、組織が意図せずインターネットに
出しているものを減らす手順をまとめています（[出典 1](#参考リンク)）。2026 年 7 月には、携帯回線のモデムで
インターネットに直接つながった PLC が水道・下水道の 100 を超える事業者で攻撃されています。

**このページの範囲：IT の露出を扱います。** CISA のガイダンスの主な対象は OT / ICS（PLC・HMI・SCADA・RTU）ですが、
4 ステップの考え方は IT の露出にもそのまま使えます。このページでは Web・VPN・リモートデスクトップ・データベース・
**AI 基盤（ローカル LLM など）**の露出を題材にします。OT の機器（Modbus・DNP3・EtherNet/IP・OPC UA・BACnet など）を
表すステンシルと脅威ルールは、CyberRiskScape にはまだありません。

**このページの前提となる知識**：[はじめに](getting-started.ja.md)の操作と、[脅威パネルの読み方](reading-threats.ja.md)。

---

## 2. CISA の 4 ステップと CyberRiskScape の作業

| CISA のステップ | やること（CISA） | CyberRiskScape でやること |
|---|---|---|
| **1. 今の露出を把握する** | インターネットから到達できる資産を特定する。Shodan・Censys・Thingful・Shadowserver などで自組織の IP 範囲を調べる。ベンダー・MSSP・システムインテグレーターのリモートアクセスも確かめる | 見つかった露出を構成図に描く（§4）。Shodan の書き出しは取り込んで下書きにできる（§4.4）。インターネット側から張る線と、FRONT_END_SERVER / GATEWAY の **Attack Surface Attribute** で露出を表す |
| **2. 露出が必要か判断する** | 業務上インターネットからのアクセスが要るものだけを残し、要らないものはアクセスを止めるか制限する | 露出ごとに要否を決め、要らない露出は**線を消す**か、VPN・踏み台の後ろへ**描き直す**（§5） |
| **3. 残す露出のリスクを下げる** | 既定のパスワードを変える、パッチを当てる、踏み台（ジャンプホスト）を置く、通信を監視する、MFA を入れる | Attack Surface Attribute（送信元 IP 制限・リモートアクセス制限・ユーザー認証・アクセスログ・WAF・DDoS 保護）と、線の認証（MFA）を実態に合わせて入れ、**消える脅威と残る脅威**を確かめる（§6） |
| **4. 定期的に評価する** | 外部の検索サービスや自前のスキャンで、IP 範囲に予期しないポートが開いていないか定期的に確かめる | 対応後の図を正本にして、新しい観測を描いた図と `diff` で比べる。**新しい露出が出たら CI を止める**（§7） |

---

## 3. 構成図の例

架空の組織の外部露出を、対応前と対応後の 2 つのテンプレートにしています。IP アドレスや組織名は含みません。

| ファイル | 内容 |
|---|---|
| [`templates/exposure-before.ja.json`](templates/exposure-before.ja.json)（[英語版](templates/exposure-before.en.json)） | 対応前：Shodan・Censys で見つかった露出をそのまま描いた図 |
| [`templates/exposure-after.ja.json`](templates/exposure-after.ja.json)（[英語版](templates/exposure-after.en.json)） | 対応後：要らない露出を消し、残す露出のリスクを下げた図 |

読み込み方は [テンプレートを作る・使う](templates.ja.md) を参照してください。

![対応前の構成図](../assets/guide/exposure/01-before.png)

**対応前の図の中身：** コンポーネント 11・データフロー 14・トラスト境界 3。外部境界（Internet）に攻撃者・リモート勤務の
社員・保守ベンダーを、自組織の公開セグメント（DMZ）に公開 Web サイトと SSL-VPN を置いています。本来は社内にあるはずの
検索基盤（Elasticsearch）・ローカル LLM（Ollama）・業務サーバーのリモートデスクトップ・保守用端末（TeamViewer）にも、
インターネットから直接線が届いています。読み込むと **91 件**（Critical 13・High 43・Medium 35）の脅威が検出されます（執筆時点）。

---

## 4. ステップ 1 — 今の露出を把握する

### 4.1 Shodan・Censys で自組織の IP 範囲を調べる

CISA は、自組織の IP 範囲とポートで絞り込む検索の例（EtherNet/IP の 44818 番）を示しています（[出典 1](#参考リンク)）。同じ形で、たとえばリモートデスクトップを調べるには次のようにします。

```text
Shodan:  port:3389 net:203.0.113.0/24
Censys:  host.services.port: 3389 and host.ip: "203.0.113.0/24"
```

`203.0.113.0/24` は説明用のアドレスです。自組織の IP 範囲に置き換えてください。Censys の検索の書き方は
製品の世代（Censys Search と Censys Platform）によって異なることがあるため、使う製品のドキュメントで確かめてください。

> **調べてよい範囲** — 検索するのは**自組織が管理する IP 範囲だけ**にし、各サービスの利用規約に従ってください。
> 検索サービスは過去にスキャンした結果を見せるだけですが、見つけたホストへ自分で接続して確かめる場合は、
> 対象を管理する部署の承認を取ってください。

**まず確かめるポート**（CISA が挙げるうち IT に関わるもの。[出典 1](#参考リンク)）：

| ポート | サービス | 露出していたら |
|---|---|---|
| 22/TCP | SSH | 管理面の露出。踏み台や VPN の後ろへ |
| 23/TCP | Telnet | 平文の管理面。原則として廃止 |
| 80/TCP・443/TCP | HTTP・HTTPS | Web と機器の管理画面。管理画面が混ざっていないか確かめる |
| 3389/TCP | RDP（リモートデスクトップ） | 管理面の露出。総当たりの標的になりやすい |
| 5900/TCP | VNC | 管理面の露出 |
| 5938/TCP | TeamViewer | ベンダーのリモート保守の経路になりがち |

**このページで加えるポート**（CISA のリストには無く、CyberRiskScape の判断で加えたもの）：AI 基盤は既定で認証を持たない
ものがあり、検証用に立てたまま公開されていることがあります。たとえば 11434/TCP（Ollama）、8000/TCP（vLLM などの
OpenAI 互換の API でよく使われる）、8888/TCP（Jupyter）、7860/TCP（Gradio）、8265/TCP（Ray Dashboard）です。
データベースの 9200/TCP（Elasticsearch）・6379/TCP（Redis）・27017/TCP（MongoDB）も合わせて確かめます。

### 4.2 ベンダーのリモートアクセスを洗い出す

CISA は、システムインテグレーター・MSSP・ベンダーが持つリモートアクセス（VPN の資格情報・携帯回線のモデム・
リモート保守ツール）を確かめ、**接続元のグローバル IP を提出してもらい、変わったら更新してもらう**ことを勧めています。
提出された IP も Shodan・Censys で調べ、ベンダー側の接続が守られているかを確かめます。

### 4.3 見つかった露出を構成図に描く

| 見つかったもの | 描き方 |
|---|---|
| インターネット上のだれでも | 外部境界（Internet）に**脅威アクター**を置き、そこから露出先へ線を引く |
| Web サイト・Web の管理画面 | `FRONT_END_SERVER`（フロントエンドサーバー）。Attack Surface Attribute の「Global IP の割り当て」を**有り** |
| VPN・リバースプロキシ・RDP / SSH / VNC の入口 | `GATEWAY`（APIゲートウェイ）。ラベルでサービスとポートを書く（例：「リモートデスクトップ（RDP 3389）」）。「Global IP の割り当て」を**有り** |
| データベース・検索基盤 | `DATA_STORE`（データストア）。脅威アクターから線を引き、認証が無ければ **None**、平文なら **Plain** |
| ローカル LLM・推論 API | `LLM`（LLMモデル）。同じく脅威アクターから線を引く |
| ベンダーのリモート保守 | 外部境界に `EXTERNAL_ENTITY`（外部主体）を置き、保守の入口へ線を引く |

**分からないことは安全側に倒します。** 検索サービスで確かめられるのは「到達できる」ことと、サービスの種類までです。
送信元 IP の制限・WAF・アクセスログなどは外からは分からないので、**確かめられた項目だけ**を入力し、残りは未入力のままにします
（未入力は「無し」として評価されます）。ポートが開いていることを示すだけの線に、パスワードや MFA の有無を推測で入れないでください。
分からない線は Password にしておき、確かめてから引き上げます。

![リモートデスクトップの Attack Surface Attribute](../assets/guide/exposure/02-rdp.png)

対応前の図で、リモートデスクトップには次の脅威が出ます。

| 脅威 | 重大度 | 発火の条件 |
|---|---|---|
| 管理面リモートアクセス（`stride-web-remote-mgmt-exposed-001`） | Critical | Global IP 有り × リモートアクセス制限 無し |
| 匿名公開アクセス組合せ（`stride-web-anonymous-on-public-001`） | Critical | Global IP 有り × ユーザー認証 無し × 送信元 IP 制限 無し |
| グローバルIP直接公開（`stride-web-global-ip-exposure-001`） | High | Global IP 有り |
| 送信元IP無制限アクセス（`stride-web-no-source-ip-restriction-001`） | High | Global IP 有り × 送信元 IP 制限 無し |
| 盲点境界：公開×無ログ（`stride-web-blind-perimeter-001`） | High | Global IP 有り × アクセスログ 無し |
| パスワード・API キー単独の認証 / 公衆網（`stride-edge-password-internet-001`） | High | インターネット経由の線が Password |

検索基盤とローカル LLM へ認証なし・平文で届く線には、なりすまし（`stride-edge-unauth-internet-001`、Critical）・
盗聴（`stride-edge-plain-encryption-001`、High）・Trust Boundary 跨ぎの直接暴露（`stride-edge-internet-exposed-sensitive-001`、Critical）が出ます。

### 4.4 Shodan の書き出しから図の下書きを作る

Shodan の検索結果は、ファイルに書き出して読み込めば、§4.3 の描き方に沿った図の下書きになります。CyberRiskScape は
Shodan に接続しません（API キーも不要です）。書き出しは、利用者が自分の Shodan アカウントで行います。

```bash
# 自組織の IP 範囲の検索結果を書き出す（exposure.json.gz ができる。プランに応じて Shodan のクレジットを消費します）
shodan download --limit 1000 exposure net:203.0.113.0/24
# 1 つの IP について書き出す（203.0.113.10.json.gz ができる）
shodan host --save 203.0.113.10
```

- **画面から**：Template → Import タブの **「Shodan の書き出しを選択」** で `.json.gz` をそのまま選びます（展開は不要です）。
- **CLI から**：`node dist-cli/main.js import-shodan exposure.json.gz --out exposure.json`

`.json.gz` のほか、展開した JSON Lines、バナーの JSON 配列、ホストの JSON（`data` にバナーの配列を持つもの）も読めます。

![Shodan の書き出しの取り込み](../assets/guide/exposure/05-shodan-import.png)

**対応**（1 サービス＝ IP・ポートの組ごとに 1 ノード。上から順に判定）：

| Shodan の情報 | CyberRiskScape の型 |
|---|---|
| タグ `ics` | `IOT`（OT / ICS のステンシルが無いため。説明欄にその旨を書く） |
| タグ `ai`、製品名が Ollama・vLLM など、ポート 11434 | `LLM`（LLMモデル） |
| タグ `database`、データベースのポート（3306・5432・6379・9200・27017 など） | `DATA_STORE`（データストア） |
| タグ `vpn`、遠隔管理のポート（22・23・445・3389・5900〜5903・5938・5985・5986） | `GATEWAY`（APIゲートウェイ） |
| HTTP の応答がある、ポート 80・443・8080・8443 | `FRONT_END_SERVER`（フロントエンドサーバー） |
| 上のどれでもない | `PROCESS`（プロセス） |

- 攻撃者からの線は、TLS の応答があれば **TLS**、無ければ **Plain** にします。認証は外から確かめられないので、すべて **Password** にします。
  認証なしで応答していることを確かめたもの（例：データベース）は、線の認証を **None** に直してください。
- Attack Surface Attribute は「Global IP の割り当て」を**有り**にし、Shodan が WAF を検出したときだけ「WAF / WAP による保護」を**有り**にします。
- 説明欄には IP・ポート・製品とバージョン・タグ・観測日と、Shodan が報告した CVE の ID（**未検証**。最大 10 件）を書きます。
  CVE は脅威としては扱いません。パッチの確認のきっかけに使ってください。
- **読み込まないもの**：バナー本文、HTTP の HTML・ヘッダ・タイトル、証明書の中身、組織名・位置情報。これらは図に載りません。
- 上限は 300 サービスです。超えた分は取り込まず、件数を表示します。

![Shodan の書き出しから作った図](../assets/guide/exposure/06-shodan-overview.png)

試すためのサンプルを [`templates/shodan-sample.json`](templates/shodan-sample.json) に置いています（説明用のアドレスで作った架空のデータ）。
サンプルからは 7 サービス（6 ホスト）の図ができ、**96 件**の脅威が検出されます（執筆時点）。

取り込んだ図は、ステップ 2 の判断の材料です。社内のどこにあるはずのものか（DMZ か社内か）、ベンダーの経路かは Shodan からは
分からないので、§3 のテンプレートのように描き足して仕上げます。

---

## 5. ステップ 2 — 露出が必要か判断する

露出 1 件ごとに「業務上、インターネットから直接届く必要があるか」を決めます。テンプレートでは次のように判断しました。

| 露出 | 判断 | 図での変更 |
|---|---|---|
| 公開 Web サイト（443） | **必要**（顧客向けの公開サイト） | 残す。ステップ 3 でリスクを下げる |
| SSL-VPN（443） | **必要**（社員とベンダーの入口をここに集める） | 残す。ステップ 3 でリスクを下げる |
| リモートデスクトップ（RDP 3389） | **不要** | 線を消す。社員の管理操作は SSL-VPN → 踏み台サーバー → 業務サーバーへ描き直す |
| 検索基盤（Elasticsearch 9200） | **不要**（Web サイトからだけ使う） | インターネットからの線を消す |
| ローカル LLM（Ollama 11434） | **不要**（検証で立てたまま公開されていた） | インターネットからの線を消す。業務サーバーからだけ使う |
| 保守用端末（TeamViewer 5938） | **不要** | 端末を消し、保守ベンダーは SSL-VPN（MFA）から踏み台を経由させる |

> **ひとこと** — ローカル LLM の脅威のうち、プロンプトインジェクションやモデルの盗用など LLM そのものに当たるもの
> （OWASP LLM Top 10・MITRE ATLAS のルール）は、インターネットからの線を消しても残ります。露出を消して減るのは、
> 「だれでも届く」ことに由来する脅威です。残ったものは、社内の利用者を前提に評価し直します。

---

## 6. ステップ 3 — 残す露出のリスクを下げる

CISA の対策と、CyberRiskScape の入力項目の対応です。

| CISA の対策 | CyberRiskScape での表し方 | 消える脅威 |
|---|---|---|
| 踏み台（ジャンプホスト）を置き、管理のアクセスをそこに集める | 社内に `GATEWAY`（踏み台サーバー）を置き、Global IP 無し・送信元 IP 制限 有り・リモートアクセス制限 有り・ユーザー認証 有り・アクセスログ 有り。管理の線は踏み台を経由させる | 管理面リモートアクセス、グローバルIP直接公開 など（RDP の入口ごと消える） |
| MFA を入れる（少なくとも踏み台では必ず） | 社員・ベンダーから SSL-VPN への線と、SSL-VPN から踏み台への線を **MFA** にする | パスワード・API キー単独の認証 / 公衆網（社員・ベンダーの線から消える。攻撃者のログイン試行を表す線には残る） |
| 入出力の通信を監視する | Attack Surface Attribute の「アクセスログ」を**有り** | アクセスログ欠如、盲点境界：公開×無ログ |
| 管理面をインターネットに出さない（集中管理されたゲートウェイ・VPN を通す） | 「リモートアクセス制限」を**有り** | 管理面リモートアクセス |
| （公開 Web の保護。CISA の明示の項目ではない） | 「WAF / WAP による保護」「DoS / DDoS 保護」を**有り** | アプリケーション層攻撃保護欠如、DoS/DDoS保護欠如 |

![対応後の構成図](../assets/guide/exposure/03-after.png)

対応後の図では脅威が **63 件**（Critical 6・High 27・Medium 30）に減ります（執筆時点）。

![対応後の公開 Web サイトの Attack Surface Attribute](../assets/guide/exposure/04-web-after.png)

**残る脅威をどう扱うか。** 対応後も、次のような脅威は残ります。いずれも「必要な露出」に由来するもので、消すことより
判断を記録することが大切です。[Analytics でリスクを評価する](analytics-assessment.ja.md)で、リスク対応方針（受容・低減など）と理由を残してください。

| 残る脅威 | 理由 | 扱いの例 |
|---|---|---|
| 公開 Web サイトの 匿名公開アクセス組合せ・認証欠如・送信元IP無制限アクセス | 公開サイトなので、だれでも認証なしで見られることが前提 | 受容（WAF・DDoS 保護・ログで低減済みと記録） |
| SSL-VPN の 送信元IP無制限アクセス・アプリケーション層攻撃保護欠如 | 社員が自宅や出張先から接続するため、送信元を絞れない | 受容、または接続元の国を絞るなどで低減 |
| AiTM フィッシングによるセッショントークン窃取（`zt-aitm-session-token-theft-001`） | MFA でも、プッシュ通知やワンタイムコードは中間者型のフィッシングで突破されうる | CISA が勧める**フィッシング耐性のある MFA**（FIDO2 / パスキー）へ移行して低減 |
| 集中 IdP を経由しないローカル資格情報（`identity-local-credential-outside-idp-001`） | 図に IdP を描いていない | VPN の認証を IdP に寄せているなら、図に IdP を置いて線の「資格情報の発行元」に指定する |

**図で表せない対策もあります。** CISA が挙げる「既定のパスワードを変える」「パッチを当て、サポートが切れた製品を入れ替える」は、
構成図の属性にありません。脅威カードの対策実装状況やメモに記録し、ステップ 4 の定期評価で確かめてください。

---

## 7. ステップ 4 — 定期的に評価する

IT 環境は変わり続けるため、CISA は外部の検索サービスや自前のスキャンで IP 範囲を**定期的に**調べ、予期しないポートを
調べることを勧めています。CyberRiskScape では、**対応後の図を正本（ベースライン）**にして、新しい観測を反映した図と比べます。

```bash
# 新しい観測を反映した図（current.json）を、対応後の図（baseline.json）と比べる
node dist-cli/main.js diff baseline.json current.json --fail-on High
```

対応後の図をベースラインにし、消したはずの露出（RDP・検索基盤・ローカル LLM・TeamViewer）が戻った図と比べると、
新しく出る High 以上の脅威が **24 件**見つかり、終了コード 1 で止まります（テンプレートで確認。執筆時点。DF・C の番号は図によって変わります）。

```text
--fail-on High: 新規かつ未抑制の脅威が 24 件しきい値以上です。
  - [Critical] DF9 無認証のクエリ なりすまし
  - [Critical] DF10 無認証のAPI呼び出し なりすまし
  ...
```

差分レポート（`--format md`）には、新しい外部インターフェース（T2）など、人が見直すべき**実行トリガー**も出ます。
GitHub Actions に組み込む方法は [AI駆動開発のCIに組み込む](ci-integration.ja.md) を参照してください。

**運用の例**

1. 月に 1 回など決まった間隔で、Shodan・Censys で自組織の IP 範囲を検索する（§4.1 と同じ検索）。
2. ベースラインに無い露出を見つけたら、構成図に描き足して `current.json` として保存する。
3. `diff --fail-on High` で判定し、新しい露出はステップ 2・3 に戻して対応する。
4. 対応が済んだら、その図を新しいベースラインにする。

**Shodan の取り込み同士を比べる。** §4.4 の取り込みで作った図は、要素の ID が IP・ポートから決まるため、前回と今回の取り込みを
そのまま `diff` で比べられます。新しく開いたポートの脅威だけが「追加」に出ます。

```bash
shodan download --limit 1000 2026-11 net:203.0.113.0/24
node dist-cli/main.js import-shodan 2026-11.json.gz --out 2026-11.json
node dist-cli/main.js diff 2026-10.json 2026-11.json --fail-on High
```

サンプルに Redis（6379）のバナーを 1 件足して比べると、追加 8 件・解消 0 件で、High 以上の 4 件（Redis の情報漏洩・データ改ざん、
線の盗聴・パスワード単独認証）で止まります（執筆時点）。手で描き足した図（§3 のテンプレートなど）と取り込んだ図は ID が違うため、
この 2 つを `diff` で比べることはできません。

---

## 8. 攻撃経路分析で対策の効き目を確かめる

対応前と対応後の図で[攻撃経路分析](attack-paths.ja.md)を開くと、インターネット上の攻撃者から顧客 DB や業務サーバーに
届く経路と、チョークポイント（1 つの対策が最も多くの経路に効く場所）を比べられます。露出を減らした結果、経路が
SSL-VPN と公開 Web サイトに集まっていれば、そこが優先して守るべき入口です。

---

## 9. 限界

- **図は観測の写しです。** CyberRiskScape は Shodan・Censys や自組織のネットワークに接続しません。描かれていない露出は評価されません。
  検索サービスのスキャンは定期的に行われるもので、最新の状態を反映しているとは限りません
- **外から見えない設定は分かりません。** 送信元 IP の制限・WAF・ログなどは、確かめてから入力してください。推測で「有り」にすると、
  脅威が消えて見えるだけになります
- **既定のパスワード・パッチの状態・既知の脆弱性（CVE）は判定しません。** 脆弱性診断やパッチ管理の結果と合わせて見てください
- **Attack Surface Attribute はフロントエンドサーバーと APIゲートウェイにしかありません。** データストアや LLM の露出は、
  インターネットからの線の認証・暗号化で表します
- **OT / ICS の機器は表せません。** PLC・HMI・SCADA・RTU と産業用プロトコルのステンシル・脅威ルールは今後の課題です。
  OT の露出は CISA のガイダンス（[出典 1](#参考リンク)）と「Secure Connectivity Principles for OT」（[出典 2](#参考リンク)）に直接あたってください

---

## 参考リンク

1. CISA, Internet Exposure Reduction Guidance（2026 年 8 月改訂） — <https://www.cisa.gov/resources-tools/resources/exposure-reduction>
2. CISA, Secure Connectivity Principles for Operational Technology (OT) — <https://www.cisa.gov/resources-tools/resources/secure-connectivity-principles-operational-technology-ot>
3. CISA, Cyber Hygiene Services（米国の重要インフラ組織などが対象の無料の脆弱性スキャン） — <https://www.cisa.gov/cyber-hygiene-services>
4. Shodan — <https://www.shodan.io/>
5. Censys — <https://censys.com/>

---

## 次に読むもの

- 残った脅威を評価して記録する — [Analytics でリスクを評価する](analytics-assessment.ja.md)
- 定期評価を CI に組み込む — [AI駆動開発のCIに組み込む](ci-integration.ja.md)
- 対策の優先順位を決める — [攻撃経路分析](attack-paths.ja.md)
- 背景にある考え方 — [Secure by Design 入門](secure-by-design.ja.md)
