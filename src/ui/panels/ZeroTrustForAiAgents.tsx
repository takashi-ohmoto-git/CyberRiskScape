import { ExternalLink, ShieldCheck } from 'lucide-react';

/**
 * 「Zero Trust for AI Agents」フレームワークの一枚絵ビュー。
 *
 * Compliance Map モーダル内の固定エントリとして表示される静的な参照ページ。
 * 内容は Anthropic「Zero Trust for AI Agents」eBook (2026) の要約で、
 * 脅威エンジンのルールではなくプレゼンテーション専用データとして本ファイルに保持する。
 * 規格本文の転載は行わず、独自要約と出典リンクのみを示す。
 * 表示文言は日本語。技術略語・固有名詞（RBAC/ABAC/MCP/constitutional classifiers 等）は原語のまま。
 */

const SOURCE_URL = 'https://www.anthropic.com';

type Principle = { title: string; body: string };

const PRINCIPLES: Principle[] = [
  {
    title: '決して信頼せず、常に検証する',
    body: 'すべてのリクエストは送信元を問わず認証・認可される — ネットワーク内部だからといって素通りはできない。',
  },
  {
    title: '侵害を前提とする',
    body: '侵入の防止だけでなく、被害の局限を前提に設計する。アイデンティティで分割し、影響範囲（ブラスト半径）を封じ込める。',
  },
  {
    title: '最小権限 → 最小エージェンシー',
    body: 'エージェントが何にアクセスできるかだけでなく、各ツールが何を・どれだけの頻度で・どこで実行できるかまで制約する。',
  },
];

const DESIGN_TEST = {
  title: '設計テスト：「面倒ではなく、不可能に」',
  body: 'エージェント型攻撃者は無限の忍耐と試行あたりほぼゼロのコストを持つため、摩擦を与えるだけの対策（レート制限、SMS による MFA）は破られる。能力を抑制する対策よりも、能力そのものを取り除く対策を優先せよ。',
};

type WhyNow = { stat: string; body: string };

const WHY_NOW: WhyNow[] = [
  {
    stat: '数か月 → 数時間',
    body: 'AI は脆弱性から悪用までの時間を、わずかなコストで圧縮する。',
  },
  {
    stat: '250 文書',
    body: 'LLM（6 億〜130 億パラメータ）にバックドアを仕込み、安全性訓練後も残存させるのに十分な量。',
  },
  {
    stat: '50% → <2%',
    body: '信頼できないコンテンツのスポットライティングにより、間接インジェクションの成功率が低下。',
  },
  {
    stat: '95%',
    body: 'constitutional classifiers が阻止したジェイルブレイク試行の割合。',
  },
];

type Tier = 'foundation' | 'enterprise' | 'advanced';

const TIER_META: Record<Tier, { label: string; tagline: string; accent: string }> = {
  foundation: {
    label: '基礎 (FOUNDATION)',
    tagline: '最低限の実装水準 — 底上げされた基準線',
    accent: 'text-sky-400 border-sky-500/60',
  },
  enterprise: {
    label: 'エンタープライズ (ENTERPRISE)',
    tagline: '多くの組織が目指すべき成熟度',
    accent: 'text-emerald-400 border-emerald-500/60',
  },
  advanced: {
    label: '高度 (ADVANCED)',
    tagline: '規制対象／高影響度の環境向け',
    accent: 'text-amber-400 border-amber-500/60',
  },
};

type Domain = {
  name: string;
  foundation: string;
  enterprise: string;
  advanced: string;
};

const DOMAINS: Domain[] = [
  {
    name: 'アイデンティティと認証',
    foundation: 'エージェントごとの暗号学的 ID、短命の IdP トークン — 静的 API キーは使わない',
    enterprise: 'ライフサイクル管理付き X.509 証明書、相互 TLS ＋証明書ピンニング',
    advanced: 'HSM/TPM によるハードウェア裏付けの ID とリモート構成証明',
  },
  {
    name: 'アクセス制御と権限',
    foundation: 'RBAC、デフォルト拒否、アイデンティティに基づくワークロード分離',
    enterprise: 'コンテキスト対応 ABAC、エージェントごとのサンドボックス実行',
    advanced: '継続的認可、JIT/JEA、コンフィデンシャルコンピューティング',
  },
  {
    name: '可観測性と監査',
    foundation: '網羅的なアクションログ、リクエスト ID で操作と契機を紐付け',
    enterprise: '改ざん不能な監査証跡、分散トレーシング（OpenTelemetry）',
    advanced: 'リアルタイム SIEM ストリーミング、入力から出力までの完全な来歴チェーン',
  },
  {
    name: '振る舞い監視',
    foundation: '手動ベースライン、モデルが一次トリアージ案を作成するアラート',
    enterprise: '学習ベースライン、自動封じ込めとアクセス失効',
    advanced: '継続的なドリフト検知、自動化された SOAR プレイブック',
  },
  {
    name: '入出力制御',
    foundation: '入力検証と長さ制限、PII／資格情報の出力フィルタリング',
    enterprise: '攻撃パターンのコンテンツフィルタリング、意味的な出力分析',
    advanced: 'constitutional classifiers ＋スポットライティング、高リスク操作への人間承認',
  },
  {
    name: '完全性と復旧',
    foundation: 'バージョン管理された構成、文書化・テスト済みのロールバック',
    enterprise: '署名付き構成、ヘルスチェック付きの自動ロールバック',
    advanced: 'イミュータブルインフラ、自己修復による自動是正',
  },
  {
    name: 'AI ガバナンス',
    foundation: '文書化された利用規定とインシデント対応方針、シャドー AI への対処',
    enterprise: '部門横断のステークホルダー監督を伴う正式なフレームワーク',
    advanced: 'デプロイパイプラインで強制される自動コンプライアンスチェック',
  },
];

type Threat = { title: string; body: string };

const THREATS: Threat[] = [
  {
    title: 'プロンプトインジェクション',
    body: '直接・間接 — LLM は情報としての文脈と、実行すべき指示とを確実に区別できない。',
  },
  {
    title: 'ツール・リソースの悪用',
    body: 'MCP ツールポイズニング、ラグプル的なツールすり替え、ツール連鎖による情報持ち出し、リソース枯渇。',
  },
  {
    title: 'アイデンティティ・権限の濫用',
    body: 'スコープ外の権限継承、混乱した代理（confused deputy）の中継、メモリを介した権限の保持。',
  },
  {
    title: 'サプライチェーンリスク',
    body: '汚染されたモデル重み、悪意ある MCP サーバー、依存関係混乱（dependency confusion）攻撃。',
  },
  {
    title: 'メモリ・コンテキストの汚染',
    body: 'RAG／ベクトル DB のポイズニング、共有コンテキストへの攻撃、長期記憶の緩やかなドリフト。',
  },
];

type Phase = { title: string; body: string };

const PHASES: Phase[] = [
  { title: '要件の特定', body: '規制・運用・ステークホルダーの整合' },
  { title: 'サプライチェーンの保護', body: 'AI-BOM、スコアカード、AI ベンダリング、署名' },
  { title: 'エージェント境界の定義', body: '一意の ID、最小エージェンシー、ブラスト半径' },
  { title: 'プロンプトインジェクション対策', body: '入力の分離、分類器、攻撃面の限定' },
  { title: 'ツールアクセスの保護', body: '許可リスト、パラメータ検証、サンドボックス' },
  { title: '資格情報の保護', body: '短命・ハードウェア紐付け・JIT・エージェントごと' },
  { title: 'メモリの保護', body: '分離、取得時の完全性チェック、TTL' },
  { title: '重要指標の測定', body: '滞留時間、カバレッジ、説明可能性' },
];

function SectionTitle({ children, accent }: { children: string; accent: string }) {
  return (
    <h4 className={`text-xs font-black uppercase tracking-widest ${accent} mb-3`}>
      {children}
    </h4>
  );
}

export function ZeroTrustForAiAgents() {
  return (
    <div className="flex-1 overflow-y-auto px-6 py-5">
      {/* ヘッダー */}
      <div className="flex items-start justify-between gap-4 flex-wrap border-b border-slate-800 pb-4">
        <div className="flex items-start gap-3">
          <ShieldCheck size={24} className="text-emerald-400 shrink-0 mt-0.5" />
          <div>
            <h3 className="text-xl font-black tracking-tight text-slate-100">
              ZERO TRUST FOR AI AGENTS
            </h3>
            <p className="text-[11px] text-slate-400 mt-0.5">
              自律型 AI エージェントをエンタープライズに展開するためのセキュリティフレームワーク
            </p>
          </div>
        </div>
        <div className="text-right">
          <p className="text-sm font-bold italic text-emerald-400">
            「何も信頼するな。すべてを検証せよ。侵害を前提とせよ。」
          </p>
          <a
            href={SOURCE_URL}
            target="_blank"
            rel="noreferrer noopener"
            className="inline-flex items-center gap-1 text-[10px] text-slate-500 hover:text-emerald-400 transition-colors mt-1"
          >
            出典: Anthropic『Zero Trust for AI Agents』eBook (2026) <ExternalLink size={10} />
          </a>
        </div>
      </div>

      {/* 原則 + 今こそ必要な理由 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-5">
        <div>
          <SectionTitle accent="text-emerald-400">原則</SectionTitle>
          <div className="flex flex-col gap-2">
            {PRINCIPLES.map((p) => (
              <div
                key={p.title}
                className="p-3 rounded-lg bg-slate-800/40 border-l-2 border-emerald-500/60"
              >
                <div className="text-xs font-bold text-slate-100">{p.title}</div>
                <p className="text-[11px] text-slate-400 leading-relaxed mt-1">{p.body}</p>
              </div>
            ))}
            <div className="p-3 rounded-lg bg-amber-500/5 border border-amber-500/40">
              <div className="text-xs font-bold text-amber-400">{DESIGN_TEST.title}</div>
              <p className="text-[11px] text-slate-400 leading-relaxed mt-1">
                {DESIGN_TEST.body}
              </p>
            </div>
          </div>
        </div>

        <div>
          <SectionTitle accent="text-emerald-400">今こそ必要な理由</SectionTitle>
          <div className="flex flex-col gap-2">
            {WHY_NOW.map((w) => (
              <div
                key={w.stat}
                className="flex items-baseline gap-3 p-3 rounded-lg bg-slate-800/40 border border-slate-800"
              >
                <span className="text-sm font-black text-sky-400 shrink-0 w-28 tabular-nums">
                  {w.stat}
                </span>
                <p className="text-[11px] text-slate-400 leading-relaxed">{w.body}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* 能力マトリクス */}
      <div className="mt-8">
        <SectionTitle accent="text-emerald-400">
          能力マトリクス — 3 ティア × 7 ドメイン
        </SectionTitle>
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full border-collapse text-left">
            <thead>
              <tr className="bg-slate-800/60">
                <th className="p-3 text-[10px] font-bold uppercase tracking-wider text-slate-500 w-44 align-top">
                  ドメイン
                </th>
                {(['foundation', 'enterprise', 'advanced'] as Tier[]).map((t) => (
                  <th
                    key={t}
                    className={`p-3 align-top border-l border-slate-800 border-t-2 ${TIER_META[t].accent}`}
                  >
                    <div className="text-xs font-black">{TIER_META[t].label}</div>
                    <div className="text-[10px] font-normal text-slate-500 italic mt-0.5">
                      {TIER_META[t].tagline}
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {DOMAINS.map((d) => (
                <tr key={d.name} className="border-t border-slate-800">
                  <td className="p-3 text-xs font-bold text-slate-200 align-top">{d.name}</td>
                  <td className="p-3 text-[11px] text-slate-400 leading-relaxed align-top border-l border-slate-800">
                    {d.foundation}
                  </td>
                  <td className="p-3 text-[11px] text-slate-400 leading-relaxed align-top border-l border-slate-800">
                    {d.enterprise}
                  </td>
                  <td className="p-3 text-[11px] text-slate-400 leading-relaxed align-top border-l border-slate-800">
                    {d.advanced}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-[11px] text-slate-500 italic mt-2">
          各ティアは前のティアの上に積み上がる。{' '}
          <span className="font-bold text-slate-400">
            「一つでも能力を飛ばせば、攻撃者はその隙を突く。」
          </span>
        </p>
      </div>

      {/* 脅威 */}
      <div className="mt-8">
        <SectionTitle accent="text-rose-400">脅威（OWASP）</SectionTitle>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {THREATS.map((t, i) => (
            <div
              key={t.title}
              className="p-3 rounded-lg bg-slate-800/40 border-l-2 border-rose-500/60"
            >
              <div className="text-xs font-bold text-slate-100">
                {i + 1}. {t.title}
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed mt-1">{t.body}</p>
            </div>
          ))}
          <div className="p-3 rounded-lg border border-emerald-500/40 bg-emerald-500/5">
            <p className="text-[11px] text-emerald-300/90 leading-relaxed">
              <span className="font-bold">基準線は上がり続ける：</span>
              今日の「高度」は明日の「エンタープライズ」に、そして「エンタープライズ」は「基礎」になると考えよ。
            </p>
          </div>
        </div>
      </div>

      {/* 実装ワークフロー */}
      <div className="mt-8">
        <SectionTitle accent="text-emerald-400">実装ワークフロー — 8 フェーズ</SectionTitle>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          {PHASES.map((p, i) => (
            <div
              key={p.title}
              className="p-3 rounded-lg bg-slate-800/40 border-t-2 border-emerald-500/60"
            >
              <div className="text-xs font-bold text-slate-100">
                {i + 1}. {p.title}
              </div>
              <p className="text-[10px] text-slate-500 leading-relaxed mt-1">{p.body}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
