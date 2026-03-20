# DMARC Report Viewer

**Your DMARC reports are telling you something. This add-on helps you listen.**

**DMARCレポートが伝えていること。このアドオンはそれを読み解く手助けをします。**

---

## Why This Exists / なぜこれを作ったか

You set up DMARC. You configured SPF. You rotated your DKIM keys. Now what?

Every day, ISPs send you XML reports buried in ZIP and GZ attachments. They contain the ground truth about your email authentication — which IPs are sending as your domain, whether they pass or fail, and what the receiving server did about it. But nobody reads raw XML. The reports pile up. Threats go unnoticed. Misconfigurations persist.

**DMARC Report Viewer turns those reports into actionable insight — entirely within Thunderbird, entirely offline, with zero data leaving your machine.**

This is not a SaaS dashboard that wants your DNS credentials. This is a local tool for engineers who own their infrastructure and want to see exactly what's happening to their domains.

---

DMARC を設定した。SPF を書いた。DKIM 鍵もローテーションした。で、その後は？

毎日 ISP から ZIP や GZ で圧縮された XML レポートが届く。そこにはメール認証の真実 — どの IP があなたのドメインで送信し、認証に成功したか失敗したか、受信サーバーがどう処理したか — がすべて記録されている。しかし誰も生の XML は読まない。レポートは積み上がり、脅威は見過ごされ、設定不備は放置される。

**DMARC Report Viewer はそれらのレポートをアクションにつながるインサイトに変える。Thunderbird の中だけで、完全にオフラインで、データは一切外に出ない。**

DNS の認証情報を要求する SaaS ダッシュボードではない。自分のインフラを自分で管理し、ドメインに何が起きているかを正確に把握したいエンジニアのためのローカルツールだ。

---

## What You Can Do / このツールでできること

### See the real picture — 実態を把握する

- **8-stat summary** per domain: Total emails, Delivered (Auth OK), Delivered (Auth Fail), Quarantined, Rejected, DKIM+SPF Pass, DKIM Pass, SPF Pass
- **Pie charts**: Domain distribution, Disposition breakdown (4 categories), Reporter distribution
- **Time series**: Disposition trends over time with automatic period aggregation (daily / weekly / monthly)
- **ドメインごとの8項目サマリー**: メール総数、配送済(認証成功)、配送済(認証失敗)、隔離、拒否、DKIM+SPFパス、DKIMパス、SPFパス
- **円グラフ**: ドメイン分布、Disposition内訳（4区分）、レポーター分布
- **時系列グラフ**: 配送処理の推移を期間に応じて自動集計（日別/週別/月別）

### Identify threats — 脅威を特定する

- **IP range classification**: Each source IP range is automatically tagged:
  - ✅ **Legitimate** — All pass, all delivered. Your real mail servers.
  - 🛡️ **Blocked** — All fail, all rejected. Attackers being stopped by your policy.
  - ⚠️ **Misconfigured** — Mix of pass and reject. A legitimate source with broken SPF/DKIM.
  - 🔴 **Threat (Unblocked)** — Auth failed but delivered. Someone is spoofing your domain and getting through.
- **IP範囲の自動分類**: 各送信元IP範囲にタグを自動付与
  - ✅ **正規** — 全認証成功・全配送。あなたの正規メールサーバー。
  - 🛡️ **ブロック済** — 全認証失敗・全拒否。ポリシーが攻撃者を正しくブロック中。
  - ⚠️ **設定不備** — passとrejectが混在。正規の送信元だがSPF/DKIM設定に問題あり。
  - 🔴 **脅威 (未ブロック)** — 認証失敗なのに配送されている。ドメイン詐称が素通りしている。

### Know your domain health — ドメインの健全度を知る

- **Health badges** per domain:
  - ✅ **Healthy** — High pass rate, reject policy active, no unblocked failures
  - 🛡️ **Under Attack** — Reject policy is blocking threats
  - ⚠️ **Needs Attention** — Unblocked auth failures exist, or policy is not `reject`
  - 🔴 **At Risk** — Significant volume of unblocked spoofing
- **ドメインごとの健全度バッジ**:
  - ✅ **健全** — 高いパス率、rejectポリシー有効、未ブロック認証失敗なし
  - 🛡️ **攻撃検知中** — rejectポリシーが脅威をブロック中
  - ⚠️ **要確認** — 未ブロックの認証失敗あり、またはポリシーが`reject`でない
  - 🔴 **危険** — 大量のドメイン詐称が素通りしている

### Spot the dangerous gap — 危険なギャップを見つける

The most critical insight: **"Delivered (Auth Fail)"** — emails that failed authentication but were delivered anyway because your policy is `none` or `quarantine`. These are the emails that `p=reject` would block. This number should be zero. If it's not, you have work to do.

最も重要なインサイト: **「配送済（認証失敗）」** — 認証に失敗したのに、ポリシーが `none` や `quarantine` だったために配送されてしまったメール。`p=reject` にすればブロックできるメール。この数字はゼロであるべきだ。ゼロでなければ、やるべきことがある。

### Deep analysis — 認証基盤の深掘り

- **DKIM signature analysis**: See which signing domains and selectors are in use. Third-party signatures (SendGrid, Mailchimp, etc.) are automatically tagged.
- **SPF domain analysis**: Identify which domains are authenticating via SPF, with helo-only warnings when MAIL FROM alignment is missing.
- **Envelope alignment**: Detect Header From / Envelope From mismatches. Distinguish legitimate third-party senders from possible spoofing attempts.
- **Policy recommendations**: Actionable advice per domain — p=none → reject migration guidance, adkim strict suggestions, pct=100 readiness checks.
- **CSV export**: Export all IP range statistics and forensic reports for incident reporting and compliance documentation.
- **DKIM 署名分析**: 使用中の署名ドメインとセレクタを一覧表示。第三者署名（SendGrid、Mailchimp等）は自動タグ付け。
- **SPF ドメイン分析**: SPF認証に使用されているドメインを特定。MAIL FROMアライメントがない場合はhelo-only警告を表示。
- **Envelope アライメント**: Header FromとEnvelope Fromの不一致を検出。正当な第三者配信とドメイン詐称の疑いを区別。
- **ポリシー推奨**: ドメインごとのアクション可能なアドバイス — p=none→reject移行ガイダンス、adkim strict提案、pct=100移行の準備状況確認。
- **CSVエクスポート**: IP範囲統計とフォレンジックレポートをCSVでエクスポート。インシデント報告やコンプライアンス文書作成に対応。

---

## Features / 機能一覧

- **Full tab dashboard** — Opens in a dedicated Thunderbird tab for comfortable analysis
- **Collapsible domain sections** — Manage multiple domains without endless scrolling
- **Automatic folder detection** — Finds DMARC report folders by naming convention
- **ISP compatibility** — Handles gzip-first detection, Microsoft XML typos, zero-record reports
- **DKIM signature analysis** — Signing domains, selectors, third-party signature detection
- **SPF domain analysis** — Authentication domains, mfrom/helo scope tracking
- **Envelope alignment** — Header From / Envelope From mismatch detection with spoofing indicators
- **Policy recommendations** — Per-domain advice for p=none → reject migration
- **CSV export** — Export IP range statistics and forensic reports
- **Forensic report viewer** — Displays RFC 6591 failure reports
- **Scan period selection** — 1 week / 1 month / 3 months / 6 months / 1 year / all time
- **Result caching** — Scan results persist across tab reopens
- **Dark mode** — Full dark mode following system preference
- **i18n** — English and Japanese
- **Privacy first** — Zero network requests. Everything stays on your machine.

---

## Prerequisites / 前提条件

### DNS Configuration / DNS設定

```
_dmarc.example.com. 300 IN TXT "v=DMARC1; p=reject; sp=reject; pct=100; adkim=s; aspf=s; fo=1; rua=mailto:dmarc-rua@example.com; ruf=mailto:dmarc-ruf@example.com"
```

### Mail Folder Setup / メールフォルダ設定

```
DMARC/
├── Aggregate    ← rua reports (auto-detected)
└── Forensic     ← ruf reports (auto-detected)
```

Route reports with mail filters by `To:` address.

---

## Installation / インストール

> Requires [JSZip](https://stuk.github.io/jszip/) and [pako](https://github.com/nodeca/pako) in the `lib/` directory.

1. `npm install` or manually place `jszip.min.js` and `pako.min.js` in `lib/`
2. Build: `./build.sh` (Linux/macOS) or `pwsh build.ps1` (Windows)
3. Install in Thunderbird: Tools → Add-ons → Install Add-on From File

---

## Architecture / アーキテクチャ

```
manifest.json               Extension manifest (manifest_version 2)
background.js               Tab management, message scanning, decompression pipeline,
                             folder auto-detection, result caching, period filtering
parser/
├─ ar_parser.js             RFC 7489 aggregate report parser with validation,
│                            IP range aggregation, deliveredPass/Fail classification,
│                            per-IP/reporter detailed stats, DKIM signature analysis,
│                            SPF domain analysis, envelope alignment detection
└─ fr_parser.js             RFC 6591 forensic report parser with validation
dashboard/
├─ dashboard.html           Full-tab dashboard UI with export button
├─ dashboard.css            CSS variables, dark mode, 8-column grid, IP tags,
│                            health badges, collapsible sections, pie/line charts,
│                            advice boxes, third-party/spoofing tags
└─ dashboard.js             Rendering logic — IP classification, health scoring,
│                            SVG charts, collapsible DOM, warning translation,
│                            DKIM/SPF/envelope tables, policy advice, CSV export
options/
├─ options.html             Settings page
└─ options.js               Folder selection & persistence
lib/
├─ jszip.min.js             ZIP decompression (user-provided)
└─ pako.min.js              GZIP decompression (user-provided)
_locales/
├─ en/messages.json         English (117 keys)
└─ ja/messages.json         日本語 (117 keys)
```

### Processing Pipeline

```
Period Filter → Auto-Detect Folders → Message Scan → Attachment Extraction
→ Decompress (GZ-first/ZIP) → XML Sanitize → Parse → Validate → Deduplicate
→ DeliveredPass/Fail Split → IP Range Classification → Domain Health Scoring
→ DKIM Signature Aggregation → SPF Domain Aggregation → Envelope Alignment
→ Per-Domain Aggregation → Time Series Bucketing → Policy Advice → Cache → Render
```

---

## Roadmap

### v0.1.4 — Operational Intelligence (planned)
- Period comparison (previous vs current)
- Reporter coverage & gap detection
- Subdomain analysis
- Policy override deep analysis
- Forensic report ↔ aggregate report cross-reference

---

## License / ライセンス

[GNU General Public License v3.0](LICENSE)

Copyright (C) 2025 Shota (SHOWTIME)
