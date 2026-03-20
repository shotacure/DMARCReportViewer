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
- **Period comparison**: Previous vs current period change indicators (↑↓→) on every stat card

### Identify threats — 脅威を特定する

- **IP range classification**: ✅ Legitimate / 🛡️ Blocked / ⚠️ Misconfigured / 🔴 Threat (Unblocked)
- **Adaptive IP aggregation**: Automatically merges IP ranges when multiple /24s share the same /16
- **Envelope alignment**: Detect Header From / Envelope From mismatches — distinguish third-party senders from spoofing
- **Subdomain analysis**: Track authentication status per subdomain

### Deep analysis — 認証基盤の深掘り

- **DKIM signature analysis**: Signing domains, selectors, third-party signature detection
- **SPF domain analysis**: Authentication domains, mfrom/helo scope tracking with helo-only warnings
- **Policy recommendations**: Per-domain advice for p=none → reject migration, adkim strict, pct=100
- **Policy override details**: Override reasons with associated IP ranges and forwarder detection

### Know your domain health — ドメインの健全度を知る

- **Health badges**: ✅ Healthy / 🛡️ Under Attack / ⚠️ Needs Attention / 🔴 At Risk
- **Delivered (Auth Fail)**: The most critical metric — emails that failed authentication but were delivered anyway

### Operational intelligence — 運用インテリジェンス

- **Forensic report cross-reference**: Forensic reports grouped per domain and linked to aggregate IP data
- **CSV export**: Export all IP range statistics and forensic reports for incident reporting
- **Result caching**: Scan results persist across tab reopens

---

## Features / 機能一覧

- **Full tab dashboard** — Opens in a dedicated Thunderbird tab
- **Collapsible domain sections** — Manage multiple domains without scrolling
- **Automatic folder detection** — Finds DMARC report folders by naming convention
- **ISP compatibility** — Handles gzip-first detection, Microsoft XML typos, zero-record reports
- **Period comparison** — Previous vs current period change detection
- **DKIM/SPF/Envelope deep analysis** — Full authentication chain visibility
- **Subdomain tracking** — Per-subdomain authentication status
- **Policy override details** — Override reasons with IP range attribution
- **Forensic cross-reference** — Forensic reports linked to domain sections
- **CSV export** — IP ranges + forensic data for compliance
- **Scan period selection** — 1 week / 1 month / 3 months / 6 months / 1 year / all time
- **Dark mode** — Full dark mode following system preference
- **i18n** — 12 languages: English, Japanese, German, French, Spanish, Italian, Korean, Chinese (Simplified/Traditional), Portuguese (BR), Russian, Arabic
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
                             folder auto-detection, result caching, period filtering,
                             previous-period comparison, forensic domain grouping
parser/
├─ ar_parser.js             RFC 7489 aggregate report parser with validation,
│                            IP range aggregation (adaptive /16 merging),
│                            deliveredPass/Fail classification, DKIM signature analysis,
│                            SPF domain analysis, envelope alignment detection,
│                            subdomain tracking, override detail attribution
└─ fr_parser.js             RFC 6591 forensic report parser with validation
dashboard/
├─ dashboard.html           Full-tab dashboard UI with export button
├─ dashboard.css            CSS variables, dark mode, 8-column grid, IP/health tags,
│                            collapsible sections, pie/line charts, advice boxes
└─ dashboard.js             Rendering logic — all analysis views, period comparison,
│                            CSV export, warning translation
options/
├─ options.html             Settings page
└─ options.js               Folder selection & persistence
lib/
├─ jszip.min.js             ZIP decompression (user-provided)
└─ pako.min.js              GZIP decompression (user-provided)
_locales/
├─ ar/  de/  en/  es/  fr/  it/  ja/  ko/  pt_BR/  ru/  zh_CN/  zh_TW/
└─ (124 keys per locale, 12 languages)
```

### Processing Pipeline

```
Period Filter (current + previous) → Auto-Detect Folders → Message Scan
→ Attachment Extraction → Decompress (GZ-first/ZIP) → XML Sanitize
→ Parse → Validate → Deduplicate → Current/Previous Period Split
→ DeliveredPass/Fail → IP Classification (adaptive merging)
→ DKIM Signature Aggregation → SPF Domain Aggregation → Envelope Alignment
→ Subdomain Detection → Override Detail Attribution → Forensic Cross-Reference
→ Domain Health Scoring → Policy Advice → Period Comparison → Cache → Render
```

---

## License / ライセンス

[GNU General Public License v3.0](LICENSE)

Copyright (C) 2025 Shota (SHOWTIME)
