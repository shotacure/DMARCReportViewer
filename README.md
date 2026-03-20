# DMARC Report Viewer

**A Thunderbird add-on to visualize and analyze DMARC aggregate and forensic reports.**
**DMARC集約レポートとフォレンジックレポートを可視化・解析するThunderbirdアドオンです。**

DMARC Report Viewer scans designated mail folders for DMARC reports, decompresses and parses the XML attachments, and presents a clear dashboard with authentication statistics, per-domain breakdowns with pie charts, and source IP range analysis — all processed entirely locally within Thunderbird.

DMARC Report Viewer は、指定されたメールフォルダからDMARCレポートをスキャンし、添付XMLを解凍・解析して、円グラフ付きの認証統計・ドメイン別詳細分析・送信元IPアドレス範囲分析を分かりやすいダッシュボードで表示します。すべての処理はThunderbird内でローカルに完結します。

---

## 🌟 Key Features / 主な機能

* **Aggregate Report Analysis:** Parses RFC 7489 compliant DMARC XML reports from ZIP/GZ attachments with ISP-specific XML sanitization.
    * **集約レポート解析:** ZIP/GZ添付のDMARC XMLレポート（RFC 7489準拠）を、ISP固有のXML不整合修正を含めて解析します。
* **Per-Domain Detail Sections:** Displays comprehensive statistics for each domain including DKIM+SPF/DKIM/SPF pass counts, disposition distribution (Delivered/Quarantine/Reject), IP address ranges, reporters, policy override reasons, and published DMARC policy. IP ranges and reporters show full breakdown counts.
    * **ドメイン別詳細セクション:** 各ドメインのDKIM+SPF/DKIM/SPFパス数、disposition分布（配送済/隔離/拒否）、IPアドレス範囲、レポーター、ポリシーオーバーライド理由、公開DMARCポリシーを含む包括的な統計を表示します。IPアドレス範囲とレポーターには詳細な内訳を含みます。
* **Pie Chart Visualization:** Summary section includes three CSS-based pie charts — domain email distribution, disposition breakdown (Delivered/Quarantine/Reject), and reporter distribution — without external dependencies.
    * **円グラフによる可視化:** サマリーセクションにドメイン別メール分布、disposition内訳（配送済/隔離/拒否）、レポーター分布の3つのCSS円グラフを外部ライブラリなしで表示します。
* **IP Address Range Aggregation:** Groups source IPs by Class C range (e.g. `192.168.1.xxx`) for meaningful network-level analysis.
    * **IPアドレス範囲集約:** 送信元IPをClass C範囲（例: `192.168.1.xxx`）で集約し、ネットワークレベルの分析を可能にします。
* **Scan Period Selection:** Choose to scan reports from the last week, month, 3 months, 6 months, year, or all time.
    * **スキャン期間選択:** 直近1週間、1か月、3か月、半年、1年、または全期間からスキャン範囲を選択できます。
* **Result Persistence:** Scan results are cached and restored when reopening the dashboard popup.
    * **結果の永続化:** スキャン結果はキャッシュされ、ダッシュボードを再度開いた際に復元されます。
* **Forensic Report Viewing:** Displays individual authentication failure reports for investigation and abuse reporting.
    * **フォレンジックレポート閲覧:** 個別の認証失敗レポートを表示し、調査や通報の材料とします。
* **Automatic Folder Detection:** Automatically detects report folders based on naming conventions. Recovers gracefully when IMAP folder names are changed.
    * **フォルダ自動検出:** 命名規則に基づきレポートフォルダを自動検出します。IMAPフォルダ名が変更された場合も自動的に再検出します。
* **Data Completeness Validation:** Detects and reports missing or incomplete fields in DMARC reports, identifying unreadable messages by category.
    * **データ完全性検証:** DMARCレポート内の欠落・不完全なフィールドを検出・報告し、読み取り不能なメールをカテゴリ別に特定します。
* **Dark Mode:** Full dark mode support following system preference.
    * **ダークモード:** システムの設定に連動した完全なダークモード対応。
* **Privacy First:** All processing is performed strictly locally within Thunderbird. No external network requests are made.
    * **プライバシー重視:** すべての処理はThunderbird内でローカルに完結します。外部通信は一切行いません。

---

## 📋 Prerequisites / 前提条件

### DNS Configuration / DNS設定

Each domain needs a DMARC record with reporting addresses:
各ドメインにレポート送信先アドレスを含むDMARCレコードが必要です:

```
_dmarc.example.com. 300 IN TXT "v=DMARC1; p=reject; sp=reject; pct=100; adkim=s; aspf=s; fo=1; rua=mailto:dmarc-rua@example.com; ruf=mailto:dmarc-ruf@example.com"
```

### Mail Folder Setup / メールフォルダ設定

Create two folders (or Gmail labels) under a parent folder containing "DMARC" in its name:
「DMARC」を含む親フォルダの下に2つのサブフォルダ（またはGmailラベル）を作成します:

```
DMARC/
├── Aggregate    ← Aggregate reports / 集約レポート
└── Forensic     ← Forensic reports / フォレンジックレポート
```

The add-on automatically detects folders matching these patterns (case-insensitive):
アドオンは以下のパターンに一致するフォルダを自動検出します（大文字小文字不問）:

* **Aggregate reports:** A folder containing "aggregate" or "ar" inside a "dmarc" parent folder
* **Forensic reports:** A folder containing "forensic" or "fr" inside a "dmarc" parent folder

Set up mail filters to route reports by `To:` address.
`To:` アドレスでフィルタ振り分けを設定してください。

---

## 📥 Installation / インストール

> **Note:** This add-on requires [JSZip](https://stuk.github.io/jszip/) and [pako](https://github.com/nicknisi/pako) libraries to be placed in the `lib/` directory for ZIP/GZ decompression.

1. Download `jszip.min.js` and `pako.min.js` and place them in the `lib/` directory
2. Build the XPI package (see below)
3. Install in Thunderbird: Tools → Add-ons → Install Add-on From File

---

## 🏗️ Building from Source / ソースからのビルド

### Windows (PowerShell)
```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File build.ps1
```

### Linux / macOS (Bash)
```bash
chmod +x build.sh
./build.sh
```

Both scripts read the version from `manifest.json`, stage the required files, produce a `.xpi` package in `.release/`, and generate a SHA-256 checksum file.

---

## 🏛️ Architecture / アーキテクチャ

```
manifest.json               Extension manifest with i18n support
background.js               Message scanning, attachment extraction, decompression pipeline,
                             folder auto-detection, result caching, period filtering
parser/
├─ ar_parser.js             Aggregate report XML parser (RFC 7489) with validation,
│                            IP range aggregation, per-IP/reporter detailed stats
└─ fr_parser.js             Forensic report parser (RFC 6591 / AFRF) with validation
dashboard/
├─ dashboard.html           Main dashboard UI with period selector
├─ dashboard.css            Styles with CSS variables, dark mode, pie charts, bar charts
└─ dashboard.js             Dashboard logic — pie charts, per-domain sections, cache restore
options/
├─ options.html             Settings page (filtered to DMARC folders only)
└─ options.js               Folder selection & persistence
lib/
├─ jszip.min.js             ZIP decompression (user-provided)
└─ pako.min.js              GZIP decompression (user-provided)
images/
└─ icon.svg                 Extension icon
_locales/
├─ en/messages.json         English (default)
└─ ja/messages.json         日本語
```

### Processing Pipeline / 処理パイプライン

```
Period Filter → Auto-Detect Folders → Message Scan → Attachment Extraction
→ Decompress (GZ/ZIP) → XML Sanitize → Parse → Validate → Deduplicate
→ Per-Domain Aggregation (IP range + reporter detailed stats) → Cache → Render
```

---

## 📄 License / ライセンス

This project is licensed under the [GNU General Public License v3.0](LICENSE).

Copyright (C) 2025 Shota (SHOWTIME)
