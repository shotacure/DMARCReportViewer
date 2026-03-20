# DMARC Report Viewer

**A Thunderbird add-on to visualize and analyze DMARC aggregate and forensic reports.**
**DMARC集約レポートとフォレンジックレポートを可視化・解析するThunderbirdアドオンです。**

DMARC Report Viewer scans designated mail folders for DMARC reports, decompresses and parses the XML attachments, and presents a clear dashboard with authentication statistics, domain breakdowns, and source IP analysis — all processed entirely locally within Thunderbird.

DMARC Report Viewer は、指定されたメールフォルダからDMARCレポートをスキャンし、添付XMLを解凍・解析して、認証統計・ドメイン別分析・送信元IP分析を分かりやすいダッシュボードで表示します。すべての処理はThunderbird内でローカルに完結します。

---

## 🌟 Key Features / 主な機能

* **Aggregate Report Analysis:** Parses RFC 7489 compliant DMARC XML reports from ZIP/GZ attachments.
    * **集約レポート解析:** ZIP/GZ添付のDMARC XMLレポート（RFC 7489準拠）を解析します。
* **Forensic Report Viewing:** Displays individual authentication failure reports for investigation and abuse reporting.
    * **フォレンジックレポート閲覧:** 個別の認証失敗レポートを表示し、調査や通報の材料とします。
* **Automatic Folder Detection:** Automatically detects report folders based on naming conventions (e.g. `DMARC/Aggregate`, `DMARC/Forensic`). Recovers gracefully when IMAP folder names are changed.
    * **フォルダ自動検出:** 命名規則（例: `DMARC/Aggregate`、`DMARC/Forensic`）に基づきレポートフォルダを自動検出します。IMAPフォルダ名が変更された場合も自動的に再検出します。
* **Comprehensive Data Extraction:** Extracts all available information from reports including metadata errors, policy override reasons, and extended AFRF fields.
    * **網羅的なデータ抽出:** メタデータエラー、ポリシーオーバーライド理由、拡張AFRFフィールドを含む全情報を抽出します。
* **Data Completeness Validation:** Detects and reports missing or incomplete fields in DMARC reports, identifying problematic messages by category (parse failure, decompression failure, missing attachments, incomplete data, unknown formats).
    * **データ完全性検証:** DMARCレポート内の欠落・不完全なフィールドを検出・報告し、問題のあるメールをカテゴリ別（パース失敗、解凍失敗、添付なし、情報欠落、不明な形式）に特定します。
* **ISP Compatibility:** Handles known XML inconsistencies from major ISPs (e.g. Microsoft tag typos, non-standard element names).
    * **ISP互換性:** 主要ISPの既知のXML不整合（Microsoftのタグ誤記、非標準要素名など）に対応します。
* **Multi-Domain Support:** Handles reports for multiple domains in a single dashboard.
    * **複数ドメイン対応:** 複数ドメインのレポートを1つのダッシュボードで管理します。
* **Statistics Dashboard:** Total emails, DKIM/SPF pass rates, rejection counts, top source IPs, reporter breakdown, and policy override reason tracking.
    * **統計ダッシュボード:** メール総数、DKIM/SPFパス率、拒否数、送信元IP上位、レポーター別集計、ポリシーオーバーライド理由を表示します。
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
                             folder auto-detection and IMAP rename recovery
parser/
├─ ar_parser.js             Aggregate report XML parser (RFC 7489) with validation
└─ fr_parser.js             Forensic report parser (RFC 6591 / AFRF) with validation
dashboard/
├─ dashboard.html           Main dashboard UI
├─ dashboard.css            Styles with CSS variables & dark mode
└─ dashboard.js             Dashboard logic — scan, render, issues display
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
Auto-Detect Folders → Mail Folder → Message Scan → Attachment Extraction
→ Decompress (GZ/ZIP) → XML Sanitize → Parse → Validate
→ Deduplicate → Aggregate → Dashboard Render
         ↓
  Issues Classification
  (no attachment / decompress failed /
   parse failed / incomplete / unknown format)
```

---

## 📄 License / ライセンス

This project is licensed under the [GNU General Public License v3.0](LICENSE).

Copyright (C) 2025 Shota (SHOWTIME)
