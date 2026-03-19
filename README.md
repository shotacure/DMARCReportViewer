# DMARC Report Viewer

**A Thunderbird add-on to visualize and analyze DMARC aggregate (rua) and forensic (ruf) reports.**
**DMARC集約レポート(rua)とフォレンジックレポート(ruf)を可視化・解析するThunderbirdアドオンです。**

DMARC Report Viewer scans designated mail folders for DMARC reports, decompresses and parses the XML attachments, and presents a clear dashboard with authentication statistics, domain breakdowns, and source IP analysis — all processed entirely locally within Thunderbird.

DMARC Report Viewer は、指定されたメールフォルダからDMARCレポートをスキャンし、添付XMLを解凍・解析して、認証統計・ドメイン別分析・送信元IP分析を分かりやすいダッシュボードで表示します。すべての処理はThunderbird内でローカルに完結します。

---

## 🌟 Key Features / 主な機能

* **Aggregate Report Analysis (rua):** Parses RFC 7489 compliant DMARC XML reports from ZIP/GZ attachments.
    * **集約レポート解析 (rua):** ZIP/GZ添付のDMARC XMLレポート（RFC 7489準拠）を解析します。
* **Forensic Report Viewing (ruf):** Displays individual authentication failure reports for investigation and abuse reporting.
    * **フォレンジックレポート閲覧 (ruf):** 個別の認証失敗レポートを表示し、調査や通報の材料とします。
* **Multi-Domain Support:** Handles reports for multiple domains in a single dashboard.
    * **複数ドメイン対応:** 複数ドメインのレポートを1つのダッシュボードで管理します。
* **Statistics Dashboard:** Total emails, DKIM/SPF pass rates, rejection counts, top source IPs, and reporter breakdown.
    * **統計ダッシュボード:** メール総数、DKIM/SPFパス率、拒否数、送信元IP上位、レポーター別集計を表示します。
* **Dark Mode:** Full dark mode support following system preference.
    * **ダークモード:** システムの設定に連動した完全なダークモード対応。
* **Privacy First:** All processing is performed strictly locally within Thunderbird. No external network requests are made.
    * **プライバシー重視:** すべての処理はThunderbird内でローカルに完結します。外部通信は一切行いません。

---

## 📋 Prerequisites / 前提条件

### DNS Configuration / DNS設定

Each domain needs a DMARC record with rua/ruf addresses:
各ドメインにrua/rufアドレスを含むDMARCレコードが必要です:

```
_dmarc.example.com. 300 IN TXT "v=DMARC1; p=reject; sp=reject; pct=100; adkim=s; aspf=s; fo=1; rua=mailto:dmarc-rua@example.com; ruf=mailto:dmarc-ruf@example.com"
```

### Mail Folder Setup / メールフォルダ設定

Create two folders (or Gmail labels) to separate report types:
レポート種別を分けるため、2つのフォルダ（またはGmailラベル）を作成します:

```
DMARC/rua    ← Aggregate reports / 集約レポート
DMARC/ruf    ← Forensic reports / フォレンジックレポート
```

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
background.js               Message scanning, attachment extraction, decompression pipeline
parser/
├─ rua_parser.js            Aggregate report XML parser (RFC 7489)
└─ ruf_parser.js            Forensic report parser (RFC 6591 / AFRF)
dashboard/
├─ dashboard.html           Main dashboard UI
├─ dashboard.css            Styles with CSS variables & dark mode
└─ dashboard.js             Dashboard logic — scan, parse, render
options/
├─ options.html             Settings page
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
Mail Folder → Message Scan → Attachment Extraction → Decompress (ZIP/GZ)
→ XML Parse → Normalize → Deduplicate → Aggregate → Dashboard Render
```

---

## 📄 License / ライセンス

This project is licensed under the [GNU General Public License v3.0](LICENSE).

Copyright (C) 2025 Shota (SHOWTIME)
