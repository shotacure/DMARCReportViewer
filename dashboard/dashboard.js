// DMARCReportViewer - dashboard/dashboard.js

(() => {
  "use strict";

  const msg = (key) => browser.i18n.getMessage(key) || key;

  const applyI18n = () => {
    document.querySelectorAll("[data-i18n]").forEach(el => {
      const key = el.getAttribute("data-i18n");
      const text = msg(key);
      if (text && text !== key) el.textContent = text;
    });
  };

  const escapeHTML = (str) => {
    const div = document.createElement("div");
    div.appendChild(document.createTextNode(String(str)));
    return div.innerHTML;
  };

  const $ = (id) => document.getElementById(id);
  const show = (el) => el.classList.remove("drv-hidden");
  const hide = (el) => el.classList.add("drv-hidden");

  const PALETTE = [
    "#1565c0", "#e65100", "#2e7d32", "#6a1b9a", "#c62828",
    "#00838f", "#ef6c00", "#283593", "#4e342e", "#558b2f"
  ];
  const COLOR_DELIVERED = "#4caf50";
  const COLOR_QUARANTINE = "#ff9800";
  const COLOR_REJECT = "#f44336";

  const formatUnixDate = (unixSec) => !unixSec ? "-" : new Date(unixSec * 1000).toLocaleDateString();
  const pct = (n, total) => total > 0 ? (n / total * 100).toFixed(2) + "%" : "0.00%";

  const manifest = browser.runtime.getManifest();
  $("version").textContent = manifest.version;

  // =========================================================
  // 警告メッセージの翻訳マップ: パーサーの field をキーにして i18n 変換
  // パーサーは英語の message を返すが、UI 側でフィールド名から翻訳する
  // record[*] パターンは正規化して汎用キーにマッチさせる
  // =========================================================
  const translateWarning = (field, fallbackMessage) => {
    // record[N] を record[*] に正規化
    const normalized = field.replace(/\[\d+\]/, "[*]");

    // フィールド → i18n キーのマッピング
    const warningKeys = {
      "org_name": "warnOrgName",
      "report_id": "warnReportId",
      "email": "warnEmail",
      "date_range.begin": "warnDateRangeBegin",
      "date_range.end": "warnDateRangeEnd",
      "policy.domain": "warnPolicyDomain",
      "policy.p": "warnPolicyP",
      "records": "warnNoRecords",
      "record[*].source_ip": "warnRecordSourceIp",
      "record[*].count": "warnRecordCount",
      "record[*].policy_evaluated.dkim": "warnRecordDkim",
      "record[*].policy_evaluated.spf": "warnRecordSpf",
      "record[*].disposition": "warnRecordDisposition",
      "record[*].auth_results": "warnRecordAuthResults",
      "record[*].header_from": "warnRecordHeaderFrom",
      // フォレンジックレポート用
      "reported-domain": "warnFrDomain",
      "source-ip": "warnFrSourceIp",
      "authentication-results": "warnFrAuthResults",
      "auth-failure": "warnFrAuthFailure",
      "from": "warnFrFrom",
      "arrival-date": "warnFrArrivalDate",
      "original-mail-from": "warnFrMailFrom"
    };

    const key = warningKeys[normalized];
    if (key) {
      const translated = msg(key);
      if (translated && translated !== key) return translated;
    }
    // i18n キーがない場合は英語フォールバック
    return fallbackMessage;
  };

  // =========================================================
  // 7枠統計カードを生成する HTML
  // =========================================================
  const buildStatCards = (agg) => {
    const t = agg.totalCount;
    const items = [
      { label: msg("totalEmails"), value: t.toLocaleString(), pctText: "", colorClass: "" },
      { label: msg("dispositionDelivered"), value: agg.noneCount.toLocaleString(), pctText: pct(agg.noneCount, t), colorClass: agg.noneCount > 0 ? "drv-delivered-text" : "" },
      { label: msg("quarantined"), value: agg.quarantineCount.toLocaleString(), pctText: pct(agg.quarantineCount, t), colorClass: agg.quarantineCount > 0 ? "drv-quarantine-text" : "" },
      { label: msg("rejected"), value: agg.rejectCount.toLocaleString(), pctText: pct(agg.rejectCount, t), colorClass: agg.rejectCount > 0 ? "drv-reject-text" : "" },
      { label: msg("dkimSpfPass"), value: agg.passCount.toLocaleString(), pctText: pct(agg.passCount, t), colorClass: "" },
      { label: msg("dkimPass"), value: agg.dkimPassCount.toLocaleString(), pctText: pct(agg.dkimPassCount, t), colorClass: "" },
      { label: msg("spfPass"), value: agg.spfPassCount.toLocaleString(), pctText: pct(agg.spfPassCount, t), colorClass: "" }
    ];

    return items.map(item => {
      const lc = item.colorClass ? ` ${item.colorClass}` : "";
      return `<div class="drv-card">
        <div class="drv-card-label${lc}">${escapeHTML(item.label)}</div>
        <div class="drv-card-value${lc}">${item.value}</div>
        ${item.pctText ? `<div class="drv-card-pct">${item.pctText}</div>` : ""}
      </div>`;
    }).join("");
  };

  // =========================================================
  // SVG 円グラフ (ツールチップ付き)
  // =========================================================
  const buildPieChart = (title, segments) => {
    const total = segments.reduce((sum, s) => sum + s.value, 0);
    if (total === 0) return "";

    const size = 140;
    const cx = size / 2;
    const cy = size / 2;
    const r = size / 2 - 2;

    let paths = "";
    let startAngle = -Math.PI / 2;
    for (const seg of segments) {
      if (seg.value === 0) continue;
      const sliceAngle = (seg.value / total) * 2 * Math.PI;
      const endAngle = startAngle + sliceAngle;

      const x1 = cx + r * Math.cos(startAngle);
      const y1 = cy + r * Math.sin(startAngle);
      const x2 = cx + r * Math.cos(endAngle);
      const y2 = cy + r * Math.sin(endAngle);
      const largeArc = sliceAngle > Math.PI ? 1 : 0;

      const pctStr = (seg.value / total * 100).toFixed(2);
      const tooltip = `${seg.label}: ${seg.value.toLocaleString()} (${pctStr}%)`;

      paths += `<path d="M${cx},${cy} L${x1},${y1} A${r},${r} 0 ${largeArc} 1 ${x2},${y2} Z"
        fill="${seg.color}"><title>${escapeHTML(tooltip)}</title></path>`;

      startAngle = endAngle;
    }

    const legendItems = segments.filter(s => s.value > 0).map(s => {
      const pctStr = (s.value / total * 100).toFixed(2);
      return `<span class="drv-pie-legend-item">
        <span class="drv-legend-dot" style="background:${s.color}"></span>
        ${escapeHTML(s.label)}: ${s.value.toLocaleString()} (${pctStr}%)
      </span>`;
    }).join("");

    return `<div class="drv-pie-box">
      <div class="drv-pie-title">${escapeHTML(title)}</div>
      <svg class="drv-pie-svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">${paths}</svg>
      <div class="drv-pie-legend">${legendItems}</div>
    </div>`;
  };

  // =========================================================
  // Disposition 積み上げバー (パーセンテージ付き)
  // =========================================================
  const buildDispositionBar = (agg) => {
    if (agg.totalCount === 0) return "";
    const t = agg.totalCount;
    const dPct = agg.noneCount / t * 100;
    const qPct = agg.quarantineCount / t * 100;
    const rPct = agg.rejectCount / t * 100;
    const dLabel = msg("dispositionDelivered");
    const qLabel = msg("quarantined");
    const rLabel = msg("rejected");

    // セグメント内にパーセンテージを表示 (幅が十分な場合)
    const segText = (label, pctVal) => pctVal > 10 ? `${label} ${pctVal.toFixed(1)}%` : (pctVal > 5 ? `${pctVal.toFixed(1)}%` : "");

    return `
      <div class="drv-stacked-bar">
        ${dPct > 0 ? `<div class="drv-stacked-bar-segment drv-stacked-delivered" style="width:${dPct}%" title="${dLabel}: ${agg.noneCount.toLocaleString()} (${dPct.toFixed(2)}%)">${segText(dLabel, dPct)}</div>` : ""}
        ${qPct > 0 ? `<div class="drv-stacked-bar-segment drv-stacked-quarantine" style="width:${qPct}%" title="${qLabel}: ${agg.quarantineCount.toLocaleString()} (${qPct.toFixed(2)}%)">${segText(qLabel, qPct)}</div>` : ""}
        ${rPct > 0 ? `<div class="drv-stacked-bar-segment drv-stacked-reject" style="width:${rPct}%" title="${rLabel}: ${agg.rejectCount.toLocaleString()} (${rPct.toFixed(2)}%)">${segText(rLabel, rPct)}</div>` : ""}
      </div>
      <div class="drv-pie-legend" style="flex-direction:row;flex-wrap:wrap;gap:8px;padding-left:0;">
        <span class="drv-pie-legend-item"><span class="drv-legend-dot drv-stacked-delivered"></span>${dLabel} ${agg.noneCount.toLocaleString()} (${dPct.toFixed(2)}%)</span>
        <span class="drv-pie-legend-item"><span class="drv-legend-dot drv-stacked-quarantine"></span>${qLabel} ${agg.quarantineCount.toLocaleString()} (${qPct.toFixed(2)}%)</span>
        <span class="drv-pie-legend-item"><span class="drv-legend-dot drv-stacked-reject"></span>${rLabel} ${agg.rejectCount.toLocaleString()} (${rPct.toFixed(2)}%)</span>
      </div>`;
  };

  // =========================================================
  // 詳細統計テーブル — 全カラム実数、色付きは値>0の場合のみ
  // =========================================================
  const buildDetailedTable = (headerLabel, entries, isCode) => {
    if (!entries || entries.length === 0) return "";

    const hCount = msg("colCount");
    const hDelivered = msg("dispositionDelivered");
    const hQuar = msg("quarantined");
    const hRej = msg("rejected");
    const hFull = msg("dkimSpfPass");
    const hDkim = msg("dkimPass");
    const hSpf = msg("spfPass");

    let html = `<table class="drv-table"><thead><tr>
      <th>${escapeHTML(headerLabel)}</th>
      <th>${escapeHTML(hCount)}</th>
      <th class="drv-delivered-text">${escapeHTML(hDelivered)}</th>
      <th class="drv-quarantine-text">${escapeHTML(hQuar)}</th>
      <th class="drv-reject-text">${escapeHTML(hRej)}</th>
      <th>${escapeHTML(hFull)}</th>
      <th>${escapeHTML(hDkim)}</th>
      <th>${escapeHTML(hSpf)}</th>
    </tr></thead><tbody>`;

    for (const e of entries) {
      const keyCell = isCode ? `<code>${escapeHTML(e.key)}</code>` : escapeHTML(e.key);
      // 色はインラインスタイルで確実に適用 (値 > 0 の場合のみ)
      const dStyle = e.delivered > 0 ? ' style="color:var(--drv-color-delivered);font-weight:bold"' : "";
      const qStyle = e.quarantine > 0 ? ' style="color:var(--drv-color-quarantine);font-weight:bold"' : "";
      const rStyle = e.reject > 0 ? ' style="color:var(--drv-color-reject);font-weight:bold"' : "";
      const fmtOrDash = (v) => v > 0 ? v.toLocaleString() : "-";
      html += `<tr>
        <td>${keyCell}</td>
        <td>${e.count.toLocaleString()}</td>
        <td${dStyle}>${fmtOrDash(e.delivered)}</td>
        <td${qStyle}>${fmtOrDash(e.quarantine)}</td>
        <td${rStyle}>${fmtOrDash(e.reject)}</td>
        <td>${fmtOrDash(e.fullPass)}</td>
        <td>${fmtOrDash(e.dkimPass)}</td>
        <td>${fmtOrDash(e.spfPass)}</td>
      </tr>`;
    }
    html += "</tbody></table>";
    return html;
  };

  // =========================================================
  // 結果描画メイン
  // =========================================================
  const renderResults = (results) => {
    $("domains-container").innerHTML = "";
    $("pie-row").innerHTML = "";

    if (results.ar.length > 0 && results.aggregate) {
      const agg = results.aggregate;

      if (agg.dateRangeMin && agg.dateRangeMax) {
        const reportsLabel = msg("colReports");
        const ipRangesLabel = msg("sectionTopIps");
        $("period-info").textContent = `${formatUnixDate(agg.dateRangeMin)} – ${formatUnixDate(agg.dateRangeMax)}` +
          ` | ${agg.reportCount} ${reportsLabel} | ${agg.uniqueIpRanges} ${ipRangesLabel}`;
        show($("period-info"));
      }

      $("summary-cards").innerHTML = buildStatCards(agg);
      renderPieCharts(agg);
      show($("summary-section"));

      if (results.domainDetails) {
        const periodDays = results.scanPeriodDays || 0;
        for (const dd of results.domainDetails) {
          renderDomainSection(dd, periodDays);
        }
      }
    }

    if (results.fr.length > 0) renderFrTable(results.fr);

    if (results.issuesSummary && results.issuesSummary.totalIssues > 0) {
      renderIssues(results.issuesSummary, results.issues);
    }
  };

  // =========================================================
  // 初期化
  // =========================================================
  const init = async () => {
    applyI18n();

    const settings = await browser.runtime.sendMessage({ command: "resolveSettings" });
    if (!settings.arFolderId && !settings.frFolderId) {
      show($("no-folder-notice"));
    } else {
      hide($("no-folder-notice"));
    }

    // キャッシュ復元
    const cached = await browser.runtime.sendMessage({ command: "getLastResults" });
    if (cached && (cached.ar?.length > 0 || cached.fr?.length > 0)) {
      renderResults(cached);
      const e = cached.errors?.length || 0;
      const errText = e > 0 ? ` (${e} ${msg("statusErrors")})` : "";
      showStatus(`${msg("statusComplete")} ${cached.ar.length} ${msg("arReports")}, ${cached.fr.length} ${msg("frReports")}${errText} (${msg("statusCached")})`);
    }
  };

  const showStatus = (text, isLoading = false) => {
    $("status-bar").classList.remove("drv-hidden");
    $("status-message").innerHTML = isLoading
      ? `<span class="drv-spinner"></span>${escapeHTML(text)}`
      : escapeHTML(text);
  };

  $("btn-settings").addEventListener("click", () => browser.runtime.openOptionsPage());

  // =========================================================
  // スキャン
  // =========================================================
  $("btn-scan").addEventListener("click", async () => {
    $("btn-scan").disabled = true;
    showStatus(msg("statusScanning"), true);

    const days = parseInt($("period-select").value, 10);
    const since = days > 0 ? Date.now() - (days * 24 * 60 * 60 * 1000) : 0;

    try {
      const results = await browser.runtime.sendMessage({ command: "scanReports", since, sinceDay: days });

      if (results.error) {
        showStatus(`Error: ${results.error}`);
        $("btn-scan").disabled = false;
        return;
      }

      renderResults(results);

      const e = results.errors.length;
      const errText = e > 0 ? ` (${e} ${msg("statusErrors")})` : "";
      showStatus(`${msg("statusComplete")} ${results.ar.length} ${msg("arReports")}, ${results.fr.length} ${msg("frReports")}${errText}`);

    } catch (err) {
      showStatus(`Error: ${err.message}`);
    } finally {
      $("btn-scan").disabled = false;
    }
  });

  // =========================================================
  // 円グラフ3つ
  // =========================================================
  const renderPieCharts = (agg) => {
    const pieRow = $("pie-row");
    pieRow.innerHTML = "";

    if (agg.domains && agg.domains.length > 0) {
      pieRow.innerHTML += buildPieChart(msg("colDomain"),
        agg.domains.map((d, i) => ({ label: d.domain, value: d.count, color: PALETTE[i % PALETTE.length] })));
    }

    const dispSegs = [
      { label: msg("dispositionDelivered"), value: agg.noneCount, color: COLOR_DELIVERED },
      { label: msg("quarantined"), value: agg.quarantineCount, color: COLOR_QUARANTINE },
      { label: msg("rejected"), value: agg.rejectCount, color: COLOR_REJECT }
    ].filter(s => s.value > 0);
    if (dispSegs.length > 0) {
      pieRow.innerHTML += buildPieChart(msg("dispositionTitle"), dispSegs);
    }

    if (agg.reporters && agg.reporters.length > 0) {
      pieRow.innerHTML += buildPieChart(msg("colReporter"),
        agg.reporters.map((r, i) => ({ label: r.name, value: r.count, color: PALETTE[i % PALETTE.length] })));
    }
  };

  // =========================================================
  // SVG 折れ線グラフ: 時系列の配送済/隔離/拒否の推移
  // timeSeries: [{ begin (unix sec), delivered, quarantine, reject }]
  // periodDays: スキャン期間(日数) → 集計単位を決定
  //   1w(7),1m(30) → 日別  3m(90),6m(180) → 週別  1y(365),all(0) → 月別
  // =========================================================
  const buildTimeSeriesChart = (timeSeries, periodDays) => {
    if (!timeSeries || timeSeries.length === 0) return "";

    // 集計単位の決定
    let unitLabel, bucketKeyFn;
    if (periodDays > 0 && periodDays <= 30) {
      unitLabel = "daily";
      bucketKeyFn = (ts) => {
        const d = new Date(ts * 1000);
        return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
      };
    } else if (periodDays > 0 && periodDays <= 180) {
      unitLabel = "weekly";
      bucketKeyFn = (ts) => {
        const d = new Date(ts * 1000);
        const day = d.getDay();
        const mondayOffset = day === 0 ? -6 : 1 - day;
        const monday = new Date(d);
        monday.setDate(d.getDate() + mondayOffset);
        return `${monday.getFullYear()}-${String(monday.getMonth() + 1).padStart(2, "0")}-${String(monday.getDate()).padStart(2, "0")}`;
      };
    } else {
      unitLabel = "monthly";
      bucketKeyFn = (ts) => {
        const d = new Date(ts * 1000);
        return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
      };
    }

    // バケットに集計
    const buckets = new Map();
    for (const entry of timeSeries) {
      if (!entry.begin) continue;
      const key = bucketKeyFn(entry.begin);
      const existing = buckets.get(key);
      if (existing) {
        existing.delivered += entry.delivered;
        existing.quarantine += entry.quarantine;
        existing.reject += entry.reject;
      } else {
        buckets.set(key, { key, delivered: entry.delivered, quarantine: entry.quarantine, reject: entry.reject });
      }
    }

    if (buckets.size === 0) return "";

    // 欠落期間を 0 で埋める: 最小キーから最大キーまで連続バケットを生成
    const allKeys = [...buckets.keys()].sort();
    const filledBuckets = [];

    if (unitLabel === "daily") {
      // 日別: 1日ずつインクリメント
      const startDate = new Date(allKeys[0] + "T00:00:00");
      const endDate = new Date(allKeys[allKeys.length - 1] + "T00:00:00");
      for (let d = new Date(startDate); d <= endDate; d.setDate(d.getDate() + 1)) {
        const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
        filledBuckets.push(buckets.get(key) || { key, delivered: 0, quarantine: 0, reject: 0 });
      }
    } else if (unitLabel === "weekly") {
      // 週別: 7日ずつインクリメント
      const startDate = new Date(allKeys[0] + "T00:00:00");
      const endDate = new Date(allKeys[allKeys.length - 1] + "T00:00:00");
      for (let d = new Date(startDate); d <= endDate; d.setDate(d.getDate() + 7)) {
        const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
        filledBuckets.push(buckets.get(key) || { key, delivered: 0, quarantine: 0, reject: 0 });
      }
    } else {
      // 月別: 1か月ずつインクリメント
      const [startY, startM] = allKeys[0].split("-").map(Number);
      const [endY, endM] = allKeys[allKeys.length - 1].split("-").map(Number);
      let y = startY, m = startM;
      while (y < endY || (y === endY && m <= endM)) {
        const key = `${y}-${String(m).padStart(2, "0")}`;
        filledBuckets.push(buckets.get(key) || { key, delivered: 0, quarantine: 0, reject: 0 });
        m++;
        if (m > 12) { m = 1; y++; }
      }
    }

    const sorted = filledBuckets;
    if (sorted.length < 2) return "";

    // 最大値の算出
    let maxVal = 0;
    for (const b of sorted) {
      maxVal = Math.max(maxVal, b.delivered, b.quarantine, b.reject);
    }
    if (maxVal === 0) maxVal = 1; // 全部0でも軸は描画する

    // SVG 描画パラメータ
    const w = 860;
    const h = 200;
    const padL = 50;   // 左余白 (Y軸ラベル用)
    const padR = 40;   // 右余白 (右端ラベル用)
    const padT = 12;
    const padB = 40;   // 下余白 (X軸ラベル用)
    const chartW = w - padL - padR;
    const chartH = h - padT - padB;
    const n = sorted.length;

    // 座標変換
    const xAt = (i) => padL + (i / (n - 1)) * chartW;
    const yAt = (v) => padT + chartH - (v / maxVal) * chartH;

    // SVG polyline の points 文字列を生成
    const toPolyline = (field) => sorted.map((b, i) => `${xAt(i).toFixed(1)},${yAt(b[field]).toFixed(1)}`).join(" ");

    // Y軸グリッド線 (5本)
    let gridLines = "";
    for (let i = 0; i <= 4; i++) {
      const yVal = Math.round(maxVal * i / 4);
      const y = yAt(yVal);
      gridLines += `<line x1="${padL}" y1="${y}" x2="${w - padR}" y2="${y}" class="drv-grid-line"/>`;
      gridLines += `<text x="${padL - 6}" y="${y + 4}" text-anchor="end" font-size="11">${yVal}</text>`;
    }

    // X軸ラベル (最大10個程度に間引く)
    let xLabels = "";
    const step = Math.max(1, Math.floor(n / 10));
    for (let i = 0; i < n; i += step) {
      const x = xAt(i);
      const label = unitLabel === "monthly" ? sorted[i].key : sorted[i].key.slice(5);
      xLabels += `<text x="${x}" y="${h - padB + 16}" text-anchor="middle" font-size="11">${label}</text>`;
    }
    // 最後のラベルも表示 (右端は end 揃えで切れないように)
    if ((n - 1) % step !== 0) {
      const x = xAt(n - 1);
      const label = unitLabel === "monthly" ? sorted[n - 1].key : sorted[n - 1].key.slice(5);
      xLabels += `<text x="${x}" y="${h - padB + 16}" text-anchor="end" font-size="11">${label}</text>`;
    }

    // データポイントのドット + ツールチップ
    let dots = "";
    for (let i = 0; i < n; i++) {
      const b = sorted[i];
      const x = xAt(i);
      const fields = [
        { field: "delivered", color: COLOR_DELIVERED, label: msg("dispositionDelivered") },
        { field: "quarantine", color: COLOR_QUARANTINE, label: msg("quarantined") },
        { field: "reject", color: COLOR_REJECT, label: msg("rejected") }
      ];
      for (const f of fields) {
        const y = yAt(b[f.field]);
        const tip = `${b.key} — ${f.label}: ${b[f.field].toLocaleString()}`;
        dots += `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="3" fill="${f.color}" opacity="0.8"><title>${escapeHTML(tip)}</title></circle>`;
      }
    }

    const dLabel = msg("dispositionDelivered");
    const qLabel = msg("quarantined");
    const rLabel = msg("rejected");

    return `<div class="drv-chart-container">
      <div class="drv-chart-title">${escapeHTML(msg("chartTimeSeries"))}</div>
      <svg class="drv-chart-svg" viewBox="0 0 ${w} ${h}" preserveAspectRatio="xMidYMid meet">
        ${gridLines}
        <line x1="${padL}" y1="${padT}" x2="${padL}" y2="${padT + chartH}" class="drv-axis-line"/>
        <line x1="${padL}" y1="${padT + chartH}" x2="${w - padR}" y2="${padT + chartH}" class="drv-axis-line"/>
        ${xLabels}
        <polyline points="${toPolyline("delivered")}" fill="none" stroke="${COLOR_DELIVERED}" stroke-width="2"/>
        <polyline points="${toPolyline("quarantine")}" fill="none" stroke="${COLOR_QUARANTINE}" stroke-width="2"/>
        <polyline points="${toPolyline("reject")}" fill="none" stroke="${COLOR_REJECT}" stroke-width="2"/>
        ${dots}
      </svg>
      <div class="drv-chart-legend-row">
        <span class="drv-pie-legend-item"><span class="drv-legend-dot" style="background:${COLOR_DELIVERED}"></span>${dLabel}</span>
        <span class="drv-pie-legend-item"><span class="drv-legend-dot" style="background:${COLOR_QUARANTINE}"></span>${qLabel}</span>
        <span class="drv-pie-legend-item"><span class="drv-legend-dot" style="background:${COLOR_REJECT}"></span>${rLabel}</span>
      </div>
    </div>`;
  };

  // =========================================================
  // ドメイン別詳細セクション
  // =========================================================
  const renderDomainSection = (dd, periodDays) => {
    const agg = dd.aggregate;
    const section = document.createElement("div");
    section.className = "drv-domain-section";

    const pol = dd.policy;
    const policyStr = `p=${pol.p} sp=${pol.sp} adkim=${pol.adkim} aspf=${pol.aspf} pct=${pol.pct}` +
      (pol.fo !== "0" ? ` fo=${pol.fo}` : "");

    let html = `<div class="drv-domain-header">
      <span>📋 ${escapeHTML(dd.domain)}</span>
      <span class="drv-domain-policy">${escapeHTML(policyStr)}</span>
      <span style="margin-left:auto;font-size:12px;color:var(--drv-text-muted);">${agg.reportCount} ${escapeHTML(msg("colReports"))}</span>
    </div>`;

    // 7枠コンパクトカード — 配送済/隔離/拒否は常に色付き
    const t = agg.totalCount;
    const compactItems = [
      { label: msg("totalEmails"), value: t.toLocaleString(), pctText: "", colorClass: "" },
      { label: msg("dispositionDelivered"), value: agg.noneCount.toLocaleString(), pctText: pct(agg.noneCount, t), colorClass: "drv-delivered-text" },
      { label: msg("quarantined"), value: agg.quarantineCount.toLocaleString(), pctText: pct(agg.quarantineCount, t), colorClass: "drv-quarantine-text" },
      { label: msg("rejected"), value: agg.rejectCount.toLocaleString(), pctText: pct(agg.rejectCount, t), colorClass: "drv-reject-text" },
      { label: msg("dkimSpfPass"), value: agg.passCount.toLocaleString(), pctText: pct(agg.passCount, t), colorClass: "" },
      { label: msg("dkimPass"), value: agg.dkimPassCount.toLocaleString(), pctText: pct(agg.dkimPassCount, t), colorClass: "" },
      { label: msg("spfPass"), value: agg.spfPassCount.toLocaleString(), pctText: pct(agg.spfPassCount, t), colorClass: "" }
    ];

    html += '<div class="drv-card-grid-compact">';
    for (const item of compactItems) {
      const lc = item.colorClass ? ` ${item.colorClass}` : "";
      html += `<div class="drv-card-compact">
        <div class="drv-card-label${lc}">${escapeHTML(item.label)}</div>
        <div class="drv-card-value${lc}">${item.value}</div>
        ${item.pctText ? `<div class="drv-card-pct">${item.pctText}</div>` : ""}
      </div>`;
    }
    html += '</div>';

    // Disposition バー (パーセンテージ付き)
    html += buildDispositionBar(agg);

    // 折れ線グラフ: 時系列の配送処理推移
    if (dd.timeSeries && dd.timeSeries.length >= 2) {
      html += buildTimeSeriesChart(dd.timeSeries, periodDays);
    }

    // IP アドレス範囲テーブル
    if (agg.topIpRanges && agg.topIpRanges.length > 0) {
      html += `<div class="drv-domain-subsection">
        <div class="drv-domain-subtitle">${escapeHTML(msg("sectionTopIps"))}</div>
        ${buildDetailedTable(msg("colIpRange"), agg.topIpRanges, true)}
      </div>`;
    }

    // レポーター別テーブル
    if (agg.topReporters && agg.topReporters.length > 0) {
      html += `<div class="drv-domain-subsection">
        <div class="drv-domain-subtitle">${escapeHTML(msg("sectionReporters"))}</div>
        ${buildDetailedTable(msg("colReporter"), agg.topReporters, false)}
      </div>`;
    }

    // ポリシーオーバーライド
    if (agg.overrideReasons && agg.overrideReasons.length > 0) {
      html += `<div class="drv-domain-subsection">
        <div class="drv-domain-subtitle">${escapeHTML(msg("sectionOverrides"))}</div>
        <table class="drv-table"><thead><tr>
          <th>${escapeHTML(msg("colOverrideType"))}</th>
          <th>${escapeHTML(msg("colCount"))}</th>
        </tr></thead><tbody>`;
      for (const entry of agg.overrideReasons) {
        html += `<tr><td>${escapeHTML(entry.type)}</td><td>${entry.count.toLocaleString()}</td></tr>`;
      }
      html += '</tbody></table></div>';
    }

    // ISP メタデータエラー
    if (agg.warningsSummary && agg.warningsSummary.reportsWithMetadataErrors > 0) {
      html += `<div class="drv-domain-subsection">
        <div class="drv-domain-subtitle">${escapeHTML(msg("ispMetadataErrors"))}</div>
        <p style="font-size:12px;color:var(--drv-warn);">
          ${agg.warningsSummary.reportsWithMetadataErrors} ${escapeHTML(msg("ispMetadataErrorsDetail"))}
        </p>
      </div>`;
    }

    section.innerHTML = html;
    $("domains-container").appendChild(section);
  };

  // =========================================================
  // フォレンジックレポート
  // =========================================================
  const renderFrTable = (frReports) => {
    const tbody = $("fr-table").querySelector("tbody");
    tbody.innerHTML = "";
    const sorted = [...frReports].sort((a, b) => new Date(b.messageDate) - new Date(a.messageDate));
    for (const r of sorted) {
      const tr = document.createElement("tr");
      const dateStr = r.messageDate ? new Date(r.messageDate).toLocaleDateString() : "-";
      tr.innerHTML = `<td>${escapeHTML(dateStr)}</td><td>${escapeHTML(r.reportedDomain)}</td>
        <td><code>${escapeHTML(r.sourceIp)}</code></td><td>${escapeHTML(r.authFailure || "-")}</td>`;
      tbody.appendChild(tr);
    }
    show($("fr-section"));
  };

  // =========================================================
  // 読み取り不能なレポート — 警告メッセージを翻訳して表示
  // =========================================================
  const renderIssues = (summary, issues) => {
    $("issue-parse-failed").textContent = summary.parseFailed.toLocaleString();
    $("issue-decompress-failed").textContent = summary.decompressFailed.toLocaleString();
    $("issue-incomplete").textContent = summary.incompleteReport.toLocaleString();
    $("issue-no-attachment").textContent = summary.noAttachment.toLocaleString();
    $("issue-unknown-format").textContent = summary.unknownFormat.toLocaleString();

    const allIssues = [];
    for (const item of issues.parseFailed) allIssues.push({ date: item.date, category: msg("issueParseFailed"), categoryClass: "drv-fail-text", subject: item.subject || "-", detail: item.error || "-" });
    for (const item of issues.decompressFailed) allIssues.push({ date: item.date, category: msg("issueDecompressFailed"), categoryClass: "drv-fail-text", subject: item.subject || "-", detail: `${item.attachment}: ${item.error || "-"}` });
    for (const item of issues.noAttachment) allIssues.push({ date: item.date, category: msg("issueNoAttachment"), categoryClass: "drv-warn-text", subject: item.subject || "-", detail: msg("issueNoAttachmentDetail") });
    for (const item of issues.unknownFormat) allIssues.push({ date: item.date, category: msg("issueUnknownFormat"), categoryClass: "drv-warn-text", subject: item.subject || "-", detail: `${item.attachment} (${item.contentType || "unknown"})` });
    for (const item of issues.incompleteReport) {
      // 警告メッセージを翻訳して表示
      const wt = item.warnings.slice(0, 3).map(w => translateWarning(w.field, w.message));
      const rem = item.warnings.length - 3;
      let detail = wt.join("; ");
      if (rem > 0) detail += ` (+${rem})`;
      allIssues.push({ date: item.date, category: msg("issueIncomplete"), categoryClass: "", subject: item.subject || "-", detail });
    }

    allIssues.sort((a, b) => {
      if (!a.date) return 1; if (!b.date) return -1;
      return new Date(b.date) - new Date(a.date);
    });

    const tbody = $("issues-table").querySelector("tbody");
    tbody.innerHTML = "";
    for (const issue of allIssues) {
      const tr = document.createElement("tr");
      const dateStr = issue.date ? new Date(issue.date).toLocaleDateString() : "-";
      tr.innerHTML = `<td>${escapeHTML(dateStr)}</td><td class="${issue.categoryClass}">${escapeHTML(issue.category)}</td>
        <td>${escapeHTML(issue.subject)}</td><td>${escapeHTML(issue.detail)}</td>`;
      tbody.appendChild(tr);
    }
    show($("issues-section"));
  };

  init();
})();
