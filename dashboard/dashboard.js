// DMARCReportViewer - dashboard/dashboard.js v0.1.2

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

  const PALETTE = ["#1565c0","#e65100","#2e7d32","#6a1b9a","#c62828","#00838f","#ef6c00","#283593","#4e342e","#558b2f"];
  const COLOR_DELIVERED = "#4caf50";
  const COLOR_DELIVERED_FAIL = "#e53935";
  const COLOR_QUARANTINE = "#ff9800";
  const COLOR_REJECT = "#f44336";

  const formatUnixDate = (s) => !s ? "-" : new Date(s * 1000).toLocaleDateString();
  const pct = (n, t) => t > 0 ? (n / t * 100).toFixed(2) + "%" : "0.00%";

  $("version").textContent = browser.runtime.getManifest().version;

  // =========================================================
  // 警告メッセージの翻訳マップ
  // =========================================================
  const translateWarning = (field, fallback) => {
    const normalized = field.replace(/\[\d+\]/, "[*]");
    const map = {
      "org_name":"warnOrgName","report_id":"warnReportId","email":"warnEmail",
      "date_range.begin":"warnDateRangeBegin","date_range.end":"warnDateRangeEnd",
      "policy.domain":"warnPolicyDomain","policy.p":"warnPolicyP","records":"warnNoRecords",
      "record[*].source_ip":"warnRecordSourceIp","record[*].count":"warnRecordCount",
      "record[*].policy_evaluated.dkim":"warnRecordDkim","record[*].policy_evaluated.spf":"warnRecordSpf",
      "record[*].disposition":"warnRecordDisposition","record[*].auth_results":"warnRecordAuthResults",
      "record[*].header_from":"warnRecordHeaderFrom",
      "reported-domain":"warnFrDomain","source-ip":"warnFrSourceIp",
      "authentication-results":"warnFrAuthResults","auth-failure":"warnFrAuthFailure",
      "from":"warnFrFrom","arrival-date":"warnFrArrivalDate","original-mail-from":"warnFrMailFrom"
    };
    const key = map[normalized];
    if (key) { const t = msg(key); if (t && t !== key) return t; }
    return fallback;
  };

  // =========================================================
  // IP 範囲の自動分類タグを算出
  // =========================================================
  const classifyIpRange = (e) => {
    // 全 pass + 全配送 → 正規の送信元
    if (e.fullPass === e.count && e.deliveredPass === e.count)
      return { tag: "legitimate", label: msg("tagLegitimate"), cls: "drv-ip-tag-legitimate", tip: msg("tagLegitimateDesc") };
    // fail あり + deliveredFail あり → 認証失敗なのに素通り (最も危険)
    if (e.deliveredFail > 0)
      return { tag: "threat", label: msg("tagThreat"), cls: "drv-ip-tag-threat", tip: msg("tagThreatDesc") };
    // 全 fail + 全 reject → 不正だがブロック済み
    if (e.fullPass === 0 && e.reject === e.count)
      return { tag: "blocked", label: msg("tagBlocked"), cls: "drv-ip-tag-blocked", tip: msg("tagBlockedDesc") };
    // pass もあるが reject/quarantine もある → 設定不備の可能性
    if (e.fullPass > 0 && (e.reject > 0 || e.quarantine > 0))
      return { tag: "misconfigured", label: msg("tagMisconfigured"), cls: "drv-ip-tag-misconfigured", tip: msg("tagMisconfiguredDesc") };
    // 全 fail + 全 reject/quarantine
    if (e.fullPass === 0 && e.count > 0)
      return { tag: "blocked", label: msg("tagBlocked"), cls: "drv-ip-tag-blocked", tip: msg("tagBlockedDesc") };
    return { tag: "unknown", label: "—", cls: "", tip: "" };
  };

  // =========================================================
  // ドメイン健全度バッジを算出
  // =========================================================
  const computeHealthBadge = (agg, policy) => {
    const hasDeliveredFail = agg.deliveredFailCount > 0;
    const isRejectPolicy = policy.p === "reject";
    const isHighPassRate = agg.fullPassRate >= 95;

    if (!hasDeliveredFail && isRejectPolicy && isHighPassRate && agg.rejectCount === 0)
      return { cls: "drv-health-healthy", label: msg("healthHealthy"), icon: "✅" };
    if (!hasDeliveredFail && agg.rejectCount > 0 && isRejectPolicy)
      return { cls: "drv-health-under-attack", label: msg("healthUnderAttack"), icon: "🛡️" };
    if (hasDeliveredFail || !isRejectPolicy)
      return { cls: "drv-health-needs-attention", label: msg("healthNeedsAttention"), icon: "⚠️" };
    return { cls: "drv-health-at-risk", label: msg("healthAtRisk"), icon: "🔴" };
  };

  // =========================================================
  // 8枠統計カード HTML
  // =========================================================
  const buildStatCards = (agg) => {
    const t = agg.totalCount;
    const items = [
      { label: msg("totalEmails"), value: t.toLocaleString(), pctText: "", colorClass: "" },
      { label: msg("deliveredPass"), value: agg.deliveredPassCount.toLocaleString(), pctText: pct(agg.deliveredPassCount, t), colorClass: "drv-delivered-text" },
      { label: msg("deliveredFail"), value: agg.deliveredFailCount.toLocaleString(), pctText: pct(agg.deliveredFailCount, t), colorClass: "drv-delivered-fail-text" },
      { label: msg("quarantined"), value: agg.quarantineCount.toLocaleString(), pctText: pct(agg.quarantineCount, t), colorClass: "drv-quarantine-text" },
      { label: msg("rejected"), value: agg.rejectCount.toLocaleString(), pctText: pct(agg.rejectCount, t), colorClass: agg.rejectCount > 0 ? "drv-reject-text" : "" },
      { label: msg("dkimSpfPass"), value: agg.passCount.toLocaleString(), pctText: pct(agg.passCount, t), colorClass: "" },
      { label: msg("dkimPass"), value: agg.dkimPassCount.toLocaleString(), pctText: pct(agg.dkimPassCount, t), colorClass: "" },
      { label: msg("spfPass"), value: agg.spfPassCount.toLocaleString(), pctText: pct(agg.spfPassCount, t), colorClass: "" }
    ];
    return items.map(i => {
      const lc = i.colorClass ? ` ${i.colorClass}` : "";
      return `<div class="drv-card"><div class="drv-card-label${lc}">${escapeHTML(i.label)}</div><div class="drv-card-value${lc}">${i.value}</div>${i.pctText ? `<div class="drv-card-pct">${i.pctText}</div>` : ""}</div>`;
    }).join("");
  };

  // =========================================================
  // SVG 円グラフ (ツールチップ付き)
  // =========================================================
  const buildPieChart = (title, segments) => {
    const total = segments.reduce((sum, s) => sum + s.value, 0);
    if (total === 0) return "";
    const size = 140, cx = size/2, cy = size/2, r = size/2 - 2;
    let paths = "", startAngle = -Math.PI / 2;
    for (const seg of segments) {
      if (seg.value === 0) continue;
      const sliceAngle = (seg.value / total) * 2 * Math.PI;
      const endAngle = startAngle + sliceAngle;
      const x1 = cx + r * Math.cos(startAngle), y1 = cy + r * Math.sin(startAngle);
      const x2 = cx + r * Math.cos(endAngle), y2 = cy + r * Math.sin(endAngle);
      const largeArc = sliceAngle > Math.PI ? 1 : 0;
      const pctStr = (seg.value / total * 100).toFixed(2);
      paths += `<path d="M${cx},${cy} L${x1},${y1} A${r},${r} 0 ${largeArc} 1 ${x2},${y2} Z" fill="${seg.color}"><title>${escapeHTML(seg.label)}: ${seg.value.toLocaleString()} (${pctStr}%)</title></path>`;
      startAngle = endAngle;
    }
    const legend = segments.filter(s => s.value > 0).map(s => {
      const p = (s.value / total * 100).toFixed(2);
      return `<span class="drv-pie-legend-item"><span class="drv-legend-dot" style="background:${s.color}"></span>${escapeHTML(s.label)}: ${s.value.toLocaleString()} (${p}%)</span>`;
    }).join("");
    return `<div class="drv-pie-box"><div class="drv-pie-title">${escapeHTML(title)}</div><svg class="drv-pie-svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">${paths}</svg><div class="drv-pie-legend">${legend}</div></div>`;
  };

  // =========================================================
  // Disposition 積み上げバー (4区分: 配送済(pass)/配送済(fail)/隔離/拒否)
  // =========================================================
  const buildDispositionBar = (agg) => {
    if (agg.totalCount === 0) return "";
    const t = agg.totalCount;
    const dpPct = agg.deliveredPassCount / t * 100;
    const dfPct = agg.deliveredFailCount / t * 100;
    const qPct = agg.quarantineCount / t * 100;
    const rPct = agg.rejectCount / t * 100;
    const dpL = msg("deliveredPass"), dfL = msg("deliveredFail"), qL = msg("quarantined"), rL = msg("rejected");
    const segText = (l, p) => p > 10 ? `${l} ${p.toFixed(1)}%` : (p > 5 ? `${p.toFixed(1)}%` : "");
    return `<div class="drv-stacked-bar">
      ${dpPct > 0 ? `<div class="drv-stacked-bar-segment drv-stacked-delivered" style="width:${dpPct}%" title="${dpL}: ${agg.deliveredPassCount.toLocaleString()}">${segText(dpL, dpPct)}</div>` : ""}
      ${dfPct > 0 ? `<div class="drv-stacked-bar-segment drv-stacked-delivered-fail" style="width:${dfPct}%" title="${dfL}: ${agg.deliveredFailCount.toLocaleString()}">${segText(dfL, dfPct)}</div>` : ""}
      ${qPct > 0 ? `<div class="drv-stacked-bar-segment drv-stacked-quarantine" style="width:${qPct}%" title="${qL}: ${agg.quarantineCount.toLocaleString()}">${segText(qL, qPct)}</div>` : ""}
      ${rPct > 0 ? `<div class="drv-stacked-bar-segment drv-stacked-reject" style="width:${rPct}%" title="${rL}: ${agg.rejectCount.toLocaleString()}">${segText(rL, rPct)}</div>` : ""}
    </div>
    <div class="drv-pie-legend" style="flex-direction:row;flex-wrap:wrap;gap:8px;padding-left:0;">
      <span class="drv-pie-legend-item"><span class="drv-legend-dot drv-stacked-delivered"></span>${dpL} ${agg.deliveredPassCount.toLocaleString()}</span>
      <span class="drv-pie-legend-item"><span class="drv-legend-dot drv-stacked-delivered-fail"></span>${dfL} ${agg.deliveredFailCount.toLocaleString()}</span>
      <span class="drv-pie-legend-item"><span class="drv-legend-dot drv-stacked-quarantine"></span>${qL} ${agg.quarantineCount.toLocaleString()}</span>
      <span class="drv-pie-legend-item"><span class="drv-legend-dot drv-stacked-reject"></span>${rL} ${agg.rejectCount.toLocaleString()}</span>
    </div>`;
  };

  // =========================================================
  // 詳細統計テーブル (IP範囲/レポーター) — IP分類タグ付き
  // =========================================================
  const buildDetailedTable = (headerLabel, entries, isCode, showIpTag) => {
    if (!entries || entries.length === 0) return "";
    const hCount = msg("colCount"), hDP = msg("deliveredPass"), hDF = msg("deliveredFail");
    const hQ = msg("quarantined"), hR = msg("rejected");
    const hFull = msg("dkimSpfPass"), hDkim = msg("dkimPass"), hSpf = msg("spfPass");
    let html = `<table class="drv-table"><thead><tr>
      <th>${escapeHTML(headerLabel)}</th>${showIpTag ? `<th>${escapeHTML(msg("colClassification"))}</th>` : ""}
      <th>${escapeHTML(hCount)}</th>
      <th style="color:var(--drv-color-delivered)">${escapeHTML(hDP)}</th>
      <th style="color:var(--drv-color-delivered-fail)">${escapeHTML(hDF)}</th>
      <th style="color:var(--drv-color-quarantine)">${escapeHTML(hQ)}</th>
      <th style="color:var(--drv-color-reject)">${escapeHTML(hR)}</th>
      <th>${escapeHTML(hFull)}</th><th>${escapeHTML(hDkim)}</th><th>${escapeHTML(hSpf)}</th>
    </tr></thead><tbody>`;
    const fmtOrDash = (v) => v > 0 ? v.toLocaleString() : "-";
    for (const e of entries) {
      const keyCell = isCode ? `<code>${escapeHTML(e.key)}</code>` : escapeHTML(e.key);
      const dpS = e.deliveredPass > 0 ? ' style="color:var(--drv-color-delivered);font-weight:bold"' : "";
      const dfS = e.deliveredFail > 0 ? ' style="color:var(--drv-color-delivered-fail);font-weight:bold"' : "";
      const qS = e.quarantine > 0 ? ' style="color:var(--drv-color-quarantine);font-weight:bold"' : "";
      const rS = e.reject > 0 ? ' style="color:var(--drv-color-reject);font-weight:bold"' : "";
      let tagCell = "";
      if (showIpTag) {
        const cl = classifyIpRange(e);
        tagCell = `<td><span class="drv-ip-tag ${cl.cls}" title="${escapeHTML(cl.tip)}">${escapeHTML(cl.label)}</span></td>`;
      }
      html += `<tr><td>${keyCell}</td>${tagCell}<td>${e.count.toLocaleString()}</td>
        <td${dpS}>${fmtOrDash(e.deliveredPass)}</td><td${dfS}>${fmtOrDash(e.deliveredFail)}</td>
        <td${qS}>${fmtOrDash(e.quarantine)}</td><td${rS}>${fmtOrDash(e.reject)}</td>
        <td>${fmtOrDash(e.fullPass)}</td><td>${fmtOrDash(e.dkimPass)}</td><td>${fmtOrDash(e.spfPass)}</td></tr>`;
    }
    html += "</tbody></table>";
    return html;
  };

  // =========================================================
  // SVG 折れ線グラフ (欠落期間 0 埋め)
  // =========================================================
  const buildTimeSeriesChart = (timeSeries, periodDays) => {
    if (!timeSeries || timeSeries.length === 0) return "";
    let unitLabel, bucketKeyFn;
    if (periodDays > 0 && periodDays <= 30) {
      unitLabel = "daily";
      bucketKeyFn = (ts) => { const d = new Date(ts * 1000); return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}-${String(d.getDate()).padStart(2,"0")}`; };
    } else if (periodDays > 0 && periodDays <= 180) {
      unitLabel = "weekly";
      bucketKeyFn = (ts) => { const d = new Date(ts * 1000); const day = d.getDay(); const mo = day === 0 ? -6 : 1-day; const m = new Date(d); m.setDate(d.getDate()+mo); return `${m.getFullYear()}-${String(m.getMonth()+1).padStart(2,"0")}-${String(m.getDate()).padStart(2,"0")}`; };
    } else {
      unitLabel = "monthly";
      bucketKeyFn = (ts) => { const d = new Date(ts * 1000); return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}`; };
    }
    const buckets = new Map();
    for (const entry of timeSeries) {
      if (!entry.begin) continue;
      const key = bucketKeyFn(entry.begin);
      const ex = buckets.get(key);
      if (ex) { ex.delivered += entry.delivered; ex.quarantine += entry.quarantine; ex.reject += entry.reject; }
      else buckets.set(key, { key, delivered: entry.delivered, quarantine: entry.quarantine, reject: entry.reject });
    }
    if (buckets.size === 0) return "";
    const allKeys = [...buckets.keys()].sort();
    const filled = [];
    if (unitLabel === "daily") {
      const s = new Date(allKeys[0]+"T00:00:00"), e = new Date(allKeys[allKeys.length-1]+"T00:00:00");
      for (let d = new Date(s); d <= e; d.setDate(d.getDate()+1)) { const k = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}-${String(d.getDate()).padStart(2,"0")}`; filled.push(buckets.get(k)||{key:k,delivered:0,quarantine:0,reject:0}); }
    } else if (unitLabel === "weekly") {
      const s = new Date(allKeys[0]+"T00:00:00"), e = new Date(allKeys[allKeys.length-1]+"T00:00:00");
      for (let d = new Date(s); d <= e; d.setDate(d.getDate()+7)) { const k = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}-${String(d.getDate()).padStart(2,"0")}`; filled.push(buckets.get(k)||{key:k,delivered:0,quarantine:0,reject:0}); }
    } else {
      const [sy,sm] = allKeys[0].split("-").map(Number), [ey,em] = allKeys[allKeys.length-1].split("-").map(Number);
      let y=sy,m=sm; while(y<ey||(y===ey&&m<=em)){const k=`${y}-${String(m).padStart(2,"0")}`;filled.push(buckets.get(k)||{key:k,delivered:0,quarantine:0,reject:0});m++;if(m>12){m=1;y++;}}
    }
    if (filled.length < 2) return "";
    let maxVal = 0;
    for (const b of filled) maxVal = Math.max(maxVal, b.delivered, b.quarantine, b.reject);
    if (maxVal === 0) maxVal = 1;
    const w=860,h=200,padL=50,padR=40,padT=12,padB=40;
    const chartW=w-padL-padR,chartH=h-padT-padB,n=filled.length;
    const xAt=(i)=>padL+(i/(n-1))*chartW, yAt=(v)=>padT+chartH-(v/maxVal)*chartH;
    const toPolyline=(f)=>filled.map((b,i)=>`${xAt(i).toFixed(1)},${yAt(b[f]).toFixed(1)}`).join(" ");
    let gridLines="";
    for(let i=0;i<=4;i++){const yVal=Math.round(maxVal*i/4),y=yAt(yVal);gridLines+=`<line x1="${padL}" y1="${y}" x2="${w-padR}" y2="${y}" class="drv-grid-line"/><text x="${padL-6}" y="${y+4}" text-anchor="end" font-size="11">${yVal}</text>`;}
    let xLabels="";const step=Math.max(1,Math.floor(n/10));
    for(let i=0;i<n;i+=step){const x=xAt(i),label=unitLabel==="monthly"?filled[i].key:filled[i].key.slice(5);xLabels+=`<text x="${x}" y="${h-padB+16}" text-anchor="middle" font-size="11">${label}</text>`;}
    if((n-1)%step!==0){const x=xAt(n-1),label=unitLabel==="monthly"?filled[n-1].key:filled[n-1].key.slice(5);xLabels+=`<text x="${x}" y="${h-padB+16}" text-anchor="end" font-size="11">${label}</text>`;}
    let dots="";
    for(let i=0;i<n;i++){const b=filled[i],x=xAt(i);[{f:"delivered",c:COLOR_DELIVERED,l:msg("deliveredPass")},{f:"quarantine",c:COLOR_QUARANTINE,l:msg("quarantined")},{f:"reject",c:COLOR_REJECT,l:msg("rejected")}].forEach(e=>{const y=yAt(b[e.f]);dots+=`<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="3" fill="${e.c}" opacity="0.8"><title>${escapeHTML(b.key+" — "+e.l+": "+b[e.f].toLocaleString())}</title></circle>`;});}
    return `<div class="drv-chart-container"><div class="drv-chart-title">${escapeHTML(msg("chartTimeSeries"))}</div>
      <svg class="drv-chart-svg" viewBox="0 0 ${w} ${h}" preserveAspectRatio="xMidYMid meet">${gridLines}
        <line x1="${padL}" y1="${padT}" x2="${padL}" y2="${padT+chartH}" class="drv-axis-line"/>
        <line x1="${padL}" y1="${padT+chartH}" x2="${w-padR}" y2="${padT+chartH}" class="drv-axis-line"/>${xLabels}
        <polyline points="${toPolyline("delivered")}" fill="none" stroke="${COLOR_DELIVERED}" stroke-width="2"/>
        <polyline points="${toPolyline("quarantine")}" fill="none" stroke="${COLOR_QUARANTINE}" stroke-width="2"/>
        <polyline points="${toPolyline("reject")}" fill="none" stroke="${COLOR_REJECT}" stroke-width="2"/>${dots}
      </svg>
      <div class="drv-chart-legend-row">
        <span class="drv-pie-legend-item"><span class="drv-legend-dot" style="background:${COLOR_DELIVERED}"></span>${msg("deliveredPass")}</span>
        <span class="drv-pie-legend-item"><span class="drv-legend-dot" style="background:${COLOR_QUARANTINE}"></span>${msg("quarantined")}</span>
        <span class="drv-pie-legend-item"><span class="drv-legend-dot" style="background:${COLOR_REJECT}"></span>${msg("rejected")}</span>
      </div></div>`;
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
        $("period-info").textContent = `${formatUnixDate(agg.dateRangeMin)} – ${formatUnixDate(agg.dateRangeMax)} | ${agg.reportCount} ${msg("colReports")} | ${agg.uniqueIpRanges} ${msg("sectionTopIps")}`;
        show($("period-info"));
      }
      $("summary-cards").innerHTML = buildStatCards(agg);
      renderPieCharts(agg);
      show($("summary-section"));
      if (results.domainDetails) {
        const pd = results.scanPeriodDays || 0;
        for (const dd of results.domainDetails) renderDomainSection(dd, pd);
      }
    }
    if (results.fr.length > 0) renderFrTable(results.fr);
    if (results.issuesSummary && results.issuesSummary.totalIssues > 0) renderIssues(results.issuesSummary, results.issues);
  };

  // =========================================================
  // 初期化
  // =========================================================
  const init = async () => {
    applyI18n();
    const settings = await browser.runtime.sendMessage({ command: "resolveSettings" });
    if (!settings.arFolderId && !settings.frFolderId) show($("no-folder-notice"));
    else hide($("no-folder-notice"));
    const cached = await browser.runtime.sendMessage({ command: "getLastResults" });
    if (cached && (cached.ar?.length > 0 || cached.fr?.length > 0)) {
      renderResults(cached);
      showStatus(`${msg("statusComplete")} ${cached.ar.length} ${msg("arReports")}, ${cached.fr.length} ${msg("frReports")} (${msg("statusCached")})`);
    }
  };

  const showStatus = (text, isLoading = false) => {
    $("status-bar").classList.remove("drv-hidden");
    $("status-message").innerHTML = isLoading ? `<span class="drv-spinner"></span>${escapeHTML(text)}` : escapeHTML(text);
  };

  $("btn-settings").addEventListener("click", () => browser.runtime.openOptionsPage());

  $("btn-scan").addEventListener("click", async () => {
    $("btn-scan").disabled = true;
    showStatus(msg("statusScanning"), true);
    const days = parseInt($("period-select").value, 10);
    const since = days > 0 ? Date.now() - (days * 24 * 60 * 60 * 1000) : 0;
    try {
      const results = await browser.runtime.sendMessage({ command: "scanReports", since, sinceDay: days });
      if (results.error) { showStatus(`Error: ${results.error}`); $("btn-scan").disabled = false; return; }
      renderResults(results);
      const e = results.errors.length;
      showStatus(`${msg("statusComplete")} ${results.ar.length} ${msg("arReports")}, ${results.fr.length} ${msg("frReports")}${e > 0 ? ` (${e} ${msg("statusErrors")})` : ""}`);
    } catch (err) { showStatus(`Error: ${err.message}`); }
    finally { $("btn-scan").disabled = false; }
  });

  // =========================================================
  // 円グラフ3つ (Disposition は4区分)
  // =========================================================
  const renderPieCharts = (agg) => {
    const pieRow = $("pie-row"); pieRow.innerHTML = "";
    if (agg.domains?.length > 0)
      pieRow.innerHTML += buildPieChart(msg("colDomain"), agg.domains.map((d,i) => ({label:d.domain,value:d.count,color:PALETTE[i%PALETTE.length]})));
    const dispSegs = [
      {label:msg("deliveredPass"),value:agg.deliveredPassCount,color:COLOR_DELIVERED},
      {label:msg("deliveredFail"),value:agg.deliveredFailCount,color:COLOR_DELIVERED_FAIL},
      {label:msg("quarantined"),value:agg.quarantineCount,color:COLOR_QUARANTINE},
      {label:msg("rejected"),value:agg.rejectCount,color:COLOR_REJECT}
    ].filter(s=>s.value>0);
    if (dispSegs.length > 0) pieRow.innerHTML += buildPieChart(msg("dispositionTitle"), dispSegs);
    if (agg.reporters?.length > 0)
      pieRow.innerHTML += buildPieChart(msg("colReporter"), agg.reporters.map((r,i) => ({label:r.name,value:r.count,color:PALETTE[i%PALETTE.length]})));
  };

  // =========================================================
  // ドメイン別詳細セクション (折りたたみ + 健全度バッジ)
  // =========================================================
  const renderDomainSection = (dd, periodDays) => {
    const agg = dd.aggregate;
    const section = document.createElement("div");
    section.className = "drv-domain-section";

    const pol = dd.policy;
    const policyStr = `p=${pol.p} sp=${pol.sp} adkim=${pol.adkim} aspf=${pol.aspf} pct=${pol.pct}${pol.fo !== "0" ? ` fo=${pol.fo}` : ""}`;
    const health = computeHealthBadge(agg, pol);

    // ヘッダー (クリックで折りたたみ)
    const sectionId = `domain-${dd.domain.replace(/[^a-zA-Z0-9]/g, "_")}`;
    let html = `<div class="drv-domain-header" data-target="${sectionId}">
      <span>📋 ${escapeHTML(dd.domain)}</span>
      <span class="drv-health-badge ${health.cls}" title="${escapeHTML(health.label)}">${health.icon} ${escapeHTML(health.label)}</span>
      <span class="drv-domain-policy">${escapeHTML(policyStr)}</span>
      <span style="font-size:12px;color:var(--drv-text-muted);">${agg.reportCount} ${escapeHTML(msg("colReports"))}</span>
      <span class="drv-toggle-icon expanded" data-toggle="${sectionId}">▼</span>
    </div>`;

    // 折りたたみ本体
    html += `<div class="drv-domain-body" id="${sectionId}"><div class="drv-domain-body-inner"><div class="drv-domain-body-content">`;

    // 8枠コンパクトカード (配送済pass/fail分離、色は常時)
    const t = agg.totalCount;
    const ci = [
      {label:msg("totalEmails"),value:t.toLocaleString(),pctText:"",cc:""},
      {label:msg("deliveredPass"),value:agg.deliveredPassCount.toLocaleString(),pctText:pct(agg.deliveredPassCount,t),cc:"drv-delivered-text"},
      {label:msg("deliveredFail"),value:agg.deliveredFailCount.toLocaleString(),pctText:pct(agg.deliveredFailCount,t),cc:"drv-delivered-fail-text"},
      {label:msg("quarantined"),value:agg.quarantineCount.toLocaleString(),pctText:pct(agg.quarantineCount,t),cc:"drv-quarantine-text"},
      {label:msg("rejected"),value:agg.rejectCount.toLocaleString(),pctText:pct(agg.rejectCount,t),cc:"drv-reject-text"},
      {label:msg("dkimSpfPass"),value:agg.passCount.toLocaleString(),pctText:pct(agg.passCount,t),cc:""},
      {label:msg("dkimPass"),value:agg.dkimPassCount.toLocaleString(),pctText:pct(agg.dkimPassCount,t),cc:""},
      {label:msg("spfPass"),value:agg.spfPassCount.toLocaleString(),pctText:pct(agg.spfPassCount,t),cc:""}
    ];
    html += '<div class="drv-card-grid-compact">';
    for (const item of ci) {
      const lc = item.cc ? ` ${item.cc}` : "";
      html += `<div class="drv-card-compact"><div class="drv-card-label${lc}">${escapeHTML(item.label)}</div><div class="drv-card-value${lc}">${item.value}</div>${item.pctText?`<div class="drv-card-pct">${item.pctText}</div>`:""}</div>`;
    }
    html += '</div>';

    html += buildDispositionBar(agg);

    if (dd.timeSeries && dd.timeSeries.length >= 2)
      html += buildTimeSeriesChart(dd.timeSeries, periodDays);

    if (agg.topIpRanges?.length > 0)
      html += `<div class="drv-domain-subsection"><div class="drv-domain-subtitle">${escapeHTML(msg("sectionTopIps"))}</div>${buildDetailedTable(msg("colIpRange"), agg.topIpRanges, true, true)}</div>`;

    if (agg.topReporters?.length > 0)
      html += `<div class="drv-domain-subsection"><div class="drv-domain-subtitle">${escapeHTML(msg("sectionReporters"))}</div>${buildDetailedTable(msg("colReporter"), agg.topReporters, false, false)}</div>`;

    if (agg.overrideReasons?.length > 0) {
      html += `<div class="drv-domain-subsection"><div class="drv-domain-subtitle">${escapeHTML(msg("sectionOverrides"))}</div><table class="drv-table"><thead><tr><th>${escapeHTML(msg("colOverrideType"))}</th><th>${escapeHTML(msg("colCount"))}</th></tr></thead><tbody>`;
      for (const entry of agg.overrideReasons) html += `<tr><td>${escapeHTML(entry.type)}</td><td>${entry.count.toLocaleString()}</td></tr>`;
      html += '</tbody></table></div>';
    }

    if (agg.warningsSummary?.reportsWithMetadataErrors > 0)
      html += `<div class="drv-domain-subsection"><div class="drv-domain-subtitle">${escapeHTML(msg("ispMetadataErrors"))}</div><p style="font-size:12px;color:var(--drv-warn);">${agg.warningsSummary.reportsWithMetadataErrors} ${escapeHTML(msg("ispMetadataErrorsDetail"))}</p></div>`;

    html += '</div></div></div>'; // close body-content, body-inner, body

    section.innerHTML = html;
    $("domains-container").appendChild(section);

    // 折りたたみイベント
    const header = section.querySelector(".drv-domain-header");
    const body = section.querySelector(".drv-domain-body");
    const icon = section.querySelector(".drv-toggle-icon");
    header.addEventListener("click", () => {
      body.classList.toggle("collapsed");
      icon.classList.toggle("expanded");
    });
  };

  // =========================================================
  // フォレンジックレポート
  // =========================================================
  const renderFrTable = (frReports) => {
    const tbody = $("fr-table").querySelector("tbody"); tbody.innerHTML = "";
    const sorted = [...frReports].sort((a,b) => new Date(b.messageDate)-new Date(a.messageDate));
    for (const r of sorted) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${escapeHTML(r.messageDate?new Date(r.messageDate).toLocaleDateString():"-")}</td><td>${escapeHTML(r.reportedDomain)}</td><td><code>${escapeHTML(r.sourceIp)}</code></td><td>${escapeHTML(r.authFailure||"-")}</td>`;
      tbody.appendChild(tr);
    }
    show($("fr-section"));
  };

  // =========================================================
  // 読み取り不能なレポート
  // =========================================================
  const renderIssues = (summary, issues) => {
    $("issue-parse-failed").textContent = summary.parseFailed.toLocaleString();
    $("issue-decompress-failed").textContent = summary.decompressFailed.toLocaleString();
    $("issue-incomplete").textContent = summary.incompleteReport.toLocaleString();
    $("issue-no-attachment").textContent = summary.noAttachment.toLocaleString();
    $("issue-unknown-format").textContent = summary.unknownFormat.toLocaleString();
    const all = [];
    for (const i of issues.parseFailed) all.push({date:i.date,cat:msg("issueParseFailed"),cls:"drv-fail-text",subj:i.subject||"-",det:i.error||"-"});
    for (const i of issues.decompressFailed) all.push({date:i.date,cat:msg("issueDecompressFailed"),cls:"drv-fail-text",subj:i.subject||"-",det:`${i.attachment}: ${i.error||"-"}`});
    for (const i of issues.noAttachment) all.push({date:i.date,cat:msg("issueNoAttachment"),cls:"drv-warn-text",subj:i.subject||"-",det:msg("issueNoAttachmentDetail")});
    for (const i of issues.unknownFormat) all.push({date:i.date,cat:msg("issueUnknownFormat"),cls:"drv-warn-text",subj:i.subject||"-",det:`${i.attachment} (${i.contentType||"unknown"})`});
    for (const i of issues.incompleteReport) {
      const wt = i.warnings.slice(0,3).map(w=>translateWarning(w.field,w.message));
      const rem = i.warnings.length - 3;
      all.push({date:i.date,cat:msg("issueIncomplete"),cls:"",subj:i.subject||"-",det:wt.join("; ")+(rem>0?` (+${rem})`:"")} );
    }
    all.sort((a,b)=>{if(!a.date)return 1;if(!b.date)return -1;return new Date(b.date)-new Date(a.date);});
    const tbody = $("issues-table").querySelector("tbody"); tbody.innerHTML = "";
    for (const i of all) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${escapeHTML(i.date?new Date(i.date).toLocaleDateString():"-")}</td><td class="${i.cls}">${escapeHTML(i.cat)}</td><td>${escapeHTML(i.subj)}</td><td>${escapeHTML(i.det)}</td>`;
      tbody.appendChild(tr);
    }
    show($("issues-section"));
  };

  init();
})();
