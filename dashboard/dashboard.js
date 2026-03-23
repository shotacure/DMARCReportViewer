// DMARCReportAnalyzer - dashboard/dashboard.js v1.0.6

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
  // HTML エスケープ: innerHTML を使わず手動で特殊文字を変換
  const escapeHTML = (str) => String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#039;");

  // innerHTML の代替: DOMParser で安全にパースして子要素を置換
  const safeHTML = (parent, htmlString) => {
    const doc = new DOMParser().parseFromString(htmlString, "text/html");
    parent.replaceChildren(...doc.body.childNodes);
  };
  // innerHTML += の代替: 既存の子要素を維持して追加
  const safeAppendHTML = (parent, htmlString) => {
    const doc = new DOMParser().parseFromString(htmlString, "text/html");
    while (doc.body.firstChild) parent.appendChild(doc.body.firstChild);
  };
  // テーブル行用: <td> をテーブルコンテキスト内でパースする
  // DOMParser は <td> を <table> 外に置くと正しくパースしないため専用ヘルパーが必要
  const safeTableRow = (tr, cellsHtml) => {
    const doc = new DOMParser().parseFromString(
      `<table><tbody><tr>${cellsHtml}</tr></tbody></table>`, "text/html");
    const parsed = doc.querySelector("tr");
    if (parsed) tr.replaceChildren(...parsed.childNodes);
  };
  const $ = (id) => document.getElementById(id);
  const show = (el) => el.classList.remove("drv-hidden");
  const hide = (el) => el.classList.add("drv-hidden");

  const PALETTE = ["#1565c0","#e65100","#2e7d32","#6a1b9a","#c62828","#00838f","#ef6c00","#283593","#4e342e","#558b2f"];
  const COLOR_DELIVERED = "#4caf50";
  const COLOR_DELIVERED_FAIL = "#e53935";
  const COLOR_QUARANTINE = "#ff9800";
  const COLOR_REJECT = "#1976d2";

  const formatUnixDate = (s) => !s ? "-" : new Date(s * 1000).toLocaleDateString();
  const pct = (n, t) => t > 0 ? (n / t * 100).toFixed(2) + "%" : "0.00%";

  $("version").textContent = browser.runtime.getManifest().version;

  // 最新のスキャン結果を保持 (エクスポート用)
  let lastResults = null;

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
    // DMARC pass (DKIM or SPF) の実績で判定
    const dp = e.dmarcPass || 0;
    // 全 DMARC pass + 全配送 → 正規の送信元
    if (dp === e.count && e.deliveredPass === e.count)
      return { tag: "legitimate", label: msg("tagLegitimate"), cls: "drv-ip-tag-legitimate", tip: msg("tagLegitimateDesc") };
    // DMARC pass の実績がある → 正規の送信元 (DKIM 秘密鍵がなければ pass は不可能)
    if (dp > 0)
      return { tag: "legitimate", label: msg("tagLegitimate"), cls: "drv-ip-tag-legitimate", tip: msg("tagLegitimateDesc") };
    // 以下 dmarcPass === 0: この送信元は認証に一度も成功していない
    // 全 reject → ポリシーが正しくブロック中
    if (e.reject === e.count)
      return { tag: "blocked", label: msg("tagBlocked"), cls: "drv-ip-tag-blocked", tip: msg("tagBlockedDesc") };
    // 一部が配送されている → 不正な送信元が素通り (最も危険)
    if (e.deliveredFail > 0)
      return { tag: "threat", label: msg("tagThreat"), cls: "drv-ip-tag-threat", tip: msg("tagThreatDesc") };
    // 全 reject/quarantine (混在)
    if (e.count > 0)
      return { tag: "blocked", label: msg("tagBlocked"), cls: "drv-ip-tag-blocked", tip: msg("tagBlockedDesc") };
    return { tag: "unknown", label: "—", cls: "", tip: "" };
  };

  // =========================================================
  // ドメイン健全度バッジを算出
  // =========================================================
  const computeHealthBadge = (agg, policy) => {
    const deliveredFail = Number(agg.deliveredFailCount) || 0;
    const rejectCount = Number(agg.rejectCount) || 0;
    const policyP = policy.p || "none";

    // アライメント非整合の検出 (情報提示用、バッジ判定には影響しない)
    const dkimPassN = Number(agg.dkimPassCount) || 0;
    const spfPassN = Number(agg.spfPassCount) || 0;
    const fullPassN = Number(agg.passCount) || 0;
    const dkimOnly = dkimPassN - fullPassN;
    const spfOnly = spfPassN - fullPassN;
    const alignNotes = [];
    if (dkimOnly > 0) alignNotes.push(msg("alignNoteSpfMismatch").replaceAll("#1", String(dkimOnly)));
    if (spfOnly > 0) alignNotes.push(msg("alignNoteDkimMismatch").replaceAll("#1", String(spfOnly)));
    const info = alignNotes.join(" ");

    // 🔴 危険: p=none、または deliveredFail > 0 (未認証メールが受信箱に到達)
    if (policyP === "none" || deliveredFail > 0) {
      const reasons = [];
      if (deliveredFail > 0)
        reasons.push(msg("healthReasonDeliveredFail").replaceAll("#1", String(deliveredFail)));
      if (policyP !== "reject")
        reasons.push(msg("healthReasonNotReject").replaceAll("#1", policyP));
      return { cls: "drv-health-at-risk", label: msg("healthAtRisk"), icon: "🔴",
        reason: reasons.join(" "), info };
    }
    // ⚠️ 要確認: p=quarantine (reject より弱い)
    if (policyP === "quarantine")
      return { cls: "drv-health-needs-attention", label: msg("healthNeedsAttention"), icon: "⚠️",
        reason: msg("healthReasonNotReject").replaceAll("#1", policyP), info };
    // 以下 p=reject, deliveredFail=0
    // 🛡️ 攻撃検知中: 不正メールをブロックしている
    if (rejectCount > 0)
      return { cls: "drv-health-under-attack", label: msg("healthUnderAttack"), icon: "🛡️",
        reason: msg("healthReasonBlocking").replaceAll("#1", String(rejectCount)), info };
    // ✅ 健全: 全メール認証成功、reject ポリシー有効
    return { cls: "drv-health-healthy", label: msg("healthHealthy"), icon: "✅", reason: "", info };
  };

  // =========================================================
  // 前期比較: 変化の表示文字列を生成
  // current/previous: 比較する値（率または絶対数）
  // upIsPositive: true なら増加が緑(良い)、false なら増加が赤(悪い)
  // =========================================================
  const buildChangeIndicator = (current, previous, upIsPositive) => {
    if (previous === undefined || previous === null) return "";
    if (previous === 0 && current === 0) return `<div class="drv-change drv-change-flat">→ 0%</div>`;
    if (previous === 0) {
      const cls = upIsPositive ? "drv-change-pos" : "drv-change-neg";
      return `<div class="drv-change ${cls}">↑ new</div>`;
    }
    const changePct = ((current - previous) / previous * 100);
    if (Math.abs(changePct) < 1) return `<div class="drv-change drv-change-flat">→ ${changePct >= 0 ? "+" : ""}${changePct.toFixed(1)}%</div>`;
    // 200%超の急増を検出 (ネガティブ方向のみ警告)
    const isSurge = !upIsPositive && changePct >= 200;
    if (changePct > 0) {
      const cls = upIsPositive ? "drv-change-pos" : (isSurge ? "drv-change-surge" : "drv-change-neg");
      return `<div class="drv-change ${cls}">↑ +${changePct.toFixed(1)}%${isSurge ? " 🔺" : ""}</div>`;
    }
    // 減少: upIsPositive なら減少は悪い(赤)、!upIsPositive なら減少は良い(緑)
    const cls = upIsPositive ? "drv-change-neg" : "drv-change-pos";
    return `<div class="drv-change ${cls}">↓ ${changePct.toFixed(1)}%</div>`;
  };

  // =========================================================
  // 前期比較ヘルパー: 率の変化を計算
  // =========================================================
  const computeRateChange = (currentCount, currentTotal, prevCount, prevTotal) => {
    if (prevTotal === undefined || prevTotal === null || prevTotal === 0) return { rateCur: 0, ratePrev: null };
    const currentRate = currentTotal > 0 ? (currentCount / currentTotal * 100) : 0;
    const previousRate = prevTotal > 0 ? (prevCount / prevTotal * 100) : 0;
    return { rateCur: currentRate, ratePrev: previousRate };
  };

  // =========================================================
  // ポリシー推奨アドバイスを生成
  // =========================================================
  const buildPolicyAdvice = (agg, policy) => {
    const advices = [];
    // p=none → reject 移行の推奨
    if (policy.p === "none") {
      advices.push({ level: "danger", text: msg("advicePNone") });
    } else if (policy.p === "quarantine") {
      if (agg.deliveredFailCount === 0) {
        advices.push({ level: "warn", text: msg("advicePQuarantine") });
      } else {
        advices.push({ level: "warn", text: msg("advicePQuarantineWithFail") });
      }
    } else if (policy.p === "reject" && agg.deliveredFailCount === 0 && agg.rejectCount === 0) {
      let text = msg("advicePRejectClean");
      const dkimOnlyA = Number(agg.dkimPassCount || 0) - Number(agg.passCount || 0);
      const spfOnlyA = Number(agg.spfPassCount || 0) - Number(agg.passCount || 0);
      const alignParts = [];
      if (dkimOnlyA > 0) alignParts.push("SPF");
      if (spfOnlyA > 0) alignParts.push("DKIM");
      if (alignParts.length > 0) text += ` (${alignParts.join("/")}${msg("adviceAlignNote")})`;
      advices.push({ level: "ok", text });
    }
    // adkim=r の推奨
    if (policy.adkim === "r") {
      advices.push({ level: "warn", text: msg("adviceAdkimRelaxed") });
    }
    // pct < 100 の推奨
    if (policy.pct < 100) {
      advices.push({ level: "warn", text: msg("advicePctPartial").replaceAll("#1", policy.pct) });
    }
    if (advices.length === 0) return "";
    return advices.map(a =>
      `<div class="drv-advice drv-advice-${a.level}">${escapeHTML(a.text)}</div>`
    ).join("");
  };

  // =========================================================
  // 8枠統計カード HTML
  // 比較は率ベース (メール総数のみ絶対数で比較)
  // =========================================================
  const buildStatCards = (agg, previousAgg) => {
    const t = agg.totalCount;
    const p = previousAgg || null;
    const pt = p?.totalCount || 0;

    // rc: rate change helper — 率の今期/前期を算出
    const rc = (cur, prev) => p ? computeRateChange(cur, t, prev, pt) : { rateCur: 0, ratePrev: null };

    // 各指標の定義: upPos = 増加がポジティブかどうか
    const items = [
      { label: msg("totalEmails"), value: t.toLocaleString(), pctText: "", colorClass: "", upPos: true,
        chgCur: t, chgPrev: p ? pt : null },
      { label: msg("deliveredPass"), value: agg.deliveredPassCount.toLocaleString(), pctText: pct(agg.deliveredPassCount, t), colorClass: "drv-delivered-text", upPos: true,
        ...rc(agg.deliveredPassCount, p?.deliveredPassCount) },
      { label: msg("deliveredFail"), value: agg.deliveredFailCount.toLocaleString(), pctText: pct(agg.deliveredFailCount, t), colorClass: "drv-delivered-fail-text", upPos: false,
        ...rc(agg.deliveredFailCount, p?.deliveredFailCount) },
      { label: msg("quarantined"), value: agg.quarantineCount.toLocaleString(), pctText: pct(agg.quarantineCount, t), colorClass: "drv-quarantine-text", upPos: false,
        ...rc(agg.quarantineCount, p?.quarantineCount) },
      { label: msg("rejected"), value: agg.rejectCount.toLocaleString(), pctText: pct(agg.rejectCount, t), colorClass: agg.rejectCount > 0 ? "drv-reject-text" : "", upPos: false,
        ...rc(agg.rejectCount, p?.rejectCount) },
      { label: msg("dkimSpfPass"), value: agg.passCount.toLocaleString(), pctText: pct(agg.passCount, t), colorClass: "", upPos: true,
        ...rc(agg.passCount, p?.passCount) },
      { label: msg("dkimPass"), value: agg.dkimPassCount.toLocaleString(), pctText: pct(agg.dkimPassCount, t), colorClass: "", upPos: true,
        ...rc(agg.dkimPassCount, p?.dkimPassCount) },
      { label: msg("spfPass"), value: agg.spfPassCount.toLocaleString(), pctText: pct(agg.spfPassCount, t), colorClass: "", upPos: true,
        ...rc(agg.spfPassCount, p?.spfPassCount) }
    ];
    return items.map(i => {
      const lc = i.colorClass ? ` ${i.colorClass}` : "";
      // メール総数は絶対数比較 (chgCur/chgPrev)、他は率比較 (rateCur/ratePrev)
      const change = p ? buildChangeIndicator(i.chgCur ?? i.rateCur, i.chgPrev ?? i.ratePrev, i.upPos) : "";
      return `<div class="drv-card"><div class="drv-card-label${lc}">${escapeHTML(i.label)}</div><div class="drv-card-value${lc}">${i.value}</div><div class="drv-card-pct">${i.pctText || "&nbsp;"}</div>${change}</div>`;
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
  // Disposition 積み上げバー (4区分)
  // =========================================================
  const buildDispositionBar = (agg) => {
    if (agg.totalCount === 0) return "";
    const t = agg.totalCount;
    // 4区分のデータ定義
    const segs = [
      { count: agg.deliveredPassCount, label: msg("deliveredPass"), cls: "drv-stacked-delivered", dotCls: "drv-stacked-delivered" },
      { count: agg.deliveredFailCount, label: msg("deliveredFail"), cls: "drv-stacked-delivered-fail", dotCls: "drv-stacked-delivered-fail" },
      { count: agg.quarantineCount, label: msg("quarantined"), cls: "drv-stacked-quarantine", dotCls: "drv-stacked-quarantine" },
      { count: agg.rejectCount, label: msg("rejected"), cls: "drv-stacked-reject", dotCls: "drv-stacked-reject" }
    ];
    // 各セグメントのパーセンテージ
    const withPct = segs.map(s => ({ ...s, pct: s.count / t * 100, pctStr: (s.count / t * 100).toFixed(2) }));
    // 棒グラフ: テキストなし、ツールチップに件数+パーセンテージ
    const bar = withPct
      .filter(s => s.count > 0)
      .map(s => `<div class="drv-stacked-bar-segment ${s.cls}" style="width:${s.pct}%" title="${escapeHTML(s.label)}: ${s.count.toLocaleString()} (${s.pctStr}%)"></div>`)
      .join("");
    // 凡例: 常に4区分すべて表示、件数 (XX.XX%) 形式
    const legend = withPct.map(s =>
      `<span class="drv-pie-legend-item"><span class="drv-legend-dot ${s.dotCls}"></span>${escapeHTML(s.label)} ${s.count.toLocaleString()} (${s.pctStr}%)</span>`
    ).join("");
    return `<div class="drv-stacked-bar">${bar}</div>
    <div class="drv-pie-legend" style="flex-direction:row;flex-wrap:wrap;gap:8px;padding-left:0;">${legend}</div>`;
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
      <th>${escapeHTML(hDP)}</th>
      <th>${escapeHTML(hDF)}</th>
      <th>${escapeHTML(hQ)}</th>
      <th>${escapeHTML(hR)}</th>
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
  // DKIM 署名テーブル
  // =========================================================
  const buildDkimSignaturesTable = (sigs) => {
    if (!sigs || sigs.length === 0) return "";
    let html = `<table class="drv-table"><thead><tr>
      <th>${escapeHTML(msg("colSigningDomain"))}</th>
      <th>${escapeHTML(msg("colSelector"))}</th>
      <th>${escapeHTML(msg("colCount"))}</th>
      <th class="drv-pass-text">Pass</th>
      <th class="drv-fail-text">Fail</th>
      <th></th>
    </tr></thead><tbody>`;
    for (const s of sigs) {
      const tag = s.isThirdParty
        ? `<span class="drv-tag drv-tag-info" title="${escapeHTML(msg("tagThirdPartyDesc"))}">🔗 ${escapeHTML(msg("tagThirdParty"))}</span>`
        : "";
      const pS = s.pass > 0 ? ' style="color:var(--drv-pass);font-weight:bold"' : "";
      const fS = s.fail > 0 ? ' style="color:var(--drv-fail);font-weight:bold"' : "";
      html += `<tr><td><code>${escapeHTML(s.domain)}</code></td><td><code>${escapeHTML(s.selector)}</code></td>
        <td>${s.count.toLocaleString()}</td><td${pS}>${s.pass > 0 ? s.pass.toLocaleString() : "-"}</td>
        <td${fS}>${s.fail > 0 ? s.fail.toLocaleString() : "-"}</td><td>${tag}</td></tr>`;
    }
    html += "</tbody></table>";
    return html;
  };

  // =========================================================
  // SPF ドメインテーブル
  // =========================================================
  const buildSpfDomainsTable = (spfDomains) => {
    if (!spfDomains || spfDomains.length === 0) return "";
    let html = `<table class="drv-table"><thead><tr>
      <th>${escapeHTML(msg("colSpfDomain"))}</th>
      <th>Scope</th>
      <th>${escapeHTML(msg("colCount"))}</th>
      <th class="drv-pass-text">Pass</th>
      <th class="drv-fail-text">Fail</th>
      <th></th>
    </tr></thead><tbody>`;
    for (const s of spfDomains) {
      const scopeStr = s.scopes.join(", ");
      // helo のみで mfrom がない場合は警告タグ
      const heloOnly = s.scopes.length === 1 && s.scopes[0] === "helo";
      const tag = heloOnly
        ? `<span class="drv-tag drv-tag-warn" title="${escapeHTML(msg("tagHeloOnlyDesc"))}">⚠️ ${escapeHTML(msg("tagHeloOnly"))}</span>`
        : "";
      const pS = s.pass > 0 ? ' style="color:var(--drv-pass);font-weight:bold"' : "";
      const fS = s.fail > 0 ? ' style="color:var(--drv-fail);font-weight:bold"' : "";
      html += `<tr><td><code>${escapeHTML(s.domain)}</code></td><td>${escapeHTML(scopeStr)}</td>
        <td>${s.count.toLocaleString()}</td><td${pS}>${s.pass > 0 ? s.pass.toLocaleString() : "-"}</td>
        <td${fS}>${s.fail > 0 ? s.fail.toLocaleString() : "-"}</td><td>${tag}</td></tr>`;
    }
    html += "</tbody></table>";
    return html;
  };

  // =========================================================
  // Envelope From / Header From 不一致テーブル
  // =========================================================
  const buildEnvelopeMismatchTable = (mismatches) => {
    if (!mismatches || mismatches.length === 0) return "";
    let html = `<table class="drv-table"><thead><tr>
      <th>Header From</th><th>Envelope From</th>
      <th>${escapeHTML(msg("colCount"))}</th>
      <th class="drv-pass-text">Pass</th>
      <th class="drv-fail-text">Fail</th>
      <th></th>
    </tr></thead><tbody>`;
    for (const m of mismatches) {
      // 全 fail の場合はスプーフィングの疑い
      const allFail = m.fail > 0 && m.pass === 0;
      const tag = allFail
        ? `<span class="drv-tag drv-tag-danger" title="${escapeHTML(msg("tagPossibleSpoofingDesc"))}">🔴 ${escapeHTML(msg("tagPossibleSpoofing"))}</span>`
        : `<span class="drv-tag drv-tag-info" title="${escapeHTML(msg("tagThirdPartySenderDesc"))}">🔗 ${escapeHTML(msg("tagThirdPartySender"))}</span>`;
      const pS = m.pass > 0 ? ' style="color:var(--drv-pass);font-weight:bold"' : "";
      const fS = m.fail > 0 ? ' style="color:var(--drv-fail);font-weight:bold"' : "";
      html += `<tr><td><code>${escapeHTML(m.headerFrom)}</code></td><td><code>${escapeHTML(m.envelopeFrom)}</code></td>
        <td>${m.count.toLocaleString()}</td><td${pS}>${m.pass > 0 ? m.pass.toLocaleString() : "-"}</td>
        <td${fS}>${m.fail > 0 ? m.fail.toLocaleString() : "-"}</td><td>${tag}</td></tr>`;
    }
    html += "</tbody></table>";
    return html;
  };

  // =========================================================
  // サブドメインテーブル
  // =========================================================
  const buildSubdomainTable = (subdomains) => {
    if (!subdomains || subdomains.length === 0) return "";
    let html = `<table class="drv-table"><thead><tr>
      <th>${escapeHTML(msg("colSubdomain"))}</th>
      <th>${escapeHTML(msg("colCount"))}</th>
      <th class="drv-pass-text">Pass</th>
      <th class="drv-fail-text">Fail</th>
      <th>${escapeHTML(msg("rejected"))}</th>
    </tr></thead><tbody>`;
    for (const s of subdomains) {
      const pS = s.pass > 0 ? ' style="color:var(--drv-pass);font-weight:bold"' : "";
      const fS = s.fail > 0 ? ' style="color:var(--drv-fail);font-weight:bold"' : "";
      const rS = s.reject > 0 ? ' style="color:var(--drv-color-reject);font-weight:bold"' : "";
      const f = (v) => v > 0 ? v.toLocaleString() : "-";
      html += `<tr><td><code>${escapeHTML(s.subdomain)}</code></td><td>${s.count.toLocaleString()}</td>
        <td${pS}>${f(s.pass)}</td><td${fS}>${f(s.fail)}</td><td${rS}>${f(s.reject)}</td></tr>`;
    }
    html += "</tbody></table>";
    return html;
  };

  // =========================================================
  // ポリシーオーバーライド詳細テーブル (理由 + IP範囲)
  // =========================================================
  const buildOverrideDetailTable = (details) => {
    if (!details || details.length === 0) return "";
    let html = `<table class="drv-table"><thead><tr>
      <th>${escapeHTML(msg("colOverrideType"))}</th>
      <th>${escapeHTML(msg("colIpRange"))}</th>
      <th>${escapeHTML(msg("colCount"))}</th>
      <th></th>
    </tr></thead><tbody>`;
    for (const d of details) {
      // forwarded 理由のIP範囲にフォワーダータグ
      const tag = d.type === "forwarded"
        ? `<span class="drv-tag drv-tag-info" title="${escapeHTML(msg("tagForwarderDesc"))}">📨 ${escapeHTML(msg("tagForwarder"))}</span>`
        : "";
      html += `<tr><td>${escapeHTML(d.type)}</td><td><code>${escapeHTML(d.ipRange)}</code></td>
        <td>${d.count.toLocaleString()}</td><td>${tag}</td></tr>`;
    }
    html += "</tbody></table>";
    return html;
  };

  // =========================================================
  // ドメイン内フォレンジックレポートのミニテーブル
  // =========================================================
  const buildDomainForensicTable = (frReports) => {
    if (!frReports || frReports.length === 0) return "";
    const sorted = [...frReports].sort((a, b) => new Date(b.messageDate) - new Date(a.messageDate)).slice(0, 10);
    let html = `<table class="drv-table"><thead><tr>
      <th>${escapeHTML(msg("colDate"))}</th>
      <th>${escapeHTML(msg("colSourceIp"))}</th>
      <th>${escapeHTML(msg("colAuthFailure"))}</th>
    </tr></thead><tbody>`;
    for (const r of sorted) {
      html += `<tr><td>${escapeHTML(r.messageDate ? new Date(r.messageDate).toLocaleDateString() : "-")}</td>
        <td><code>${escapeHTML(r.sourceIp)}</code></td><td>${escapeHTML(r.authFailure || "-")}</td></tr>`;
    }
    if (frReports.length > 10) html += `<tr><td colspan="3" style="text-align:center;color:var(--drv-text-muted)">… ${frReports.length - 10} more</td></tr>`;
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
      if (ex) { ex.delivered += entry.delivered; ex.deliveredFail += (entry.deliveredFail || 0); ex.quarantine += entry.quarantine; ex.reject += entry.reject; }
      else buckets.set(key, { key, delivered: entry.delivered, deliveredFail: entry.deliveredFail || 0, quarantine: entry.quarantine, reject: entry.reject });
    }
    if (buckets.size === 0) return "";
    const allKeys = [...buckets.keys()].sort();
    const filled = [];
    const emptyBucket = (k) => ({key:k,delivered:0,deliveredFail:0,quarantine:0,reject:0});
    if (unitLabel === "daily") {
      const s = new Date(allKeys[0]+"T00:00:00"), e = new Date(allKeys[allKeys.length-1]+"T00:00:00");
      for (let d = new Date(s); d <= e; d.setDate(d.getDate()+1)) { const k = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}-${String(d.getDate()).padStart(2,"0")}`; filled.push(buckets.get(k)||emptyBucket(k)); }
    } else if (unitLabel === "weekly") {
      const s = new Date(allKeys[0]+"T00:00:00"), e = new Date(allKeys[allKeys.length-1]+"T00:00:00");
      for (let d = new Date(s); d <= e; d.setDate(d.getDate()+7)) { const k = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}-${String(d.getDate()).padStart(2,"0")}`; filled.push(buckets.get(k)||emptyBucket(k)); }
    } else {
      const [sy,sm] = allKeys[0].split("-").map(Number), [ey,em] = allKeys[allKeys.length-1].split("-").map(Number);
      let y=sy,m=sm; while(y<ey||(y===ey&&m<=em)){const k=`${y}-${String(m).padStart(2,"0")}`;filled.push(buckets.get(k)||emptyBucket(k));m++;if(m>12){m=1;y++;}}
    }
    if (filled.length < 2) return "";
    let maxVal = 0;
    for (const b of filled) maxVal = Math.max(maxVal, b.delivered, b.deliveredFail, b.quarantine, b.reject);
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
    // 4系列: 配送済(認証成功) / 配送済(認証失敗) / 隔離 / 拒否
    const series = [
      {f:"delivered",c:COLOR_DELIVERED,l:msg("deliveredPass")},
      {f:"deliveredFail",c:COLOR_DELIVERED_FAIL,l:msg("deliveredFail")},
      {f:"quarantine",c:COLOR_QUARANTINE,l:msg("quarantined")},
      {f:"reject",c:COLOR_REJECT,l:msg("rejected")}
    ];
    let dots="";
    for(let i=0;i<n;i++){const b=filled[i],x=xAt(i);series.forEach(e=>{const y=yAt(b[e.f]);dots+=`<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="3" fill="${e.c}" opacity="0.8"><title>${escapeHTML(b.key+" — "+e.l+": "+b[e.f].toLocaleString())}</title></circle>`;});}
    return `<div class="drv-chart-container"><div class="drv-chart-title">${escapeHTML(msg("chartTimeSeries"))}</div>
      <svg class="drv-chart-svg" viewBox="0 0 ${w} ${h}" preserveAspectRatio="xMidYMid meet">${gridLines}
        <line x1="${padL}" y1="${padT}" x2="${padL}" y2="${padT+chartH}" class="drv-axis-line"/>
        <line x1="${padL}" y1="${padT+chartH}" x2="${w-padR}" y2="${padT+chartH}" class="drv-axis-line"/>${xLabels}
        ${series.map(e => `<polyline points="${toPolyline(e.f)}" fill="none" stroke="${e.c}" stroke-width="2"/>`).join("\n        ")}${dots}
      </svg>
      <div class="drv-chart-legend-row">
        ${series.map(e => `<span class="drv-pie-legend-item"><span class="drv-legend-dot" style="background:${e.c}"></span>${e.l}</span>`).join("\n        ")}
      </div></div>`;
  };

  // =========================================================
  // CSV エクスポート: 全分析データを CSV で出力
  // =========================================================
  const csvEscape = (val) => `"${String(val ?? "").replace(/"/g, '""')}"`;
  const exportCsv = (results) => {
    if (!results || !results.domainDetails) return;
    const rows = [];

    // === IP アドレス範囲 ===
    rows.push("# IP Address Ranges");
    rows.push(["Domain","IP Range","Classification","Count",
      "Delivered (Auth OK)","Delivered (Auth Fail)","Quarantined","Rejected",
      "DKIM+SPF Pass","DKIM Pass","SPF Pass"].join(","));
    for (const dd of results.domainDetails) {
      for (const e of (dd.aggregate.topIpRanges || [])) {
        const cl = classifyIpRange(e);
        rows.push([csvEscape(dd.domain), csvEscape(e.key), csvEscape(cl.tag),
          e.count, e.deliveredPass, e.deliveredFail,
          e.quarantine, e.reject, e.fullPass, e.dkimPass, e.spfPass].join(","));
      }
    }

    // === DKIM 署名 ===
    rows.push("", "# DKIM Signatures");
    rows.push(["Domain","Signing Domain","Selector","Count","Pass","Fail","Third-party"].join(","));
    for (const dd of results.domainDetails) {
      for (const s of (dd.aggregate.dkimSignatures || [])) {
        rows.push([csvEscape(dd.domain), csvEscape(s.domain), csvEscape(s.selector),
          s.count, s.pass, s.fail, s.isThirdParty ? "yes" : "no"].join(","));
      }
    }

    // === SPF ドメイン ===
    rows.push("", "# SPF Domains");
    rows.push(["Domain","SPF Domain","Scopes","Count","Pass","Fail"].join(","));
    for (const dd of results.domainDetails) {
      for (const s of (dd.aggregate.spfDomains || [])) {
        rows.push([csvEscape(dd.domain), csvEscape(s.domain), csvEscape(s.scopes.join(";")),
          s.count, s.pass, s.fail].join(","));
      }
    }

    // === Envelope 不一致 ===
    rows.push("", "# Envelope Mismatches");
    rows.push(["Domain","Header From","Envelope From","Count","Pass","Fail"].join(","));
    for (const dd of results.domainDetails) {
      for (const m of (dd.aggregate.envelopeMismatches || [])) {
        rows.push([csvEscape(dd.domain), csvEscape(m.headerFrom), csvEscape(m.envelopeFrom),
          m.count, m.pass, m.fail].join(","));
      }
    }

    // === サブドメイン ===
    const hasSubdomains = results.domainDetails.some(dd => dd.aggregate.subdomains?.length > 0);
    if (hasSubdomains) {
      rows.push("", "# Subdomains");
      rows.push(["Domain","Subdomain","Count","Pass","Fail","Rejected"].join(","));
      for (const dd of results.domainDetails) {
        for (const s of (dd.aggregate.subdomains || [])) {
          rows.push([csvEscape(dd.domain), csvEscape(s.subdomain),
            s.count, s.pass, s.fail, s.reject].join(","));
        }
      }
    }

    // === フォレンジックレポート ===
    if (results.fr && results.fr.length > 0) {
      rows.push("", "# Forensic Reports");
      rows.push(["Date","Domain","Source IP","Auth Failure","Feedback Type"].join(","));
      for (const r of results.fr) {
        rows.push([csvEscape(r.messageDate), csvEscape(r.reportedDomain), csvEscape(r.sourceIp),
          csvEscape(r.authFailure), csvEscape(r.feedbackType)].join(","));
      }
    }

    const blob = new Blob(["\uFEFF" + rows.join("\n")], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `dmarc-analysis-${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // =========================================================
  // 結果描画メイン
  // =========================================================
  const renderResults = (results) => {
    lastResults = results;
    // 全セクションを初期化してから再描画
    $("domains-container").replaceChildren();
    $("pie-row").replaceChildren();
    $("summary-cards").replaceChildren();
    hide($("period-info"));
    hide($("summary-section"));
    hide($("fr-section"));
    hide($("issues-section"));
    hide($("btn-export"));
    hide($("btn-toggle-all"));
    allExpanded = true;
    $("btn-toggle-all").textContent = msg("btnCollapseAll");
    hide($("no-results-notice"));
    if (results.ar.length === 0 && results.fr.length === 0) {
      // スキャン完了したが結果が 0 件
      show($("no-results-notice"));
      return;
    }
    if (results.ar.length > 0 && results.aggregate) {
      const agg = results.aggregate;
      if (agg.dateRangeMin && agg.dateRangeMax) {
        $("period-info").textContent = `${formatUnixDate(agg.dateRangeMin)} – ${formatUnixDate(agg.dateRangeMax)} | ${agg.reportCount} ${msg("colReports")} | ${agg.uniqueIpRanges} ${msg("ipRangeCountLabel")}`;
        show($("period-info"));
      }
      safeHTML($("summary-cards"), buildStatCards(agg, results.previousAggregate || null));
      renderPieCharts(agg);
      show($("summary-section"));
      show($("btn-export"));
      if (results.domainDetails) {
        const pd = results.scanPeriodDays || 0;
        for (const dd of results.domainDetails) renderDomainSection(dd, pd);
        // ドメインが2つ以上あれば全展開/折りたたみボタンを表示
        if (results.domainDetails.length >= 2) show($("btn-toggle-all"));
      }
    }
    if (results.fr.length > 0) renderFrTable(results.fr);
    if (results.issuesSummary && results.issuesSummary.totalIssues > 0) renderIssues(results.issuesSummary, results.issues);
  };

  // =========================================================
  // 期間選択の記憶キー
  // =========================================================
  const PERIOD_STORAGE_KEY = "dmarcraPeriod";

  // =========================================================
  // 初期化
  // =========================================================
  const init = async () => {
    applyI18n();
    // 前回選択した期間を復元
    try {
      const stored = await browser.storage.local.get(PERIOD_STORAGE_KEY);
      if (stored[PERIOD_STORAGE_KEY]) $("period-select").value = stored[PERIOD_STORAGE_KEY];
    } catch (e) { /* 初回起動時はストレージが空 */ }
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
    safeHTML($("status-message"), isLoading ? `<span class="drv-spinner"></span>${escapeHTML(text)}` : escapeHTML(text));
  };

  $("btn-settings").addEventListener("click", () => browser.runtime.openOptionsPage());
  $("btn-export").addEventListener("click", () => exportCsv(lastResults));

  // 期間変更時にストレージに保存
  $("period-select").addEventListener("change", () => {
    browser.storage.local.set({ [PERIOD_STORAGE_KEY]: $("period-select").value });
  });

  // 全展開/全折りたたみトグル
  let allExpanded = true;
  $("btn-toggle-all").addEventListener("click", () => {
    allExpanded = !allExpanded;
    const bodies = $("domains-container").querySelectorAll(".drv-domain-body");
    const icons = $("domains-container").querySelectorAll(".drv-toggle-icon");
    bodies.forEach(b => { if (allExpanded) b.classList.remove("collapsed"); else b.classList.add("collapsed"); });
    icons.forEach(ic => { if (allExpanded) ic.classList.add("expanded"); else ic.classList.remove("expanded"); });
    $("btn-toggle-all").textContent = allExpanded ? msg("btnCollapseAll") : msg("btnExpandAll");
  });

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
    const pieRow = $("pie-row"); pieRow.replaceChildren();
    if (agg.domains?.length > 0)
      safeAppendHTML(pieRow, buildPieChart(msg("colDomain"), agg.domains.map((d,i) => ({label:d.domain,value:d.count,color:PALETTE[i%PALETTE.length]}))));
    const dispSegs = [
      {label:msg("deliveredPass"),value:agg.deliveredPassCount,color:COLOR_DELIVERED},
      {label:msg("deliveredFail"),value:agg.deliveredFailCount,color:COLOR_DELIVERED_FAIL},
      {label:msg("quarantined"),value:agg.quarantineCount,color:COLOR_QUARANTINE},
      {label:msg("rejected"),value:agg.rejectCount,color:COLOR_REJECT}
    ].filter(s=>s.value>0);
    if (dispSegs.length > 0) safeAppendHTML(pieRow, buildPieChart(msg("dispositionTitle"), dispSegs));
    if (agg.reporters?.length > 0)
      safeAppendHTML(pieRow, buildPieChart(msg("colReporter"), agg.reporters.map((r,i) => ({label:r.name,value:r.count,color:PALETTE[i%PALETTE.length]}))));
  };

  // =========================================================
  // ドメイン別詳細セクション (折りたたみ + 健全度バッジ + アドバイス + 深掘り分析)
  // =========================================================
  const renderDomainSection = (dd, periodDays) => {
    const agg = dd.aggregate;
    const section = document.createElement("div");
    section.className = "drv-domain-section";

    const pol = dd.policy;
    const policyStr = `p=${pol.p} sp=${pol.sp} adkim=${pol.adkim} aspf=${pol.aspf} pct=${pol.pct}${pol.fo !== "0" ? ` fo=${pol.fo}` : ""}`;
    const health = computeHealthBadge(agg, pol);

    const sectionId = `domain-${dd.domain.replace(/[^a-zA-Z0-9]/g, "_")}`;
    let html = `<div class="drv-domain-header" data-target="${sectionId}">
      <span>📋 ${escapeHTML(dd.domain)}</span>
      <span class="drv-health-badge ${health.cls}" title="${escapeHTML(health.reason || health.label)}">${health.icon} ${escapeHTML(health.label)}</span>${health.reason ? `<span style="font-size:11px;font-weight:normal;color:var(--drv-text-muted);margin-left:4px">${escapeHTML(health.reason)}</span>` : ""}${health.info ? `<span style="font-size:11px;font-weight:normal;color:var(--drv-text-muted);margin-left:4px">ℹ️ ${escapeHTML(health.info)}</span>` : ""}
      <span class="drv-domain-policy">${escapeHTML(policyStr)}</span>
      <span style="font-size:12px;color:var(--drv-text-muted);">${agg.reportCount} ${escapeHTML(msg("colReports"))}</span>
      <span class="drv-toggle-icon expanded" data-toggle="${sectionId}">▼</span>
    </div>`;

    html += `<div class="drv-domain-body" id="${sectionId}"><div class="drv-domain-body-inner"><div class="drv-domain-body-content">`;

    // ポリシー推奨アドバイス
    html += buildPolicyAdvice(agg, pol);

    // 8枠コンパクトカード (率ベースの前期比較付き)
    const t = agg.totalCount;
    const pa = dd.previousAggregate || null;
    const pat = pa?.totalCount || 0;
    const rc2 = (cur, prev) => pa ? computeRateChange(cur, t, prev, pat) : { rateCur: 0, ratePrev: null };
    const ci = [
      {label:msg("totalEmails"),value:t.toLocaleString(),pctText:"",cc:"",upPos:true,chgCur:t,chgPrev:pa?pat:null},
      {label:msg("deliveredPass"),value:agg.deliveredPassCount.toLocaleString(),pctText:pct(agg.deliveredPassCount,t),cc:"drv-delivered-text",upPos:true,...rc2(agg.deliveredPassCount,pa?.deliveredPassCount)},
      {label:msg("deliveredFail"),value:agg.deliveredFailCount.toLocaleString(),pctText:pct(agg.deliveredFailCount,t),cc:"drv-delivered-fail-text",upPos:false,...rc2(agg.deliveredFailCount,pa?.deliveredFailCount)},
      {label:msg("quarantined"),value:agg.quarantineCount.toLocaleString(),pctText:pct(agg.quarantineCount,t),cc:"drv-quarantine-text",upPos:false,...rc2(agg.quarantineCount,pa?.quarantineCount)},
      {label:msg("rejected"),value:agg.rejectCount.toLocaleString(),pctText:pct(agg.rejectCount,t),cc:"drv-reject-text",upPos:false,...rc2(agg.rejectCount,pa?.rejectCount)},
      {label:msg("dkimSpfPass"),value:agg.passCount.toLocaleString(),pctText:pct(agg.passCount,t),cc:"",upPos:true,...rc2(agg.passCount,pa?.passCount)},
      {label:msg("dkimPass"),value:agg.dkimPassCount.toLocaleString(),pctText:pct(agg.dkimPassCount,t),cc:"",upPos:true,...rc2(agg.dkimPassCount,pa?.dkimPassCount)},
      {label:msg("spfPass"),value:agg.spfPassCount.toLocaleString(),pctText:pct(agg.spfPassCount,t),cc:"",upPos:true,...rc2(agg.spfPassCount,pa?.spfPassCount)}
    ];
    html += '<div class="drv-card-grid-compact">';
    for (const item of ci) {
      const lc = item.cc ? ` ${item.cc}` : "";
      const change = pa ? buildChangeIndicator(item.chgCur ?? item.rateCur, item.chgPrev ?? item.ratePrev, item.upPos) : "";
      html += `<div class="drv-card-compact"><div class="drv-card-label${lc}">${escapeHTML(item.label)}</div><div class="drv-card-value${lc}">${item.value}</div><div class="drv-card-pct">${item.pctText || "&nbsp;"}</div>${change}</div>`;
    }
    html += '</div>';

    html += buildDispositionBar(agg);

    if (dd.timeSeries && dd.timeSeries.length >= 2)
      html += buildTimeSeriesChart(dd.timeSeries, periodDays);

    // IP アドレス範囲テーブル (分類タグ付き)
    if (agg.topIpRanges?.length > 0)
      html += `<div class="drv-domain-subsection"><div class="drv-domain-subtitle">${escapeHTML(msg("sectionTopIps"))}</div>${buildDetailedTable(msg("colIpRange"), agg.topIpRanges, true, true)}</div>`;

    // レポーター別テーブル
    if (agg.topReporters?.length > 0)
      html += `<div class="drv-domain-subsection"><div class="drv-domain-subtitle">${escapeHTML(msg("sectionReporters"))}</div>${buildDetailedTable(msg("colReporter"), agg.topReporters, false, false)}</div>`;

    // DKIM 署名分析
    if (agg.dkimSignatures?.length > 0)
      html += `<div class="drv-domain-subsection"><div class="drv-domain-subtitle">${escapeHTML(msg("sectionDkimSignatures"))}</div>${buildDkimSignaturesTable(agg.dkimSignatures)}</div>`;

    // SPF ドメイン分析
    if (agg.spfDomains?.length > 0)
      html += `<div class="drv-domain-subsection"><div class="drv-domain-subtitle">${escapeHTML(msg("sectionSpfDomains"))}</div>${buildSpfDomainsTable(agg.spfDomains)}</div>`;

    // Envelope From / Header From 不一致
    if (agg.envelopeMismatches?.length > 0)
      html += `<div class="drv-domain-subsection"><div class="drv-domain-subtitle">${escapeHTML(msg("sectionEnvelopeAlignment"))}</div>${buildEnvelopeMismatchTable(agg.envelopeMismatches)}</div>`;

    // サブドメイン分析
    if (agg.subdomains?.length > 0)
      html += `<div class="drv-domain-subsection"><div class="drv-domain-subtitle">${escapeHTML(msg("sectionSubdomains"))}</div>${buildSubdomainTable(agg.subdomains)}</div>`;

    // ポリシーオーバーライド詳細 (理由 + IP範囲)
    if (agg.overrideDetails?.length > 0) {
      html += `<div class="drv-domain-subsection"><div class="drv-domain-subtitle">${escapeHTML(msg("sectionOverrides"))}</div>${buildOverrideDetailTable(agg.overrideDetails)}</div>`;
    } else if (agg.overrideReasons?.length > 0) {
      // 詳細がない場合はフォールバックで従来の簡易テーブル
      html += `<div class="drv-domain-subsection"><div class="drv-domain-subtitle">${escapeHTML(msg("sectionOverrides"))}</div><table class="drv-table"><thead><tr><th>${escapeHTML(msg("colOverrideType"))}</th><th>${escapeHTML(msg("colCount"))}</th></tr></thead><tbody>`;
      for (const entry of agg.overrideReasons) html += `<tr><td>${escapeHTML(entry.type)}</td><td>${entry.count.toLocaleString()}</td></tr>`;
      html += '</tbody></table></div>';
    }

    // ドメインに紐づくフォレンジックレポート
    if (dd.forensicReports?.length > 0)
      html += `<div class="drv-domain-subsection"><div class="drv-domain-subtitle">${escapeHTML(msg("sectionForensic"))} (${dd.forensicReports.length})</div>${buildDomainForensicTable(dd.forensicReports)}</div>`;

    // ISP メタデータエラー
    if (agg.warningsSummary?.reportsWithMetadataErrors > 0)
      html += `<div class="drv-domain-subsection"><div class="drv-domain-subtitle">${escapeHTML(msg("ispMetadataErrors"))}</div><p style="font-size:12px;color:var(--drv-warn);">${agg.warningsSummary.reportsWithMetadataErrors} ${escapeHTML(msg("ispMetadataErrorsDetail"))}</p></div>`;

    html += '</div></div></div>';

    safeHTML(section, html);
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
    const tbody = $("fr-table").querySelector("tbody"); tbody.replaceChildren();
    const sorted = [...frReports].sort((a,b) => new Date(b.messageDate)-new Date(a.messageDate));
    for (const r of sorted) {
      const tr = document.createElement("tr");
      safeTableRow(tr, `<td>${escapeHTML(r.messageDate?new Date(r.messageDate).toLocaleDateString():"-")}</td><td>${escapeHTML(r.reportedDomain)}</td><td><code>${escapeHTML(r.sourceIp)}</code></td><td>${escapeHTML(r.authFailure||"-")}</td>`);
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
    const tbody = $("issues-table").querySelector("tbody"); tbody.replaceChildren();
    for (const i of all) {
      const tr = document.createElement("tr");
      safeTableRow(tr, `<td>${escapeHTML(i.date?new Date(i.date).toLocaleDateString():"-")}</td><td class="${escapeHTML(i.cls)}">${escapeHTML(i.cat)}</td><td>${escapeHTML(i.subj)}</td><td>${escapeHTML(i.det)}</td>`);
      tbody.appendChild(tr);
    }
    show($("issues-section"));
  };

  init();
})();
