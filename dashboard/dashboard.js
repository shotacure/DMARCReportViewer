// DMARCReportViewer - dashboard/dashboard.js
// ダッシュボード画面のメインロジック
// background.js へメッセージを送信してデータ取得 → UI 描画
// popup 再表示時はキャッシュから復元する

(() => {
  "use strict";

  // =========================================================
  // i18n ヘルパー
  // =========================================================
  const msg = (key) => browser.i18n.getMessage(key) || key;

  const applyI18n = () => {
    document.querySelectorAll("[data-i18n]").forEach(el => {
      const key = el.getAttribute("data-i18n");
      const text = msg(key);
      if (text && text !== key) el.textContent = text;
    });
  };

  // =========================================================
  // HTML エスケープ (XSS 防止)
  // =========================================================
  const escapeHTML = (str) => {
    const div = document.createElement("div");
    div.appendChild(document.createTextNode(String(str)));
    return div.innerHTML;
  };

  // =========================================================
  // UI 要素の参照
  // =========================================================
  const $ = (id) => document.getElementById(id);

  const btnScan = $("btn-scan");
  const btnSettings = $("btn-settings");
  const periodSelect = $("period-select");
  const statusBar = $("status-bar");
  const statusMessage = $("status-message");
  const noFolderNotice = $("no-folder-notice");
  const periodInfo = $("period-info");
  const summarySection = $("summary-section");
  const reporterSection = $("reporter-section");
  const frSection = $("fr-section");
  const issuesSection = $("issues-section");
  const domainsContainer = $("domains-container");

  // =========================================================
  // ステータス表示
  // =========================================================
  const showStatus = (text, isLoading = false) => {
    statusBar.classList.remove("drv-hidden");
    statusMessage.innerHTML = isLoading
      ? `<span class="drv-spinner"></span>${escapeHTML(text)}`
      : escapeHTML(text);
  };

  const show = (el) => el.classList.remove("drv-hidden");
  const hide = (el) => el.classList.add("drv-hidden");

  // =========================================================
  // パス率に応じた CSS クラスを返す
  // =========================================================
  const passRateClass = (rate) => {
    if (rate >= 99) return "drv-pass-text";
    if (rate < 90) return "drv-fail-text";
    return "drv-warn-text";
  };

  // =========================================================
  // 日付フォーマット (Unix 秒 → ローカル日付文字列)
  // =========================================================
  const formatUnixDate = (unixSec) => {
    if (!unixSec) return "-";
    return new Date(unixSec * 1000).toLocaleDateString();
  };

  // =========================================================
  // バージョン表示
  // =========================================================
  const manifest = browser.runtime.getManifest();
  $("version").textContent = manifest.version;

  // =========================================================
  // 結果描画メイン: スキャン結果を受け取り全セクションを描画
  // =========================================================
  const renderResults = (results) => {
    // 既存のドメインセクションをクリア
    domainsContainer.innerHTML = "";

    if (results.ar.length > 0 && results.aggregate) {
      const agg = results.aggregate;

      // レポート期間表示
      if (agg.dateRangeMin && agg.dateRangeMax) {
        periodInfo.textContent = `${formatUnixDate(agg.dateRangeMin)} – ${formatUnixDate(agg.dateRangeMax)}` +
          ` | ${agg.reportCount} reports | ${agg.uniqueIpRanges} IP ranges`;
        show(periodInfo);
      }

      renderSummary(agg);
      renderDomainChart(agg);
      renderDispositionBar(agg, $("disposition-bar"));
      renderReporterTable(agg);

      // ドメイン別詳細セクションを動的に生成
      if (results.domainDetails) {
        for (const dd of results.domainDetails) {
          renderDomainSection(dd);
        }
      }
    }

    if (results.fr.length > 0) {
      renderFrTable(results.fr);
    }

    if (results.issuesSummary && results.issuesSummary.totalIssues > 0) {
      renderIssues(results.issuesSummary, results.issues);
    }
  };

  // =========================================================
  // 初期化: フォルダ設定チェック & キャッシュ復元
  // =========================================================
  const init = async () => {
    applyI18n();

    // フォルダ設定を検証・自動検出してからチェック
    const settings = await browser.runtime.sendMessage({ command: "resolveSettings" });
    if (!settings.arFolderId && !settings.frFolderId) {
      show(noFolderNotice);
    } else {
      hide(noFolderNotice);
    }

    // popup を再度開いた時にキャッシュされた結果を復元
    const cached = await browser.runtime.sendMessage({ command: "getLastResults" });
    if (cached && (cached.ar?.length > 0 || cached.fr?.length > 0)) {
      renderResults(cached);
      const totalErrors = cached.errors?.length || 0;
      const statusText = (msg("statusComplete") || "Scan complete.") +
        ` ${cached.ar.length} ` + (msg("arReports") || "aggregate reports") +
        `, ${cached.fr.length} ` + (msg("frReports") || "forensic reports") +
        (totalErrors > 0 ? ` (${totalErrors} errors)` : "") +
        ` (cached)`;
      showStatus(statusText);
    }
  };

  // =========================================================
  // 設定画面を開く
  // =========================================================
  btnSettings.addEventListener("click", () => {
    browser.runtime.openOptionsPage();
  });

  // =========================================================
  // スキャン実行
  // =========================================================
  btnScan.addEventListener("click", async () => {
    btnScan.disabled = true;
    showStatus(msg("statusScanning") || "Scanning folders...", true);

    // 期間フィルタ: 選択された日数から since (Unix ms) を計算
    const days = parseInt(periodSelect.value, 10);
    const since = days > 0 ? Date.now() - (days * 24 * 60 * 60 * 1000) : 0;

    try {
      const results = await browser.runtime.sendMessage({
        command: "scanReports",
        since
      });

      if (results.error) {
        showStatus(`Error: ${results.error}`);
        btnScan.disabled = false;
        return;
      }

      renderResults(results);

      // ステータス更新
      const totalErrors = results.errors.length;
      const statusText = (msg("statusComplete") || "Scan complete.") +
        ` ${results.ar.length} ` + (msg("arReports") || "aggregate reports") +
        `, ${results.fr.length} ` + (msg("frReports") || "forensic reports") +
        (totalErrors > 0 ? ` (${totalErrors} errors)` : "");
      showStatus(statusText);

    } catch (e) {
      showStatus(`Error: ${e.message}`);
    } finally {
      btnScan.disabled = false;
    }
  });

  // =========================================================
  // 大サマリー描画
  // =========================================================
  const renderSummary = (agg) => {
    $("stat-total").textContent = agg.totalCount.toLocaleString();
    $("stat-pass-rate").textContent = agg.fullPassRate.toFixed(1) + "%";
    $("stat-dkim-rate").textContent = agg.dkimPassRate.toFixed(1) + "%";
    $("stat-spf-rate").textContent = agg.spfPassRate.toFixed(1) + "%";
    $("stat-reject").textContent = agg.rejectCount.toLocaleString();
    $("stat-quarantine").textContent = agg.quarantineCount.toLocaleString();

    const passRateEl = $("stat-pass-rate");
    passRateEl.className = "drv-card-value";
    passRateEl.classList.add(passRateClass(agg.fullPassRate));

    show(summarySection);
  };

  // =========================================================
  // ドメイン別メール数割合の横棒グラフ (大サマリー内)
  // =========================================================
  const renderDomainChart = (agg) => {
    const container = $("domain-chart");
    container.innerHTML = "";
    if (!agg.domains || agg.domains.length === 0) return;

    const maxCount = agg.domains[0].count;
    let html = '<div class="drv-bar-chart">';
    for (const d of agg.domains) {
      const pct = maxCount > 0 ? (d.count / maxCount * 100) : 0;
      const totalPct = agg.totalCount > 0 ? (d.count / agg.totalCount * 100).toFixed(1) : "0";
      html += `<div class="drv-bar-row">
        <span class="drv-bar-label" title="${escapeHTML(d.domain)}">${escapeHTML(d.domain)}</span>
        <div class="drv-bar-track"><div class="drv-bar-fill drv-bar-fill-accent" style="width:${pct}%"></div></div>
        <span class="drv-bar-value">${d.count.toLocaleString()} (${totalPct}%)</span>
      </div>`;
    }
    html += '</div>';
    container.innerHTML = html;
  };

  // =========================================================
  // Disposition 分布の積み上げバー
  // =========================================================
  const renderDispositionBar = (agg, container) => {
    container.innerHTML = "";
    if (agg.totalCount === 0) return;

    const nonePct = (agg.noneCount / agg.totalCount * 100);
    const quarPct = (agg.quarantineCount / agg.totalCount * 100);
    const rejPct = (agg.rejectCount / agg.totalCount * 100);

    container.innerHTML = `
      <div class="drv-stacked-bar">
        ${nonePct > 0 ? `<div class="drv-stacked-bar-segment drv-stacked-none" style="width:${nonePct}%">${nonePct > 8 ? "none" : ""}</div>` : ""}
        ${quarPct > 0 ? `<div class="drv-stacked-bar-segment drv-stacked-quarantine" style="width:${quarPct}%">${quarPct > 8 ? "quar." : ""}</div>` : ""}
        ${rejPct > 0 ? `<div class="drv-stacked-bar-segment drv-stacked-reject" style="width:${rejPct}%">${rejPct > 8 ? "reject" : ""}</div>` : ""}
      </div>
      <div class="drv-stacked-legend">
        <span class="drv-stacked-legend-item"><span class="drv-legend-dot drv-stacked-none"></span>None ${agg.noneCount.toLocaleString()}</span>
        <span class="drv-stacked-legend-item"><span class="drv-legend-dot drv-stacked-quarantine"></span>Quarantine ${agg.quarantineCount.toLocaleString()}</span>
        <span class="drv-stacked-legend-item"><span class="drv-legend-dot drv-stacked-reject"></span>Reject ${agg.rejectCount.toLocaleString()}</span>
      </div>
    `;
  };

  // =========================================================
  // レポーター別テーブル描画 (全体)
  // =========================================================
  const renderReporterTable = (agg) => {
    const tbody = $("reporter-table").querySelector("tbody");
    tbody.innerHTML = "";
    for (const r of agg.reporters) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${escapeHTML(r.name)}</td><td>${r.count}</td>`;
      tbody.appendChild(tr);
    }
    show(reporterSection);
  };

  // =========================================================
  // ドメイン別詳細セクション描画 (1ドメインにつき1セクション)
  // =========================================================
  const renderDomainSection = (dd) => {
    const agg = dd.aggregate;
    const section = document.createElement("div");
    section.className = "drv-domain-section";

    // ポリシー情報の文字列
    const pol = dd.policy;
    const policyStr = `p=${pol.p} sp=${pol.sp} adkim=${pol.adkim} aspf=${pol.aspf} pct=${pol.pct}` +
      (pol.fo !== "0" ? ` fo=${pol.fo}` : "");

    // --- ヘッダー + ポリシー ---
    let html = `<div class="drv-domain-header">
      <span>📋 ${escapeHTML(dd.domain)}</span>
      <span class="drv-domain-policy">${escapeHTML(policyStr)}</span>
      <span style="margin-left:auto;font-size:12px;color:var(--drv-text-muted);">${agg.reportCount} reports</span>
    </div>`;

    // --- コンパクト統計カード ---
    html += `<div class="drv-card-grid-compact">
      <div class="drv-card-compact">
        <div class="drv-card-label">${escapeHTML(msg("totalEmails"))}</div>
        <div class="drv-card-value">${agg.totalCount.toLocaleString()}</div>
      </div>
      <div class="drv-card-compact">
        <div class="drv-card-label">${escapeHTML(msg("fullPassRate"))}</div>
        <div class="drv-card-value ${passRateClass(agg.fullPassRate)}">${agg.fullPassRate.toFixed(1)}%</div>
      </div>
      <div class="drv-card-compact">
        <div class="drv-card-label">DKIM</div>
        <div class="drv-card-value">${agg.dkimPassRate.toFixed(1)}%</div>
      </div>
      <div class="drv-card-compact">
        <div class="drv-card-label">SPF</div>
        <div class="drv-card-value">${agg.spfPassRate.toFixed(1)}%</div>
      </div>
      <div class="drv-card-compact drv-card-warn">
        <div class="drv-card-label">${escapeHTML(msg("rejected"))}</div>
        <div class="drv-card-value">${agg.rejectCount.toLocaleString()}</div>
      </div>
      <div class="drv-card-compact">
        <div class="drv-card-label">${escapeHTML(msg("quarantined"))}</div>
        <div class="drv-card-value">${agg.quarantineCount.toLocaleString()}</div>
      </div>
    </div>`;

    // --- Disposition 分布バー ---
    html += `<div class="drv-domain-disposition-bar"></div>`;

    // --- IP アドレス範囲テーブル ---
    if (agg.topIpRanges && agg.topIpRanges.length > 0) {
      html += `<div class="drv-domain-subsection">
        <div class="drv-domain-subtitle">${escapeHTML(msg("sectionTopIps"))}</div>
        <table class="drv-table"><thead><tr>
          <th>${escapeHTML(msg("colIpRange"))}</th>
          <th>${escapeHTML(msg("colCount"))}</th>
        </tr></thead><tbody>`;
      for (const entry of agg.topIpRanges) {
        html += `<tr><td><code>${escapeHTML(entry.range)}</code></td><td>${entry.count.toLocaleString()}</td></tr>`;
      }
      html += `</tbody></table></div>`;
    }

    // --- レポーター別テーブル ---
    if (agg.reporters && agg.reporters.length > 0) {
      html += `<div class="drv-domain-subsection">
        <div class="drv-domain-subtitle">${escapeHTML(msg("sectionReporters"))}</div>
        <table class="drv-table"><thead><tr>
          <th>${escapeHTML(msg("colReporter"))}</th>
          <th>${escapeHTML(msg("colReports"))}</th>
        </tr></thead><tbody>`;
      for (const r of agg.reporters) {
        html += `<tr><td>${escapeHTML(r.name)}</td><td>${r.count}</td></tr>`;
      }
      html += `</tbody></table></div>`;
    }

    // --- ポリシーオーバーライド理由 ---
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
      html += `</tbody></table></div>`;
    }

    // --- ISP メタデータエラー ---
    if (agg.warningsSummary && agg.warningsSummary.reportsWithMetadataErrors > 0) {
      html += `<div class="drv-domain-subsection">
        <div class="drv-domain-subtitle">ISP Metadata Errors</div>
        <p style="font-size:12px;color:var(--drv-warn);">
          ${agg.warningsSummary.reportsWithMetadataErrors} report(s) contain ISP-side metadata errors
        </p>
      </div>`;
    }

    section.innerHTML = html;
    domainsContainer.appendChild(section);

    // Disposition バーを DOMInsert 後に描画
    const dispBarEl = section.querySelector(".drv-domain-disposition-bar");
    if (dispBarEl) {
      renderDispositionBar(agg, dispBarEl);
    }
  };

  // =========================================================
  // フォレンジックレポートテーブル描画
  // =========================================================
  const renderFrTable = (frReports) => {
    const tbody = $("fr-table").querySelector("tbody");
    tbody.innerHTML = "";

    const sorted = [...frReports].sort((a, b) =>
      new Date(b.messageDate) - new Date(a.messageDate)
    );

    for (const r of sorted) {
      const tr = document.createElement("tr");
      const dateStr = r.messageDate
        ? new Date(r.messageDate).toLocaleDateString()
        : "-";
      tr.innerHTML = `
        <td>${escapeHTML(dateStr)}</td>
        <td>${escapeHTML(r.reportedDomain)}</td>
        <td><code>${escapeHTML(r.sourceIp)}</code></td>
        <td>${escapeHTML(r.authFailure || "-")}</td>
      `;
      tbody.appendChild(tr);
    }

    show(frSection);
  };

  // =========================================================
  // Issues セクション描画
  // =========================================================
  const renderIssues = (summary, issues) => {
    $("issue-parse-failed").textContent = summary.parseFailed.toLocaleString();
    $("issue-decompress-failed").textContent = summary.decompressFailed.toLocaleString();
    $("issue-incomplete").textContent = summary.incompleteReport.toLocaleString();
    $("issue-no-attachment").textContent = summary.noAttachment.toLocaleString();
    $("issue-unknown-format").textContent = summary.unknownFormat.toLocaleString();

    const allIssues = [];

    for (const item of issues.parseFailed) {
      allIssues.push({ date: item.date, category: msg("issueParseFailed") || "Parse Failed", categoryClass: "drv-fail-text", subject: item.subject || "-", detail: item.error || "-" });
    }
    for (const item of issues.decompressFailed) {
      allIssues.push({ date: item.date, category: msg("issueDecompressFailed") || "Decompress Failed", categoryClass: "drv-fail-text", subject: item.subject || "-", detail: `${item.attachment}: ${item.error || "-"}` });
    }
    for (const item of issues.noAttachment) {
      allIssues.push({ date: item.date, category: msg("issueNoAttachment") || "No Attachment", categoryClass: "drv-warn-text", subject: item.subject || "-", detail: msg("issueNoAttachmentDetail") || "No DMARC report attachment found" });
    }
    for (const item of issues.unknownFormat) {
      allIssues.push({ date: item.date, category: msg("issueUnknownFormat") || "Unknown Format", categoryClass: "drv-warn-text", subject: item.subject || "-", detail: `${item.attachment} (${item.contentType || "unknown"})` });
    }
    for (const item of issues.incompleteReport) {
      const warnTexts = item.warnings.slice(0, 3).map(w => w.message);
      const remaining = item.warnings.length - 3;
      let detail = warnTexts.join("; ");
      if (remaining > 0) detail += ` (+${remaining} more)`;
      allIssues.push({ date: item.date, category: msg("issueIncomplete") || "Incomplete Data", categoryClass: "", subject: item.subject || "-", detail });
    }

    allIssues.sort((a, b) => {
      if (!a.date) return 1;
      if (!b.date) return -1;
      return new Date(b.date) - new Date(a.date);
    });

    const tbody = $("issues-table").querySelector("tbody");
    tbody.innerHTML = "";

    for (const issue of allIssues) {
      const tr = document.createElement("tr");
      const dateStr = issue.date ? new Date(issue.date).toLocaleDateString() : "-";
      tr.innerHTML = `
        <td>${escapeHTML(dateStr)}</td>
        <td class="${issue.categoryClass}">${escapeHTML(issue.category)}</td>
        <td>${escapeHTML(issue.subject)}</td>
        <td>${escapeHTML(issue.detail)}</td>
      `;
      tbody.appendChild(tr);
    }

    show(issuesSection);
  };

  // =========================================================
  // 起動
  // =========================================================
  init();
})();
