// DMARCReportViewer - dashboard/dashboard.js
// ダッシュボード画面のメインロジック
// background.js へメッセージを送信してデータ取得 → パーサーで解析 → UI 描画

(() => {
  "use strict";

  // =========================================================
  // i18n ヘルパー
  // =========================================================
  const msg = (key, substitutions) => {
    return browser.i18n.getMessage(key, substitutions) || key;
  };

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
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
  };

  // =========================================================
  // UI 要素の参照
  // =========================================================
  const $ = (id) => document.getElementById(id);

  const btnScan = $("btn-scan");
  const btnSettings = $("btn-settings");
  const statusBar = $("status-bar");
  const statusMessage = $("status-message");
  const noFolderNotice = $("no-folder-notice");
  const summarySection = $("summary-section");
  const domainSection = $("domain-section");
  const reporterSection = $("reporter-section");
  const ipSection = $("ip-section");
  const rufSection = $("ruf-section");

  // =========================================================
  // ステータス表示
  // =========================================================
  const showStatus = (text, isLoading = false) => {
    statusBar.classList.remove("drv-hidden");
    statusMessage.innerHTML = isLoading
      ? `<span class="drv-spinner"></span>${escapeHTML(text)}`
      : escapeHTML(text);
  };

  const hideStatus = () => {
    statusBar.classList.add("drv-hidden");
  };

  const show = (el) => el.classList.remove("drv-hidden");
  const hide = (el) => el.classList.add("drv-hidden");

  // =========================================================
  // バージョン表示
  // =========================================================
  const manifest = browser.runtime.getManifest();
  $("version").textContent = manifest.version;

  // =========================================================
  // 初期化: フォルダ設定状態チェック
  // =========================================================
  const init = async () => {
    applyI18n();

    const settings = await browser.runtime.sendMessage({ command: "getSettings" });
    if (!settings.ruaFolderId && !settings.rufFolderId) {
      show(noFolderNotice);
    } else {
      hide(noFolderNotice);
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

    try {
      // 1. background.js にスキャンを依頼 (パース済みデータが返る)
      const results = await browser.runtime.sendMessage({ command: "scanReports" });

      if (results.error) {
        showStatus(`Error: ${results.error}`);
        btnScan.disabled = false;
        return;
      }

      // 2. UI 描画 (データは background 側で重複排除・パース済み)
      if (results.rua.length > 0 && results.aggregate) {
        renderSummary(results.aggregate);
        renderDomainTable(results.domainDetails || []);
        renderReporterTable(results.aggregate);
        renderIpTable(results.aggregate);
      }

      if (results.ruf.length > 0) {
        renderRufTable(results.ruf);
      }

      // 3. ステータス更新
      const totalErrors = results.errors.length;
      const statusText = (msg("statusComplete") || "Scan complete.") +
        ` ${results.rua.length} ` + (msg("ruaReports") || "rua reports") +
        `, ${results.ruf.length} ` + (msg("rufReports") || "ruf reports") +
        (totalErrors > 0 ? ` (${totalErrors} errors)` : "");
      showStatus(statusText);

    } catch (e) {
      showStatus(`Error: ${e.message}`);
    } finally {
      btnScan.disabled = false;
    }
  });

  // =========================================================
  // サマリー描画
  // =========================================================
  const renderSummary = (agg) => {
    $("stat-total").textContent = agg.totalCount.toLocaleString();
    $("stat-pass-rate").textContent = agg.fullPassRate.toFixed(1) + "%";
    $("stat-dkim-rate").textContent = agg.dkimPassRate.toFixed(1) + "%";
    $("stat-spf-rate").textContent = agg.spfPassRate.toFixed(1) + "%";
    $("stat-reject").textContent = agg.rejectCount.toLocaleString();
    $("stat-quarantine").textContent = agg.quarantineCount.toLocaleString();

    // パス率に応じた色分け
    const passRateEl = $("stat-pass-rate");
    passRateEl.className = "drv-card-value";
    if (agg.fullPassRate >= 99) passRateEl.classList.add("drv-pass-text");
    else if (agg.fullPassRate < 90) passRateEl.classList.add("drv-fail-text");
    else passRateEl.classList.add("drv-warn-text");

    show(summarySection);
  };

  // =========================================================
  // ドメイン別テーブル描画
  // =========================================================
  const renderDomainTable = (domainDetails) => {
    const tbody = $("domain-table").querySelector("tbody");
    tbody.innerHTML = "";

    for (const d of domainDetails) {
      const tr = document.createElement("tr");
      const passClass = d.aggregate.fullPassRate >= 99 ? "drv-pass-text"
                      : d.aggregate.fullPassRate < 90 ? "drv-fail-text"
                      : "drv-warn-text";

      tr.innerHTML = `
        <td><strong>${escapeHTML(d.domain)}</strong></td>
        <td>${d.aggregate.totalCount.toLocaleString()}</td>
        <td class="${passClass}">${d.aggregate.fullPassRate.toFixed(1)}%</td>
        <td>${d.reportCount}</td>
      `;
      tbody.appendChild(tr);
    }

    show(domainSection);
  };

  // =========================================================
  // レポーター別テーブル描画
  // =========================================================
  const renderReporterTable = (agg) => {
    const tbody = $("reporter-table").querySelector("tbody");
    tbody.innerHTML = "";

    for (const r of agg.reporters) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${escapeHTML(r.name)}</td>
        <td>${r.count}</td>
      `;
      tbody.appendChild(tr);
    }

    show(reporterSection);
  };

  // =========================================================
  // 送信元 IP テーブル描画
  // =========================================================
  const renderIpTable = (agg) => {
    const tbody = $("ip-table").querySelector("tbody");
    tbody.innerHTML = "";

    for (const entry of agg.topSourceIps) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><code>${escapeHTML(entry.ip)}</code></td>
        <td>${entry.count.toLocaleString()}</td>
      `;
      tbody.appendChild(tr);
    }

    show(ipSection);
  };

  // =========================================================
  // ruf テーブル描画
  // =========================================================
  const renderRufTable = (rufReports) => {
    const tbody = $("ruf-table").querySelector("tbody");
    tbody.innerHTML = "";

    // 日付降順でソート
    const sorted = [...rufReports].sort((a, b) =>
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

    show(rufSection);
  };

  // =========================================================
  // 起動
  // =========================================================
  init();
})();
