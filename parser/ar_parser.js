// DMARCReportViewer - parser/ar_parser.js
// 集約レポート (Aggregate Report) XML パーサー
// RFC 7489 に準拠した DMARC 集約レポート XML を正規化データに変換する。
// DOMParser を使用し、外部ライブラリに依存しない。
// 全要素を網羅的に取得し、情報欠落を warnings として報告する。

const ArParser = (() => {
  "use strict";

  // =========================================================
  // ヘルパー: XML 要素から安全にテキストを取得
  // =========================================================
  const getText = (parent, tagName) => {
    if (!parent) return "";
    const el = parent.querySelector(tagName);
    return el?.textContent?.trim() || "";
  };

  const getInt = (parent, tagName) => {
    const val = parseInt(getText(parent, tagName), 10);
    return isNaN(val) ? 0 : val;
  };

  // =========================================================
  // IP アドレスを Class C 範囲に変換 (最終オクテットを xxx に置換)
  // IPv4: "192.168.1.42" → "192.168.1.xxx"
  // IPv6: 先頭48ビット (/48) を残し末尾を省略
  //        "2001:0db8:85a3::1" → "2001:db8:85a3:xxxx:..."
  // =========================================================
  const toIpRange = (ip) => {
    if (!ip) return "unknown";

    // IPv4 判定
    if (ip.includes(".") && !ip.includes(":")) {
      const parts = ip.split(".");
      if (parts.length === 4) {
        return `${parts[0]}.${parts[1]}.${parts[2]}.xxx`;
      }
      return ip;
    }

    // IPv6 判定: 先頭3グループ (/48相当) を残す
    try {
      let expanded = ip;
      if (expanded.includes("::")) {
        const halves = expanded.split("::");
        const left = halves[0] ? halves[0].split(":") : [];
        const right = halves[1] ? halves[1].split(":") : [];
        const missing = 8 - left.length - right.length;
        const middle = Array(missing).fill("0");
        expanded = [...left, ...middle, ...right].join(":");
      }
      const groups = expanded.split(":");
      if (groups.length >= 3) {
        const prefix = groups.slice(0, 3).map(g =>
          g.replace(/^0+/, "") || "0"
        ).join(":");
        return `${prefix}:xxxx:...`;
      }
    } catch (e) {
      // パース失敗時はそのまま返す
    }
    return ip;
  };

  // =========================================================
  // 詳細統計ヘルパー: レコード群をキー別にグループ化し、各キーの統計を算出
  // IP 範囲テーブルやレポーター別テーブルで
  // パス率・隔離数・拒否数を表示するために使用
  // =========================================================
  const computeDetailedStats = (entries) => {
    // entries: [{ key, count, dkimPass, spfPass, fullPass, delivered, quarantine, reject }]
    // → キー別に集約して実数ベースの統計を返す
    const map = new Map();
    for (const e of entries) {
      const existing = map.get(e.key);
      if (existing) {
        existing.count += e.count;
        existing.dkimPass += e.dkimPass;
        existing.spfPass += e.spfPass;
        existing.fullPass += e.fullPass;
        existing.delivered += e.delivered;
        existing.quarantine += e.quarantine;
        existing.reject += e.reject;
      } else {
        map.set(e.key, { ...e });
      }
    }

    return [...map.values()]
      .sort((a, b) => b.count - a.count)
      .slice(0, 20)
      .map(s => ({
        key: s.key,
        count: s.count,
        fullPass: s.fullPass,
        dkimPass: s.dkimPass,
        spfPass: s.spfPass,
        delivered: s.delivered,
        quarantine: s.quarantine,
        reject: s.reject
      }));
  };

  // =========================================================
  // XML サニタイズ: ISP 固有の XML 不整合を DOMParser に渡す前に修正
  // =========================================================
  const sanitizeXml = (xmlText) => {
    let sanitized = xmlText;

    // Microsoft の既知の typo: <diskim> → <dkim> (開始タグの誤記)
    sanitized = sanitized.replace(/<diskim>/g, "<dkim>");

    return sanitized;
  };

  // =========================================================
  // 情報欠落チェック: レポート全体の完全性を検証
  // =========================================================
  const validateReport = (report) => {
    const warnings = [];

    if (!report.reporter.orgName) {
      warnings.push({ field: "org_name", message: "Reporter organization name is missing" });
    }
    if (!report.reportId) {
      warnings.push({ field: "report_id", message: "Report ID is missing" });
    }
    if (!report.reporter.email) {
      warnings.push({ field: "email", message: "Reporter contact email is missing" });
    }
    if (report.dateRange.begin === 0) {
      warnings.push({ field: "date_range.begin", message: "Report date range begin is missing or zero" });
    }
    if (report.dateRange.end === 0) {
      warnings.push({ field: "date_range.end", message: "Report date range end is missing or zero" });
    }
    if (!report.policy.domain) {
      warnings.push({ field: "policy.domain", message: "Published policy domain is missing" });
    }
    if (!report.policy.p) {
      warnings.push({ field: "policy.p", message: "Published policy disposition (p=) is missing" });
    }
    if (report.records.length === 0) {
      warnings.push({ field: "records", message: "Report contains no record entries" });
    }

    for (let i = 0; i < report.records.length; i++) {
      const rec = report.records[i];
      const prefix = `record[${i}]`;

      if (!rec.sourceIp) {
        warnings.push({ field: `${prefix}.source_ip`, message: `Record #${i + 1}: source IP is missing` });
      }
      if (rec.count === 0) {
        warnings.push({ field: `${prefix}.count`, message: `Record #${i + 1}: message count is zero` });
      }
      if (!rec.dkimPolicyResult) {
        warnings.push({ field: `${prefix}.policy_evaluated.dkim`, message: `Record #${i + 1}: DKIM policy evaluation result is missing` });
      }
      if (!rec.spfPolicyResult) {
        warnings.push({ field: `${prefix}.policy_evaluated.spf`, message: `Record #${i + 1}: SPF policy evaluation result is missing` });
      }
      if (!rec.disposition) {
        warnings.push({ field: `${prefix}.disposition`, message: `Record #${i + 1}: disposition is missing` });
      }
      if (rec.dkimResults.length === 0 && rec.spfResults.length === 0) {
        warnings.push({ field: `${prefix}.auth_results`, message: `Record #${i + 1}: no DKIM or SPF auth_results present` });
      }
      if (!rec.headerFrom) {
        warnings.push({ field: `${prefix}.header_from`, message: `Record #${i + 1}: header_from identifier is missing` });
      }
    }

    return warnings;
  };

  // =========================================================
  // メイン: XML テキスト → 正規化済みレポートオブジェクト
  // =========================================================
  const parse = (xmlText) => {
    const sanitizedXml = sanitizeXml(xmlText);
    const parser = new DOMParser();
    const doc = parser.parseFromString(sanitizedXml, "text/xml");

    const parseError = doc.querySelector("parsererror");
    if (parseError) {
      throw new Error(`XML parse error: ${parseError.textContent}`);
    }

    const feedback = doc.querySelector("feedback");
    if (!feedback) {
      throw new Error("Invalid DMARC report: <feedback> element not found.");
    }

    // --- report_metadata ---
    const metadata = feedback.querySelector("report_metadata");
    const orgName = getText(metadata, "org_name");
    const email = getText(metadata, "email");
    const extraContactInfo = getText(metadata, "extra_contact_info");
    const reportId = getText(metadata, "report_id");
    const dateRange = metadata?.querySelector("date_range");
    const dateBegin = getInt(dateRange, "begin");
    const dateEnd = getInt(dateRange, "end");

    const metadataErrors = [];
    const errorElements = metadata?.querySelectorAll("error") || [];
    for (const errEl of errorElements) {
      const errText = errEl.textContent?.trim();
      if (errText) metadataErrors.push(errText);
    }

    // --- policy_published ---
    const policy = feedback.querySelector("policy_published");
    const domain = getText(policy, "domain");
    const policyAdkim = getText(policy, "adkim") || "r";
    const policyAspf = getText(policy, "aspf") || "r";
    const policyP = getText(policy, "p");
    const policySp = getText(policy, "sp") || policyP;
    const policyPct = getInt(policy, "pct") || 100;
    const policyFo = getText(policy, "fo") || "0";
    const policyNp = getText(policy, "np");

    // --- records ---
    const recordElements = feedback.querySelectorAll("record");
    const records = [];

    for (const rec of recordElements) {
      const row = rec.querySelector("row");
      const sourceIp = getText(row, "source_ip");
      const count = getInt(row, "count");
      const headerFrom = getText(rec, "identifiers > header_from");
      const envelopeFrom = getText(rec, "identifiers > envelope_from");
      const envelopeTo = getText(rec, "identifiers > envelope_to");

      const pe = row?.querySelector("policy_evaluated");
      const disposition = getText(pe, "disposition");
      const dkimPolicyResult = getText(pe, "dkim");
      const spfPolicyResult = getText(pe, "spf");

      const reasons = [];
      const reasonElements = pe?.querySelectorAll("reason") || [];
      for (const r of reasonElements) {
        reasons.push({
          type: getText(r, "type"),
          comment: getText(r, "comment")
        });
      }

      const authResults = rec.querySelector("auth_results");

      const dkimResults = [];
      const dkimElements = authResults?.querySelectorAll("dkim") || [];
      for (const d of dkimElements) {
        dkimResults.push({
          domain: getText(d, "domain"),
          selector: getText(d, "selector"),
          // 一部 ISP は result タグの代わりに r タグを使用するためフォールバック
          result: getText(d, "result") || getText(d, "r"),
          humanResult: getText(d, "human_result")
        });
      }

      const spfResults = [];
      const spfElements = authResults?.querySelectorAll("spf") || [];
      for (const s of spfElements) {
        spfResults.push({
          domain: getText(s, "domain"),
          scope: getText(s, "scope"),
          // 一部 ISP は result タグの代わりに r タグを使用するためフォールバック
          result: getText(s, "result") || getText(s, "r")
        });
      }

      records.push({
        sourceIp, count, headerFrom, envelopeFrom, envelopeTo,
        disposition, dkimPolicyResult, spfPolicyResult,
        reasons, dkimResults, spfResults
      });
    }

    const reportKey = `${orgName}!${domain}!${dateBegin}!${dateEnd}!${reportId}`;

    const report = {
      reportKey, reportId,
      reporter: { orgName, email, extraContactInfo },
      dateRange: { begin: dateBegin, end: dateEnd },
      metadataErrors,
      policy: {
        domain, adkim: policyAdkim, aspf: policyAspf,
        p: policyP, sp: policySp, pct: policyPct, fo: policyFo, np: policyNp
      },
      records,
      summary: computeSummary(records),
      warnings: []
    };

    report.warnings = validateReport(report);
    return report;
  };

  // =========================================================
  // サマリー計算: レコード群から統計値を算出
  // =========================================================
  const computeSummary = (records) => {
    let totalCount = 0;
    let passCount = 0;
    let dkimPassCount = 0;
    let spfPassCount = 0;
    let rejectCount = 0;
    let quarantineCount = 0;
    let noneCount = 0;
    const sourceIps = new Map();
    const ipRanges = new Map();
    const overrideReasons = new Map();

    // IP範囲別・詳細統計用の生データ
    const ipRangeEntries = [];

    for (const rec of records) {
      totalCount += rec.count;

      const isDkimPass = rec.dkimPolicyResult === "pass";
      const isSpfPass = rec.spfPolicyResult === "pass";
      const isFullPass = isDkimPass && isSpfPass;

      if (isDkimPass) dkimPassCount += rec.count;
      if (isSpfPass) spfPassCount += rec.count;
      if (isFullPass) passCount += rec.count;

      switch (rec.disposition) {
        case "reject":     rejectCount += rec.count;     break;
        case "quarantine": quarantineCount += rec.count;  break;
        default:           noneCount += rec.count;        break;
      }

      const ipTotal = sourceIps.get(rec.sourceIp) || 0;
      sourceIps.set(rec.sourceIp, ipTotal + rec.count);

      const range = toIpRange(rec.sourceIp);
      const rangeTotal = ipRanges.get(range) || 0;
      ipRanges.set(range, rangeTotal + rec.count);

      // IP範囲別の詳細統計データ
      ipRangeEntries.push({
        key: range,
        count: rec.count,
        dkimPass: isDkimPass ? rec.count : 0,
        spfPass: isSpfPass ? rec.count : 0,
        fullPass: isFullPass ? rec.count : 0,
        delivered: (rec.disposition !== "quarantine" && rec.disposition !== "reject") ? rec.count : 0,
        quarantine: rec.disposition === "quarantine" ? rec.count : 0,
        reject: rec.disposition === "reject" ? rec.count : 0
      });

      for (const reason of rec.reasons) {
        if (reason.type) {
          const existing = overrideReasons.get(reason.type) || 0;
          overrideReasons.set(reason.type, existing + rec.count);
        }
      }
    }

    return {
      totalCount, passCount, dkimPassCount, spfPassCount,
      rejectCount, quarantineCount, noneCount,
      dkimPassRate: totalCount > 0 ? (dkimPassCount / totalCount * 100) : 0,
      spfPassRate: totalCount > 0 ? (spfPassCount / totalCount * 100) : 0,
      fullPassRate: totalCount > 0 ? (passCount / totalCount * 100) : 0,
      uniqueSourceIps: sourceIps.size,
      uniqueIpRanges: ipRanges.size,
      topSourceIps: [...sourceIps.entries()]
        .sort((a, b) => b[1] - a[1]).slice(0, 20)
        .map(([ip, count]) => ({ ip, count })),
      // Class C 範囲ごとの詳細統計 (パス率、隔離、拒否を含む)
      topIpRanges: computeDetailedStats(ipRangeEntries),
      overrideReasons: [...overrideReasons.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([type, count]) => ({ type, count }))
    };
  };

  // =========================================================
  // 複数レポートの統合サマリー
  // =========================================================
  const aggregateSummaries = (reports) => {
    let totalCount = 0;
    let passCount = 0;
    let dkimPassCount = 0;
    let spfPassCount = 0;
    let rejectCount = 0;
    let quarantineCount = 0;
    let noneCount = 0;
    const sourceIps = new Map();
    const reporters = new Map();
    const domains = new Map();
    const overrideReasons = new Map();

    // 詳細統計用の生データ集約
    const ipRangeEntries = [];
    const reporterEntries = [];

    let dateRangeMin = Infinity;
    let dateRangeMax = 0;

    let totalWarnings = 0;
    let reportsWithWarnings = 0;
    let reportsWithMetadataErrors = 0;
    const warningFieldCounts = new Map();

    for (const report of reports) {
      const s = report.summary;
      totalCount += s.totalCount;
      passCount += s.passCount;
      dkimPassCount += s.dkimPassCount;
      spfPassCount += s.spfPassCount;
      rejectCount += s.rejectCount;
      quarantineCount += s.quarantineCount;
      noneCount += s.noneCount;

      if (report.dateRange.begin > 0 && report.dateRange.begin < dateRangeMin) {
        dateRangeMin = report.dateRange.begin;
      }
      if (report.dateRange.end > 0 && report.dateRange.end > dateRangeMax) {
        dateRangeMax = report.dateRange.end;
      }

      // レポーター別: レポート数のみ (reporters Map)
      const rCount = reporters.get(report.reporter.orgName) || 0;
      reporters.set(report.reporter.orgName, rCount + 1);

      // ドメイン別
      const dCount = domains.get(report.policy.domain) || 0;
      domains.set(report.policy.domain, dCount + s.totalCount);

      // 個別 IP
      for (const ipEntry of s.topSourceIps) {
        const existing = sourceIps.get(ipEntry.ip) || 0;
        sourceIps.set(ipEntry.ip, existing + ipEntry.count);
      }

      // IP 範囲詳細統計: 各レポートの topIpRanges を集約 (実数ベース)
      for (const entry of s.topIpRanges) {
        ipRangeEntries.push({
          key: entry.key,
          count: entry.count,
          dkimPass: entry.dkimPass,
          spfPass: entry.spfPass,
          fullPass: entry.fullPass,
          delivered: entry.delivered,
          quarantine: entry.quarantine,
          reject: entry.reject
        });
      }

      // レポーター別の詳細統計: レコードごとにレポーター名をキーにして集計
      for (const rec of report.records) {
        const isDkimPass = rec.dkimPolicyResult === "pass";
        const isSpfPass = rec.spfPolicyResult === "pass";
        const isFullPass = isDkimPass && isSpfPass;
        const isDelivered = rec.disposition !== "quarantine" && rec.disposition !== "reject";
        reporterEntries.push({
          key: report.reporter.orgName,
          count: rec.count,
          dkimPass: isDkimPass ? rec.count : 0,
          spfPass: isSpfPass ? rec.count : 0,
          fullPass: isFullPass ? rec.count : 0,
          delivered: isDelivered ? rec.count : 0,
          quarantine: rec.disposition === "quarantine" ? rec.count : 0,
          reject: rec.disposition === "reject" ? rec.count : 0
        });
      }

      // ポリシーオーバーライド
      for (const reason of s.overrideReasons) {
        const existing = overrideReasons.get(reason.type) || 0;
        overrideReasons.set(reason.type, existing + reason.count);
      }

      // 警告
      if (report.warnings && report.warnings.length > 0) {
        reportsWithWarnings++;
        totalWarnings += report.warnings.length;
        const seenFields = new Set();
        for (const w of report.warnings) {
          const category = w.field.replace(/\[\d+\]/, "[*]");
          if (!seenFields.has(category)) {
            seenFields.add(category);
            const fc = warningFieldCounts.get(category) || 0;
            warningFieldCounts.set(category, fc + 1);
          }
        }
      }

      if (report.metadataErrors && report.metadataErrors.length > 0) {
        reportsWithMetadataErrors++;
      }
    }

    return {
      totalCount, passCount, dkimPassCount, spfPassCount,
      rejectCount, quarantineCount, noneCount,
      dkimPassRate: totalCount > 0 ? (dkimPassCount / totalCount * 100) : 0,
      spfPassRate: totalCount > 0 ? (spfPassCount / totalCount * 100) : 0,
      fullPassRate: totalCount > 0 ? (passCount / totalCount * 100) : 0,
      reportCount: reports.length,
      uniqueSourceIps: sourceIps.size,
      uniqueIpRanges: new Set(ipRangeEntries.map(e => e.key)).size,
      dateRangeMin: dateRangeMin === Infinity ? 0 : dateRangeMin,
      dateRangeMax,
      topSourceIps: [...sourceIps.entries()]
        .sort((a, b) => b[1] - a[1]).slice(0, 20)
        .map(([ip, count]) => ({ ip, count })),
      // IP 範囲別の詳細統計
      topIpRanges: computeDetailedStats(ipRangeEntries),
      // レポーター別の詳細統計 (パス率・隔離・拒否を含む)
      topReporters: computeDetailedStats(reporterEntries),
      // レポーター別のレポート数 (従来互換)
      reporters: [...reporters.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([name, count]) => ({ name, count })),
      domains: [...domains.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([domain, count]) => ({ domain, count })),
      overrideReasons: [...overrideReasons.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([type, count]) => ({ type, count })),
      warningsSummary: {
        totalWarnings, reportsWithWarnings, reportsWithMetadataErrors,
        byField: [...warningFieldCounts.entries()]
          .sort((a, b) => b[1] - a[1])
          .map(([field, count]) => ({ field, count }))
      }
    };
  };

  return { parse, computeSummary, aggregateSummaries, toIpRange };
})();
