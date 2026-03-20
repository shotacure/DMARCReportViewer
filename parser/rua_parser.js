// DMARCReportViewer - parser/rua_parser.js
// rua (集約レポート) XML パーサー
// RFC 7489 に準拠した DMARC 集約レポート XML を正規化データに変換する。
// DOMParser を使用し、外部ライブラリに依存しない。
// 全要素を網羅的に取得し、情報欠落を warnings として報告する。

const RuaParser = (() => {
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
  // XML サニタイズ: ISP 固有の XML 不整合を DOMParser に渡す前に修正
  // =========================================================
  const sanitizeXml = (xmlText) => {
    let sanitized = xmlText;

    // Microsoft の既知の typo: <diskim> → <dkim> (開始タグの誤記)
    // 例: <diskim>fail</dkim> → <dkim>fail</dkim>
    sanitized = sanitized.replace(/<diskim>/g, "<dkim>");

    // 開始・終了タグの不一致を汎用的に検出・修正するのは危険なため、
    // 個別の既知パターンのみ対応する。新たな不整合が見つかり次第追加する。

    return sanitized;
  };

  // =========================================================
  // 情報欠落チェック: レポート全体の完全性を検証
  // =========================================================
  const validateReport = (report) => {
    const warnings = [];

    // --- レポートメタデータの検証 ---
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

    // --- ポリシー公開情報の検証 ---
    if (!report.policy.domain) {
      warnings.push({ field: "policy.domain", message: "Published policy domain is missing" });
    }
    if (!report.policy.p) {
      warnings.push({ field: "policy.p", message: "Published policy disposition (p=) is missing" });
    }

    // --- レコードの検証 ---
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
    // ISP 固有の XML 不整合を修正してからパースする
    const sanitizedXml = sanitizeXml(xmlText);
    const parser = new DOMParser();
    const doc = parser.parseFromString(sanitizedXml, "text/xml");

    // パースエラーチェック
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

    // report_metadata > error: ISP がレポート生成時のエラーを記載する場合がある
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
    // np: サブドメインが存在しない場合のポリシー (一部 ISP が実装)
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

      // policy_evaluated
      const pe = row?.querySelector("policy_evaluated");
      const disposition = getText(pe, "disposition");
      const dkimPolicyResult = getText(pe, "dkim");
      const spfPolicyResult = getText(pe, "spf");

      // policy_evaluated > reason (複数ある場合がある)
      // ポリシーオーバーライドの理由: forwarded, sampled_out, mailing_list,
      // trusted_forwarder, local_policy, other 等
      const reasons = [];
      const reasonElements = pe?.querySelectorAll("reason") || [];
      for (const r of reasonElements) {
        reasons.push({
          type: getText(r, "type"),
          comment: getText(r, "comment")
        });
      }

      // auth_results
      const authResults = rec.querySelector("auth_results");

      // auth_results > dkim (複数署名に対応)
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

      // auth_results > spf (複数ある場合がある)
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
        sourceIp,
        count,
        headerFrom,
        envelopeFrom,
        envelopeTo,
        disposition,
        dkimPolicyResult,
        spfPolicyResult,
        reasons,
        dkimResults,
        spfResults
      });
    }

    // --- 一意な reportKey (重複排除用) ---
    // 多くの ISP は org_name!domain!begin!end 形式で reportId を生成するが、
    // reportId が重複する可能性もあるため orgName も含める
    const reportKey = `${orgName}!${domain}!${dateBegin}!${dateEnd}!${reportId}`;

    const report = {
      reportKey,
      reportId,
      reporter: {
        orgName,
        email,
        extraContactInfo
      },
      dateRange: {
        begin: dateBegin,
        end: dateEnd
      },
      // ISP がレポート生成時に記録したエラー情報
      metadataErrors,
      policy: {
        domain,
        adkim: policyAdkim,
        aspf: policyAspf,
        p: policyP,
        sp: policySp,
        pct: policyPct,
        fo: policyFo,
        np: policyNp
      },
      records,
      // 集計用サマリー (パース時に事前計算)
      summary: computeSummary(records),
      // 情報欠落の警告 (validateReport で後付け)
      warnings: []
    };

    // 情報欠落チェックを実行
    report.warnings = validateReport(report);

    return report;
  };

  // =========================================================
  // サマリー計算: レコード群から統計値を算出
  // =========================================================
  const computeSummary = (records) => {
    let totalCount = 0;
    let passCount = 0;      // DKIM pass かつ SPF pass (policy_evaluated)
    let dkimPassCount = 0;
    let spfPassCount = 0;
    let rejectCount = 0;
    let quarantineCount = 0;
    let noneCount = 0;
    const sourceIps = new Map(); // IP → 合計カウント

    // ポリシーオーバーライド理由の集計
    const overrideReasons = new Map(); // reason type → 合計カウント

    for (const rec of records) {
      totalCount += rec.count;

      if (rec.dkimPolicyResult === "pass") dkimPassCount += rec.count;
      if (rec.spfPolicyResult === "pass") spfPassCount += rec.count;
      if (rec.dkimPolicyResult === "pass" && rec.spfPolicyResult === "pass") {
        passCount += rec.count;
      }

      switch (rec.disposition) {
        case "reject":     rejectCount += rec.count;     break;
        case "quarantine": quarantineCount += rec.count;  break;
        default:           noneCount += rec.count;        break;
      }

      const ipTotal = sourceIps.get(rec.sourceIp) || 0;
      sourceIps.set(rec.sourceIp, ipTotal + rec.count);

      // ポリシーオーバーライド理由を集計
      for (const reason of rec.reasons) {
        if (reason.type) {
          const existing = overrideReasons.get(reason.type) || 0;
          overrideReasons.set(reason.type, existing + rec.count);
        }
      }
    }

    return {
      totalCount,
      passCount,
      dkimPassCount,
      spfPassCount,
      rejectCount,
      quarantineCount,
      noneCount,
      dkimPassRate: totalCount > 0 ? (dkimPassCount / totalCount * 100) : 0,
      spfPassRate: totalCount > 0 ? (spfPassCount / totalCount * 100) : 0,
      fullPassRate: totalCount > 0 ? (passCount / totalCount * 100) : 0,
      uniqueSourceIps: sourceIps.size,
      topSourceIps: [...sourceIps.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 20)
        .map(([ip, count]) => ({ ip, count })),
      // ポリシーオーバーライド理由のサマリー
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
    const reporters = new Map();       // orgName → レポート数
    const domains = new Map();         // domain → 合計カウント
    const overrideReasons = new Map(); // reason type → 合計カウント

    // 警告の集計カウンタ
    let totalWarnings = 0;
    let reportsWithWarnings = 0;
    let reportsWithMetadataErrors = 0;
    const warningFieldCounts = new Map(); // field → 出現レポート数

    for (const report of reports) {
      const s = report.summary;
      totalCount += s.totalCount;
      passCount += s.passCount;
      dkimPassCount += s.dkimPassCount;
      spfPassCount += s.spfPassCount;
      rejectCount += s.rejectCount;
      quarantineCount += s.quarantineCount;
      noneCount += s.noneCount;

      // レポーター別集計
      const rCount = reporters.get(report.reporter.orgName) || 0;
      reporters.set(report.reporter.orgName, rCount + 1);

      // ドメイン別集計
      const dCount = domains.get(report.policy.domain) || 0;
      domains.set(report.policy.domain, dCount + s.totalCount);

      // IP 集計
      for (const ipEntry of s.topSourceIps) {
        const existing = sourceIps.get(ipEntry.ip) || 0;
        sourceIps.set(ipEntry.ip, existing + ipEntry.count);
      }

      // ポリシーオーバーライド理由を統合
      for (const reason of s.overrideReasons) {
        const existing = overrideReasons.get(reason.type) || 0;
        overrideReasons.set(reason.type, existing + reason.count);
      }

      // 警告情報の集計
      if (report.warnings && report.warnings.length > 0) {
        reportsWithWarnings++;
        totalWarnings += report.warnings.length;
        // フィールド別の出現数を集計 (record[N] プレフィックスはカテゴリに正規化)
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

      // ISP 側のメタデータエラーを集計
      if (report.metadataErrors && report.metadataErrors.length > 0) {
        reportsWithMetadataErrors++;
      }
    }

    return {
      totalCount,
      passCount,
      dkimPassCount,
      spfPassCount,
      rejectCount,
      quarantineCount,
      noneCount,
      dkimPassRate: totalCount > 0 ? (dkimPassCount / totalCount * 100) : 0,
      spfPassRate: totalCount > 0 ? (spfPassCount / totalCount * 100) : 0,
      fullPassRate: totalCount > 0 ? (passCount / totalCount * 100) : 0,
      reportCount: reports.length,
      uniqueSourceIps: sourceIps.size,
      topSourceIps: [...sourceIps.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 20)
        .map(([ip, count]) => ({ ip, count })),
      reporters: [...reporters.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([name, count]) => ({ name, count })),
      domains: [...domains.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([domain, count]) => ({ domain, count })),
      // ポリシーオーバーライド理由のサマリー
      overrideReasons: [...overrideReasons.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([type, count]) => ({ type, count })),
      // 警告サマリー
      warningsSummary: {
        totalWarnings,
        reportsWithWarnings,
        reportsWithMetadataErrors,
        byField: [...warningFieldCounts.entries()]
          .sort((a, b) => b[1] - a[1])
          .map(([field, count]) => ({ field, count }))
      }
    };
  };

  return { parse, computeSummary, aggregateSummaries };
})();
