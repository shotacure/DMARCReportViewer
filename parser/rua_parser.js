// DMARCReportViewer - parser/rua_parser.js
// rua (集約レポート) XML パーサー
// RFC 7489 に準拠した DMARC 集約レポート XML を正規化データに変換する。
// DOMParser を使用し、外部ライブラリに依存しない。

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
  // メイン: XML テキスト → 正規化済みレポートオブジェクト
  // =========================================================
  const parse = (xmlText) => {
    const parser = new DOMParser();
    const doc = parser.parseFromString(xmlText, "text/xml");

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

    // --- policy_published ---
    const policy = feedback.querySelector("policy_published");
    const domain = getText(policy, "domain");
    const policyAdkim = getText(policy, "adkim") || "r";
    const policyAspf = getText(policy, "aspf") || "r";
    const policyP = getText(policy, "p");
    const policySp = getText(policy, "sp") || policyP;
    const policyPct = getInt(policy, "pct") || 100;
    const policyFo = getText(policy, "fo") || "0";

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
          result: getText(d, "result"),
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
          result: getText(s, "result")
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

    return {
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
      policy: {
        domain,
        adkim: policyAdkim,
        aspf: policyAspf,
        p: policyP,
        sp: policySp,
        pct: policyPct,
        fo: policyFo
      },
      records,
      // 集計用サマリー (パース時に事前計算)
      summary: computeSummary(records)
    };
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
        .map(([ip, count]) => ({ ip, count }))
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
    const reporters = new Map();   // orgName → レポート数
    const domains = new Map();     // domain → 合計カウント

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
        .map(([domain, count]) => ({ domain, count }))
    };
  };

  return { parse, computeSummary, aggregateSummaries };
})();
