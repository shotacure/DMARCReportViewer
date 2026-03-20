// DMARCReportViewer - parser/fr_parser.js
// フォレンジックレポート (Forensic Report) パーサー
// AFRF (RFC 6591) 形式のフォレンジックレポートを正規化データに変換する。
// フォレンジックレポートは来る ISP が少なく形式もバラつくため、防御的にパースする。
// 全要素を網羅的に取得し、情報欠落を warnings として報告する。

const FrParser = (() => {
  "use strict";

  // =========================================================
  // メイン: メールヘッダ群 → 正規化済みフォレンジックレポート
  // =========================================================
  const parse = (messageId, messageDate, subject, headers) => {
    // フォレンジックメールのヘッダから情報を抽出
    // 多くの場合 AFRF (Authentication Failure Reporting Format) に準拠し、
    // Content-Type: multipart/report; report-type=feedback-report として届く

    const from = extractFirst(headers, "from");
    const to = extractFirst(headers, "to");
    const arrivalDate = extractFirst(headers, "arrival-date") ||
                        extractFirst(headers, "date") ||
                        messageDate;

    // Feedback-Type ヘッダ (AFRF 固有)
    const feedbackType = extractFirst(headers, "feedback-type") || "auth-failure";

    // 認証失敗の詳細
    const authFailure = extractFirst(headers, "auth-failure") || "";
    const authResults = extractFirst(headers, "authentication-results") || "";
    const reportedDomain = extractFirst(headers, "reported-domain") ||
                           extractDomainFromHeader(from);

    // 送信元 IP
    const sourceIp = extractFirst(headers, "source-ip") ||
                     extractFirst(headers, "source") || "";

    // オリジナルメールの情報
    const originalMailFrom = extractFirst(headers, "original-mail-from") || "";
    const originalRcptTo = extractFirst(headers, "original-rcpt-to") || "";
    const originalEnvelopeId = extractFirst(headers, "original-envelope-id") || "";

    // DKIM/SPF の個別結果
    const dkimDomain = extractFirst(headers, "dkim-domain") || "";
    const dkimIdentity = extractFirst(headers, "dkim-identity") || "";
    const dkimSelector = extractFirst(headers, "dkim-selector") || "";

    // 追加フィールド: 一部 ISP が付与する拡張情報
    const reportedUri = extractFirst(headers, "reported-uri") || "";
    const incidents = parseInt(extractFirst(headers, "incidents") || "1", 10) || 1;
    const deliveryResult = extractFirst(headers, "delivery-result") || "";
    const identityAlignment = extractFirst(headers, "identity-alignment") || "";
    const userAgent = extractFirst(headers, "user-agent") || "";
    const version = extractFirst(headers, "version") || "";

    // 認証結果のパース (Authentication-Results ヘッダ)
    const parsedAuth = parseAuthenticationResults(authResults);

    // 一意キー
    const reportKey = `fr!${messageId}!${sourceIp}!${reportedDomain}`;

    // 情報欠落チェック
    const warnings = validateFrReport({
      reportedDomain, sourceIp, authResults, authFailure,
      from, arrivalDate, originalMailFrom
    });

    return {
      reportKey,
      type: "forensic",
      messageId,
      messageDate,
      subject,
      feedbackType,
      authFailure,
      reportedDomain,
      sourceIp,
      from,
      to,
      arrivalDate,
      original: {
        mailFrom: originalMailFrom,
        rcptTo: originalRcptTo,
        envelopeId: originalEnvelopeId
      },
      dkim: {
        domain: dkimDomain,
        identity: dkimIdentity,
        selector: dkimSelector
      },
      // 追加の拡張フィールド
      reportedUri,
      incidents,
      deliveryResult,
      identityAlignment,
      userAgent,
      version,
      authResults: parsedAuth,
      // 情報欠落の警告
      warnings,
      // 通報用: 生ヘッダを保全
      rawHeaders: headers
    };
  };

  // =========================================================
  // 情報欠落チェック: フォレンジックレポートの完全性を検証
  // =========================================================
  const validateFrReport = (fields) => {
    const warnings = [];

    if (!fields.reportedDomain) {
      warnings.push({ field: "reported-domain", message: "Reported domain could not be determined" });
    }
    if (!fields.sourceIp) {
      warnings.push({ field: "source-ip", message: "Source IP is missing" });
    }
    if (!fields.authResults) {
      warnings.push({ field: "authentication-results", message: "Authentication-Results header is missing" });
    }
    if (!fields.authFailure) {
      warnings.push({ field: "auth-failure", message: "Auth-Failure type is missing" });
    }
    if (!fields.from) {
      warnings.push({ field: "from", message: "Report sender (From) is missing" });
    }
    if (!fields.arrivalDate) {
      warnings.push({ field: "arrival-date", message: "Arrival date could not be determined" });
    }
    if (!fields.originalMailFrom) {
      warnings.push({ field: "original-mail-from", message: "Original MAIL FROM is missing" });
    }

    return warnings;
  };

  // =========================================================
  // ヘルパー: ヘッダ配列から最初の値を取得
  // =========================================================
  const extractFirst = (headers, key) => {
    const values = headers[key] || headers[key.toLowerCase()];
    if (!values) return "";
    if (Array.isArray(values)) return values[0]?.trim() || "";
    return String(values).trim();
  };

  // =========================================================
  // ヘルパー: From ヘッダからドメインを抽出
  // =========================================================
  const extractDomainFromHeader = (fromHeader) => {
    if (!fromHeader) return "";
    const match = fromHeader.match(/@([^>]+)/);
    return match ? match[1].toLowerCase().trim() : "";
  };

  // =========================================================
  // Authentication-Results ヘッダの簡易パース
  // =========================================================
  const parseAuthenticationResults = (arHeader) => {
    if (!arHeader) return { spf: "unknown", dkim: "unknown", dmarc: "unknown" };

    const result = { spf: "unknown", dkim: "unknown", dmarc: "unknown" };

    // SPF
    const spfMatch = arHeader.match(/spf=(pass|fail|softfail|neutral|none|temperror|permerror)/i);
    if (spfMatch) result.spf = spfMatch[1].toLowerCase();

    // DKIM
    const dkimMatch = arHeader.match(/dkim=(pass|fail|none|temperror|permerror|neutral)/i);
    if (dkimMatch) result.dkim = dkimMatch[1].toLowerCase();

    // DMARC
    const dmarcMatch = arHeader.match(/dmarc=(pass|fail|none|temperror|permerror)/i);
    if (dmarcMatch) result.dmarc = dmarcMatch[1].toLowerCase();

    return result;
  };

  return { parse };
})();
