// DMARCReportViewer - background.js
// バックグラウンドスクリプト: フォルダ内メッセージのスキャン、添付ファイル抽出、
// レポート解析パイプラインの管理を担当する。
// 外部通信は一切行わない。すべての処理はローカルで完結する。

// =========================================================
// 定数
// =========================================================
const STORAGE_KEY_SETTINGS = "dmarcrvSettings";
const DEFAULT_SETTINGS = {
  arFolderId: null,   // 集約レポートフォルダの accountId/path
  frFolderId: null,   // フォレンジックレポートフォルダの accountId/path
  lastScanTime: 0     // 最終スキャン日時 (Unix ms)
};

// =========================================================
// スキャン結果のメモリキャッシュ
// popup が閉じるとメモリが消えるため、background のグローバル変数に保持する。
// Thunderbird の background script は拡張が無効化されるまで永続する。
// =========================================================
let cachedResults = null;

// =========================================================
// 設定の読み書き
// =========================================================
const getSettings = async () => {
  const data = await browser.storage.local.get(STORAGE_KEY_SETTINGS);
  return { ...DEFAULT_SETTINGS, ...(data[STORAGE_KEY_SETTINGS] || {}) };
};

const saveSettings = async (settings) => {
  await browser.storage.local.set({ [STORAGE_KEY_SETTINGS]: settings });
};

// =========================================================
// フォルダ一覧の取得: パスに "dmarc" を含むフォルダのみ返す
// =========================================================
const getAllFolders = async () => {
  const accounts = await browser.accounts.list();
  const folders = [];

  const walk = (folderList, accountName) => {
    for (const folder of folderList) {
      // パスに "dmarc" を含むフォルダのみ候補に含める (大文字小文字不問)
      if (folder.path.toLowerCase().includes("dmarc")) {
        folders.push({
          accountId: folder.accountId,
          path: folder.path,
          name: folder.name,
          accountName,
          label: `${accountName} - ${folder.path}`
        });
      }
      if (folder.subFolders?.length) {
        walk(folder.subFolders, accountName);
      }
    }
  };

  for (const account of accounts) {
    walk(account.folders, account.name);
  }
  return folders;
};

// =========================================================
// フォルダ自動検出: "dmarc" を含む親フォルダの子からパターンマッチ
// 集約レポート: "aggregate" または "ar" を含む子フォルダ
// フォレンジック: "forensic" または "fr" を含む子フォルダ
// =========================================================
const autoDetectFolders = async () => {
  const accounts = await browser.accounts.list();
  let detectedAr = null;
  let detectedFr = null;

  const walk = (folderList, accountName, parentIsDmarc) => {
    for (const folder of folderList) {
      const lowerName = folder.name.toLowerCase();
      const lowerPath = folder.path.toLowerCase();
      const isDmarcFolder = lowerPath.includes("dmarc");

      // "dmarc" を含むフォルダの直下の子フォルダをチェック
      if (parentIsDmarc) {
        if (!detectedAr && (lowerName.includes("aggregate") || lowerName.includes("ar"))) {
          detectedAr = { accountId: folder.accountId, path: folder.path };
        }
        if (!detectedFr && (lowerName.includes("forensic") || lowerName.includes("fr"))) {
          detectedFr = { accountId: folder.accountId, path: folder.path };
        }
      }

      if (folder.subFolders?.length) {
        walk(folder.subFolders, accountName, isDmarcFolder);
      }
    }
  };

  for (const account of accounts) {
    walk(account.folders, account.name, false);
    if (detectedAr && detectedFr) break;
  }

  return { arFolderId: detectedAr, frFolderId: detectedFr };
};

// =========================================================
// フォルダ解決: 保存済み設定を検証し、見つからなければ自動検出にフォールバック
// IMAP サーバー上でフォルダ名が変更された場合にも対応する
// =========================================================
const resolveFolders = async (settings) => {
  let needsSave = false;
  const allFolders = await getAllFolders();

  const folderExists = (folderId) => {
    if (!folderId) return false;
    return allFolders.some(f =>
      f.accountId === folderId.accountId && f.path === folderId.path
    );
  };

  const arValid = folderExists(settings.arFolderId);
  const frValid = folderExists(settings.frFolderId);

  if (!arValid || !frValid) {
    const detected = await autoDetectFolders();

    if (!arValid && detected.arFolderId) {
      settings.arFolderId = detected.arFolderId;
      needsSave = true;
    }
    if (!frValid && detected.frFolderId) {
      settings.frFolderId = detected.frFolderId;
      needsSave = true;
    }

    if (needsSave) {
      await saveSettings(settings);
    }
  }

  return settings;
};

// =========================================================
// メッセージスキャン: 指定フォルダ内の全メッセージを取得
// =========================================================
const listMessagesInFolder = async (accountId, path) => {
  const accounts = await browser.accounts.list();
  const account = accounts.find(a => a.id === accountId);
  if (!account) return [];

  const findFolder = (folders, targetPath) => {
    for (const f of folders) {
      if (f.path === targetPath) return f;
      if (f.subFolders?.length) {
        const found = findFolder(f.subFolders, targetPath);
        if (found) return found;
      }
    }
    return null;
  };

  const folder = findFolder(account.folders, path);
  if (!folder) return [];

  const messages = [];
  let page = await browser.messages.list(folder);
  messages.push(...page.messages);
  while (page.id) {
    page = await browser.messages.continueList(page.id);
    messages.push(...page.messages);
  }
  return messages;
};

// =========================================================
// 添付ファイル抽出: メッセージから DMARC レポートの添付を取得
// =========================================================
const ATTACHMENT_MIME_TYPES = [
  "application/zip",
  "application/x-zip-compressed",
  "application/gzip",
  "application/x-gzip",
  "application/xml",
  "text/xml"
];

const extractReportAttachments = async (messageId) => {
  const attachments = await browser.messages.listAttachments(messageId);
  const reportFiles = [];

  for (const att of attachments) {
    const isReportType = ATTACHMENT_MIME_TYPES.includes(att.contentType?.toLowerCase());
    const name = (att.name || "").toLowerCase();
    const isReportExt = name.endsWith(".zip") || name.endsWith(".gz") ||
                        name.endsWith(".xml") || name.endsWith(".gzip");

    if (isReportType || isReportExt) {
      const file = await browser.messages.getAttachmentFile(messageId, att.partName);
      const arrayBuffer = await file.arrayBuffer();
      reportFiles.push({
        name: att.name,
        contentType: att.contentType,
        data: arrayBuffer
      });
    }
  }
  return reportFiles;
};

// =========================================================
// 解凍パイプライン: zip/gz → XML テキストに展開
// 重要: gzip チェックを zip チェックより先に行う。
// "application/gzip".includes("zip") が true になるため、
// 順序を誤ると gzip ファイルが ZIP ブランチに入り JSZip で失敗する。
// =========================================================
const decompressAttachment = async (attachment) => {
  const { name, data } = attachment;
  const lowerName = (name || "").toLowerCase();
  const contentType = (attachment.contentType || "").toLowerCase();
  const xmlTexts = [];

  if (lowerName.endsWith(".gz") || lowerName.endsWith(".gzip") ||
      contentType.includes("gzip")) {
    // GZIP 展開 — lib/pako.min.js に依存 (zip より先に判定する)
    const xml = decompressGzip(data);
    if (xml) xmlTexts.push(xml);
  } else if (lowerName.endsWith(".zip") || contentType === "application/zip" ||
             contentType === "application/x-zip-compressed") {
    // ZIP 展開 — lib/jszip.min.js に依存
    if (typeof JSZip === "undefined") {
      console.error("DMARCReportViewer: JSZip is not loaded.");
      return xmlTexts;
    }
    const zip = await JSZip.loadAsync(data);
    for (const [filename, zipEntry] of Object.entries(zip.files)) {
      if (zipEntry.dir) continue;
      const entryName = filename.toLowerCase();

      if (entryName.endsWith(".xml")) {
        xmlTexts.push(await zipEntry.async("string"));
      } else if (entryName.endsWith(".gz") || entryName.endsWith(".gzip")) {
        const gzData = await zipEntry.async("arraybuffer");
        const xml = decompressGzip(gzData);
        if (xml) xmlTexts.push(xml);
      }
    }
  } else if (lowerName.endsWith(".xml") || contentType.includes("xml")) {
    const decoder = new TextDecoder("utf-8");
    xmlTexts.push(decoder.decode(data));
  }

  return xmlTexts;
};

// Gzip 展開ヘルパー (pako 使用)
const decompressGzip = (arrayBuffer) => {
  if (typeof pako === "undefined") {
    console.error("DMARCReportViewer: pako is not loaded.");
    return null;
  }
  try {
    const decompressed = pako.inflate(new Uint8Array(arrayBuffer));
    return new TextDecoder("utf-8").decode(decompressed);
  } catch (e) {
    console.error("DMARCReportViewer: gzip decompression failed:", e);
    return null;
  }
};

// =========================================================
// メッセージハンドラ: ダッシュボード/オプション画面からのリクエスト処理
// =========================================================
browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const handle = async () => {
    switch (request.command) {
      // --- 設定関連 ---
      case "getSettings":
        return await getSettings();

      case "saveSettings":
        await saveSettings(request.settings);
        return { success: true };

      case "getFolders":
        return await getAllFolders();

      case "autoDetectFolders":
        return await autoDetectFolders();

      // --- 設定を検証・自動検出してから返す (popup 初期化時用) ---
      case "resolveSettings": {
        let settings = await getSettings();
        settings = await resolveFolders(settings);
        return settings;
      }

      // --- キャッシュされたスキャン結果を取得 (popup 再表示時) ---
      case "getLastResults":
        return cachedResults;

      // --- スキャン実行 ---
      // パース処理は background 側で行い、解析済みデータを返す。
      // popup は閉じるとメモリが消えるため、重い処理は background で完結させる。
      case "scanReports": {
        let settings = await getSettings();
        settings = await resolveFolders(settings);

        // スキャン期間フィルタ: since (Unix ms) が指定された場合、
        // それ以降の日付のメッセージのみ処理する
        const sinceMs = request.since || 0;

        const results = { ar: [], fr: [], errors: [] };
        const seenKeys = new Set();

        // スキャン期間(日数)を結果に含める (折れ線グラフの集計単位決定用)
        const sinceDay = request.sinceDay || 0;
        results.scanPeriodDays = sinceDay;

        results.issues = {
          noAttachment: [],
          decompressFailed: [],
          parseFailed: [],
          incompleteReport: [],
          unknownFormat: []
        };

        // 集約レポートフォルダのスキャン
        if (settings.arFolderId) {
          try {
            const { accountId, path } = settings.arFolderId;
            const messages = await listMessagesInFolder(accountId, path);
            for (const msg of messages) {
              // 期間フィルタ: 指定期間より古いメッセージをスキップ
              if (sinceMs > 0 && msg.date && msg.date.getTime() < sinceMs) {
                continue;
              }

              try {
                const attachments = await extractReportAttachments(msg.id);

                if (attachments.length === 0) {
                  results.issues.noAttachment.push({
                    messageId: msg.id,
                    date: msg.date?.toISOString(),
                    subject: msg.subject,
                    folder: "aggregate"
                  });
                  continue;
                }

                for (const att of attachments) {
                  let xmlTexts;
                  try {
                    xmlTexts = await decompressAttachment(att);
                  } catch (decompErr) {
                    results.issues.decompressFailed.push({
                      messageId: msg.id,
                      date: msg.date?.toISOString(),
                      subject: msg.subject,
                      attachment: att.name,
                      error: decompErr.message || decompErr.toString()
                    });
                    continue;
                  }

                  if (xmlTexts.length === 0) {
                    results.issues.unknownFormat.push({
                      messageId: msg.id,
                      date: msg.date?.toISOString(),
                      subject: msg.subject,
                      attachment: att.name,
                      contentType: att.contentType
                    });
                    continue;
                  }

                  for (const xml of xmlTexts) {
                    try {
                      const report = ArParser.parse(xml);
                      if (!seenKeys.has(report.reportKey)) {
                        seenKeys.add(report.reportKey);
                        results.ar.push(report);

                        if (report.warnings.length > 0) {
                          results.issues.incompleteReport.push({
                            messageId: msg.id,
                            date: msg.date?.toISOString(),
                            subject: msg.subject,
                            reportKey: report.reportKey,
                            reporter: report.reporter.orgName,
                            domain: report.policy.domain,
                            warningCount: report.warnings.length,
                            warnings: report.warnings
                          });
                        }
                      }
                    } catch (parseErr) {
                      results.issues.parseFailed.push({
                        messageId: msg.id,
                        date: msg.date?.toISOString(),
                        subject: msg.subject,
                        attachment: att.name,
                        error: parseErr.message
                      });
                    }
                  }
                }
              } catch (e) {
                results.errors.push({
                  messageId: msg.id,
                  subject: msg.subject,
                  error: e.toString()
                });
              }
            }
          } catch (e) {
            results.errors.push({ folder: "aggregate", error: e.toString() });
          }
        }

        // フォレンジックレポートフォルダのスキャン
        if (settings.frFolderId) {
          try {
            const { accountId, path } = settings.frFolderId;
            const messages = await listMessagesInFolder(accountId, path);
            for (const msg of messages) {
              // 期間フィルタ
              if (sinceMs > 0 && msg.date && msg.date.getTime() < sinceMs) {
                continue;
              }

              try {
                const full = await browser.messages.getFull(msg.id);
                const report = FrParser.parse(
                  msg.id,
                  msg.date?.toISOString(),
                  msg.subject,
                  full.headers || {}
                );
                if (!seenKeys.has(report.reportKey)) {
                  seenKeys.add(report.reportKey);
                  results.fr.push(report);

                  if (report.warnings.length > 0) {
                    results.issues.incompleteReport.push({
                      messageId: msg.id,
                      date: msg.date?.toISOString(),
                      subject: msg.subject,
                      reportKey: report.reportKey,
                      reporter: "(forensic)",
                      domain: report.reportedDomain,
                      warningCount: report.warnings.length,
                      warnings: report.warnings
                    });
                  }
                }
              } catch (e) {
                results.errors.push({
                  messageId: msg.id,
                  subject: msg.subject,
                  error: e.toString()
                });
              }
            }
          } catch (e) {
            results.errors.push({ folder: "forensic", error: e.toString() });
          }
        }

        // issues サマリーを事前計算
        results.issuesSummary = {
          noAttachment: results.issues.noAttachment.length,
          decompressFailed: results.issues.decompressFailed.length,
          parseFailed: results.issues.parseFailed.length,
          incompleteReport: results.issues.incompleteReport.length,
          unknownFormat: results.issues.unknownFormat.length,
          totalIssues: results.issues.noAttachment.length +
                       results.issues.decompressFailed.length +
                       results.issues.parseFailed.length +
                       results.issues.incompleteReport.length +
                       results.issues.unknownFormat.length,
          fatalErrors: results.errors.length
        };

        // 集約サマリーとドメイン別詳細を事前計算
        if (results.ar.length > 0) {
          results.aggregate = ArParser.aggregateSummaries(results.ar);

          // ドメイン別にレポートを分類し、各ドメインの完全な統計を計算
          const byDomain = new Map();
          for (const r of results.ar) {
            const d = r.policy.domain;
            if (!byDomain.has(d)) byDomain.set(d, []);
            byDomain.get(d).push(r);
          }
          results.domainDetails = [];
          for (const [domain, domainReports] of byDomain) {
            // 各ドメインの最新のポリシー情報を取得 (最新レポートのものを使用)
            const latestReport = domainReports.reduce((a, b) =>
              a.dateRange.end > b.dateRange.end ? a : b
            );
            results.domainDetails.push({
              domain,
              reportCount: domainReports.length,
              policy: latestReport.policy,
              // ドメインごとの完全な統計 (IP範囲集約含む)
              aggregate: ArParser.aggregateSummaries(domainReports),
              // 折れ線グラフ用: 各レポートの期間開始日と disposition 件数
              timeSeries: domainReports.map(r => ({
                begin: r.dateRange.begin,
                delivered: r.summary.noneCount,
                quarantine: r.summary.quarantineCount,
                reject: r.summary.rejectCount
              }))
            });
          }
          results.domainDetails.sort((a, b) =>
            b.aggregate.totalCount - a.aggregate.totalCount
          );
        }

        // 最終スキャン時刻を更新
        settings.lastScanTime = Date.now();
        await saveSettings(settings);

        // 結果をキャッシュに保存
        cachedResults = results;

        return results;
      }

      default:
        return { error: `Unknown command: ${request.command}` };
    }
  };

  handle().then(sendResponse).catch(e => sendResponse({ error: e.toString() }));
  return true;
});
