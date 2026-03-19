// DMARCReportViewer - background.js
// バックグラウンドスクリプト: フォルダ内メッセージのスキャン、添付ファイル抽出、
// レポート解析パイプラインの管理を担当する。
// 外部通信は一切行わない。すべての処理はローカルで完結する。

// =========================================================
// 定数
// =========================================================
const STORAGE_KEY_SETTINGS = "dmarcrvSettings";
const DEFAULT_SETTINGS = {
  ruaFolderId: null,   // rua フォルダの accountId/path
  rufFolderId: null,   // ruf フォルダの accountId/path
  lastScanTime: 0      // 最終スキャン日時 (Unix ms)
};

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
// フォルダ一覧の取得 (設定画面・ダッシュボード用)
// =========================================================
const getAllFolders = async () => {
  const accounts = await browser.accounts.list();
  const folders = [];

  const walk = (folderList, accountName) => {
    for (const folder of folderList) {
      folders.push({
        accountId: folder.accountId,
        path: folder.path,
        name: folder.name,
        accountName,
        label: `${accountName} - ${folder.path}`
      });
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
// メッセージスキャン: 指定フォルダ内の全メッセージを取得
// =========================================================
const listMessagesInFolder = async (accountId, path) => {
  const accounts = await browser.accounts.list();
  const account = accounts.find(a => a.id === accountId);
  if (!account) return [];

  // フォルダを再帰的に検索
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
    // MIME type または拡張子で判定
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
// =========================================================
const decompressAttachment = async (attachment) => {
  const { name, data } = attachment;
  const lowerName = (name || "").toLowerCase();
  const xmlTexts = [];

  if (lowerName.endsWith(".zip") || attachment.contentType?.includes("zip")) {
    // ZIP 展開 — lib/jszip.min.js に依存
    // JSZip は background.js より先に manifest で読み込むか、
    // importScripts() で動的に読み込む
    if (typeof JSZip === "undefined") {
      console.error("DMARCReportViewer: JSZip is not loaded.");
      return xmlTexts;
    }
    const zip = await JSZip.loadAsync(data);
    for (const [filename, zipEntry] of Object.entries(zip.files)) {
      if (zipEntry.dir) continue;
      const entryName = filename.toLowerCase();

      if (entryName.endsWith(".xml")) {
        // ZIP 内の XML をそのまま取得
        xmlTexts.push(await zipEntry.async("string"));
      } else if (entryName.endsWith(".gz") || entryName.endsWith(".gzip")) {
        // ZIP 内にさらに gz が入っている場合（入れ子対応）
        const gzData = await zipEntry.async("arraybuffer");
        const xml = decompressGzip(gzData);
        if (xml) xmlTexts.push(xml);
      }
    }
  } else if (lowerName.endsWith(".gz") || lowerName.endsWith(".gzip") ||
             attachment.contentType?.includes("gzip")) {
    // GZIP 展開 — lib/pako.min.js に依存
    const xml = decompressGzip(data);
    if (xml) xmlTexts.push(xml);
  } else if (lowerName.endsWith(".xml") || attachment.contentType?.includes("xml")) {
    // 非圧縮 XML
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

      // --- スキャン実行 ---
      // パース処理は background 側で行い、解析済みデータを返す。
      // popup は閉じるとメモリが消えるため、重い処理は background で完結させる。
      case "scanReports": {
        const settings = await getSettings();
        const results = { rua: [], ruf: [], errors: [] };
        const seenKeys = new Set(); // 重複排除用

        // rua フォルダのスキャン
        if (settings.ruaFolderId) {
          try {
            const { accountId, path } = settings.ruaFolderId;
            const messages = await listMessagesInFolder(accountId, path);
            for (const msg of messages) {
              try {
                const attachments = await extractReportAttachments(msg.id);
                for (const att of attachments) {
                  const xmlTexts = await decompressAttachment(att);
                  for (const xml of xmlTexts) {
                    try {
                      const report = RuaParser.parse(xml);
                      // 重複排除 (reportKey ベース)
                      if (!seenKeys.has(report.reportKey)) {
                        seenKeys.add(report.reportKey);
                        results.rua.push(report);
                      }
                    } catch (parseErr) {
                      results.errors.push({
                        messageId: msg.id,
                        subject: msg.subject,
                        error: `XML parse: ${parseErr.message}`
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
            results.errors.push({ folder: "rua", error: e.toString() });
          }
        }

        // ruf フォルダのスキャン
        if (settings.rufFolderId) {
          try {
            const { accountId, path } = settings.rufFolderId;
            const messages = await listMessagesInFolder(accountId, path);
            for (const msg of messages) {
              try {
                const full = await browser.messages.getFull(msg.id);
                const report = RufParser.parse(
                  msg.id,
                  msg.date?.toISOString(),
                  msg.subject,
                  full.headers || {}
                );
                if (!seenKeys.has(report.reportKey)) {
                  seenKeys.add(report.reportKey);
                  results.ruf.push(report);
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
            results.errors.push({ folder: "ruf", error: e.toString() });
          }
        }

        // 集約サマリーを事前計算して含める
        if (results.rua.length > 0) {
          results.aggregate = RuaParser.aggregateSummaries(results.rua);

          // ドメイン別集計も事前計算
          const byDomain = new Map();
          for (const r of results.rua) {
            const d = r.policy.domain;
            if (!byDomain.has(d)) byDomain.set(d, []);
            byDomain.get(d).push(r);
          }
          results.domainDetails = [];
          for (const [domain, domainReports] of byDomain) {
            results.domainDetails.push({
              domain,
              reportCount: domainReports.length,
              aggregate: RuaParser.aggregateSummaries(domainReports)
            });
          }
          // メール数降順でソート
          results.domainDetails.sort((a, b) =>
            b.aggregate.totalCount - a.aggregate.totalCount
          );
        }

        // 最終スキャン時刻を更新
        settings.lastScanTime = Date.now();
        await saveSettings(settings);

        return results;
      }

      default:
        return { error: `Unknown command: ${request.command}` };
    }
  };

  // 非同期処理のため Promise を返す
  handle().then(sendResponse).catch(e => sendResponse({ error: e.toString() }));
  return true;
});
