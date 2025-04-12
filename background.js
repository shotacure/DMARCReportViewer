// background.js

browser.messageDisplayScripts.register({
  js: [{ file: "messagedisplay.js" }],
  runAt: "document_end"
}).catch(console.error);

browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.command !== "analyzeDMARC") return;

  (async () => {
    try {
      const header = await browser.messageDisplay.getDisplayedMessage();
      if (!header?.id) throw new Error("表示中メッセージが取得できませんでした。");
      const messageId = header.id;

      const full = await browser.messages.getFull(messageId);
      const headers = full.headers || {};
      const subject = headers.subject?.[0] || "";
      const isDMARCSubject = /^\s*report\s+domain:/i.test(subject);
      const isDMARCRecipient = (headers.to || [])
        .some(addr => addr.toLowerCase().startsWith("dmarc-report@"));
      if (!isDMARCSubject || !isDMARCRecipient) {
        sendResponse({ result: null });
        return;
      }

      const atts = await browser.messages.listAttachments(messageId);
      const target = atts.find(att => {
        const fn = att.filename || att.name || "";
        return /\.(zip|gz)$/i.test(fn);
      });
      if (!target) throw new Error("DMARCレポートの添付ファイルが見つかりませんでした。");

      const file = await browser.messages.getAttachmentFile(messageId, target.partName);
      const buf = await file.arrayBuffer();
      const uint8 = new Uint8Array(buf);

      let xmlText;
      const fn = target.filename || target.name;
      if (/\.zip$/i.test(fn)) {
        const zip = await JSZip.loadAsync(uint8);
        const xmlName = Object.keys(zip.files).find(n => /\.xml$/i.test(n));
        if (!xmlName) throw new Error("ZIP内にXMLファイルがありません。");
        xmlText = await zip.files[xmlName].async("string");
      } else {
        xmlText = pako.ungzip(uint8, { to: "string" });
      }

      const rowsHtml = processDMARCReport(xmlText);
      sendResponse({ result: rowsHtml });

    } catch (e) {
      const msg = (e.message || e.toString()) + "\n" + (e.stack || "");
      sendResponse({ error: msg });
    }
  })();

  return true;
});

function formatDate(ts) {
  const d = new Date(ts * 1000);
  const pad = n => String(n).padStart(2, '0');
  const wk = ['日','月','火','水','木','金','土'][d.getDay()];
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}(${wk}) ` +
         `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function fmtStatus(status) {
  const s = status.toLowerCase();
  if (s === 'pass')      return `<span style="color:green;">✅ pass</span>`;
  if (s === 'fail')      return `<span style="color:red;">❌ fail</span>`;
  if (s === 'softfail' || s === 'none') return `<span style="color:orange;">⚠ ${s}</span>`;
  return status;
}

// ポリシー結果説明
function explainPolicy(val) {
  const s = val.toLowerCase();
  if (s === 'none')       return 'none (何もしない)';
  if (s === 'quarantine') return 'quarantine (隔離を推奨)';
  if (s === 'reject')     return 'reject (拒否)';
  return val;
}

// adkim/aspf 説明
function explainAlignment(tag, val) {
  const s = val.toLowerCase();
  if (s === 'r') {
    const eng = tag === 'adkim' ? 'relaxed' : 'relaxed';
    return `r (${eng}; 緩やかな一致を許可)`;
  }
  if (s === 's') {
    const eng = tag === 'adkim' ? 'strict' : 'strict';
    return `s (${eng}; 厳密な一致を要求)`;
  }
  return val;
}

function processDMARCReport(xmlText) {
  const parser = new DOMParser();
  const xml = parser.parseFromString(xmlText, "application/xml");
  if (xml.querySelector("parsererror")) {
    return `<tr><td colspan="2" style="color:red;">XML解析に失敗しました</td></tr>`;
  }

  let rows = "";

  // 報告メタデータ
  const md = xml.querySelector("report_metadata");
  if (md) {
    rows += `<tr class="section"><td colspan="2">報告メタデータ</td></tr>`;
    const begin = md.querySelector("date_range>begin")?.textContent;
    const end   = md.querySelector("date_range>end")?.textContent;
    rows += `<tr><th>報告期間</th><td>${formatDate(begin)} ～ ${formatDate(end)}</td></tr>`;
    [['org_name','発信元組織'],['email','問い合わせ先'],['report_id','レポートID']]
      .forEach(([tag,label]) => {
        const v = md.querySelector(tag)?.textContent;
        if (v) rows += `<tr><th>${label}</th><td>${v}</td></tr>`;
      });
  }

  // ポリシー設定
  const pp = xml.querySelector("policy_published");
  if (pp) {
    rows += `<tr class="section"><td colspan="2">ポリシー設定</td></tr>`;
    [['domain','ドメイン'],['adkim','adkim'],['aspf','aspf'],
     ['p','ポリシー(p)'],['sp','サブドメインポリシー(sp)'],['pct','適用率(pct)']]
      .forEach(([tag,label]) => {
        const v = pp.querySelector(tag)?.textContent;
        if (!v) return;
        let disp;
        if (tag === 'p' || tag === 'sp') {
          disp = explainPolicy(v);
        } else if (tag === 'adkim' || tag === 'aspf') {
          disp = explainAlignment(tag, v);
        } else {
          disp = v;
        }
        rows += `<tr><th>${label}</th><td>${disp}</td></tr>`;
      });
  }

  // レコード詳細
  const recs = xml.getElementsByTagName("record");
  Array.from(recs).forEach((r,i) => {
    rows += `<tr class="section"><td colspan="2">レコード #${i+1}</td></tr>`;
    const row = r.querySelector("row");
    const sip = row.querySelector("source_ip")?.textContent;
    const cnt = row.querySelector("count")?.textContent;
    const disp = row.querySelector("policy_evaluated>disposition")?.textContent;
    const dkim = row.querySelector("policy_evaluated>dkim")?.textContent;
    const spf  = row.querySelector("policy_evaluated>spf")?.textContent;
    if (sip) rows += `<tr><th>送信元 IP</th><td>${sip}</td></tr>`;
    if (cnt) rows += `<tr><th>カウント</th><td>${cnt}</td></tr>`;
    if (disp) rows += `<tr><th>処理結果</th><td>${explainPolicy(disp)}</td></tr>`;
    if (dkim) rows += `<tr><th>DKIM</th><td>${fmtStatus(dkim)}</td></tr>`;
    if (spf)  rows += `<tr><th>SPF</th><td>${fmtStatus(spf)}</td></tr>`;
  });

  return rows;
}
