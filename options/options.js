// DMARCReportAnalyzer - options/options.js
// 設定画面のロジック: フォルダ一覧取得、選択保存、復元
// パスに "dmarc" を含むフォルダのみ選択肢に表示する

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

  const arSelect = document.getElementById("ar-folder");
  const frSelect = document.getElementById("fr-folder");
  const btnSave = document.getElementById("btn-save");
  const savedMsg = document.getElementById("saved-msg");

  // =========================================================
  // フォルダ一覧をドロップダウンに追加 (dmarc を含むフォルダのみ)
  // =========================================================
  const populateFolders = async () => {
    const folders = await browser.runtime.sendMessage({ command: "getFolders" });

    for (const folder of folders) {
      const value = JSON.stringify({ accountId: folder.accountId, path: folder.path });

      const optAr = document.createElement("option");
      optAr.value = value;
      optAr.textContent = folder.label;
      arSelect.appendChild(optAr);

      const optFr = document.createElement("option");
      optFr.value = value;
      optFr.textContent = folder.label;
      frSelect.appendChild(optFr);
    }
  };

  // =========================================================
  // 現在の設定を復元
  // =========================================================
  const restoreSettings = async () => {
    const settings = await browser.runtime.sendMessage({ command: "getSettings" });

    if (settings.arFolderId) {
      arSelect.value = JSON.stringify(settings.arFolderId);
    }
    if (settings.frFolderId) {
      frSelect.value = JSON.stringify(settings.frFolderId);
    }
  };

  // =========================================================
  // 保存
  // =========================================================
  btnSave.addEventListener("click", async () => {
    const settings = {
      arFolderId: arSelect.value ? JSON.parse(arSelect.value) : null,
      frFolderId: frSelect.value ? JSON.parse(frSelect.value) : null
    };

    await browser.runtime.sendMessage({ command: "saveSettings", settings });

    savedMsg.classList.add("show");
    setTimeout(() => savedMsg.classList.remove("show"), 2000);
  });

  // =========================================================
  // 初期化
  // =========================================================
  const init = async () => {
    applyI18n();
    await populateFolders();
    await restoreSettings();
  };

  init();
})();
