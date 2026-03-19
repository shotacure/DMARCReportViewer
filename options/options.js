// DMARCReportViewer - options/options.js
// 設定画面のロジック: フォルダ一覧取得、選択保存、復元

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

  const ruaSelect = document.getElementById("rua-folder");
  const rufSelect = document.getElementById("ruf-folder");
  const btnSave = document.getElementById("btn-save");
  const savedMsg = document.getElementById("saved-msg");

  // =========================================================
  // フォルダ一覧をドロップダウンに追加
  // =========================================================
  const populateFolders = async () => {
    const folders = await browser.runtime.sendMessage({ command: "getFolders" });

    for (const folder of folders) {
      const value = JSON.stringify({ accountId: folder.accountId, path: folder.path });

      const optRua = document.createElement("option");
      optRua.value = value;
      optRua.textContent = folder.label;
      ruaSelect.appendChild(optRua);

      const optRuf = document.createElement("option");
      optRuf.value = value;
      optRuf.textContent = folder.label;
      rufSelect.appendChild(optRuf);
    }
  };

  // =========================================================
  // 現在の設定を復元
  // =========================================================
  const restoreSettings = async () => {
    const settings = await browser.runtime.sendMessage({ command: "getSettings" });

    if (settings.ruaFolderId) {
      ruaSelect.value = JSON.stringify(settings.ruaFolderId);
    }
    if (settings.rufFolderId) {
      rufSelect.value = JSON.stringify(settings.rufFolderId);
    }
  };

  // =========================================================
  // 保存
  // =========================================================
  btnSave.addEventListener("click", async () => {
    const settings = {
      ruaFolderId: ruaSelect.value ? JSON.parse(ruaSelect.value) : null,
      rufFolderId: rufSelect.value ? JSON.parse(rufSelect.value) : null
    };

    await browser.runtime.sendMessage({ command: "saveSettings", settings });

    // 保存完了のフィードバック
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
