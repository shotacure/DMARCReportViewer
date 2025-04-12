// messagedisplay.js

(async () => {
  const resp = await browser.runtime.sendMessage({ command: "analyzeDMARC" });
  if (resp.error) {
    console.error("DMARC解析例外:\n", resp.error);
    return;
  }
  if (!resp.result) return;

  const wrapper = document.createElement("div");
  Object.assign(wrapper.style, {
    margin: "10px 0",
    fontSize: "small"
  });
  wrapper.innerHTML = `
    <h3 style="margin:0 0 8px;">DMARC レポート詳細</h3>
    <table class="dmarcTable" style="
      width:auto;
      border-collapse:collapse;
      text-align:left;
      margin-left:8px;
    ">
      <tbody>
        ${resp.result}
      </tbody>
    </table>
    <style>
      .dmarcTable th {
        min-width:140px;
        padding:8px 12px;
        background:#f9f9f9;
        white-space: nowrap;
      }
      .dmarcTable td {
        padding:8px 12px;
      }
      .dmarcTable tr:nth-child(odd) td {
        background:#fff;
      }
      .dmarcTable tr:nth-child(even) td {
        background:#f4f4f4;
      }
      .dmarcTable tr.section td {
        background:#ddd;
        font-weight:bold;
        text-align:center;
        padding:10px;
      }
    </style>
  `;

  const authBox = document.querySelector("div.authBox");
  if (authBox) {
    authBox.insertAdjacentElement("afterend", wrapper);
  } else {
    document.body.insertAdjacentElement("afterbegin", wrapper);
  }
})();
