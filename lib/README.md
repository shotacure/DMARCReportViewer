## Required Libraries / 必要なライブラリ

This directory should contain the following third-party libraries:
このディレクトリには以下のサードパーティライブラリを配置してください:

### jszip.min.js
- **Source:** https://stuk.github.io/jszip/
- **License:** MIT (or GPLv3)
- **Purpose:** ZIP file decompression for rua report attachments

### pako.min.js
- **Source:** https://github.com/nicknisi/pako
- **License:** MIT
- **Purpose:** GZIP decompression for rua report attachments

### How to obtain / 入手方法

```bash
# npm 経由
npm install jszip pako
cp node_modules/jszip/dist/jszip.min.js lib/
cp node_modules/pako/dist/pako.min.js lib/

# または CDN から直接ダウンロード
curl -o lib/jszip.min.js https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js
curl -o lib/pako.min.js https://cdnjs.cloudflare.com/ajax/libs/pako/2.1.0/pako.min.js
```
