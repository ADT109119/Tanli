# M6 Code Review 請求（第二意見）

你是資深資安工具程式設計師。請對本 repo **未 commit 的 working tree 變更**（`git diff` + 新增未追蹤檔）做嚴格 code review。

## 本次變更範圍（M6）
1. `src/redteam/cvss.py`（新）— CVSS v3.1 base score 確定性評分層：官方公式 + Roundup（無條件進位）+ `severity_to_vector()` 查表 + `annotate_cvss()`；由 `findings.convert_all()` 對所有來源統一評分。
2. `src/redteam/report.py` — 報告顯示 CVSS 向量、High/Critical 人工複核門禁標示、§6 修復建議對照表（OWASP A01-A10 / category / LLMxx）。
3. `src/redteam/scanners.py` + `cli.py` — nuclei 模板限縮（`-severity`、`-exclude-protocols`、優先掛 `templates/http/`）。
4. `src/redteam/target_lab.py` — 新增 OpenAI 相容 `POST /v1/chat/completions`，`behavior="vulnerable"|"hardened"` 關鍵詞行為。
5. `src/redteam/cli.py` — `self-test` 新增斷言 5-7（LLM playbook 打真實靶場 vulnerable/hardened + 報告含 CVSS 向量與實質修復建議）。

## 請特別審查（這些是我的已知風險點）
- **CVSS 實作正確性**：Roundup 是否為無條件進位（非四捨五入）？浮點誤差處理？Scope Changed 的 PR 權重是否用了不同表？Impact<=0 時是否為 0.0？請用官方例子心算驗證幾個向量。
- **自動評分的誠實性**：`severity_to_vector()` 查表把 severity 換成向量再算分，這本質是「以嚴重度推 CVSS」而非獨立評分。報告標示是否足夠誠實（不會讓讀者誤以為是人工逐項評分）？有沒有把 info 誤評分？
- **人工複核門禁是否只是裝飾**：規格書要求 High/Critical 需人工確認才可定稿。目前是 render 層標示。這個標示在自動化流程（CI/self-test）中是否可能被忽略而發出未審報告？是否需要 exit code / 額外開關？
- **靶場行為的確定性與安全**：
  - 是否可能因關鍵詞子字串誤命中（例如 `dan` 子串、`指令` 泛用）導致 vulnerable 模式對基準問題誤「服從」→ self-test 假陽性？
  - hardened 模式是否真的「絕不回顯 REDTEAM_ 標記」（有無路徑洩漏標記，例如 prefill 分支、echo 分支順序錯誤）？
  - `behavior` 參數是否可能被誤用成對外掃描目標？靶場是否嚴格只綁 127.0.0.1？
  - POST body 讀取是否有 Content-Length 缺失/超大會導致 hang 或 OOM？
- **既有不變式是否被破壞**：ScopeGuard/RedTeamHTTP 路徑、既有偵測 regex（REFUSAL_PATTERNS/SYS_PROMPT_PATTERNS）、既有 web GET 端點語義、既有 self-test 前 4 斷言。
- **nuclei 限縮**：`-exclude-protocols` 是否可能把 ssl/TLS 檢查一起排掉（A02 覆蓋倒退）？`-severity` 排除 info 是否會讓某些依賴 info 級模板的鏈失去？模板目錄 fallback（無 http/ 子目錄時）是否仍正確？掛載點與 `-t` 路徑是否一致（容器內路徑 vs host 路徑）？
- **測試品質**：是否有假陽性斷言（永遠恆綠）？是否真的覆蓋了 CVSS 官方例子？是否有測試依賴 docker 或外部網路？
- **繁體中文/術語**：註解與 UI 是否有簡體洩漏或大陸術語（應為「回應標頭」等非「響應頭」）。功能性偵測字串的簡繁雙寫例外是否被正確保留。

## 輸出格式
逐條 finding：`[嚴重度 Critical/High/Medium/Low/Info] 檔案:行 — 問題 — 具體修法`。
請實際跑 `.venv/bin/python -m pytest tests/ -q`、`.venv/bin/python -m redteam.cli self-test`、以及你自己的驗證指令（例如直接用 python 算 CVSS 對照官方值）來**確認**每個 finding，不要只靠讀碼推測。沒有問題的部分請明確說「未發現問題」。
