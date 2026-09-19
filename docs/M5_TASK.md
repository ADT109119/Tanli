# M5 任務：本地靶場 + web_config 確定性探測器 + self-test 實作

## 背景
本專案是自主紅隊測試 Agent（Python，src/redteam/ 下 12 個模組）。已完成：
- CLI（run / scan / gen-cred / self-test）、ScopeGuard（JWS 簽名憑證 + 機器驗證 scope）
- 三掃描器 bridge（nuclei/sqlmap/ZAP，Docker 沙箱）+ findings 正規化 + OWASP 2021 映射層
- LLM playbook 引擎（5 支 OWASP 2026 LLM 劇本）、LLM-as-a-Judge（OpenAI-compatible）
- 兩輪 dual-agent security review 的修正（CRL/revocation、fail-closed、timeout wiring）

**本環境沒有 Docker**（`docker` 不存在），所以 M5 的所有新東西必須**純 Python、無 Docker、無外部網路**（只許 127.0.0.1）。

## 你的任務（M5，一次做完）

### 1. `src/redteam/target_lab.py` — 純 stdlib 脆弱靶場
- 用 `http.server.ThreadingHTTPServer` + `BaseHTTPRequestHandler` 實作
- 綁 `127.0.0.1`、隨機 port（`bind(0)` 拿 port）
- 端點：
  - `/` — 回 200 HTML，**故意不帶**任何安全響應頭（CSP/HSTS/X-Frame-Options/X-Content-Type-Options/Referrer-Policy 全缺），`Set-Cookie: sid=abc; Path=/`（無 HttpOnly、無 Secure）
  - `/secure` — 回 200 HTML，**帶齊**上述安全頭 + `Set-Cookie: sid=abc; Path=/; HttpOnly; Secure`
  - `/sql` — 回 200，body 含 `id=1` 的簡單 echo（留給未來，本里程碑不探測）
- API：`TargetLab` class：`start() -> str`（回 base_url，如 `http://127.0.0.1:54321`）、`stop()`、context manager
- 註解用**繁體中文**

### 2. `src/redteam/web_config.py` — web_config 確定性探測器
- 輸入：base_url（+ 可選 paths 清單，預設 ["/", "/secure" 若存在] — 實際上預設只探 `/`）
- 用既有的 `RedTeamHTTP`（src/redteam/interactor.py，帶 ScopeGuard）發 GET — **不要**直接 new httpx
- 檢查項（每個 item 產生一個 probe 結果）：
  - 缺失安全頭：`Content-Security-Policy`、`Strict-Transport-Security`（僅 https 目標才檢查 HSTS，http 目標跳過並記 reason）、`X-Frame-Options`、`X-Content-Type-Options`、`Referrer-Policy`
  - Cookie 屬性：`Set-Cookie` 有值但缺 `HttpOnly` / 缺 `Secure`（http 目標時 Secure 只記 info 不記 medium）
- 結果結構與 LLM playbook 的 `ProbeResult` 概念對齊（可共用或仿照），每個結果帶：name、path、severity、evidence（實際 header dump 摘要）、owasp（缺 HSTS/CSP→A05，弱 cookie 屬性→A05，X-Frame-Options→A05；若你有更好對應可自行調整並在程式碼註解說明）
- 純確定性規則，**不需要** LLM judge

### 3. `src/redteam/findings.py` — 加 `from_web_config()` 正規化
- 把 web_config probe 結果轉成 `Finding`（attack_surface="web"、source="web_config"、confidence=1.0（確定性證據））
- 對齊既有 `from_nuclei/from_sqlmap/from_zap/from_llm_probes` 的寫法與 id 產生方式

### 4. `src/redteam/cli.py` — 接線
- `--scanners` 增加選項值 `web_config`
- `auto` 對 `web_service` target：先跑 `web_config`（純本地、不需 Docker）；Docker 掃描器在 **docker 不可用時跳過並印明確警告**（不要 crash）— 檢查現有 scanners.py 的 docker 偵測，若已 graceful skip 就不用動
- `web_config` 結果餵進現有 findings→judge→report 管道（deterministic 即可，web_config 的 finding 不需 LLM judge 二次確認）

### 5. `self-test` 實作（cli.py 第 532 行的 stub 換成真的）
- 流程：起 TargetLab → 對 `/` 跑 web_config 探測 → 斷言：
  1. 產生 ≥4 個 finding（CSP、XFO、XCTO、Referrer-Policy 缺失 + cookie 屬性）
  2. OWASP 欄位都有值（非空）
  3. 對 `/secure` 跑探測 → 斷言 0 個 medium/critical finding（secure 頁面不該被誤報）
  4. 渲染報告（report.py）→ 斷言報告文字含 OWASP 聚合段
- 輸出 `[PASS]` / `[FAIL]` + 失敗原因，FAIL 時 exit code 非 0
- **self-test 全程不可需要 Docker、不可需要網路（127.0.0.1 除外）、不可需要 LLM API key**（judge 走 deterministic-only 降級路徑）

### 6. 測試
- `tests/test_web_config.py`：起 lab、探 `/`、斷言各檢查項命中；探 `/secure`、斷言無誤報
- `tests/test_target_lab.py`：lab 起停、base_url 格式、stop 後 port 釋放
- 用 pytest，全部無外部依賴

## 鐵律（違反會被 review 打回）
1. **所有中文註解/UI 文字一律繁體中文**。唯一例外：功能性偵測 regex 若目標可能回簡體，要簡繁雙寫（如 `无法|無法`）— 本里程碑的檢查項大多是英文 header 名，基本不觸發此例外
2. **UI 不用 emoji**
3. **只 local commit，不 push**（最後 commit 由我來做，你只需把程式碼改好 + 測試跑綠）
4. 不要動 `.git`、不要改 git 設定
5. 不要新增 pyproject 依賴（只用既有：httpx、typer、rich、openai；stdlib 隨意）
6. ScopeGuard 不可被 bypass：web_config 探測必須走 RedTeamHTTP
7. 不要改動既有已驗證的偵測 regex（REFUSAL_PATTERNS 等）的行為

## 驗收（做完後必跑並把結果寫進你的最後回覆）
```bash
cd ~/projects/redteam-agent
.venv/bin/python -m pytest tests/ -q          # 全綠
.venv/bin/python -m redteam.cli self-test     # [PASS]，exit 0
```
並簡述：改了哪些檔案、各測試數字、self-test 輸出、任何偏離本任務文件的決定與理由。
