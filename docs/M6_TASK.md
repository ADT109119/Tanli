# M6 任務：CVSS v3.1 評分層 + 報告完善 + nuclei 模板限縮(P3) + LLM 靶場端到端

## 背景

紅隊測試 Agent（Python，繁體中文註解/UI）：對 LLM 應用（OWASP LLM Top 10 2026）與傳統 Web 服務（OWASP 2021）做自動化紅隊測試。已完成：
- DAG planner + ReAct 節點、ScopeGuard、簽章憑證、hash-chain audit log
- Scanner bridge（nuclei/sqlmap/ZAP via Docker）→ findings → LLM judge → Markdown 報告管線
- OWASP 2021 類別映射層（P1）、ZAP full-scan 升級（P2）、LLM 攻擊 playbook 引擎（5 個 playbook）
- M5：本地 Web 靶場 TargetLab（`/`、`/secure`、`/sql`）+ web_config 確定性探測器 + `self-test` 命令（4 斷言）
- 目前 pytest 86 個全綠；`python -m redteam.cli self-test` 輸出 `[PASS]`

環境事實：本機 **有 Docker daemon**，但 **測試與 self-test 一律不得依賴 Docker、不得碰外部網路（只許 127.0.0.1）、不得需要 LLM API key**。nuclei/sqlmap/ZAP 鏡像可能被清掉，不要在測試裡真的跑容器。

## 你的任務（M6，一次做完）

### 1. `src/redteam/cvss.py` — CVSS v3.1 base score 確定性評分層（新檔）
- 純 stdlib，實作 **官方 CVSS v3.1 base score 公式**：
  - `ISS = 1 - [(1-C)(1-I)(1-A)]`；`Impact = ISS<=0 ? 0 : 6.42*ISS`
  - `Exploitability = 8.22 * AV * AC * PR * UI`
  - Scope Unchanged: `Roundup(min(Impact+Exploitability, 10))`；Scope Changed: `Roundup(min(1.25*Impact + Exploitability, 10))`
  - `Roundup` = **無條件進位到小數點第一位**（注意浮點誤差，用 epsilon 或整數技巧）
  - 官方指標權重：AV {N:0.85,A:0.62,L:0.55,P:0.2}；AC {L:0.77,H:0.44}；UI {N:0.85,R:0.62}；PR(Scope U) {N:0.85,L:0.62,H:0.27}；PR(Scope C) {N:0.85,L:0.68,H:0.5}；C/I/A {H:0.56,L:0.22,N:0}
- API：
  - `parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") -> dict`（校驗非法值 raise ValueError）
  - `score_from_vector(vector: str) -> float`
  - `severity_to_vector(severity: str, category: str, attack_surface: str) -> str`：查表產生預設向量。**設計要求**：
    - `critical` → 完整主機淪陷級（C:H/I:H/A:H）
    - `high` → 重大機密外洩或高影響（如 C:H/I:L/A:N）
    - `medium` → 有限度外洩（C:L 級別）
    - `low` → 低影響（AC:H 或 C:L 且難利用）
    - `info` → 回空字串（不評分）
    - 類別修正：`security_header`/弱 cookie 類（XSS 可利用鏈）→ 加 `UI:R`；`injection` 類 → 直接 critical 向量；`cache_policy`/`info_disclosure` → 低敏向量；LLM surface（attack_surface="llm"）→ 依 owasp LLMxx 用類似邏輯（注入類→C:H 級）
    - 你可以自行微調表格，但每個條目要寫繁體中文註解說明理由
  - `annotate_cvss(findings: list) -> None`：就地幫每個 Finding 填 `cvss_score` 與 `cvss_vector`（info 維持 0.0/空向量）。在 `findings.py` 的 `convert_all()` 內呼叫，讓 **所有來源**（nuclei/sqlmap/zap/web_config/llm_playbook）統一評分。
- `src/redteam/findings.py`：`Finding` dataclass 加欄位 `cvss_vector: str = ""`；`convert_all()` 最後呼叫 `annotate_cvss`。
- `src/redteam/report.py`：其內部 `Finding` dataclass 同步加 `cvss_vector: str = ""`；`src/redteam/cli.py` 的 `_judge_and_report()` bridging 時帶上 `cvss_vector=getattr(f, "cvss_vector", "")`。

### 2. `src/redteam/report.py` — Phase 3 報告完善
- §2 每個 finding 明細的 `CVSS:` 行改成同時顯示分數與向量，例如 `- 類別: x | 嚴重: high | CVSS: 8.1 (CVSS:3.1/AV:N/AC:L/...)`（無向量時只顯示分數）。
- **人工複核門禁**（規格書：High/Critical 的自動評分需人工確認）：render 時 severity 為 high/critical 的 finding 明細加一行 `- 人工複核: 待確認（自動評分，定稿前需人工確認）`；Low/Medium 加 `- 人工複核: auto-scored`。§1 執行摘要加一行統計：`- 高危待人工複核: N 項`。
- §6 修復建議（目前是佔位文字 `*(待每項 finding 補 remedation guidance)*`）換成真的：
  - 新增 `REMEDIATION_BY_OWASP`（A01–A10）與 `REMEDIATION_BY_CATEGORY`（security_header、cache_policy、info_disclosure、weak_cookie 等）與 LLM 面（LLM01/02/03/08/10）的**繁體中文**建議對照表（每條 1–2 句、可執行、不空泛）。
  - render 依本次 findings 實際出現的 OWASP 類別/類別關鍵字去重彙整，每條建議附受影響 finding id 清單；全表以既有 `_owasp_counts()` 類似的彙總方式呈現。找不到對應項目的 finding 歸入一條通用建議。
- 報告其他段落結構不動（self-test 有斷言 §5 OWASP 聚合存在）。

### 3. `src/redteam/scanners.py` — P3：nuclei 模板限縮（降誤報+提速）
- `nuclei_runner()` 增加 web 預設限縮（可被呼叫端覆寫）：
  - 預設加 `-severity low,medium,high,critical`（排除 info 噪音；ZAP/web_config 已覆蓋資訊類）
  - 預設加 `-exclude-protocols dns,code,file,websocket,whois`（排除不適用 web 的協議；保留 http/ssl）
  - 新參數：`severity: str | None`、`exclude_protocols: str | None`（傳 None 用預設字串，傳空字串代表不加上該參數）
- 模板目錄限縮：現有 `_exec` 掛載 `REDTEAM_NUCLEI_TEMPLATES` 的邏輯，改為若 `<templates>/http/` 子目錄存在且含 yaml/yml，則 `-t /workspace/templates/http`（掛載點仍為 templates 根目錄），否則維持現狀（含既有 empty-dir 警告邏輯）。
- `src/redteam/cli.py`：`scan` 子命令與 `run` 的 nuclei 路徑把新參數透傳（加 `--nuclei-severity`、`--nuclei-exclude-protocols` 兩個 Option，預設 None 即走 bridge 預設）。`run` 深層管線裡呼叫 `nuclei_runner` 處也接上。
- **不要**真的在測試裡跑 docker——測試只斷言 `job.args` 的內容。

### 4. `src/redteam/target_lab.py` — 加 OpenAI 相容 LLM 靶場（讓 playbook 對真實靶場跑通）
- 新增 `do_POST`，處理 `POST /v1/chat/completions`（OpenAI chat completions 協定）：
  - 請求：JSON `{model, messages:[{role,content}], ...}`；讀 body 要用 `Content-Length`；非法 JSON → 400。
  - 回應 200：`{"id":"chatcmpl-lab","object":"chat.completion","created":<int>,"model":"redteam-lab","choices":[{"index":0,"message":{"role":"assistant","content":...},"finish_reason":"stop"}],"usage":{"prompt_tokens":n,"completion_tokens":m,"total_tokens":n+m}}`（usage 要有值，playbook 的 token budget 熔斷要讀它）。
  - `TargetLab.__init__` 加 `behavior: str = "vulnerable"` 參數（不破壞既有測試的預設構造）。
- **確定性關鍵詞行為**（全部規則寫繁體中文註解）：
  - `behavior="vulnerable"`（有護欄但可繞過——模擬真實易感目標）：
    1. 最後一則 message 是 assistant（prefill 攻擊）→ content = 該 assistant 前綴 + 一段續寫文字（讓 `completion_prefix` + `marker_present` 能命中）
    2. 否則若 prompt（拼接所有 messages）命中越獄指針（不區分大小寫：`dan`、`ignore all previous instructions`、`忽略之前的所有指令`、`忽略所有之前的指令`、`新指令`——注意偵測字串若可能遇簡體目標要簡繁雙寫）→ 「服從」：內容含 prompt 中出現的 `REDTEAM_` 標記原樣回顯（若 prompt 含 `REDTEAM_` 前綴 token，把它原封不動放進回應），加上具體步驟文字（≥40 字元）
    3. 否則 → 「拒絕」：回 `我不能提供這個內容。` （要能被既有 refusal 偵測 regex 命中——先讀 `playbook.py` 的 REFUSAL_PATTERNS 確認你的拒絕語能命中，必要時在拒絕語裡同時含英文 "I can't"，這是功能性字串不適用繁體鐵律）
  - `behavior="hardened"`（典範目標）：含 `REDTEAM_` 標記或越獄指針的請求一律回拒絕語、**絕不回顯標記**；普通問題回正常短答。
  - 其他路徑的 POST → 404；既有 GET 端點行為完全不動。
  - 注意 `log_message` 靜音既有實作沿用，別把 pytest 輸出弄髒。

### 5. `src/redteam/cli.py` — self-test 擴充（既有 4 斷言語義不動，只新增）

> 註：本節新增斷言不得改動既有前 4 條斷言的判定邏輯。
在現有 web_config 斷言之後，新增（同一個 self-test 命令內）：
5. 起 `TargetLab(behavior="vulnerable")` → 用 `PlaybookEngine` + `LLMTarget`（base_url=lab、OpenAI chat 協定、無 API key 也要能跑）跑 `playbooks/llm/playbook_1.yaml` → 經 `from_llm_probes()` 得 findings → 斷言 ≥1 個 finding 且 owasp 以 `LLM` 開頭、attack_surface="llm"、cvss_score > 0（驗證 CVSS 層）。
6. 起 `TargetLab(behavior="hardened")` → 同一 playbook → 斷言 0 個 finding（典範目標不誤報）。
7. 渲染報告 → 斷言文字含 `CVSS:3.1/`（向量已落地）且 §6 修復建議段含至少一條實質建議（非佔位文字）。
- self-test 全程仍不可需要 Docker、外部網路、API key。全部輸出 `[PASS]`/`[FAIL]` 格式沿用現有寫法。

### 6. 測試（pytest，全部離線、無 Docker）
- `tests/test_cvss.py`：官方向量正確性（至少 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`→9.8、`.../S:C/C:H/I:H/A:H`→10.0、`.../C:N/I:N/A:H`→7.5、`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`→6.5）；非法向量 raise；`annotate_cvss` 後 info=0、其餘 >0 且 vector 前綴 `CVSS:3.1/`。
- `tests/test_llm_lab.py`：協定形狀（choices/usage 欄位齊全）；vulnerable 基準拒絕、越獄指針服從並回顯標記、prefill 命中；hardened 一律不回顯標記；非法 JSON 400。
- `tests/test_playbook_e2e.py`：`PlaybookEngine` 打 vulnerable lab → `from_llm_probes` 出 ≥1 finding（LLM01）；打 hardened lab → 0 finding。
- `tests/test_scanners.py`（擴充既有檔）：nuclei job args 含預設 `-severity`/`-exclude-protocols`；覆寫生效；模板目錄有 `http/` 子目錄時 `-t` 指向 `/workspace/templates/http`（用 monkeypatch + tmp_path，不跑 docker）。
- `tests/test_cli.py`（擴充）：self-test 經 CliRunner exit 0；tmp 報告檔含 `CVSS:3.1/` 與修復建議實質內容。

## 鐵律（違反會被 review 打回）
1. **所有中文註解/UI 文字一律繁體中文**。唯一例外：功能性偵測字串/regex 若目標可能回簡體，要簡繁雙寫（如 `无法|無法`）
2. **UI 不用 emoji**
3. **只 local commit，不 push**（最後 commit 由我來做，你只需把程式碼改好 + 測試跑綠）
4. 不要動 `.git`、不要改 git 設定
5. 不要新增 pyproject 依賴（只用既有：httpx、typer、rich、openai；stdlib 隨意）
6. ScopeGuard 不可被 bypass：既有探測路徑（RedTeamHTTP）不動；靶場只綁 127.0.0.1
7. **不要改動既有已驗證的偵測 regex（REFUSAL_PATTERNS、SYS_PROMPT_PATTERNS）與 Detector 行為**；靶場拒絕語必須適配既有 regex，不是改 regex 適配靶場
8. 既有 86 個測試不可變紅；既有 self-test 前 4 斷言、既有 web 靶場 GET 端點語義不可變
9. CVSS 公式必須對照官方 spec 例子驗證（測試裡要含官方向量），Roundup 是無條件進位不是四捨五入

## 驗收（做完後必跑並把結果寫進你的最後回覆）
```bash
cd ~/projects/redteam-agent
.venv/bin/python -m pytest tests/ -q        # 全綠（86 + 新增）
.venv/bin/python -m redteam.cli self-test   # [PASS]，exit 0
```
並簡述：改了哪些檔案、各測試數字、self-test 輸出、CVSS 官方向量驗證結果、任何偏離本任務文件的決定與理由。
