# 自主紅隊測試 Agent (Red Team Agent) — 最終綜合規格書 v3.4

> **來源**: agy + opencode 雙 agent 協同規劃 + 雙評審 + 二輪外部審閱整合
> **範圍**: LLM 紅隊測試 + 傳統網頁服務系統安全評估（雙軌）
> **日期**: 2026-08-13
> **狀態**: 規格 v3.4 — 整合二輪審閱，狀態一致性邊界已釐清

### 0.1 已決策設計選擇 (Decided)
| 項目 | 決策 |
|:--|:--|
| 優先目標 | **Web 優先** — agent 依使用者指定目標自行判斷 (`target_type`)，一般網頁服務默認 `web_service` |
| 核心 LLM | **使用者自訂** — configurable，支持 LiteLLM 多 provider 切換 |
| 沙箱層級 | **Docker 為主** (標準容器) — Hermes 決定；必要時可升 gVisor |
| 交付形式 | **Markdown 報告** — 含複現方式 (step-by-step PoC) + 偷到的資料/成功達達成的結果 |
| License | **Apache 2.0** — 開源 repo |
| 主動掃描 | **全自動** — nuclei/sqlmap/ZAP 自動化整合 |

---

## 1. 專案概述與範圍 (Overview & Scope)

### 1.1 專案目標
構建一個**自主紅隊測試 Agent (Autonomous Red Team Agent)**，同時評估兩類目標安全：
1. **LLM 應用**：LLM 應用、RAG 系統、AI Agent、LLM API
2. **傳統網頁服務**：Web 應用、REST/GraphQL API、CLI 後端

該 Agent 自動化執行：指令執行、工具調用、多步驟規劃、自動化結構化報告。

### 1.2 適用範疇 (In Scope)

**A. LLM 專屬風險** (OWASP Top 10 for LLM Applications v1.1)：
- Direct & Indirect Prompt Injection
- Sensitive Info Disclosure / System Prompt Leaking
- Jailbreak & Safety Guardrail Bypass
- Insecure Output Handling（衍生 SQLi、XSS、命令注入）
- Excessive Agency / Privilege Escalation
- Data Exfiltration via SSRF / Markdown / Tool Abuse

**B. 傳統 Web 服務** (OWASP Top 10 2021 for Web)：

| # | 類別 | OWASP | 覆蓋內容 |
|:--|:--|:--|:--|
| W-01 | 注入 | A03 | SQLi (boolean/time/union/error)、NoSQLi、XSS (Reflected/Stored/DOM)、Cmd Injection、LDAP、SSTI、Path Traversal |
| W-02 | 認證/會話 | A07 | Broken Auth、Session Fixation、Cookie Flags、JWT 誤用 (alg none/HS256弱鍵) |
| W-03 | 訪問控制 | A01 | IDOR、Horizontal/Vertical PrivEsc、Method 繞過、強行瀏覽 |
| W-04 | 資料暴露/配置 | A02/A05 | Sensitive Data、Misconfiguration (CORS/Header/Debug) |
| W-05 | 解析/服務端 | A05/A10/A06/A09 | XXE (OOB)、SSRF、過時組件、Logging 缺失 |
| W-06 | API 專屬 | A01/A03 | Mass Assignment、GraphQL Introspection/DoS、Rate Limit Bypass |

### 1.3 非適用範疇 (Out of Scope)
- 傳統 OS/網絡層 DDoS、二進位 Zero-Day
- 無授權目標、未授權社會工程、serverless 帳戶攻防以外的領域
- 破壞性數據抹除 / 不可逆硬體損毀

---

## 2. 系統架構 (System Architecture)

### 2.1 組件圖
```mermaid
flowchart TB
    subgraph UI_CLI [使用者介面 / 控制檯]
        CLI[CLI / REST API]
        Config[組態 (Target, Scope, Rate, Auth Token, ROE)]
    end

    subgraph Agent_Core [Agent 核心 (LangGraph StateGraph)]
        Perceive[1. Perceive]
        Plan[2. Plan (DAG 任務樹)]
        Act[3. Act]
        Observe[4. Observe]
        Knowledge[(Attack Context & State)]
    end

    subgraph Capability [能力與工具層]
        Sandbox[沙箱引擎 (Docker/gVisor)]
        ToolRegistry[工具註冊表]
        Interactor[Unified HTTP/CLI Interactor]
        Mutator[Payload 變異器]
        Judge[Judge (Regex + LLM-as-a-Judge)]
        ScopeGuard[Scope / Allow-Deny / ROE Enforcer]
        Scanner[掃描器橋 (nuclei/sqlmap/ZAP)]
        OOB[OOB Listener]
    end

    subgraph Target [目標系統]
        LLM_App[LLM App / Agent / RAG]
        Web_App[傳統 Web 服務 / API]
    end

    subgraph Report [報告引擎]
        ReportGen[JSON/Markdown/HTML 報告]
    end

    CLI --> Agent_Core
    Config --> Agent_Core
    Agent_Core <--> Knowledge
    Act --> Sandbox
    Act --> ScopeGuard
    Sandbox --> ToolRegistry
    ToolRegistry --> Interactor
    ToolRegistry --> Mutator
    ToolRegistry --> Scanner
    ToolRegistry --> OOB
    Interactor --> LLM_App
    Interactor --> Web_App
    OOB --> Web_App
    Observe --> Judge
    Observe --> ReportGen
```

### 2.2 Agent 核心循環 (ReAct + DAG 雙層)
**架構模型：DAG 定義高層階段，每個節點內部跑 ReAct 循環**
1. **Planner 產 DAG 任務樹**（§3.3）：`Recon → Fingerprint → Inject/Probe → Verify → PoC → Report` 爲高層階段順序。
2. **每個 DAG 節點內部跑一次 ReAct 迴圈**（Perceive→Plan→Act→Observe），節點間通過 Knowledge State 傳遞上下文。
3. 決策流：Planner（LLM）生成 DAG 圖 → LangGraph StateGraph 按依賴執行節點 → 節點內 ReAct 循環調度工具調用 → Observe 回寫 State。
> ⚠️ 明確邊界：**只有 Planner 生成/修改 DAG 結構；節點內 ReAct 只決定工具調用順序**，避免兩套狀態機打架。

### 2.3 計畫 vs 執行 狀態機關係
- **Planner StateGraph**：管理 DAG 圖、節點依賴、branch/retry/fallback（§3.3 容錯）。
- **執行器 (Node executor)**：跑節點內 ReAct 循環，管理工具調用與沙箱執行。
- 兩層共享 **Knowledge State Store**（§3.4 Checkpoint），但職責分離。

---

## 2.4 Agent 自身安全 (Self-Defense / Anti-confused-deputy)
> 審查發現：Agent 在測試 LLM 目標時，Planner/Judge LLM 會直接讀取目標響應內容。惡意/被攻陷目標可在響應中注入 prompt injection 反向操控 Red Team Agent 自身（confused deputy 問題）。

**防護規則：**
1. **目標響應僅作「資料」不作「指令」**：Observe 階段讀取的目標響應，只能被 Judge 當作被分析的數據；**不具備直接觸發 Act 階段工具調用的權限**。
2. **工具調用權限分級**：所有工具調用必須經 Agent 內部（Planner）顯式生成爲 Plan 節點，目標響應內容不能注入工具調用路徑。
3. **Respond 隔離**：Judge/Planner 處理目標響應時，用防注入處理（剝離控制指令模式、內容當純文本字符串）。
4. **Scope 雙保險**：即使目標響應誘導超 scope 操作，ScopeGuard 仍在網絡/命令層強制執行（Allow/Deny）。
5. **審計**：記錄任何「目標響應疑似注入 Agent」事件供追溯。

---

## 3. 核心能力規格 (Core Capabilities)

### 3.1 指令執行引擎 (Per-Profile)
- **隔離沙箱**：Docker/gVisor（network namespace + seccomp + 無 root + read-only FS）
- **資源限制（Per-Profile）**：
  | Profile | 命令超時 | 內存 | CPU |
  |:--|:--|:--|:--|
  | LLM 測試 | 30s | 512MB | 1.0 vCPU |
  | Web 掃描 | 600s | 1GB | 2.0 vCPU |
- **掃描 job 超時 vs 命令超時**：
  - `30s/600s` 是**單條命令/單次請求**的超時。
  - **掃描 job（nuclei/ZAP/sqlmap 長任務）**：採用 **job queue + 非同步輪詢** 機制，不阻塞 Agent 核心循環：
    - 提交 job → 返回 job_id → Agent 繼續其他節點 → 輪詢 job 狀態/定時收結果。
    - job 級超時可配（默認 30min），**超時後 kill + 標記 partial，不判直接失敗**，保留已掃結果。
- **網絡出口**：僅 Target CIDR；掃描器統一出站於沙箱，禁宿主機直連。
- **非交互執行**：`subprocess` 封裝，關閉 stdin，捕獲 stdout/stderr/exit code。

### 3.2 工具層 (Tool Registry)
外掛式架構（聲明式 Protocol / `BaseTool` 繼承）：

| 工具 | 分類 | 功能 |
|:--|:--|:--|
| `target_http_interactor` (統一) | 傳輸 | REST/GraphQL/WebSocket/表單，Cookie Jar、Session 持久化、重導向控制、代理/Burp-ZAP 橋接、全量 IO 紀錄 |
| `prompt_mutator` | LLM 攻擊 | Roleplay/Base64/ROT13/Unicode/Leetspeak/多語言 |
| `system_prompt_extractor` | LLM 劇本 | Repeat/Translation/Completion 泄漏模式 |
| `vulnerability_judge` | 檢測 | Regex 規則庫 + LLM-as-a-Judge 二次判定 |
| `sandbox_shell` | 執行 | curl/python3 白名單 |
| `web_request_lib` | Web 傳輸 | 手工/腳本 HTTP、Params fuzz、響應萃取 |
| `sqlmap_runner` | 注入 | 匯入捕獲請求，`--batch --level=1`，需顯式 flag |
| `nuclei_runner` | 掃描 | hash 校驗 template，JSON 輸出→Judge |
| `zap_api_scan` | DAST | ZAP API headless 掃描 |
| `oob_listener` | 驗證 | 自建 HTTP/DNS 監聽點 (OOB-XXE/SSRF/Exfil) |
| `jwt_cracker` / `session_analyzer` | 認證 | JWT alg/弱鍵、Session fixed、Cookie Flags |
| `web_tool` / `file_tool` | 通用 | 網頁抓取、文件讀寫（符合 Allow/Deny） |

### 3.3 多步驟規劃器
- **DAG 任務樹**：`Recon → Fingerprint → Inject/Probe → Verify → PoC → Report`
- **劇本 typed**：`target_type: llm_app | web_service | hybrid`
  - LLM-only 節點：prompt 變異、系統提示詞提取
  - Web-only 節點：掃描器、手工注入、OOB 監聽
  - **hybrid**：LLM Insecure Output Handling → 下游 SQLi/XSS/SSRF（一劇本 cover 兩目標）
- **`target_type` 自動判斷 (Profiling)**：Recon/Fingerprint 階段依規格化規則表判定目標類型：
  | 訊號 | → 判定 |
  |:--|:--|
  | 存在 `/v1/chat/completions`、`/api/generate`、SSE streaming 端點 | `llm_app` |
  | HTML 含 chat 輸入框 + 流式渲染、LLM 風格回應 | `llm_app` (前端) |
  | 登錄表單、CRUD 端點、SQL/文件上傳特徵 | `web_service` |
  | 不確定/歧義 (如 LLM 的 Web 前端) | 默認 `web_service`，並提示用戶 |
  - 用戶可 **CLI 覆寫**：`--target-type llm_app|web_service|hybrid` 手動指定，越過自動判斷。
- **狀態持續性**：Cookie、Context、Scope List、獲取 Key
- **容錯**：`429` 指數退避；防護欄阻擋 → 3 次變異；判定分歧 → LLM-as-a-Judge

### 3.4 Checkpoint / 斷點續跑 (State Persistence)
> 審查注意：長時間多劇Ｐ測試（尤其 hybrid）中途 crash / SIGSTOP 後需能 resume。
- **Knowledge State Store** 定期持久化至磁盤（`state/checkpoint<ts>.json`）：DAG 進度、節點結果、已獲取 Key、Cookie、Scope 狀態。
- **節點執行狀態機**（resume 的核心）：每個 DAG 節點記錄
  ```
  status: not_started | in_flight | completed
  ```
  - `not_started` → resume 時正常執行。
  - `completed` → 跳過（結果已回寫）。
  - `in_flight`（請求已發出但未回寫結果）→ **不簡單跳過**，策略：
    - **唯讀/無副作用 payload**（SELECT、sleep、GET probe）：可安全重跑。
    - **有狀態/副作用 payload**（登錄嘗試、rate-limit 觸發、寫型 API）：**標記 `unknown` 需人工確認**（`--resume --resolve-inflight <id>` 由操作者決定重跑或棄），避免重複造成非預期副作用。
- **斷點續跑**：`--resume <checkpoint>` 從 checkpoint 恢復（按上方狀態機處理各節點）。
- **SIGSTOP/SIGTERM/Kill 場景**：
  - 收到中止信號 → 先 flush 當前 State 到 checkpoint（含 in_flight 標記）→ 再清理沙箱。
  - 重啓後 `--resume` 可繼續，不從頭開始。
- 沙箱爲**無狀態**（重建），但 State Store 持久化保留上下文（§2.3 共享）。

---

## 4. 測試劇本庫 (Attack Playbook Library)

### LLM 劇本 (1-5)
**劇本 1：Direct Jailbreak & Guardrail Bypass**
Baseline → Roleplay (DAN/Opposites/Dev Mode) → Obfuscation (Base64/Unicode/外語) → Prefill 誘導

**劇本 2：Indirect Prompt Injection (RAG/Tool)**
Craft 含隱藏指令文件 → 輸入 target → Trigger query → 驗執行

**劇本 3：System Prompt Leaking**
Rule Override → 翻譯/改述 → Completion trick → 語意相似度評估

**劇本 4：Downstream Injection & SSRF (Excessive Agency)**
Tool Recon → SSRF (`169.254.169.254`) → Cmd Injection (`;id`) → 響應分析

**劇本 5：Data Exfil via Markdown/HTML**
注入 token → 指示渲染外網圖片 URL → OOB 監聽驗證

### 傳統 Web 劇本 (6-10)
**劇本 6：SQLi — 認證繞過/資料提取 (W-01)**
Enum endpoints → Fingerprint DB → `' OR 1=1--`/boolean/time probes → sqlmap_runner → 重複驗證 → PoC

**劇本 7：IDOR / 垂直提權 (W-03)**
userA 登入取資源表 → 建 userB → Horizontal ID 替換 → Vertical admin endpoint / method 篡改 → 回應差異驗證

**劇本 8：Broken Auth — Session Fixation / JWT (W-02)**
Baseline 登錄/Cookie → 預置 SESSIONID 驗是否變 → `alg=none`/HS256弱鍵爆破 → 重放驗證

**劇本 9：XXE / SSRF / Path Traversal (W-05)**
定位 XML 解析/URL 下載點 → XXE OOB → 內網 SSRF → `../../etc/passwd` → OOB 監聽 PoC

**劇本 10：API Mass Assign / GraphQL / Rate Limit (W-06)**
Enum schema/introspection → 夾帶 `role=admin` → GraphQL alias/批次放大 → XFF 輪替繞 429 → 驗證

---

## 5. 安全與沙箱 (Safety & Sandboxing)

### 5.1 授權與隔離
- **授權 + 範圍雙驗證**：書面授權令牌 (`--authorization-token`) + **Target Scope Statement 強制填寫**，缺少則拒絕啓動。
- **默認範圍 vs 簽名憑證的優先序**（釐清 §12.2 矛盾）：
  - **未籤核狀態（無有效簽名憑證）**：強制退回到 **localhost-only** 默認（`localhost`/`127.0.0.1`/`example.com`），無論 Scope Statement 寫什麼均不生效。
  - **僅當 Scope Statement 的 targets 被合法簽名憑證覆蓋（§5.1.1 驗籤通過）**，聲明範圍才生效並允許訪問 `10.0.0.0/24` 等內網目標。
  - 即：**簽名憑證是範圍生效的前置條件**，Scope 聲明 + 簽名兩者缺一不可，否則一律限 localhost。
- **Target Scope Statement schema**（機器可驗證，非僅文件審查）：
  ```yaml
  scope_statement:
    authorized_by: "<姓名/組織>"        # 籤核人
    auth_token_hash: "sha256:..."      # 授權令牌 hash (見 5.1.1)
    targets:
      - { host: "10.0.0.5", cidr: "10.0.0.0/24", ports: [80,443,8080], paths: ["/api","/login"], methods: ["GET","POST"], window: "2026-08-13T00:00Z/2026-08-14T00:00Z", contact: "ops@example.com" }
    allowed_out_of_band: ["oob.example.com"]   # OOB 回調域
  ```
  - **程序化匹配**：每次請求前，ScopeGuard 驗證目標 IP∈cidr、port∈ports、path 前綴、方法、時間窗口；**不在聲明範圍內立即阻斷並記錄**（不是僅人工審查）。
- **容器隔離**：Docker/gVisor，無 root，network namespace + seccomp。
- **資料層**：一次性工作目錄，對外不留敏感數據。

### 5.1.1 法務籤核的技術保證 (Authorization Enforcement)
- 僅 `--authorization-token` 是**不可靠的 boolean flag**（誰都能加上）。改爲**簽名授權憑證**：
  - 授權憑證爲 **JWS (JSON Web Signature, Ed25519)**，由籤核方私鑰簽發，內容 = Scope Statement + 過期時間。
  - Agent 持公鑰驗籤：啓動時驗證簽名、scope、有效期；**簽名無效/過期 → 拒絕啓動或終止任務**。
  - `--allow-production` 同理：僅當憑證含 `production: true` 聲明且簽名有效時才放行。
- `--aggressive` 掃描 flag 同理受憑證 scope 約束（聲明內纔可）。
- **憑證輪替 / 撤銷機制**：
  - 短效期 + 定期換髮（默認憑證效期 ≤ 目標 window，防長期密鑰外洩影響）。
  - **撤銷清單 (CRL)**：維護 `revoked.jws` 列表（憑證 kid + 撤銷時間），Agent 啓動與會期定期拉取校驗；籤核方私鑰外洩或授權提前終止 → 加入 CRL 即失效。
- **時間窗口 (`window`) 檢查頻率**：不是啓動時一次性，而是**每次請求前**由 ScopeGuard 校驗當前時間 ∈ window；**長任務跨過 window 結束 → 立即中止後續動作**（已完成的結果保留，已啓動的 in_flight 按 §3.4 處理）。

### 5.1.2 OOB Listener 網路拓樸
> 審查注意：自建 HTTP/DNS OOB listener 需**公網可達**才能收到內網 target 回連（XXE/SSRF 驗證核心），與默認 localhost 目標矛盾。
- 解決方案：OOB 採用**三模式**：
  1. **內置輕量 OOB 服務**（interactsh-like）：Agent 自建 HTTP/DNS callback 監聽，生成 `oob.<公網域>` 回調地址，config 中聲明（見 Scope Statement `allowed_out_of_band`）。適用公網可達的測試環境。
  2. **自帶模式**：用戶提供自己的 Burp Collaborator / interactsh token 作爲 OOB 端點（離線/內網測試場景）。
  3. **同網段沙箱部署**（補充：解決內網目標收不到回調問題）：OOB listener 可部署在**與目標同一網段的沙箱容器內**，使 `10.0.0.5` 等內網目標能直接回連（而非僅本機迴環），適用於內網/容器網格測試場景。
- 默認（無公網基礎設施）：OOB 驗證**降級爲本地迴環驗證** — 對 localhost 目標，可監聽 `127.0.0.1` 端口驗證 Callback（適用於本地靶場），並明確提示 OOB 外網/內網驗證可用性取決於部署模式。

### 5.2 Allow / Deny 清單
| 類別 | 允許 | 禁止 |
|------|------|------|
| 命令 | curl/python3/sqlite3/git/dig/jq + 掃描工具 (sqlmap/nuclei/zap-cli/gobuster/ffuf/nikto) | rm -rf /, format, shutdown, dd, 非沙箱外網 probe |
| 網絡 | Target CIDR + 重導向後複驗 Scope；OOB 回調域 (Scope 聲明) | 其他生產網段、廣播、SMTP、未聲明網段 |
| 文件 | 工作目錄、`/tmp/redteam-*` | /etc/shadow、$HOME 外敏感路徑 |
| 工具權限 | 按 schema 聲明 | 未註冊工具；**動態下載新命令需 hash 校驗快照**（nuclei templates 例外） |

> ⚠️ **Python 圖靈完備聲明**：Allow/Deny 把 `python3` 列爲允許命令，但 python3 是圖靈完備語言，**命令層白名單無法限制其執行內容**。真正的防線只在容器層 + ScopeGuard 網絡過濾。補充限制：
> - **Python 運行時加固**（沙箱容器內）：禁用 `subprocess`/`os.system` 再 fork、黑限危險 import（`socket` 網連、`ctypes`）、可設 `sys.settrace` 審計鉤子。
> - 網絡出口仍由容器 network namespace 強制（Python 無法繞過容器層網絡過濾）。
> - 明確：Allow/Deny 命令清單提供**易用性而非安全保證**，安全邊界在容器 + 網絡隔離層。

### 5.3 護欄 (Guardrails)
- 啟停開關 (`SIGSTOP/SIGTERM`/`/stop`) + 自動清理沙箱（**清理沙箱前先持久化 Checkpoint State 至 §3.4**，可 resume）。
- 內容審查閘門（LLM 變異 prompt 先輕量審查）
- `--dry-run` 輸計劃圖不實攻擊；掃描型劇本預設 dry-run，需 `--aggressive`（簽名憑證內聲明）才放行
- 禁止破壞性 Payload：Fuzz 限「唯讀 + 延時型」（SELECT/sleep），禁 DROP/UPDATE
- QPS/Per-Endpoint 併發上限防 DoS；`--allow-production` 需簽名憑證聲明 + 驗籤
- **審計日誌防竄改 (Tamper-evident)**：日誌採用 **append-only + hash chain**（每筆記錄含前一筆的 hash → Merkle 鏈），存 write-once 存儲；報告附鏈尾 hash 可驗證未被事後修改，作法務憑證。
  - **防竄改級別聲明**：本機 hash chain 可被 root 整體重寫並重算鏈，故標爲「**防意外竄改 / 防篡改**」級；若需「防惡意竄改」作正式法務證據，**定期將鏈尾 hash 上報外部不可控系統**（第三方時間戳服務 RFC3161 / 對象存儲 Object Lock），爲可選增強。

---

## 6. 報告與評分 (Reporting & Scoring)

### 6.1 嚴重級別 — 統一 CVSS v3.1 基線
| 級別 | 定義 | 範例 (LLM + Web) |
|------|------|------|
| **Critical** | RCE、資料庫 dump、雲 Metadata 內網 SSRF、全面越權 | 下游 Cmd Injection、SQLi→提権、Cloud Metadata (169.254.169.254) SSRF |
| **High** | 完全繞過防護 / 完全提示詞泄漏 / 大規模 IDOR / JWT 偽造 | 完整 Jailbreak、核心提示詞提取、普通內網 SSRF（非 Metadata） |
| **Medium** | 部分泄漏 / 可控 Markdown 外洩 / 低危 IDOR | 部分提示詞、低風險工具偏轉 |
| **Low** | 輕微格式異常 / 技術棧泄漏 | 錯誤訊息暴露版本 |

- LLM finding：`CVSS + OWASP LLM Top 10 + confidence(0-1)`
- Web finding：`CVSS + OWASP Top 10 Web + attack_surface: llm|web|hybrid`

### 6.2 報告 JSON schema
```json
{
  "run_id": "uuid",
  "target": {"type": "llm_app|web_service|hybrid"},
  "summary": {"total_steps": 0, "findings": 0, "critical": 0},
  "findings": [{
    "id": "f-001",
    "attack_surface": "llm|web|hybrid",
    "category": "prompt_injection|jailbreak|leak|sqli|nosqli|xss|cmd_injection|ldap|ssti|path_traversal|auth|session|idor|privesc|xxe|ssrf|misconfig|outdated|mass_assignment|graphql|rate_limit",
    "severity": "critical|high|medium|low|info",
    "cvss": {"vector": "CVSS:3.1/...", "score": 0.0},
    "title": "", "description": "",
    "reproducible": true,
    "evidence_ids": ["evt-001"],
    "steps": ["重現步驟"],
    "confidence": 0.0-1.0,
    "false_positive_risk": "low|medium|high"
  }],
  "evidence": [{"id": "evt-001", "type": "http|command|prompt|response|file|oob", "data": "", "ts": ""}]
}
```
輸出：JSON (CI/CD) + Markdown/HTML。含 Executive Summary、Details、可復現 PoC、Remediation Guidance。

### 6.3 CVSS 計算與人工複核
> 審查注意：LLM 自動生成 CVSS 準確度存疑。
- CVSS vector 由 Judge LLM **初步生成**，但：
  - **High/Critical finding 強制人工複核 gate**：寫入最終報告前需人工確認（CLI `--review` 交互 / 報告標註 `pending_review`）。
  - Low/Medium 可自動寫入，但報告標註「auto-scored」。
- CVSS 依據：參照 NVD/OWASP 基準，vector 需可解釋（各 metric 對應 finding 證據）。

### 6.4 Confidence / False Positive 計算規範
> 審查注意：`confidence(0-1)` 與 `false_positive_risk` 需明確定義，非 LLM 自由發揮。
- **最低驗證標準**（標爲 high confidence 至少滿足）：
  1. **確定性證據**（Regex 命中 / 狀態碼 / 響應特徵）**且**
  2. **LLM-as-a-Judge 二次確認**一致。
  3. **PoC 可復現**（重跑一次仍成立）。
- confidence 分級：
  | confidence | 條件 |
  |:--|:--|
  | 0.9-1.0 (high) | 確定性證據 + Judge 確認 + 可復現 |
  | 0.6-0.8 (med) | 確定性證據 或 Judge 確認（其一） |
  | <0.6 (low) | 僅 LLM 推斷，無確定性證據 → 報告標「低置信，待驗證」 |
- `false_positive_risk`：基於證據確定性（Regex/狀態碼 → low；純語義 → high）。

---

## 7. 技術選型 (Tech Stack)

| 層 | 選型 |
|:--|:--|
| 語言 | Python 3.11+ |
| Agent 編排 | **LangGraph** |
| LLM 適配 | LiteLLM / LangChain Core |
| HTTP | httpx (async) + requests + playwright (DOM) |
| HTML 解析 | parsel / BeautifulSoup4 |
| 主動掃描 | **nuclei** + **OWASP ZAP API** |
| 注入専用 | **sqlmap** (`--batch`, flag 啟用) |
| Burp 整合 (選配) | Burp REST API bridge |
| OOB | 內建 `oob_listener` / interactsh |
| Judge | pydantic + re + LLM-as-a-Judge |
| 沙箱 | docker-py / gVisor |
| CLI | typer + rich |

掃描器一律經工具入沙箱，不將任意命令直接暴露給 LLM 端。

### 7.1 LiteLLM 核心模型配置 (Configurable Brain)
使用者通過 config 自訂紅隊 Agent 的核心 LLM（Planner/Mutator/Judge 可設不同 Role Profile）：
```yaml
# config.yaml (示例)
llm:
  planner:    # 規劃器 (DAG 任務分解)
    provider: openai
    model: gpt-4o
  mutator:    # Payload 變異器 (可用低成本模型)
    provider: litellm
    model: anthropic/claude-3-haiku
  judge:      # 判定器 (LLM-as-a-Judge)
    provider: litellm
    model: groq/llama-3-70b
  fallback:   # 核心 LLM 不可用時的回退
    provider: ollama
    model: qwen2.5:14b
  token_budget: 500000   # 全局 token 上限 (接 §9.2 成本治理)
```
- Provider 白名單：openai / anthropic / groq / ollama / vllm / deepseek 等 (LiteLLM 支持)。
- API key 管理：從 env / secret file 讀取，不寫入 repo。
- **`sqlmap` 授權隔離 (GPLv2)**: 僅允許 **Subprocess CLI / Docker 容器** 調用 (`sqlmap_runner` 內部 `subprocess`/`docker run`)，**禁止任何 Python `import sqlmap`**，保 Apache 2.0 獨立性。nuclei templates 同理外部拉取 + hash 校驗。

---

## 8. 里程碑規劃 (Roadmap)
- **Phase 1: MVP (Week 1-3)**：CLI、Unified HTTP Client、輕量沙箱、劇本 1/3 (LLM) + 劇本 6 (SQLi)。
- **Phase 2: Advanced (Week 4-7)**：LangGraph Planner、變異引擎、劇本 2/4/5 + 劇本 7-10 (Web)、LLM-as-a-Judge、nuclei/sqlmap/ZAP 整合。
- **Phase 3: Production (Week 8-10)**：資安控制、統一 CVSS 報告、CI/CD、OOB 監聽完善。

---

## 9. 風險與約束
1. **法務/授權**：ROE + Target Scope Statement 雙強制，授權文件缺失拒絕啓動；禁生產掃描（除 `--allow-production` + 籤核）。
2. **成本 vs 流量雙治理**：LLM 側 token budget；Web 側 request budget + Per-Endpoint 併發。
   - **超預算行爲**（明確定義，影響長任務可靠性）：
     - **token budget 超限**：默認**降級到 fallback 模型**（config 的 `llm.fallback`），維持任務；若 fallback 也超預 → 告警並**暫停新節點**，已完成保留，等待人工決定（`--continue` 重設預算或終止）。
     - **request budget 超限**：默認**告警 + 降速**（降低 QPS），不硬中斷（避免掃描中半途失敗）；若觸發硬上限（config `hard_stop: true`）則中止。
     - 均可 `--budget-policy stop|degrade|warn` 覆蓋。
3. **誤報/漏報**：雙軌驗證（Web: Regex/Status 確定；LLM: LLM-as-a-Judge），多輪測試。
4. **治理成本**：nuclei template hash 校驗、掃描器/CVE 庫定期更新。
5. **誤傷防護**：重導向後複驗 Scope、DNS rebinding/open redirect 防護。
6. **WAF / 反機器人 (Cloudflare等)**：掃描結果可能全被攔截造成僞陰性。應對：
   - 對目標響應做**反攔截檢測**（識別 challenge 頁面特徵：`cf-challenge`、驗證碼 DOM、HTTP 403 + JS challenge）。
   - **隱性限流/降速檢測**（補充：現代 WAF 少用明顯 challenge 頁）：響應時間異常升高 + 無 challenge 頁 + 間歇 429/5xx → 判定爲隱性限流，標記「結果不可靠 / 疑似被降速」。
   - 命中則標記「結果不可靠 / 被 WAF 攔截」而非「通過」，報告對用戶警示。
7. **多 LLM Provider 一致性**：Planner/Mutator/Judge 用不同模型可能產生不可復現結果。應對：
   - **Judge 角色固定單一模型**（config 默認，可調），並提供 **校準測試集**（benchmark）驗證跨模型一致性。
   - **推論參數確定性**（補充）：Judge 推理固定 `temperature=0`、固定 `seed`、關閉 streaming 隨機性，確保同輸入→同判定、跨 run 可復現（benchmark 校準的前提）。
8. **`--full` 脫敏解除的存取控制**（§11 脫敏規範的補充）：
   - `--full` 需額外授權（同簽名憑證驗證，見 §5.1.1），非單純 CLI flag。
   - 完整敏感數據默認僅存本地工作目錄（一次性），報告默認脫敏。
9. **Benchmark / 驗收標準**：爲驗證 Agent 自身準確度，定 benchmark：
   - 針對 **DVWA / WebGoat / OWASP Juice Shop / OWASP Vulnerable-Llama** 等已知漏洞靶場。
   - 量測 **precision/recall**（檢出已知漏洞 / 無 false positive）。
   - **通過門檻數值**（補充，`--self-test` 驗收達標標準）：
     - recall ≥ **90%**（檢出已知漏洞）
     - false positive rate ≤ **5%**（無過誤報）
     - 未達門檻 → `--self-test` 判失敗，報告 diff。
   - 新增於 Phase 2（`tests/benchmark/`）。

---

## 10. 澄清點決策記錄 (Resolved Decisions)

所有澄清點已於 2026-08-13 決策：

1. **優先目標** → **Web 優先**：agent 依使用者指定目標自行判斷 `target_type`，一般網頁服務默認 `web_service`，LLM/hybrid 按目標特性選擇。
2. **核心 LLM (Brain)** → **使用者自訂**：config (LiteLLM) 指定 provider/model，默認可回退本地模型。
3. **沙箱層級** → **Docker 標準容器**：Hermes 決定；架構保留可升 gVisor/Kata 的接口。
4. **交付形式** → **Markdown 報告** (`.md`)：必須包含複現方式 + 偷到的資料/成功達成的結果。
5. **授權 token 方式** → **ROE + Target Scope Statement 雙強制**（見 §5）。
6. **開源** → **是，Apache 2.0**：公開 repo，劇本庫兼顧安全敏感度。
7. **主動掃描深度** → **全自動**：nuclei/sqlmap/ZAP 自動化整合，CLI 一鍵運行。

---

## 11. 交付報告格式 (Deliverable - Markdown Report)

MVP 交付為一個 Markdown 報告文件（`report_<target>_<timestamp>.md`），結構：

```markdown
# 紅隊測試報告 — <target>

> **審核信息**：授權 token hash `...` | Scope Statement：`...` | 測試者：`...`
> **時間線**：started_at → ended_at | 總 steps：N

## 1. 執行摘要 (Executive Summary)
- 目標：`<url>` | 類型：`web_service` | 時間窗口：`...`
- 發現總計：N (Critical x, High x, ...)

## 2. 複現方式 (Reproduction / PoC)
每項 finding 附：
- **步驟**：step-by-step 請求/指令序列（含完整 HTTP 請求原文）
- **PoC**：可直接複製運行的 curl / python 代碼
- Raw HTTP Request/Response 統一用 `<details><summary>Raw HTTP</summary>...</details>` 摺疊呈現

## 3. 偷到的資料 / 達成的結果 (Exfiltrated Data / Achieved)
- 提取的資料（token、密鑰、系統 prompt、DB 數據）
  > ⚠️ 敏感資料默認脫敏（部分遮蔽），完整版本僅存本地並可 `--full` 輸出
- 達成的結果（越權操作、提権、文件讀取、RCE 證明）

**脫敏遮蔽規範**（默認開啓，`--full` 關閉）：
| 資料類型 | 遮蔽樣式 |
|:--|:--|
| API Key / Token | 僅顯示前 4 後 4 碼：`sk-****abcd` |
| JWT | 僅保留 header+簽名指紋：`eyJ****.sig` |
| Session Cookie | 遮蔽 value，留 name |
| System Prompt | 僅顯示首 2 行摘要 |
| DB 數據 | 敏感字段部分遮蔽（手機/郵箱中間打 *） |

## 4. 漏洞詳情 (Vulnerability Details)
| ID | 類別 | 嚴重 | CVSS | 可復現 | PoC |
|:--|:--|:--|:--|:--|:--|

## 5. 修復建議 (Remediation)
```

---

## 12. 開源治理 (Open-Source Governance, Apache 2.0)

專案將開源 (Apache 2.0)，劇本庫為最有安全敏感度的資產，需以下治理：

1. **劇本去武器化 + 分層授權 (De-weaponization, layered)**：
   - **流程/邏輯完全開源**：劇Ｐ的 DAG 流程、抽象步驟、判定邏輯全部隨 repo 分發（可學習、可貢獻）。
   - **payload 數據集分層授權**（避免開源版淪與「示範骨架」）：
     - L0 (開源)：基礎安全探針（無害 payload、通用 fuzz 模板）。
     - L1 (受限 submodule)：完整爆破字典、SSRF Metadata payload、特化 jailbreak 庫 — 需**聲明合法用途**（簽名憑證, §5.1.1）後拉取私有 submodule。
     - L2 (本地)：用戶自有 payload 擴展目錄，不入 repo。
   - **L1 存取留痕**（補充）：每次 L1 submodule 拉取記錄審計（誰、何時、哪張簽名憑證 kid、拉取的 payload 庫版本 hash），寫入審計日誌，供事後追溯。
   - 真實/高危 Payload 也可通過外部拉取 (nuclei templates) + hash 校驗。
2. **默認目標限制**：默認 target 僅限 `localhost` / `127.0.0.1` / `example.com`，掃描外部需顯式合法性聲明。
3. **免責聲明 + README 警告**：明確「僅用於授權測試，未經授權攻擊非法」。
4. **SECURITY.md / CONTRIBUTING.md**：漏洞披露流程 + 貢獻者安全指南。
5. **授權隔離**：sqlmap (GPLv2) 等 GPL 工具僅經 subprocess/容器調用，不 import，保 Apache 2.0 獨立。(見 §7.1)
6. **劇本類別隱私**：Jailbreak/SSRF 等雙用途劇Ｐ默認藏於 `playbooks/` 獨立目錄，可 `git submodule` 私有拉取。
7. **License 文件**：根目錄 Apache-2.0 LICENSE + COPYRIGHT NOTICE。

