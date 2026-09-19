# 規格範圍調整：傳統網頁服務 (Traditional Web Services) 安全評估

> **編號**: v2.1 (WEB-ADDON)
> **上游**: SPECIFICATION-v2.md
> **日期**: 2026-08-13
> **狀態**: 規格草案 — 待整合進 SPECIFICATION-v2 並確認協調點

---

## A. 新增適用範疇 (Added Scope)

傳統 Web 服務測試覆蓋以下類別 (對齊 OWASP Top 10 2021 for Web Applications)：

| # | 測試類別 | OWASP 2021 | 覆蓋內容 / 判定方式 |
|:--|:--|:--|:--|
| W-01 | 注入類 Injection | A03 | SQLi (boolean/time/union/error-based)、NoSQLi、XSS (Reflected/Stored/DOM)、Command Injection、LDAP Injection、Template Injection (SSTI)、Path Traversal |
| W-02 | 認證與會話管理 | A07 | Broken Authentication、Session Fixation、Session 失效/固定、Cookie Flags (Secure/HttpOnly/SameSite)、JWT 簽名誤用 (alg none/HS256 弱密鑰、過期/輪替) |
| W-03 | 訪問控制 | A01 | Broken Access Control、IDOR、Horizontal/Vertical Privilege Escalation、Methods 繞過 (GET→POST)、強行瀏覽 (Forced Browsing) |
| W-04 | 資料暴露與配置 | A02/A05 | Sensitive Data Exposure (明文傳輸、可解碼密文)、Security Misconfiguration (CORS、安全 Header、Debug 模式、錯誤訊息洩漏) |
| W-05 | 解析與伺服器側 | A05/A10/A06/A09 | XXE (含 OOB)、SSRF (內網/雲 Metadata)、過時組件 (Outdated Components)、Logging & Monitoring 缺失偵測 |
| W-06 | API 專屬 | A01/A03 | Mass Assignment、GraphQL Introspection/批次 DoS/Limit 繞過、Rate Limit Bypass (XFF/輪替)、錯誤處理洩漏 |

**判定原則**：判定以 POSITIVE 驗證為主（響應特徵 + 可重現 PoC + OOB 監聽點），非單純依賴掃描器命中。

---

## B. 與 LLM 紅隊維度的整合設計

### B.1 指令執行引擎 / 沙箱 — 共用，改 profile
- **同一沙箱** (Docker/gVisor, §3.1)，新增「Web 掃描 Profile」：
  - 超時：單次命令 `30s` → 掃描型任務 `600s`；記憶體上限 `512MB → 1GB`。
  - **同一 Allow/Deny 網路白名單**（僅 TARGET CIDR），新增掃描工具二進位白名單：`sqlmap`、`nuclei`、`zap-cli`、`gobuster`、`ffuf`、`nikto`。
  - 「運行中動態下載」規則協調：`nuclei` template 屬動態下載 → 需 **hash 校驗 + 快照目錄**（見 §E 衝突點）。
- **速率節流共用**：Web 掃描流量更大，全局 QPS 上限與 `429` 指數退避 (§3.3) 直接繼承，另加 Per-Endpoint 併發限制防 DoS。

### B.2 工具層 (Tool Protocol) — 升級 Interactor + 新增掃描工具
- **升級 `target_http_interactor`**（§3.2）：增加經典 Web 掃描與手工請求能力：
  - Cookie Jar / Session 持久化、自訂 Header、重導向跟隨（可關閉）、代理出口 (Burp/ZAP 橋接)、多部分表單、輸入編碼器、Request/Response 全量紀錄。
  - **重導向後最終 URL 必須再次過 Scope 檢查**（防 DNS rebinding / open redirect 誤傷）。
- 新增工具（繼承 `BaseTool`，依 W 分類註冊）：

| 新工具 | 分類 | 功能 |
|:---|:---|:---|
| `web_request_lib` | 核心傳輸 | 手工/腳本化 HTTP 請求、Params fuzz 模板、Response 萃取 |
| `sqlmap_runner` | 注入檢測 | 以 interactor 捕獲的請求匯入，`--batch --level=1`，需顯式 flag 啟用 |
| `nuclei_runner` | 模板掃描 | 載入 hash 校驗的 template，標準 JSON 輸出入 Judge |
| `zap_api_scan` | 主動掃描 | ZAP API 掃描器 (DAST)，配置 MVP/Auth 腳本 |
| `oob_listener` | 驗證 | 自建 HTTP/DNS 監聽點，驗證 XXE/OOB-SSRF/Exfil |
| `jwt_cracker` / `session_analyzer` | 認證 | JWT alg/弱密鑰、Session 固定與 Cookie Flags 檢測 |

### B.3 多步驟規劃器 — Playbook 型別化
- 劇本加入 **`target_type` 欄位**：`llm_app` | `web_service` | `hybrid`（LLM 應用 + 傳統後端）。
- **共用 DAG 骨架**（§3.3）：`Recon → Fingerprint → Inject/Probe → Verify → PoC → Report`，兩種維度節點可混合：
  - LLM-only 節點：prompt 變異、系統提示詞提取。
  - Web-only 節點：掃描器、手工注入、OOB 監聽。
  - **雜交劇本**（hybrid）：LLM 的 Insecure Output Handling 如何落成下游 SQLi/XSS/SSRF — 一個劇本同時涵蓋兩類目標。
- 狀態持續性共用（Cookie、Context、Scope List），容錯策略 (§3.3 `429`/退避/二次 Judge) 不變。

### B.4 報告與評分 — 統一基線 = CVSS v3.1
- **所有 finding 強制附 CVSS v3.1 vector + 分數** 為統一基線。
- LLM 專屬 finding：`CVSS 基線 + OWASP LLM Top 10 對映 + 語意證據分 (confidence/0-1)`。
- Web finding：`CVSS + OWASP Top 10 for Web 對映`，重點補 **`attack_surface: llm|web|hybrid`** 欄位。
- 嚴重級別表 (§6.1) 擴充範例：Critical = RCE/資料庫 dump/SQLi→提權；High = IDOR 大規模橫向、JWT 偽造、完整 SSRF。
- findings `category` enum 擴充：`sqli|nosqli|xss|cmd_injection|ldap|ssti|path_traversal|auth|session|idor|privesc|xxe|ssrf|misconfig|outdated|mass_assignment|graphql|rate_limit` 等既有值保留。

---

## C. 新增劇本示例 (至少 4 個傳統 Web 劇本)

### 劇本 6：SQL Injection — 認證繞過 / 資料提取 (W-01)
1. *Recon*：枚舉 endpoints、登入表單、參數列。第二動作 2. *Fingerprint*：由錯誤訊息/漢字特徵判斷 DB(WAF 偵測)。
2. *Payload Probe*：`' OR 1=1--`、boolean `1=1/1=2`、time-based `sleep`。
3. *Automation*：以 interactor 捕獲請求 → 交 `sqlmap_runner --batch`。
4. *Verify*：確認成功登入 / 資料提取，重複一次排除誤報。
5. *PoC*：記錄原始請求、dump 內容與修復建議。

### 劇本 7：IDOR / 垂直提權 (W-03)
1. *Setup*：以 userA 登入，取得資源 ID 清單；建立 userB。
2. *Horizontal*：替換 ID 訪問 userB 資源，Judge 比對跨使用者內容。
3. *Vertical*：低權帳號直呼 admin endpoint；method 篡改 (GET→POST/PATCH)；缺失授權 Header。
4. *Verify*：狀態碼 + 響應內容差異；PoC 收錄請求序列。

### 劇本 8：Broken Authentication — Session Fixation / JWT (W-02)
1. *Baseline*：登入流程、Cookie Flags、JWT 發行/過期行為。
2. *Session Fixation*：登入前預置 `SESSIONID`，登入後檢驗是否不變。
3. *JWT Attack*：`alg=none`、弱 HS256 密鑰暴破 (`jwt_cracker`)、過期 token 重用。
4. *Verify / PoC*：以被固定 session 或偽造 token 重放請求並驗證。

### 劇本 9：XXE / SSRF / Path Traversal (W-05)
1. *Recon*：定位 XML 上傳/解析、URL 參數、檔案下載 endpoints。
2. *XXE OOB*：DOCTYPE 實體指向 `oob_listener`，驗證外傳證據。
3. *SSRF*：URL 參數指向內網/雲 metadata (`169.254.169.254`)，檢測回顯。
4. *Path Traversal*：`../../../../etc/passwd` 於下載參數驗證。
5. *PoC*：OOB 監聽紀錄 + 響應特徵 + 修復建議。

### 劇本 10：API Mass Assignment / GraphQL / Rate Limit (W-06)
1. *Recon*：枚舉 API schema、POST body、GraphQL introspection query (預設開啟才驗)。
2. *Mass Assignment*：註冊/更新請求夾帶 `role=admin`、`is_admin=true` 等隱藏欄位。
3. *GraphQL*：alias/batching 放大查詢 → DoS/Rate Limit 探測；introspection 全量 dump。
4. *Rate Limit Bypass*：`X-Forwarded-For` 輪替、多帳號併發繞過 `429`。
5. *Verify / PoC*：權限欄位生效或 `429` 缺口證據。

---

## D. 技術選型補充 (補充 §7)

| 層 | 選型 | 用途 |
|:--|:--|:--|
| 主動掃描器 (整合層) | **nuclei** (yaml template, JSON 輸出) + **OWASP ZAP API** (`zap-api-scan` headless) | DAST / 模板化漏洞驗證 |
| 注入專用 | **sqlmap** (`--batch`, 需顯式 flag) | SQLi 自動化 |
| Burp 整合 (選配) | Burp Suite REST API (headless / PRO) 橋接 interactor 出口 | 進階手動 + 中繼紀錄 |
| 純 Python HTTP | `httpx` (async, Cookie Jar)、`requests`、`pycurl`、`gql` | 手工請求/GraphQL |
| 解析/萃取 | `parsel` / `BeautifulSoup4` | 響應萃取、隱藏欄位發現 |
| 瀏覽器流 | `playwright` (首選) / `selenium` | DOM XSS、Stored XSS、登入流程、CSRF |
| 輔助 | `jwt`、`httpx_socks`、`yaml` (nuclei template loader) | JWT 檢測、代理隧道、模板快照 |
| OOB | 內建 `oob_listener` (HTTP/DNS) 或 `interactsh` | OOB-XXE / SSRF / Exfil |

掃描器一律透過 `nuclei_runner`/`zap_api_scan`/`sqlmap_runner` 工具進入沙箱，不將任意命令直接暴露給 LLM 端。

---

## E. 風險與約束補充 (補充 §9)

1. **授權 / 法務強制**：
   - 執行前需**書面授權文件** + **Target Scope Statement 強制填寫**（host/IP/port/path/允許方法/時段/聯絡窗口），缺少則 Agent 拒絕啟動（等同現行 `--authorization-token` 機制擴充為「授權 + 範圍雙驗證」）。
   - 掃描型劇本（W-05/09 主動、sqlmap）預設 `--dry-run`，需額外 `--aggressive` flag 才放行。
2. **範圍聲明強制性**：
   - Scope 為單一權威來源：`probe` 前的每個請求最終 URL（含重導向後）必須命中 Scope，否則中止並記錄。
   - 禁止掃描生產環境，除非顯式 `--allow-production` + 法務簽核。
3. **影響控制 (DoS 防範)**：Web 掃描流量高，除全局 QPS 外另設 Per-Endpoint 併發數上限；`429` 一律指數退避。
4. **誤傷防護**：DNS rebinding / open redirect → 重導向後復驗 Scope；掃描器由沙箱統一出站，禁宿主機直連。
5. **合規留痕**：完整審計日誌（Raw Request/Response、Payload、Timestamp、報文 hash）同時作為法務憑證，輸出 SOP 供客戶留存。
6. **新增治理成本**：nuclei template 動態下載需 hash 校驗；掃描器版本與 CVE 知識庫需定期更新。

---

## F. 與現有 LLM 側規格的衝突 / 協調點

1. **§6.1 嚴重級別表**：現行表以 LLM 為中心，需擴充 Web 漏洞範例並引入完整 CVSS vector（見 B.4）。
2. **§6.2 findings.category enum**：需擴充 Web/API 類別（見 B.4）。
3. **§3.2 工具表 + §5.2 Allow/Deny**：需新增掃描工具白名單；「動態下載新命令」禁止規則需例外協調（nuclei templates → hash 校驗快照）。
4. **§3.1 資源限制**：Web 掃描需更大超時/記憶體 Profile（見 B.1），改為 Per-Profile 設定而非固定值。
5. **§1.3 Out of Scope**：現行排除「傳統 OS/網絡層 DDoS 與二進位 Zero-Day」**不衝突**，但需明確定義本擴展不進入：完整 OS 滲透、未授權社會工程、交付版 serverless 帳戶攻防以外領域。
6. **§8 Roadmap**：需新增 Web 劇本階段（建議 Phase 2 併入），sqlmap/nuclei 整合屬 MVP 後期。
7. **速率治理雙標準**：LLM 側以 token 成本為約束、Web 側以流量/併發為約束，需在 §9.2 token budget 之外補「請求預算 (request budget)」。