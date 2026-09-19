# OWASP Top 10 (2021) Web 檢測覆蓋度研究與補全方案報告

> **項目**: `redteam-agent` — 自動紅隊測試 Agent
> **日期**: 2026-08-14
> **評估標準**: OWASP Top 10 (2021) Web Application Security Risks
> **分析對象**: 當前三層掃描架構（Nuclei + sqlmap + OWASP ZAP baseline）及源碼實現 (`scanners.py`, `findings.py`)

---

## 一、 當前檢測架構現狀

當前系統採用 **三層 Docker 沙箱掃描器** 執行傳統 Web 服務的安全評估：

1. **Nuclei (`projectdiscovery/nuclei:latest`)**:
   - **模板庫現狀**: `/tmp/redteam-nuclei-templates/http/` 共計 **11,163** 個 YAML 模板，劃分爲 17 個子分類。
   - **主要類別分佈**: CVEs (4,182)、Exposed Panels (1,557)、OSINT (1,078)、Misconfiguration (980)、Vulnerabilities (939)、Technologies (907)、Exposures (697)、Default Logins (305)、Token Spray (247)、SSRF (195)、Takeovers (73)、CNVD (44)、Credential Stuffing (14)、Fuzzing (12) 等。
   - **調用方式**: 掛載模板目錄，通過 `-u <target> -jsonl -irr` 執行全量/指定掃描。
2. **sqlmap (`ilyaglow/sqlmap:latest`)**:
   - **功能定位**: 專精於 SQL 注入檢測（默認 `--batch --level 1 --risk 1`）。
   - **轉化邏輯**: 僅當檢測到明確的 `injectable` 或 `is vulnerable` 標記時生成高/中危 Finding，有效防止誤報。
3. **OWASP ZAP Baseline (`ghcr.io/zaproxy/zaproxy:latest`)**:
   - **功能定位**: 被動掃描 + 1 分鐘 Spider（`zap-baseline.py`）。
   - **轉化邏輯**: 解析 `WARN-NEW` / `FAIL-NEW` 告警信息。目前僅硬編碼映射了 8 個 Header/信息泄露相關的 ZAP Alert ID。

---

## 二、 OWASP Top 10 (2021) 覆蓋度矩陣

下表展示了當前三層工具組合對 OWASP Top 10 (2021) 目標的實際檢測能力評估（**高 / 中 / 低 / 無**）：

| 編號 | OWASP 分類名稱 | 覆蓋等級 | Nuclei 貢獻 | ZAP Baseline 貢獻 | sqlmap 貢獻 | 瓶頸/限制原因 |
|:---|:---|:---:|:---|:---|:---|:---|
| **A01** | **Broken Access Control**<br>(失效的訪問控制) | **低 (Low)** | 含少量特定的越權/403 繞過模板 (如 `fuzzing/xff-403-bypass.yaml`，8 個 IDOR 模板) | 無主動越權探查 | 無 | 缺乏登錄態管理、多角色 Token 對比及 API 路由上下文理解能力。 |
| **A02** | **Cryptographic Failures**<br>(加密失敗 / 敏感數據泄漏) | **中低 (Med-Low)** | `exposures/` (697) 發現泄漏的配置文件/私鑰/密鑰，`jwt` 標籤模板 (9 個) | 告警 10036 (信息泄露)、10049 (Cache-Control) | 無 | 缺少動態 TLS 協議/弱加密套件檢測，JWT 弱密鑰爆破/算法繞過能力薄弱。 |
| **A03** | **Injection**<br>(注入) | **高 (High)** | 覆蓋主流注入模板: XSS (1205)、RCE (950)、LFI (857)、SQLi (589)、SSTI (30) | 僅能被動匹配部分已知響應中的報錯模式 | **極強 (High)**<br>深度覆蓋各種 SQLi Payload | 針對已知模式和標準 Payload 極強；盲注入/複雜多步邏輯注入依賴 OOB。 |
| **A04** | **Insecure Design**<br>(不安全的設計) | **無 (None)** | 僅有極少撞庫/弱口令模板 | 無 | 無 | 屬於架構與業務邏輯缺陷（如防重放缺失、速率限制邏輯空洞），DAST 工具無法理解語義。 |
| **A05** | **Security Misconfiguration**<br>(安全配置錯誤) | **高 (High)** | `misconfiguration/` (980)、`exposed-panels/` (1557)、`technologies/` (907) | **極強 (High)**<br>覆蓋 CSP/HSTS/X-Frame 等安全響應頭 | 無 | 工具層覆蓋度極高，各層協同良好。 |
| **A06** | **Vulnerable & Outdated Components**<br>(易受攻擊和過時的組件) | **高 (High)** | `cves/` (4182)、`vulnerabilities/` (939)、`cnvd/` (44) | 指紋匹配 (Alert 10036) | 無 | 基於已知 CVE 庫檢測極其完善；僅對未知私有組件存在盲區。 |
| **A07** | **Identification & Auth Failures**<br>(識別和身份驗證失敗) | **中 (Medium)** | `default-logins/` (305)、`token-spray/` (247)、`credential-stuffing/` (14) | Cookie 屬性檢查 (`HttpOnly`, `Secure`, `SameSite`) | 無 | 能有效檢測默認口令與泄露 Token，但對特定應用的自定義登錄爆破、MFA 繞過缺乏支持。 |
| **A08** | **Software & Data Integrity Failures**<br>(軟件和數據完整性失敗) | **低 (Low)** | `takeovers/` (73) 子域名接管，已知 Java/Fastjson 反序列化 CVE 模板 | 無 | 無 | DAST 無法檢測 CI/CD 管道安全、未驗證的依賴包導入和固件簽名校驗。 |
| **A09** | **Security Logging & Monitoring Failures**<br>(安全日誌和監控失敗) | **無 (None)** | 僅能通過 Log4j 等 CVE 觸發日誌記錄點 | 無 | 無 | 屬於防守方（Blue Team）內部審計與告警機制，黑盒 DAST 無法直接檢驗。 |
| **A10** | **Server-Side Request Forgery (SSRF)**<br>(服務端請求僞造) | **中 (Medium)** | 包含 195 個 SSRF 模板 (CVE + 通用，如 `fuzzing/ssrf-via-proxy.yaml`) | 無 | 無 | **無盲 SSRF 依賴外部 OOB 監聽器**，未開啓 Interactsh 時部分盲 SSRF 無法檢出。 |

---

## 三、 缺口清單 (Gap Analysis)

### 1. 工具能力限制引發的缺口
- **缺少帶外 (OOB - Out-of-Band) 監聽機制**:
  當前 Nuclei 命令未啓用 `-oob interactsh` 或自建監聽服務器。導致無盲 SSRF (A10)、帶外 XXE (A05)、盲 RCE (A03) 無法獲取回調確認。
- **ZAP baseline 能力受限**:
  `zap-baseline.py` 僅爲被動掃描，不進行主動 Payload 攻擊，且 `findings.py` 中 `ZAP_CATEGORY_HINT` 字典只映射了 8 個 Alert ID（如 10020, 10021, 10035），絕大部分 ZAP 發現被直接歸類爲 `misconfig`。
- **Nuclei 全量掃描效率瓶頸**:
  `scanners.py` 默認加載 `/workspace/templates` 全部 11,163+ 模板，未做協議或標籤篩選（包含了大量的 DNS/FTP/SSH 模板），影響 Web 服務掃描的精準度與時間。

### 2. 黑盒 DAST 本質無法覆蓋的類別（需受限/人工/LLM ReAct）
- **A01 越權與訪問控制**: 無 Session 上下文與雙角色身份對比，黑盒掃描器無法知道 `API /user/1001` 是否能被 `user/1002` 訪問。
- **A04 不安全的設計**: 涉及工作流防重放、積分套利、業務限制繞過等，無法通過靜態 Payload 模式匹配。
- **A09 日誌與監控失敗**: 無法直接檢驗目標後端的 Logging 記錄與 SIEM 報警。

---

## 四、 可落地補齊方案 (Actionable Implementation Plan)

### 方案 1：Nuclei 掃描策略精細化與 OOB 補強（低成本高收益）
1. **限定 Web 協議模板目錄**:
   將 Nuclei 默認掃描路徑限制在 `/workspace/templates/http`，避免無關協議掃描。
2. **啓用 OOB 交互**:
   在 `scanners.py` 的 `nuclei_runner` 中添加 `-oob interactsh` 參數（或自建 `interactsh-server`），解決 A10 (SSRF) 與 A03 (盲注入) 的漏洞響應判定問題。
3. **增加 Tag / Profile 篩選機制**:
   爲 `nuclei_runner` 增加預設 Profile（例如 `fast` / `cve` / `fuzzing` / `auth`）：
   ```python
   # scanners.py 增強
   def nuclei_runner(self, target: str, *, profile: str = "web_default") -> ScannerJob:
       args = ["-u", target, "-t", "/workspace/templates/http"]
       if profile == "fast":
           args += ["-tags", "exposure,misconfig,panel,default-login", "-severity", "medium,high,critical"]
       elif profile == "cve":
           args += ["-t", "/workspace/templates/http/cves,/workspace/templates/http/vulnerabilities"]
       elif profile == "fuzzing":
           args += ["-t", "/workspace/templates/http/fuzzing"]
       args += ["-jsonl", "-irr", "-oob", "interactsh"]
       return self._submit("nuclei", args)
   ```

### 方案 2：拓展輕量級原生 Python 專用檢測模塊（補齊 A02 / A05 / A07）
在無需引入大型重量級工具的前提下，在 `src/redteam/` 中新建輕量原生模塊：
1. **TLS/SSL 協議與安全配置檢查器 (`tls_checker.py`)**：
   - 檢測 TLS 1.0/1.1 弱協議、弱加密套件、證書過期及 SNI 匹配問題（提升 A02 覆蓋度）。
2. **JWT 漏洞校驗器 (`jwt_scanner.py`)**：
   - 檢查 API 返回的 JWT Token，嘗試 `alg: none` 簽名剝離繞過、`RS256 -> HS256` 算法混淆及弱密鑰爆破（提升 A02 / A07 覆蓋度）。
3. **安全響應頭與 CORS 檢出器 (`header_checker.py`)**：
   - 檢查 `Access-Control-Allow-Origin: *` 帶憑證、缺失 `Strict-Transport-Security` / `Content-Security-Policy` / `X-Frame-Options`（提升 A05 覆蓋度）。

### 方案 3：ZAP 掃描器能力升級與 Finding 映射擴充
1. **擴充 `ZAP_CATEGORY_HINT` 映射**:
   在 `src/redteam/findings.py` 中充實 ZAP Alert ID 字典，支持 SQLi (40018)、XSS (40012/40014/40016/40017)、Path Traversal (6)、Directory Browsing (10010)、CORS (10098) 等 50+ 個常見 Alert ID 映射。
2. **引入 ZAP Active Scan / Full Scan 支持**:
   提供運行 `zap-full-scan.py` 或針對關鍵 URL 進行主動探測的選擇，以被動+主動方式挖掘深度漏洞。

### 方案 4：Agent 邏輯層越權與業務邏輯探查（針對 A01 / A04）
1. **多身份 Context 對比**:
   在 Agent ReAct 節點中構建雙身份憑證測試流程（Token A vs Token B），對比相同 API 端點在不同身份下返回的 HTTP Code 與 Body 結構，判定 IDOR / 水平越權。

---

## 五、 補齊方案優先級排序 (ROI Ranking)

按 **投入產出比 (ROI)** 由高到低排序落地優先級：

| 階段 | 任務名稱 | 預計工時 | 核心收益與覆蓋提升 |
|:---:|:---|:---:|:---|
| **P0** | **Nuclei 參數優化與 OOB 開啓** | 0.5 天 | 避免全量目錄掃描無效消耗；立刻提升 A10 (SSRF)、A03 (盲注入)、A05 (盲 XXE) 檢出能力 **300%**。 |
| **P0** | **擴充 `findings.py` 中的 ZAP Alert ID 映射** | 0.5 天 | 解決 ZAP Findings 大量降級爲通用 `misconfig` 的分類模糊問題，精確對應 OWASP 類別。 |
| **P1** | **輕量級 Python 原生檢測器 (TLS / JWT / Header)** | 1.5 天 | 低成本填補 A02 (加密失敗)、A05 (安全配置)、A07 (認證失效) 的檢測空白。 |
| **P1** | **Nuclei 分級 Profile 機制 (Fast / CVE / Fuzz)** | 1 天 | 配合 Agent 階段性 ReAct 節點（Recon -> CVE -> Fuzzing），顯著提升掃描速度與針對性。 |
| **P2** | **Agent 多身份 (Dual-Token) IDOR 越權對比探查** | 2 天 | 打破 DAST 無法檢測 A01 (失效訪問控制) 的天然屏障。 |
| **P2** | **ZAP Full Scan / 帶 Auth 主動掃描集成** | 2 天 | 深入挖掘單頁應用 (SPA) 及帶登錄態 API 的注入與邏輯風險。 |

---
