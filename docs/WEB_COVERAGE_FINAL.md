# Web 檢測覆蓋度研究 — 最終報告

> 研究方式: 獨立分析（模板統計 + 實機驗證）+ opencode/agy 並行研究。
> 目標: 評估當前對一般網站服務 (web_service) 的 OWASP Top 10 (2021) 覆蓋度。

## 一、結論：基本"足夠"但有 5 個可落地增強

當前三層掃描器（nuclei 全量 234423 模板 + sqlmap + ZAP baseline）對
OWASP 2021 的**主動可測類別覆蓋"良好"**，但有 5 個具體缺口可按優先級補齊。

## 二、實測覆蓋度矩陣

### OWASP 2021 → 當前檢出能力

| OWASP 2021 | 類別 | 檢出手段 | 覆蓋度 |
|:--|:--|:--|:--|
| A03 | 注入 (SQLi/XSS/RCE/LFI/SSTI/XXE) | sqlmap + nuclei(647+1204+1088+869+31+46模板) | ✅ 高 |
| A05 | 安全配置錯誤 | nuclei(misconfig 975+header 6) + ZAP baseline | ✅ 高 |
| A06 | 易受攻擊組件 | nuclei (CVE 4229模板) | ✅ 高 |
| A07 | 認證失敗 | nuclei (default-login 331 + 技術識別) | 🟡 中 |
| A10 | SSRF | nuclei (195模板, 需OOB) | 🟡 中 |
| A02 | 加密失敗 | nuclei (jwt 41) + 少量; 無 TLS 檢查 | 🟡 中 |
| A01 | 訪問控制 (IDOR) | nuclei (20模板, 弱) | 🔴 低 |
| A04 | 不安全設計 | 無 (需業務邏輯) | 🔴 低（不可黑盒）|
| A08 | 軟件完整性 | 無 (需供應鏈) | 🔴 低（不可黑盒）|
| A09 | 日誌監控失敗 | 無（需運維證據） | ⛔ 不可測 |

### 實機驗證
- ZAP baseline 對本地靶場: 60 PASS / 7 WARN（回應標頭類）
- **ZAP full-scan 實機驗證: 136 PASS / 6 WARN**（SQLi boolean、SSTI blind、
  NoSQL 時間盲注、cmd 注入時間盲注等主動探測）→ **主動覆蓋提升 2.3x**

## 三、5 個具體缺口

1. **OWASP 類別未標準化**（最影響可用性）
   `from_nuclei` 的 category 用模板名自由文本（如 "CVE-2023-xxx"），
   **不映射到 OWASP 2021 (A01-A10)**。規格書 §B 聲稱 W-01~W-06 分段，
   實際未落地 → 報告無法按 OWASP 聚合。
2. **ZAP 只用 baseline**（最大檢出提升機會）
   鏡像裏已有 `zap-full-scan.py`（主動注入探測）和 `zap-api-scan.py`
   （API/GraphQL）未啓用。實測 full-scan 主動覆蓋 2.3x。
3. **nuclei 全量模板 → 效率 + 誤報**
   當前掛載整個模板庫（含 iot/dns/cloud 不適用 web 的模板），應限定 http/
   或按 tags/severity。
4. **A01 IDOR/業務邏輯不可黑盒**
   需登錄態 + 雙賬戶對比——標註"需人工/受限"，不是工具能覆蓋的。
5. **A04/A08/A09 結構性不可黑盒檢測**
   不安全設計、軟件完整性、日誌監控本質需代碼/供應鏈/運維證據。
   不應假裝"已覆蓋"，應在報告標註"超出主動掃描範圍"。

## 四、補全方案（按 ROI 排序）

**P1 [立即]** OWASP 類別映射層 — findings 增加 `owasp` 字段（A01-A10），
   nuclei template 用 tags 映射（`tags: sqli → A03`），ZAP alert-id 已知映射。
   低工作量、報告立即可按 OWASP 聚合。
   **✅ 已實現 (2026-08-14)**: findings.py 新增 OWASP_NAMES/NUCLEI_TAG_TO_OWASP/
   NUCLEI_KEYWORD_TO_OWASP/ZAP_ALERT_TO_OWASP + map_nuclei_to_owasp/
   map_zap_to_owasp；Finding.owasp 字段；from_nuclei/from_sqlmap/from_zap/
   from_llm_probes 填值；report.py 增加 OWASP 聚合表(§5) + 詳情表 OWASP 列；
   報告按 attack_surface 分組、未映射單獨列出。實機驗證: baseline 報告
   "OWASP 2021 聚合: A02:1, A05:5, 未映射:1"。

**P2 [高]** ZAP 升級 full-scan + api-scan — 改 scanners.py 的 `zap_api_scan`
   用 `zap-full-scan.py`（web）或 `-s zap-api`（API），實測可用。
   **✅ 已實現 (2026-08-14)**: zap_api_scan 加 mode 參數 (baseline|full|api) +
   api_format (openapi|soap|graphql)；_exec 按 job.mode 選 entrypoint；
   full-scan 加 -s/-I/-m/-T 限界參數（opencode/agy review 修正：
   -s 是 short output 非主動開關、需 -m/-T 防無限 spider、-I 忽略 WARN 退出碼）；
   cli 加 --zap-mode/--zap-api-format；full 模式自動放大 job_timeout。
   實機驗證: full-scan **136 PASS** vs baseline 60 (主動覆蓋 2.3x)。

**P3 [高]** nuclei 限定到 http/ 模板目錄 + tags 過濾 —
   提升速度、降誤報。
   **✅ 已實現 (2026-09-18, M6)**: nuclei_runner 預設 -severity
   low,medium,high,critical(排除 info 噪音) + -exclude-protocols
   dns,code,file,websocket,whois(保留 http/ssl 不傷 A02);模板目錄若含
   http/ 子目錄自動 -t /workspace/templates/http;CLI 新增
   --nuclei-severity / --nuclei-exclude-protocols 覆寫(傳 '' 關閉限縮)。

**P4 [中]** 獨立 web_config 探測器 — httpx 驅動的 header/TLS 檢查
   （安全回應標頭、HSTS、TLS 版本/證書），補 ZAP 之外 (A02/A05)。

**P5 [低]** 自定義 IDOR/業務邏輯探測器 — 需要登錄態，標爲"受限模式"。

## 五、對照規格書
規格書 §B (W-01~W-06) 聲稱的覆蓋骨架與當前實現基本一致，但
**category 未標準化到 OWASP 編號** 導致宣稱 ≈ 實際落地之間有空隙。
建議按 P1 落地後更新規格書。
