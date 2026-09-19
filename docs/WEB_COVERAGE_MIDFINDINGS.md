# Web 檢測覆蓋度研究 — 中期發現（待彙總agv/opencode）

## 實測模板統計 (nuclei http/ 234423 模板文件)
| OWASP 2021 類別 | nuclei 模板數 | 補充工具 | 總覆蓋 |
|:--|:--|:--|:--|
| A03 注入 (SQLi/XSS/RCE/LFI/SSTI/XXE) | 647+1204+1088+869+31+46 | sqlmap (SQLi), ZAP (主動XSS) | **高** |
| A06 易攻組件 (CVE) | 4229 | ZAP version check | **高** |
| A05 安全配置錯誤 | 975 misconfig + 6 security-header | ZAP baseline (header) | **高** |
| A07 認證失敗 | 331 default-login | nuclei技術識別 | 中 |
| A04 不安全設計 | ~0 | 需自定義 | **低/無** |
| A08 軟件完整性 | ~0 | 需供應鏈檢查 | **低/無** |
| A09 日誌/監控 | ~0 | 無法黑盒檢測 | **無（不可測）** |
| A10 SSRF | 195 | 需OOB交互 | 中 |
| A01 訪問控制 (IDOR) | 20 | 需業務邏輯+登錄 | **低** |
| A02 加密失敗 | 41 jwt + 少量 | 需TLS檢查 | 中 |

## 已識別缺口
1. **OWASP 類別未標準化**：from_nuclei 的 category 用模板名自由文本（如 "CVE-2023-xxx"），不映射到 OWASP 2021 (A01-A10)。規格書 §B 的 W-01~W-06 分段沒有落地。報告無法按 OWASP 聚合。
2. **ZAP 只用基線**：zap-baseline.py 主要是被動+響應頭檢查。鏡像裏有 zap-full-scan.py（主動 SQLi/XSS/SSRF 探測）和 zap-api-scan.py（API/GraphQL）未用。
3. **nuclei 全量模板效率低**：掛載整個模板庫（含 iot/dns/cloud 等 web 不適用），應限定 http/ 或按 tags。
4. **A04/A08 不可黑盒主動檢測**：不安全設計（如缺失權限校驗邏輯）、軟件完整性（如惡意依賴）需要代碼/供應鏈分析，超出黑盒掃描範圍。
5. **IDOR/業務邏輯 (A01)**：需要登錄態 + 雙賬戶對比，當前三層工具無法覆蓋，需自定義探測器。
6. **安全頭/配置類只有 ZAP**：nuclei 的 security-header 模板僅 6 個，依賴 ZAP baseline。建議加獨立 header 檢查器（httpx 驅動）。
7. **TLS/A02 無檢測**：沒有 TLS 配置檢查（弱 cipher/證書/降級）。

## 優先級建議（初步）
P1: OWASP 類別映射（findings.category 標準化到 A01-A10）
P2: ZAP 升級 full-scan/api-scan + 限定 nuclei 到 http/ 模板
P3: 加獨立 web_config 檢測器（header/TLS 檢查）
P4: 自定義 IDOR/業務邏輯探測器（需登錄態）— 標爲受限
