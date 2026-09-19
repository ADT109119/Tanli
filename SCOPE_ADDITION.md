# 規格範圍調整：加入「傳統網頁服務系統安全評估」

在已有規格書 (SPECIFICATION-v2.md) 的基礎上，客戶希望將專案範圍從「純 LLM 紅隊測試」擴展為同時支持**傳統網頁服務系統 (Traditional Web Services) 安全評估**。

請以資深 Web 應用安全測試架構師身份，為這個擴展維度補充以下規格內容：

## 請輸出

1. **新增適用範疇 (Added Scope)** — 傳統 Web 服務應覆蓋的安全測試類別 (參考 OWASP Top 10 2021 for Web Apps)：
   - 注入類 (SQLi, NoSQLi, XSS, Command Injection, LDAP Injection)
   - 認證與會話管理 (Broken Authentication, Session Fixation, Token Handling)
   - 訪問控制 (Broken Access Control, IDOR, Privilege Escalation, Horizontal/Vertical)
   - 資料暴露與配置 (Sensitive Data Exposure, Security Misconfiguration)
   - XXE / SSRF / 過時組件 / 日誌監測缺失
   - Server-Side Template Injection (SSTI), Path Traversal
   - API 專屬 (Mass Assignment, GraphQL Introspection/DoS, Rate Limit Bypass)

2. **與 LLM 紅隊維度的整合設計** — 兩者應如何共用同一套：
   - 指令執行引擎 / 沙箱
   - 工具層 (HTTP Interactor 現在需支持經典 Web 掃描與手工請求)
   - 多步驟規劃器 (劇本如何同時 cover 兩類目標)
   - 報告與評分 (如何統一傳統漏洞 CVSS + LLM 專屬評分)

3. **新增劇本示例 (至少 4 個傳統 Web 劇本)** — 每類給具體步驟流

4. **技術選型補充** — 傳統 Web 測試可用的庫/框架 (如 OWASP ZAP, sqlmap, nuclei, Burp 集成, 或純 Python: requests, httpx, playwright)

5. **風險與約束補充** — 傳統滲透測試的法律/授權要求、目標範圍聲明的強製性

請精簡輸出，中文。若與現有 LLM 側規格有衝突或需要協調的點也請指出。
