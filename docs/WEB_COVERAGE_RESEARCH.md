# Web 檢測覆蓋度研究任務

項目: Tanli (探驪) — 自動紅隊測試 Agent。
請求: 評估當前對**一般網站服務 (web_service)** 的安全檢測是否充足及其缺口，參照 OWASP Top 10 2021。

## 當前檢測手段（三層）
1. **nuclei** (projectdiscovery/nuclei, Docker): 官方模板集在 /tmp/redteam-nuclei-templates (13536 yaml)，http/ 子目錄含 17 類（cves/exposures/misconfiguration/vulnerabilities/default-logins 等），用 `nuclei -t /tmp/redteam-nuclei-templates/http -jsonl`。實際執行: `docker run --rm --add-host host.docker.internal:host-gateway projectdiscovery/nuclei:latest -t /workspace/templates -u <target> -jsonl`
2. **sqlmap** (ilyaglow/sqlmap, Docker): SQL 注入檢測，`--batch --level 1 --risk 1`。結果轉爲 finding（僅 injectable 時）。
3. **OWASP ZAP baseline** (ghcr.io/zaproxy/zaproxy, Docker): ZAP baseline 被動+主動掃描, 只讀 WARN/FAIL alert 摘要（如缺安全響應頭 10020/10021/10035, 信息泄露 10036 等），未用完整 ZAP 規則集。

## 規格書聲稱覆蓋 (SPECIFICATION-FINAL.md §B)
- W-01 注入 (A03): SQLi/NoSQLi/XSS/Cmd Injection/LDAP/SSTI/Path Traversal
- W-02 認證/會話 (A07): Broken Auth/Session Fixation/Cookie Flags/JWT 誤用
- W-03 訪問控制 (A01): IDOR/PrivEsc/Method 繞過/強行瀏覽
- W-04 數據暴露/配置 (A02/A05): Sensitive Data/Misconfiguration
- W-05 解析/服務端 (A05/A10/A06/A09): XXE/SSRF/過時組件/Logging
- W-06 API 專屬 (A01/A03): Mass Assignment/GraphQL/速率限制繞過

## 你的任務
對當前實現做 **OWASP Top 10 (2021) 覆蓋度矩陣**，評估：

1. **逐類別覆蓋評估**：當前三層工具對 A01~A10 的實際檢出能力（高/中/低/無）。要具體：nuclei 模板裏哪些能覆蓋哪些類別，ZAP baseline 只能檢出哪些（響應頭/配置類），sqlmap 只能 SQLi。
2. **缺口清單**：OWASP 2021 含但當前幾乎檢測不到的類別（特別是 A02 密碼學失敗、A04 不安全設計、A08 完整性失敗、A09 日誌監控失敗 等非主動掃描可測的項）。
3. **實用建議**：給出低成本高收益的補齊方案——
   - nuclei 應該用哪些特定模板/參數增強（-tags, -severity, 特定目錄）
   - ZAP 是否應升級到完整 `zap-full-scan.py`/主動掃描或加自定義規則
   - 是否需要新增檢測器（如 httpx 驅動的簡單 header/配置檢查、TLS 檢查、JWT 弱密鑰驗證等）
   - 哪些 OWASP 類別本質上需要登錄態/業務邏輯（非黑盒可達），應標爲"需人工/受限"
4. **優先級排序**：按 ROI 排序缺口補齊方案（先做什麼最提升覆蓋度）
5. **產出**：Markdown 覆蓋度矩陣表 + 缺口列表 + 補全方案（可落地的具體步驟）

參考: /tmp/redteam-nuclei-templates 目錄結構、src/redteam/scanners.py、src/redteam/findings.py、SPECIFICATION-FINAL.md §B。
