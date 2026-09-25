# P1 + P2 實現設計 — OWASP 映射層 + ZAP full-scan

## 背景
Tanli(探驪)項目的 web_service 檢測覆蓋度研究已完結（docs/WEB_COVERAGE_FINAL.md）。
核心缺口：
- **P1**: findings.category 未標準化到 OWASP 2021 (A01-A10)，報告無法按 OWASP 聚合。
  規格書 §B (W-01~W-06) 聲稱的覆蓋骨架與實現之間有縫隙。
- **P2**: ZAP 只用 zap-baseline.py（被動），鏡像裏有 zap-full-scan.py（主動探測 SQLi/XSS/SSRF）
  實測 full-scan 主動覆蓋 2.3x (136 PASS vs baseline 60)。未啓用。

## P1 設計（OWASP 類別映射層）

### 1. Finding dataclass 增加字段
```python
@dataclass
class Finding:
    ...
    owasp: str = ""  # "A01".."A10" 或 ""（未映射/LLM 類別用 LLMxx）
```

### 2. 映射表（findings.py 新增）
- `NUCLEI_TAG_TO_OWASP`: nuclei tags（info.tags 數組）→ OWASP
  - sqli, sql-injection, xss, rce, lfi, ssti, cmd-injection → A03
  - misconfig, misconfiguration, security-misconfiguration → A05
  - cve, known-vuln, exposed-panel → A06
  - default-login, weak-login, broken-auth, jwt → A07
  - ssrf → A10
  - idor, broken-access-control → A01
  - tls, ssl, weak-crypto → A02
  - tech-detect, exposure, exposed → A05 (技術識別噪音默認歸 A05，report 可配置)
- `CATEGORY_KEYWORD_TO_OWASP`: 模板名關鍵詞（fallback 映射，tags 缺失時用）
- `ZAP_ALERT_TO_OWASP`: ZAP alert-id → OWASP
  - 10020/10021/10035/10038/10063/90004 (security headers) → A05
  - 10036 (info disclosure) → A02
  - 10049 (cache) → A05
  - 10053/10054 (cookie flags) → A07
  - 10009/10010/10015 (SQLi/XSS active) → A03
  - 10096/10097 (CSP) → A05
  - 10098 (CORS) → A05
  - 10202/10203 (CVE/software) → A06
  - 90022/90033 (SSRF / open redirect) → A10

### 3. 轉換函數填充 owasp
- `from_nuclei`: 優序 tags → 模板名關鍵詞 → 默認 "A05"（如果無法判斷歸 misconfig）
- `from_sqlmap`: "A03"
- `from_zap`: alert-id 映射，缺省 A05
- `from_llm_probes`: LLM 類別已在 owasp 字段（LLM01..LLM10），保留

### 4. report.py 增加 OWASP 聚合
- section 4 漏洞詳情表格加 OWASP 列
- 新增「按 OWASP 聚合」表格: | OWASP | 類別 | 數量 |
- 響應頭/安全頭等歸 A05

## P2 設計（ZAP full-scan）

### scanners.py
- `zap_api_scan(target, mode="baseline")`: mode ∈ {"baseline","full","api"}
  - baseline: `--entrypoint zap-baseline.py` (保持默認)
  - full: `--entrypoint zap-full-scan.py` + `-s` 大量探測 + `-t target -J zap-report.json`
  - api: `--entrypoint zap-api-scan.py` + `-t target`（針對 API/GraphQL）
- `_exec`: entrypoint 從 mode 決定，full-scan 需要更長 timeout（job_timeout 可配置）

### cli.py
- `run` 命令加 `--zap-mode` flag (baseline|full|api)
- `scan` 命令加 `--zap-mode` flag
- 默認保持 baseline？還是切 full？→ **默認 full**（研究結論 P2: 主動覆蓋 2.3x，立即可落地）
  但給用戶 flag 可降回 baseline。

### 測試
- test_findings.py: 新增 owasp 字段斷言（nuclei tags 映射、sqlmap A03、zap alert 映射）
- test_scanners.py: 新增 zap_api_scan mode="full" 斷言 entrypoint 參數、_exec mode 分支

## 協作安排
- 本設計先給 agy + opencode 審查（並行後臺），收集反饋後合併進實現。
- 實現完成後同樣跑雙 agent review（如 skill 所述已驗證流程）。
