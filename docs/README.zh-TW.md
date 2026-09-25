<p align="center">
  <img src="../assets/logo.png" alt="探驪 Tanli logo" width="160" />
</p>

<h1 align="center">探驪 Tanli</h1>

<p align="center">
  <em>「千金之珠，必在九重之淵而驪龍頷下。」——《莊子·列禦寇》</em>
</p>

<p align="center">
  <a href="../README.md">English</a> | <strong>繁體中文</strong>
</p>

<p align="center">
  <a href="#授權條款">授權條款：Apache-2.0</a> ·
  <a href="../SECURITY.md">安全與負責任使用</a> ·
  <a href="../CONTRIBUTING.md">貢獻指南</a>
</p>

<p align="center">
  <img src="../assets/banner.jpg" alt="探驪 Tanli banner — 深入目標之淵，取回漏洞之珠" width="92%" />
</p>

**自主紅隊測試 Agent** — 同時評估 LLM 應用與傳統網頁服務的安全。深入目標之淵，取回潛藏的漏洞之珠。

探驪是一個自主紅隊測試代理：你給定一個授權目標，它自行規劃多步驟攻擊路徑、調用工具、執行探測、判定結果，並產出附重現步驟的結構化安全報告。

> **僅用於授權測試**。未經授權對任何系統進行掃描或攻擊在多數司法轄區是違法行為。使用本工具即表示你同意僅對你有明確書面授權的目標進行測試。詳見 [SECURITY.md](../SECURITY.md)。

## 為什麼叫「探驪」

成語「探驪得珠」（也作「探珠驪頷」），典出《莊子·列禦寇》：驪珠相傳藏在驪龍頷下；驪龍棲息深淵之中，欲取驪珠，必須潛入深淵，待驪龍入睡後，再伺機竊取。本指獲得極為珍貴的寶物，後引申為寫作能抓住重點、深得題旨的精髓。

紅隊測試正是一場潛淵：真正的高危漏洞藏於系統深處，防衛如驪龍蟠伏在側——必須蟄伏、耐心等待，以低噪音的方式規劃並抓住時機，才取得那顆「珠」。

- **淵** = 目標系統（黑箱，深度未知）
- **睡龍** = 安睡的防衛（低噪音、不驚動告警的滲透方式）
- **伺機** = 多步驟自主規劃：探測 → 假設 → 利用 → 判定 → 覆核
- **珠** = 真實漏洞（帶 CVSS 評分與 PoC 重現）

## 雙軌攻擊面

| 軌道 | 目標 | 覆蓋框架 |
|:--|:--|:--|
| **LLM 應用** | LLM API、RAG 系統、AI Agent | OWASP GenAI LLM Top 10（越獄、提示注入、系統提示洩漏、過度代理、輸出處理…） |
| **網頁服務** | Web 應用、REST/GraphQL API | OWASP Top 10 2021（注入、認證、存取控制、配置、SSRF…） |

## 核心能力

- **多步驟自主執行**：DAG 規劃器 + ReAct 執行循環，依目標類型自動路由攻擊面
- **掃描器自動化**：nuclei / sqlmap / OWASP ZAP 於 Docker 沙箱內全自動執行，結果自動轉為 findings
- **LLM 攻擊劇本 (Playbook)**：十一套 OWASP GenAI 劇本（5 套執行型 + 6 套越獄方法論），基線對照 + 哨兵標記 + 確定性規則 + LLM judge 二次判定，誤報過濾
- **框架與基礎設施暴露面劇本**：三十三套 Web 方法論劇本——SQLi/XSS/SSRF/SSTI/CSRF/BOLA 全譜，外加 CMS/框架配置錯誤族（WordPress 設定檔備份與 xmlrpc 放大、Laravel `.env` / Django DEBUG / phpinfo 探針、Spring Boot Actuator `/heapdump`、`.git` 目錄與 SourceMap）及互聯網掃描器族（未授權 Redis/Elasticsearch、Jenkins/Tomcat 管理控制台、Docker/K8s 控制面、子網域接管、JWT 棧缺陷），再加實戰蒸餾的差分測試劇本（同 controller 閘門差分、日期視窗拉取與否定性結果防呆、WAF 覆蓋差分＋JS 字串語法破壞判定）——全部被動探測、僅存證據（端點+狀態碼+雜湊；外洩 secret 一律不下載不摘錄）
- **CVSS v3.1 自動評分**：內嵌官方公式（2592 向量對權威庫零誤差），severity/category 自動映射評分量表
- **人工複核門禁**：High/Critical 發現一律標記「待人工確認」，報告未定稿前 CLI 明確警示，防止草稿被當正式報告發布
- **簽名授權模型**：預設僅限 localhost；擴大範圍需 Ed25519 JWS 簽名憑證 + Scope Statement 強制校驗，越界即中止
- **離線靶場自測**：內建 `TargetLab`（純 stdlib 脆弱/加固雙行為靶場，含 LLM chat 端點），`self-test` 一條指令端到端驗證整個引擎，無需 Docker、無需外部網路
- **報告產出**：Markdown 報告，含 CVSS 向量、PoC 重現步驟、偷到的資料/達成結果、依 OWASP 類別去重彙整的修復建議

## 安裝

需要 Python >= 3.11。

```bash
git clone https://github.com/ADT109119/Tanli.git && cd Tanli
pip install -e .

# 冒煙測試(無依賴)
tanli --help
```

掃描器全自動模式需要 Docker（拉取 nuclei/sqlmap/zap 官方鏡像）；LLM judge 需要任一 OpenAI 兼容端點（可選，無則降級為確定性規則）。

## 快速開始

```bash
# 1. 離線自測:啟動本地靶場,8 項斷言端到端驗證(推薦第一步)
tanli self-test

# 2. 對本地目標預覽計畫(不實際攻擊)
tanli run http://127.0.0.1:8080 -t web_service --dry-run

# 3. Web 全自動掃描(掃描器 + judge + CVSS + 報告)
tanli run http://127.0.0.1:8080 -t web_service --scanners all

# 4. LLM 應用紅隊(目標為 OpenAI 兼容 chat/completions 端點)
tanli run http://127.0.0.1:8080 -t llm_app --scanners llm_playbook

# 5. 單一掃描器 / 單一劇本
tanli scan http://127.0.0.1:8080 --scanner nuclei
tanli run http://127.0.0.1:8080 -t llm_app --playbook src/redteam/playbooks/llm/playbook_1.yaml

# 6. CVE 直查:精確 CVE ID,或產品級(該套件/框架全部已發布 CVE)
#    附 EPSS 利用機率 + CISA KEV(已被真實利用)標記
tanli cve CVE-2025-55182
tanli cve django -e pip            # GHSA + OSV 雙源合併
tanli cve nginx                    # 非套件生態自動改走 NVD 關鍵字查

# 7. 自主 Agent 模式:LLM tool-loop 自行決定每一步
#    (指紋 → 產品級 CVE 核實 → 動態嘗試;絕不輕信目標自報版本)。
#    所有工具都在 ScopeGuard/read-only/預算圍籬內執行,模型繞不過。
#    作戰紀律:--roe 載入參戰規則,第一顆封包前先注入 RoE + MITRE ATT&CK
#    對應 OPPLAN;--workspace 提供跨會話記憶 + 大輸出卸載(同目標重跑不
#    會從零開始);scratchpad 工作記憶＋finish 守門讓長航不失焦;
#    --context-window 防護上下文爆倉(自動壓縮);目標回應一律過提示注入防護。
tanli agent http://127.0.0.1:8080 --steps 30 --probes 60
tanli agent TARGET --auth-cred credential.jws --public-key signer_public.pem --read-only
tanli agent TARGET --context-window 200000 --context-compress-at 24000   # 長航
tanli agent TARGET --report-dir ~/tanli-data/reports                     # 報告指定目錄
tanli roe --init roe.yaml && tanli agent TARGET --roe roe.yaml
```

`--scanners`:`auto`（預設：web→全部，llm_app→劇本）| `none` | `web_config` | `nuclei` | `sqlmap` | `zap` | `llm_playbook`。
ZAP 深度：`--zap-mode baseline|full|api`;nuclei 限縮：`--nuclei-severity`、`--nuclei-exclude-protocols`。
Agent 上下文控制：`--context-window 0`（預設不限；設定後以 API 回報的 `prompt_tokens` 為準，逼近上限深度壓縮）、`--context-compress-at <字元數>`（壓縮閾值，預設 24000）、`--token-budget 0`（不限；`--steps`/`--probes` 硬閘仍在）。模型取樣覆寫：`REDTEAM_AGENT_TEMPERATURE`、`REDTEAM_AGENT_MAX_TOKENS`、`REDTEAM_AGENT_EXTRA_BODY`（JSON，gateway thinking 開關透傳）。

## 授權模型 (Authorization)

預設 Scope 僅限 `localhost` / `127.0.0.1` / `example.com`。對任何內網或外部目標運作，需簽發簽名憑證：

```bash
# 以 Ed25519 私鑰簽發授權憑證
tanli gen-cred --scope scope.yaml --key signer_private.pem --out credential.jws

# 帶憑證執行
tanli run TARGET --auth-cred credential.jws --public-key signer_public.pem
```

ScopeGuard 在每個請求前比對憑證範圍，越界即中止並留下稽核記錄。這是硬性門禁，不是警告。

## LLM Judge 設定

判定使用任一 OpenAI 兼容端點，不綁定 provider:

```bash
export REDTEAM_JUDGE_BASE_URL="https://your-endpoint/v1"   # vLLM / ollama / 雲端皆可
export REDTEAM_JUDGE_MODEL="your-model"
export REDTEAM_JUDGE_API_KEY="***"          # 本地端點可免
```

- 確定性參數（`temperature=0`、固定 seed），保證可重現
- 無端點時自動降級：跳過 LLM 判定，僅用確定性規則，不影響掃描流程

## LLM 攻擊劇本

| Playbook | OWASP GenAI | 攻擊面 |
|:--|:--|:--|
| llm-001 | LLM01 | 直接越獄 / 護欄繞過（DAN roleplay、prefill、混淆） |
| llm-002 | LLM08 | 間接提示注入（隱藏上下文 / RAG 覆蓋） |
| llm-003 | LLM02 | 系統提示洩漏（指令自披露 / 翻譯 / roleplay） |
| llm-004 | LLM10 | 不當輸出處理（Markdown/HTML XSS,hybrid） |
| llm-005 | LLM03 | 過度代理內省（工具/計畫自披露） |
| llm-006 | LLM01 | 多輪與偽造歷史越獄（Crescendo、Many-shot、Skeleton Key、prefill） |
| llm-007 | LLM01 | 人格虛擬化與敘事包裝（DeepInception、Policy Puppetry、情感槓桿） |
| llm-008 | LLM01 | 編碼與混淆繞過（Base64、自訂密碼、低資源語言、零寬字元、ASCII 藝術字） |
| llm-009 | LLM01 | 間接注入武器化（零點擊 Markdown 外洩、Confused Deputy、記憶投毒） |
| llm-010 | LLM01 | Reasoning 模型攻擊與護欄錯配（Bad Likert Judge、Echo Chamber、思考預算） |
| llm-011 | LLM01 | 多模態視覺語言注入（OCR 夾帶指令、隱形對比度、版面劫持） |

安全設計：payload 全部無害化（`payload_policy: benign`）、token 預算熔斷、具副作用劇本一律需授權憑證。

劇本同時是自主 Agent 的**攻擊理論知識庫**：`tanli agent` 提供 `get_playbook` 工具（目錄 / 關鍵字 / OWASP 過濾），讓 LLM 依標準流程規劃而非臨場發揮——不需要向量資料庫，YAML 本身就是知識庫，完全可稽核。Web 方法論劇本（如 web-006 SQLi 流程）供 agent 查詢參考；實際執行仍走掃描器管線，受 ScopeGuard/read-only 圍籬約束。

## 報告

每次執行輸出 `report_<target>_<timestamp>.md` 於目前工作目錄（`--report-dir <目錄>` 可改輸出位置，目錄不存在自動建立）:

1. 摘要與嚴重度統計（含未覆核高危計數）
2. OWASP 類別聚合（含 OWASP GenAI LLM 面）
3. 每項發現：CVSS v3.1 向量與分數、PoC 重現步驟、證據、人工複核狀態
4. 修復建議：依 category → OWASP 類別 → 通用三級映射，自動去重彙整

## 給 AI Agent 的使用說明

本 repo 附上一份 **agent 專用技能檔**：[SKILL.md](../SKILL.md)——精簡操作手冊，供任何 AI agent
（Hermes / OpenCode / Codex / Claude Code）在自主驅動 `tanli` 前閱讀：六步作戰流程
（RoE → 簽憑證 → agent 探測 → 報告複核）、命令速查、安全圍籬、實務坑（WAF 假陽性判讀、
CVE 資料源滯後、token 預算、workspace 跨會話記憶）。

Tanli 自身的 agent 亦支援執行期注入使用者技能：把 `*.md` 放進 `~/.tanli/skills/`
即進入其 `get_playbook` 知識庫，不需重裝、不需改碼。

## 開發

```bash
pip install -e ".[dev]"
pytest tests/ -q          # 226 項測試,全程離線
tanli self-test           # 靶場端到端煙霧測試,須全綠
```

- 規格書：`SPECIFICATION-FINAL.md`（v3.4,agy + opencode 雙 agent 協同規劃）
- 貢獻指南：[CONTRIBUTING.md](../CONTRIBUTING.md) · 安全政策：[SECURITY.md](../SECURITY.md)

## 專案狀態

M1–M6 完成：CLI / 授權模型 / 規劃器 / 掃描器橋接 / findings 轉換 / LLM judge / 四十四套攻擊劇本（LLM 11 套：5 執行型 + 6 越獄方法論；Web 33 套方法論含框架與基礎設施暴露面族＋實戰蒸餾差分族）/ CVSS 評分層 / 報告門禁與修復建議 / 雙行為靶場 self-test / RoE 作戰紀律 / 工作區跨會話記憶 / EPSS-KEV CVE 情報 / triage 風險分 / 使用者可注入技能。v0.0.3 長航層：會話內上下文壓縮與 `--context-window` 防護、三層記憶（scratchpad＋正則搜尋卸載＋finish 守門）、重大發現 watchdog、擷取資料閉環進報告 §3。226 項測試全綠。

## 授權條款

[Apache-2.0](../LICENSE)
