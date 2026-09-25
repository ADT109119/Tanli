---
name: tanli-redteam
description: "Use when you need to run an authorized security assessment with the Tanli (探驪) autonomous red-team agent: fingerprinting, CVE intelligence, WAF-aware probing, and structured reports. Covers setup, RoE discipline, credential flow, agent tuning, and real-world pitfalls."
version: 1.1.0
license: Apache-2.0
---

# 探驪 Tanli — Agent 操作技能檔

> 本檔案提供給 **AI agent**（Hermes / OpenCode / Codex / Claude Code 等）閱讀，
> 說明如何正確使用本專案對**已授權目標**執行安全檢測。
> 人類使用者請看 [README.md](README.md)。

## 0. 鐵律（先讀這個）

1. **僅限授權測試**。對未經授權的系統掃描/攻擊在多數司法管轄區屬違法。
   執行前確認持有書面授權，並把授權範圍寫進 RoE 與 scope.yaml。
2. **預設 localhost-only**。不簽發憑證時 ScopeGuard 物理封鎖外網目標——這是特性不是 bug，
   不要用繞過方式硬闖。
3. 生產環境務必 `--read-only`（物理封鎖非安全 HTTP 方法）。
4. 報告中 High/Critical findings 一律標記「待人工複核」，agent 不得自行發布為官方報告。
5. 本專案 `state/` 目錄（憑鑰、憑證、transcript）已 gitignore，**嚴禁 commit**。

## 1. 安裝與驗證

```bash
git clone https://github.com/ADT109119/Tanli && cd Tanli
python3.11 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/tanli self-test        # 必須全綠（本地靶場、無 Docker、無 LLM key）
```

- Python ≥ 3.11。CLI 入口 `tanli`（模組名 `redteam`）。
- `self-test` 是煙霧測試：任何時候改完程式碼前後都先跑一遍。

## 2. 標準作戰流程（六步）

```bash
# ① 建立工作目錄(放 state/ 下,已被 gitignore)
mkdir -p state/<engagement>

# ② 產 RoE 範本並依實際授權編輯(目標/方法/速率/排除路徑/停火條件)
tanli roe --init state/<engagement>/roe.yaml

# ③ 簽發授權憑證(Ed25519 JWS)
python3 -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as K; \
from cryptography.hazmat.primitives import serialization as S; k=K.generate(); \
open('state/<engagement>/priv.pem','wb').write(k.private_bytes(S.Encoding.PEM,S.PrivateFormat.PKCS8,S.NoEncryption())); \
open('state/<engagement>/pub.pem','wb').write(k.public_key().public_bytes(S.Encoding.PEM,S.PublicFormat.SubjectPublicKeyInfo))"
cat > state/<engagement>/scope.yaml <<'EOF'
authorized_by: "<授權人>"
production: true
targets:
  - host: target.example.com
    ports: [443]
    paths: ["/"]
    methods: [GET, HEAD, OPTIONS]
    window: "2020-01-01T00:00:00Z/2020-01-07T23:59:59Z"
    contact: "<聯絡方式>"
EOF
tanli gen-cred state/<engagement>/scope.yaml -k state/<engagement>/priv.pem \
  -o state/<engagement>/credential.jws --kid eng-<date>

# ④ 自主 agent 探測(主力命令)
tanli agent "https://target.example.com/path" \
  --goal "唯讀安全檢測:指紋、安全標頭、TLS、設定缺陷、CVE 候選評估" \
  --auth-cred state/<engagement>/credential.jws \
  --public-key state/<engagement>/pub.pem \
  --read-only --roe state/<engagement>/roe.yaml \
  --workspace workspaces/<engagement> \
  --steps 24 --probes 50 --token-budget 400000

# ⑤ 讀報告:cwd 下 report_<target>_<timestamp>.md + transcript(state/)
#    逐條核對「複現方式」段的證據,再決定是否升級為正式報告

# ⑥ 回歸確認:修復後重跑同一命令,workspace 記憶會自動帶入前次發現
```

`--auth-cred` 若給了就**必須**同時給 `--public-key`（拒絕不可驗證的憑證，fail-closed）。

## 3. 命令速查

| 命令 | 用途 | 關鍵參數 |
|---|---|---|
| `tanli agent <url>` | **自主 LLM tool-loop**（主力）：模型自行規劃探測步驟 | `--goal` `--steps` `--probes` `--token-budget` `--roe` `--workspace` `--report-dir` `--context-window` `--context-compress-at` `--no-docker` |
| `tanli run <url>` | 固定 6 節點 DAG（recon→fingerprint→inject→verify→poc→report），無需 LLM 也能跑 | `-t llm_app\|web_service\|hybrid` `--dry-run` `--scanners` `--resume` `--cve-watch` |
| `tanli scan <url>` | Docker 沙箱跑 nuclei/sqlmap/zap | `-s nuclei\|sqlmap\|zap\|all` `--tags <CVE-ID>` `--zap-mode baseline\|full\|api` |
| `tanli cve <ID或產品名>` | GHSA+OSV+NVD 三源 CVE 查詢 | `-e npm` `-v 3.5.1` `--json` |
| `tanli roe --init/--show` | 作戰紀律管理 | — |
| `tanli gen-cred <scope.yaml>` | 簽發 JWS 授權憑證 | `-k priv.pem` `--kid` `--ttl` |
| `tanli self-test` | 端到端煙霧測試 | — |

## 4. LLM brain 環境變數（agent 模式必需）

`tanli agent` 需要 OpenAI 相容端點；未設定會直接以「brain 不可用」退出（不降級、不編造）：

```bash
export REDTEAM_JUDGE_BASE_URL="http://<gateway>:<port>/v1"
export REDTEAM_JUDGE_API_KEY="***"
export REDTEAM_JUDGE_MODEL="<model-id>"     # 例 your-model-id
```

其他：`REDTEAM_PUBLIC_KEY`（可替代 --public-key）、`REDTEAM_REVOKED_KIDS`（CRL 吊銷名單）、
`REDTEAM_PLAYBOOK_DIR`、`REDTEAM_CVE_ECOSYSTEM`。

Brain 取樣覆寫（gateway 調參用）：`REDTEAM_AGENT_TEMPERATURE`、`REDTEAM_AGENT_MAX_TOKENS`、
`REDTEAM_AGENT_EXTRA_BODY`（JSON 字串，直接透傳 gateway 的 thinking 開關等 extra body；
注意本專案不認 OpenAI 標準 `reasoning_effort`，thinking 開關走這裡）。

## 5. 安全圍籬（agent 繞不過，你也不用擔心失控）

- **ScopeGuard**：每個封包出口檢查 host/port/path/method/時間窗，越界即中斷。
- **read-only 保險絲**：`--read-only` 物理封鎖 POST/PUT/DELETE；sqlmap/ZAP 的 full/api 模式一併拒絕。
- **預算**：`--steps`（LLM 循環步數）、`--probes`（HTTP 探測硬預算）、`--token-budget` 三重上限，
  耗盡如實停止，不無限跑。
- **redaction**：無簽名憑證時報告自動去敏；`--full`（關遮罩）需要憑證。
- **注入防護**：目標回應以 `<target-data>` 定界符包裹；目標內容中的 jailbreak 指令會被
  標記為「注入面證據」而**不被執行**。
- **稽核**：全程 transcript 落盤 `state/agent_transcript_*.json`。

## 6. 實務坑與判讀守則（測試經驗提煉）

1. **WAF 假陽性**：站前有商業 WAF 時，探 `/.git/HEAD`、`/web.config`、
   `/.env` 常回 **HTTP 200 + 封鎖頁**（含 `Unauthorized Activity Detected` 字樣）。
   這是防護生效，**不是漏洞**——先比對回應內文再報 finding。把這條寫進 `--goal` 可防 agent 誤報。
2. **不信任自報版本**：指紋抓到的 `X-AspNetMvc-Version`、JS 檔頭版號僅作 CANDIDATE 線索；
   一定要抓原始檔內容比對（例：jQuery 檔案首行註解）後再查 CVE。
3. **CVE 資料源滯後**：NVD 常回 406/限流，自動降級 GHSA/OSV；「查無 CVE」要在報告標註
   「可能是資料源滯後」，不得宣稱「無弱點」。GHSA 的 ASP.NET Core 與 ASP.NET MVC 5.x
   是**不同產品線**，別互相套用。
4. **無 Docker 降級**：Docker daemon 不可用時 `nuclei_cve_probe` 動態嘗試自動關閉，
   agent 會如實回報——必要時加 `--no-docker` 明示，避免 agent 反覆嘗試。
5. **token 預算要給夠**：實測單一 web 目標 22 步燒掉 ~20.5 萬 token 仍未收工。
   建議 `--token-budget 400000` 起跳，或 `--steps 12` 做快速偵察。
6. **API key 抓取**：從別的工具（如 ~/.hermes/config.yaml）撈 key 時注意多段同名欄位，
   先以 `/v1/models` 打一次驗證再起跑，避免 401 白燒一輪。
7. **跨會話記憶**：`--workspace workspaces/<name>` 會累積「先前發現/死路/教訓」，
   第二次測同一目標步數明顯減少（實測 9 步 → 4 步）。重測同一目標**務必沿用同一 workspace 名**。
   不想要記憶就 `--workspace none`。
8. **大輸出卸載**：>8KB 的工具輸出自動落盤，agent 只收到 stub+路徑（`read_tool_output` 讀回）。
   若 agent 說「輸出太大」，是機制正常，不是失敗。
9. **報告 triage 分**：每條 finding 有固定公式風險分（影響×真實性×likelihood×可達性），
   排序照分數走；`auto-scored` 不等於人工確認過。
10. **Cookie/session 探測**：預設不帶 cookie 的探測每次是新 session；需帶登入態時用
    `--auth-header "Cookie: <value>"`（值絕不進報告）。
11. **長航上下文防護（v0.0.3）**：`--context-window <tokens>` 給定後以 API 回報的
    `prompt_tokens` 為準——逼近上限先深度壓縮（舊工具輸出截頭＋卸載指針，零 LLM 成本），
    仍超線則優美停止**保住已有報告**，不硬炸。`--context-compress-at`（預設 24000 字元）
    控制何時開始壓縮。實測：不加防護時 22 步燒 20.5 萬 token 未收工；壓縮後同目標
    正常 finish＋有 finding。
12. **scratchpad 工作記憶（v0.0.3）**：agent 內建 `scratchpad` 工具維護 TEST/DONE/DEAD
    待辦清單，每步自動回音；尚有未結項時 `finish` 會被擋一次（只擋一次，尊重模型最終
    決定）。驅動 agent 時可在 `--goal` 要求「先立 scratchpad 計畫再探測」，可防中途
    分心收工（run1 教訓：69KB 中斷輸出帶走注意力，step 11 就提前 finish）。
13. **重大發現 watchdog（v0.0.3）**：agent 思考中出現重大發現措辭但整個 run 零立案時，
    會自動注入一次「請落檔」提醒。看到報告 0 findings 但 transcript 有「重大發現」字樣,
    就是 watchdog 也沒救回的情況——此時人工看 transcript 撿證據。
14. **擷取資料閉環（v0.0.3）**：agent 宣稱擷取到敏感資料時走 `add_finding(exfiltrated_data=...)`
    → 清洗 → 自動脫敏 → 報告 §3。judge 有反幻覺條款：宣稱擷取物未逐字見於證據不得
    CONFIRM。`--full` 報告會如實標註 UNREDACTED 且終端警示。
15. **純文字旁白誤收工已修（v0.0.3）**：模型約 1/6 機率回「空 tool_calls＋純文字分析」,
    舊版直接收工；現在第一次會提示續跑,連續第二次純文字才視為真總結。驅動時若看到
    「(narration → continue)」提示即此機制在運作。

## 7. LLM 應用目標（第二軌道）

目標是 LLM API / RAG / AI agent 時：`tanli run <url> -t llm_app --scanners llm_playbook`
內含 11 本 OWASP GenAI playbook（越獄、提示注入、系統提示洩漏、過度代理、輸出處理、
多輪遞進、人格虛擬化、編碼繞過、間接注入武器化、推理模型攻擊、多模態注入），
基線對照 + 哨標 + 確定性規則 + LLM judge 二審。playbook 為 YAML 知識庫
（`src/redteam/playbooks/{web,llm}/*.yaml`，Web 軌道另有 33 本方法論劇本含
CMS/框架暴露面族 WordPress/Laravel/Actuator/.git 與互聯網掃描器族
Redis/ES/Jenkins/Docker-K8s/子網域接管/JWT），可直接擴寫；`--playbook <file>` 指定單本。

## 8. 產出物位置

| 產出 | 路徑 |
|---|---|
| Markdown 報告 | `report_<sanitized-target>_<YYYYMMDD_HHMMSS>.md`（cwd） |
| 探測實錄 transcript | `state/agent_transcript_*.json` |
| 作戰紀律包 | `workspaces/<ws>/<target>/engagement_package.json` |
| 跨會話記憶 | `workspaces/<ws>/<target>/memory.json` |
| 大輸出卸載 | `workspaces/<ws>/<target>/tool-outputs/` |
| scratchpad 持久化 | `workspaces/<ws>/<target>/notes/_scratchpad.md` |
