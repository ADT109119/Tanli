# LLM Playbook 攻擊路徑 — 設計草案 v1

## 背景
`run` 命令對 `llm_app` 目標的 inject 階段目前是 TBD（代碼註釋）。
目標：補全 LLM 攻擊 playbook 執行路徑，覆蓋 OWASP GenAI LLM Top 10 (2026)。

## 權威依據：OWASP GenAI LLM Top 10 2026
1. LLM01 Prompt Injection
2. LLM02 Sensitive Information Disclosure
3. LLM03 Excessive Agency
4. LLM04 Supply Chain
5. LLM05 Data and Model Poisoning
6. LLM06 Unbounded Consumption
7. LLM07 Misinformation
8. LLM08 Hidden Context Exposure
9. LLM09 Vector and Embedding Weaknesses
10. LLM10 Improper Output Handling

## 現有資源
- `playbooks/llm/playbook_1.yaml` — Direct Jailbreak & Guardrail Bypass (LLM01)
- `playbooks/llm/playbook_3.yaml` — System Prompt Leaking (LLM02/LLM08)
- `playbooks/web/playbook_6.yaml` — SQLi Auth Bypass (web)
- cli.py 中 `llm_playbook` scanner 選項已存在但執行路徑 TBD

## 設計目標
1. **playbook.py 執行引擎**：加載 yaml playbook，逐步執行攻擊步驟
2. **攻擊分類覆蓋**：至少 LLM01/02/03/06/10 可自動化
3. **結果 → findings → judge → 報告** 全鏈路
4. **安全**：所有 paylo 經 ScopeGuard；sandbox 隔離；無害化（只讀探測，不造成真實破壞）

## 待討論的問題（給 opencode/agy 評審）
1. playbook yaml schema 應該怎樣擴展才能承載可執行的攻擊步驟（prompt template + 發送方法 + 判定條件）？
2. LLM 目標的交互協議：OpenAI 兼容 /chat/completions？還是要抽象通用 LLM 接口？
3. 攻擊判定的標準（如何判斷 jailbreak 成功 / prompt 泄露）？
4. 哪些 OWASP 2026 類別適合 MVP 自動化，哪些留作人工？
5. playbook 與現有 findings/judge/report 管線的如何銜接？
