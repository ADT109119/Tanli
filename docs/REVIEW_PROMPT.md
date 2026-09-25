# Tanli (探驪) 代碼審查任務

請對 ~/projects/tanli 這個自動紅隊測試 Agent 項目進行 deep code review。
專注最近一次功能變更：**run 命令接入掃描器**（commit 401abd2）以及 **掃描結果→findings→LLM judge→報告管線**（commit b16a427）。

## 審查重點

1. **安全性/授權邊界**：
   - `auth.py` 的 ScopeGuard 範圍檢查是否可能被繞過（尤其是彩 code 中的 target 重寫、Docker network 處理）
   - scanners.py 的 `_rewrite_localhost` 是否會造成 SSRF 風險（把 target 重寫成 host.docker.internal 的邊界）
   - JWS 憑證驗證是否有 stub（Phase 2 TODO）遺漏點

2. **代碼正確性**：
   - cli.py run 命令的 DAG 節點狀態機（in_flight/completed、verify_only 邏輯）
   - ScannerBridge 異步 job queue 的狀態轉換是否有競態
   - findings.py 的 severity/category 映射是否合理
   - judge.py 的 LLM 降級邏輯（無 key 時 graceful）

3. **架構/一致性**：
   - 是否符合 SPECIFICATION-FINAL.md v3.4 的設計（DAG+ReAct、Docker 沙箱、LiteLLM 可配置）
   - 是否有 TODO/stub 應標記但被遺漏的

4. **真實 bug 判定**：請區分「真實 bug」「防禦性改進」「誤報」三類，每類給出依據。

## 輸出格式

| 編號 | 文件:行 | 問題 | 嚴重度 (🔴真實bug/🟡defense/🟢FP) | 依據 |
|------|---------|------|------|------|
