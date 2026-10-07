"""PortSwigger Top10 知識庫擴充回歸(2026-09-20):新 web-007..018 可載入、可查詢、非執行型。"""
from redteam.knowledge import load_library, search, get_by_id


def test_new_playbooks_load():
    lib = load_library()
    ids = {d.id for d in lib}
    want = {f"web-{n:03d}" for n in range(7, 19)}
    assert want <= ids, f"缺少: {want - ids}"


def test_new_playbooks_not_executable():
    lib = load_library()
    for d in lib:
        if d.id >= "web-007":
            assert not d.executable and d.payload_policy in (
                "methodology-only", "reference-only")


def test_top10_topics_searchable():
    lib = load_library()
    for q, tid in [("Confusion", "web-007"), ("WorstFit", "web-008"),
                   ("Smuggling", "web-009"), ("OAuth", "web-010"),
                   ("Cache", "web-011"), ("normalization", "web-012"),
                   ("DOMPurify", "web-013"), ("DoubleClickjacking", "web-014"),
                   ("SSL VPN", "web-015"), ("JWT", "web-016"),
                   ("PAN-OS", "web-017"), ("提示詞注入", "web-018")]:
        hits = search(lib, query=q)
        assert tid in {d.id for d in hits}, f"查詢 {q} 未命中 {tid}: {[d.id for d in hits]}"


def test_render_and_source_provenance():
    lib = load_library()
    d = get_by_id(lib, "web-007")
    text = d.render()
    assert "Apache" in text and "PortSwigger" in text


def test_bola_family_playbooks():
    """操作者案例(web-019 開放式發信中繼)與泛 BOLA 家族(web-020)入庫可查。"""
    lib = load_library()
    for q, tids in [("BOLA", {"web-019", "web-020"}), ("IDOR", {"web-019", "web-020"}),
                    ("Open Relay", {"web-019"}), ("OTP", {"web-019"})]:
        hits = {d.id for d in search(lib, query=q)}
        assert tids <= hits, f"查詢 {q} 未命中 {tids}: {hits}"
    d = get_by_id(lib, "web-019")
    assert d is not None
    rendered = d.render()
    assert "OWASP API" in rendered and "Open Relay" in rendered
    assert not d.executable  # 鐵律:利用步驟僅方法論,不直接執行


def test_llm_jailbreak_expansion_playbooks():
    """越獄技術分類擴充(llm-006~011)入庫可查,payload 全良性。"""
    lib = load_library()
    for q, tid in [("Crescendo", "llm-006"), ("Skeleton Key", "llm-006"),
                   ("Many-shot", "llm-006"), ("persona", "llm-007"),
                   ("Policy Puppetry", "llm-007"), ("Base64", "llm-008"),
                   ("ArtPrompt", "llm-008"), ("exfil", "llm-009"),
                   ("Confused Deputy", "llm-009"), ("Likert", "llm-010"),
                   ("Echo Chamber", "llm-010"), ("Vision", "llm-011"),
                   ("OCR", "llm-011")]:
        hits = {d.id for d in search(lib, query=q)}
        assert tid in hits, f"查詢 {q} 未命中 {tid}: {hits}"
    # llm 家族是 benign probe 劇本(同 llm-001 設計):可執行但 payload 全良性標記
    for n in range(6, 12):
        d = get_by_id(lib, f"llm-{n:03d}")
        assert d is not None, f"llm-{n:03d} 未入庫"
        assert d.target_type == "llm_app"
        assert d.payload_policy == "benign", f"llm-{n:03d} 必須良性 payload"
    # 出處標注:方法來源論文/機構名入庫
    d6 = get_by_id(lib, "llm-006")
    assert d6 is not None and "Crescendo" in d6.render() and "Anthropic" in d6.render()
    d10 = get_by_id(lib, "llm-010")
    assert d10 is not None and "Unit 42" in d10.render()
    # 安全紅線:外洩向量只用假域名
    d9 = get_by_id(lib, "llm-009")
    r9 = d9.render()
    assert "example.invalid" in r9


def test_infra_exposure_playbooks():
    """基礎設施暴露面族(31-35):數據服務/管理控制台/容器控制面/子網域接管/JWT。"""
    lib = load_library()
    for q, tid in [("redis", "web-031"), ("elasticsearch", "web-031"),
                   ("jenkins", "web-032"), ("adminer", "web-032"),
                   ("docker", "web-033"), ("kubernetes", "web-033"),
                   ("subdomain", "web-034"), ("cname", "web-034"),
                   ("jwt", "web-035"), ("jku", "web-035")]:
        hits = {d.id for d in search(lib, query=q)}
        assert tid in hits, f"查詢 {q} 未命中 {tid}: {hits}"
    for n in range(31, 36):
        d = get_by_id(lib, f"web-{n:03d}")
        assert d is not None and not d.executable, f"web-{n:03d} 必須是方法論劇本"
        assert d.payload_policy == "methodology-only"
    # 真實 campaign 出處與紅線敘事入庫
    d32 = get_by_id(lib, "web-032")
    assert "Trend Micro" in d32.render() and "嚴禁" in d32.render()
    d34 = get_by_id(lib, "web-034")
    assert "Censys" in d34.render()
    d35 = get_by_id(lib, "web-035")
    assert "RFC 8725" in d35.render()


def test_framework_exposure_playbooks():
    """框架暴露面族(27-30):WordPress/Laravel-Django 調試/Actuator/.git 暴露入庫可查。"""
    lib = load_library()
    for q, tid in [("wordpress", "web-027"), ("xmlrpc", "web-027"),
                   ("wp-config", "web-027"), ("laravel", "web-028"),
                   ("phpinfo", "web-028"), ("django", "web-028"),
                   ("actuator", "web-029"), ("heapdump", "web-029"),
                   ("jolokia", "web-029"), (".git", "web-030"),
                   ("sourcemap", "web-030")]:
        hits = {d.id for d in search(lib, query=q)}
        assert tid in hits, f"查詢 {q} 未命中 {tid}: {hits}"
    # 全部非執行型(方法論),且證據紀律入庫:得 200 也不落地 secret
    for n in range(27, 31):
        d = get_by_id(lib, f"web-{n:03d}")
        assert d is not None and not d.executable, f"web-{n:03d} 必須是方法論劇本"
        assert d.payload_policy == "methodology-only"
    d27 = get_by_id(lib, "web-027")
    assert d27 is not None and "WPScan" in d27.render()
    d29 = get_by_id(lib, "web-029")
    assert d29 is not None and "heapdump" in d29.render()
    # 嚴禁全量拉取/施壓的紅線敘事必須在知識文本裡
    assert "嚴禁" in d29.render() and "嚴禁" in get_by_id(lib, "web-030").render()


def test_operator_doc_playbooks():
    """操作者文件《現代 Web 攻擊底層邏輯》提煉的六本(21-26)+web-006 升級入庫可查。"""
    lib = load_library()
    for q, tid in [("SSRF", "web-021"), ("IMDS", "web-021"), ("SSTI", "web-022"),
                   ("Slowloris", "web-026"), ("憑證填充", "web-026"),
                   ("Fail-Open", "web-025"), ("Ambient", "web-024")]:
        hits = {d.id for d in search(lib, query=q)}
        assert tid in hits, f"查詢 {q} 未命中 {tid}: {hits}"
    # 文件出處標注
    d21 = get_by_id(lib, "web-021")
    assert d21 is not None and "Common_Web_Attack_Techniques" in d21.render()
    # 全部非執行型(方法論)
    for n in range(21, 27):
        d = get_by_id(lib, f"web-{n:03d}")
        assert d is not None and not d.executable, f"web-{n:03d} 必須是方法論劇本"
    # web-006 升級後六步驟與探測細節保留(向後相容)
    d6 = get_by_id(lib, "web-006")
    assert d6 is not None
    kinds = [s["name"] for s in d6.steps]
    for step in ("recon", "fingerprint", "probe", "automate", "verify", "poc"):
        assert step in kinds
    assert "參數化查詢" in d6.render()  # 升級:架構級修復原理入庫


def test_public_disclosure_playbooks():
    """公開通報蒸餾族(39-41):業務邏輯狀態機/請求來源信任/回調網址信任入庫可查。"""
    lib = load_library()
    for q, tid in [("邀請碼", "web-039"), ("優惠券", "web-039"),
                   ("狀態機", "web-039"), ("X-Forwarded-For", "web-040"),
                   ("轉發頭", "web-040"), ("稽核", "web-040"),
                   ("重定向", "web-041"), ("回調", "web-041"),
                   ("redirect", "web-041")]:
        hits = {d.id for d in search(lib, query=q)}
        assert tid in hits, f"查詢 {q} 未命中 {tid}: {hits}"
    for n in (39, 40, 41):
        d = get_by_id(lib, f"web-{n:03d}")
        assert d is not None and not d.executable, f"web-{n:03d} 必須是方法論劇本"
        assert d.payload_policy == "methodology-only"
        assert d.phase in ("recon", "fingerprint", "inject", "verify", "poc", "report"), \
            f"web-{n:03d} phase 非法: {d.phase}"
        # 誤報防呆與紅線敘事必須在知識文本裡
        assert "嚴禁" in d.render(), f"web-{n:03d} 缺少紅線敘事"
    # 核心方法論入庫(去識別化:不斷言任何可反向關聯受害站的通報流水號)
    assert "三段證據鏈" in get_by_id(lib, "web-039").render()
    assert "快取" in get_by_id(lib, "web-040").render()  # CDN 快取漂移歸因防呆
    assert "密碼重設" in get_by_id(lib, "web-041").render()  # ATO 掛鏈分級
    # web-032 暴露面擴張(自建 CMS 弱口令+監控設備)與 web-025 認證閘門差分入庫
    assert "缺失性觀察" in get_by_id(lib, "web-032").render()
    assert "認證閘門" in get_by_id(lib, "web-025").render()


def test_zero_day_research_reinforcement():
    """2026-10-03 公開通報研究補強批:web-032 弱口令證據方法論/web-006 信任鏈分岔/
    web-023 教育類儲存點/web-030 目錄索引與活動殘件,入庫可查且紅線敘事齊全。"""
    lib = load_library()
    for q, tid in [("殭屍活動站", "web-032"), ("預設密碼", "web-032"),
                   ("個資密度", "web-032"), ("目錄索引", "web-030"),
                   ("社團", "web-023")]:
        hits = {d.id for d in search(lib, query=q)}
        assert tid in hits, f"查詢 {q} 未命中 {tid}: {hits}"
    d32 = get_by_id(lib, "web-032")
    # 非侵入性證據鏈:文件化口令線索 + 存在登入頁≠弱口令 防呆
    assert "簡章" in d32.render() and "存在登入頁" in d32.render()
    assert "pending-approval" in d32.render()
    # web-006 信任鏈分岔必須交叉引用 web-040(轉發頭信任族)
    d6 = get_by_id(lib, "web-006")
    assert "web-040" in d6.render()
    # web-030 目錄索引 probe 掛 web-032 立案紀律,嚴禁第三人資料落盤
    d30 = get_by_id(lib, "web-030")
    assert "Index of /" in d30.render() and "嚴禁下載" in d30.render()
    # web-023 學校語境敘事三軸
    d23 = get_by_id(lib, "web-023")
    assert "學生會" in d23.render() and "審核意見" in d23.render()


def test_triage_matrix_playbook_and_reinforcement():
    """2026-10-07 研究建議批次:新增 web-042 分診矩陣(上游分診層)+
    web-036 資源形態差分/web-006 注入佇列與產業分級/web-030 LLM 金鑰分流/
    web-020 登錄申報高危族/web-032 賽後殘件軸,入庫可查且紅線敘事齊全。"""
    lib = load_library()
    # --- web-042 新本體:可載入、非執行、phase 合法、關鍵詞可檢索 ---
    d42 = get_by_id(lib, "web-042")
    assert d42 is not None
    assert not d42.executable and d42.payload_policy == "methodology-only"
    assert d42.phase in ("recon", "fingerprint", "inject", "verify", "poc", "report")
    for q in ("分診矩陣", "技術堆疊指紋", "產業資料敏感度"):
        hits = {d.id for d in search(lib, query=q)}
        assert "web-042" in hits, f"查詢 {q} 未命中 web-042: {hits}"
    r42 = d42.render()
    # 執行順序鐵律(暴露面優先)+煞車(憑證不做利用)+產業加權+誤報防呆三條回指
    assert "暴露面優先" in r42 and "不做利用" in r42
    assert "醫療" in r42 and "教育" in r42 and "公部門" in r42
    for ref in ("web-006", "web-030", "web-036", "web-037", "web-038", "web-032"):
        assert ref in r42, f"web-042 缺少對 {ref} 的分診交叉引用"
    assert "台灣漏洞通報平台" in r42  # 出處去識別化(無通報流水號)
    # --- web-036 資源形態差分:第一命中形態入庫 ---
    d36 = get_by_id(lib, "web-036")
    assert "資源形態差分" in d36.render()
    assert "列表" in d36.render() and "單筆詳情" in d36.render()
    assert "欄位全遮罩" in d36.render()  # 遮罩≠有授權檢查防呆
    assert "Swagger" in d36.render()  # 詳情端點清單反推捷徑
    # --- web-006 注入側:內容端點佇列+產業分級+假陰性防呆 ---
    d6 = get_by_id(lib, "web-006")
    r6 = d6.render()
    assert "內容端點優先佇列" in r6 and "web-042" in r6
    assert "web-038" in r6 and "時間盲注" in r6  # 假陰性改道,不得直接判無漏洞
    assert "醫療" in r6  # 產業資料敏感度定錨
    kinds6 = [s["name"] for s in d6.steps]
    assert kinds6[-1] == "reference"  # note 不穿插 probe 紀律維持
    # --- web-030 LLM/AI 金鑰分流+三軸影響敘事+雙橋接 ---
    d30 = get_by_id(lib, "web-030")
    r30 = d30.render()
    assert "金鑰類型分流" in r30
    assert "計費濫用" in r30 and "出境" in r30 and "第二信任邊界" in r30
    assert "web-016" in r30 and "web-018" in r30  # 反向橋接+ACRSTEALER 同鏈
    hits = {d.id for d in search(lib, query="AI 供應商金鑰")}
    assert "web-030" in hits
    # --- web-020 登錄/申報多租戶高危族+欄位白名單缺失性觀察 ---
    d20 = get_by_id(lib, "web-020")
    assert "登錄/申報" in d20.render()
    assert "回應欄位白名單" in d20.render()
    hits = {d.id for d in search(lib, query="登錄/申報")}
    assert "web-020" in hits
    # --- web-032 賽後登錄申報站殘件軸與 web-030 串接 ---
    d32 = get_by_id(lib, "web-032")
    assert "無人看守" in d32.render() and "web-030" in d32.render()
    hits = {d.id for d in search(lib, query="賽後登錄")}
    assert "web-032" in hits
