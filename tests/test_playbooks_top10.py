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
    """操作者實務案例(web-019 開放式發信中繼)與泛 BOLA 家族(web-020)入庫可查。"""
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
