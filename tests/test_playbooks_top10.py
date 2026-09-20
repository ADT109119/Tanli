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
