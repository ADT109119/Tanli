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
