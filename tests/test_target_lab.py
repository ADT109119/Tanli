"""TargetLab 本地靶場測試(M5)- 全程僅 127.0.0.1,無 Docker、無外部依賴。"""

import socket
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from redteam.target_lab import TargetLab

#: /secure 應帶齊的安全回應標頭(與靶場定義一致)
EXPECTED_SECURE_HEADERS = {
    "content-security-policy": "default-src 'self'",
    "strict-transport-security": "max-age=63072000; includeSubDomains",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
}


def _get(url: str):
    resp = urllib.request.urlopen(url, timeout=5)
    headers = {k.lower(): v for k, v in resp.getheaders()}
    return resp.status, headers, resp.read().decode()


def test_base_url_format():
    """start() 回傳的 base_url 應為 http://127.0.0.1:<port> 格式。"""
    lab = TargetLab()
    assert lab.base_url == ""  # 未啟動前無 base_url
    url = lab.start()
    try:
        assert url.startswith("http://127.0.0.1:")
        port = int(url.rsplit(":", 1)[1])
        assert 1 <= port <= 65535
        # 冪等:重複 start() 回傳同一個 base_url
        assert lab.start() == url
    finally:
        lab.stop()


def test_insecure_home_missing_all_security_headers():
    """/ 刻意全缺安全回應標頭,cookie 缺 HttpOnly/Secure。"""
    with TargetLab() as lab:
        status, headers, body = _get(lab.base_url + "/")
        assert status == 200
        assert "insecure" in body
        for h in EXPECTED_SECURE_HEADERS:
            assert h not in headers, f"/ 不應帶 {h}"
        sc = headers.get("set-cookie", "")
        assert "sid=abc" in sc
        assert "httponly" not in sc.lower()
        assert "secure" not in sc.lower()


def test_secure_page_full_hardening():
    """/secure 帶齊安全回應標頭 + cookie 屬性完整。"""
    with TargetLab() as lab:
        status, headers, body = _get(lab.base_url + "/secure")
        assert status == 200
        assert "secure" in body
        for h, expect in EXPECTED_SECURE_HEADERS.items():
            assert headers.get(h) == expect, f"/secure 的 {h} 應為 {expect!r}"
        sc = headers.get("set-cookie", "").lower()
        assert "sid=abc" in sc
        assert "httponly" in sc and "secure" in sc


def test_sql_echo():
    """/sql echo id 參數(預設 id=1)。"""
    with TargetLab() as lab:
        _, _, default_body = _get(lab.base_url + "/sql")
        assert default_body.strip() == "id=1"
        _, _, echoed = _get(lab.base_url + "/sql?id=42")
        assert echoed.strip() == "id=42"


def test_unknown_path_404():
    with TargetLab() as lab:
        import urllib.error

        try:
            urllib.request.urlopen(lab.base_url + "/nope", timeout=5)
            assert False, "should raise HTTPError"
        except urllib.error.HTTPError as e:
            assert e.code == 404


def test_stop_releases_port():
    """stop() 後原 port 應已釋放(可重新 bind 成功)。"""
    lab = TargetLab()
    url = lab.start()
    port = int(url.rsplit(":", 1)[1])
    lab.stop()
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))  # bind 成功即代表 port 已釋放
    finally:
        s.close()


def test_stop_idempotent_and_noop():
    """stop() 可重複呼叫;未啟動就 stop() 為 no-op。"""
    lab = TargetLab()
    lab.stop()  # no-op,不應拋例外
    lab.start()
    lab.stop()
    lab.stop()  # 重複 stop 安全
