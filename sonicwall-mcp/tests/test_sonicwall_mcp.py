import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import httpx, pytest
import sonicwall_mcp as s


def make(handler):
    http = httpx.Client(base_url="https://fw", transport=httpx.MockTransport(handler))
    return s.SonicWallClient(client=http, user="u", password="p")


def test_login_then_get_and_redact():
    calls = []

    def h(req):
        calls.append((req.method, req.url.path))
        if req.method == "POST":
            assert req.headers["authorization"].startswith("Basic ")
            return httpx.Response(200, json={"status": {"success": True}})
        return httpx.Response(200, json={"address_objects": [{"name": "a", "psk": "x", "shared_secret": ""}]})

    c = make(h)
    out = s.render(c.get("address-objects/ipv4"))
    assert calls == [("POST", "/api/sonicos/auth"), ("GET", "/api/sonicos/address-objects/ipv4")]
    assert "***REDACTED***" in out and '"x"' not in out


def test_relogin_on_401():
    state = {"n": 0}

    def h(req):
        if req.method == "POST":
            return httpx.Response(200, json={})
        state["n"] += 1
        return httpx.Response(401) if state["n"] == 1 else httpx.Response(200, json={"ok": 1})

    assert make(h).get("version") == {"ok": 1}


@pytest.mark.parametrize("p", ["../etc/passwd", "auth", "export/current-config", "version?x=1", "administration"])
def test_blocked_paths(p):
    with pytest.raises(s.SonicWallError):
        s.validate_path(p)


def test_only_get_is_ever_sent():
    methods = set()

    def h(req):
        methods.add(req.method)
        return httpx.Response(200, json={})

    c = make(h)
    c.get("zones")
    assert methods <= {"POST", "GET"} and not methods & {"PUT", "PATCH", "DELETE"}  # POST는 /auth 로그인 전용


def test_truncate_list():
    out = s.render({"items": list(range(500))}, limit=10)
    assert "500개 중 10개" in out
