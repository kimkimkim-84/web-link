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
            if "authorization" not in req.headers:
                return httpx.Response(401, headers={"WWW-Authenticate": 'Basic realm="x"'})
            assert req.headers["authorization"].startswith("Basic ")
            return httpx.Response(200, json={"status": {"success": True}})
        return httpx.Response(200, json={"address_objects": [{"name": "a", "psk": "x", "shared_secret": ""}]})

    c = make(h)
    out = s.render(c.get("address-objects/ipv4"))
    assert calls[-1] == ("GET", "/api/sonicos/address-objects/ipv4") and ("POST", "/api/sonicos/auth") in calls
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


def test_pin_match_and_mismatch(monkeypatch):
    fp = "ab" * 32
    monkeypatch.setattr(s, "server_cert_fingerprint", lambda h, p: fp)
    http = httpx.Client(base_url="https://fw", transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"ok": 1})))
    c = s.SonicWallClient(client=http, user="u", password="p")
    c._pin, c._host, c._port = s.normalize_fp(fp.upper()), "fw", 443
    assert c.get("version") == {"ok": 1}

    sent = []
    http2 = httpx.Client(base_url="https://fw", transport=httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(200, json={})))
    c2 = s.SonicWallClient(client=http2, user="u", password="p")
    c2._pin, c2._host, c2._port = "cd" * 32, "fw", 443
    with pytest.raises(s.SonicWallError, match="지문 불일치"):
        c2.get("version")
    assert sent == []  # 지문이 다르면 계정 정보를 보내지 않는다


def test_login_failure_shows_server_reason():
    def h(req):
        return httpx.Response(401, headers={"WWW-Authenticate": "Basic realm=x"},
                              json={"status": {"info": [{"message": "Bad credentials"}]}})

    with pytest.raises(s.SonicWallError) as e:
        make(h).get("version")
    msg = str(e.value)
    assert "401" in msg and "Basic realm" in msg and "Bad credentials" in msg


def test_digest_sha256_login():
    seen = []

    def h(req):
        if req.method == "POST":
            auth = req.headers.get("authorization", "")
            seen.append(auth[:20])
            if not auth:
                return httpx.Response(401, headers={"WWW-Authenticate": (
                    'Digest algorithm=SHA-256, realm="admin-users@fw", qop="auth", nonce="abc", opaque="xyz"')})
            assert auth.startswith("Digest ") and "algorithm=SHA-256" in auth and 'username="u"' in auth
            return httpx.Response(200, json={"ok": 1})
        return httpx.Response(200, json={"version": "8.2"})

    assert make(h).get("version") == {"version": "8.2"}
    assert seen[0] == "" and seen[-1].startswith("Digest ")
