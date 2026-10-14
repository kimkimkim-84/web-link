import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import hashlib
import json
import httpx, pytest
import sonicwall_mcp as s

TOKEN = "tok-123"
REALM = "admin-users@fw"
CHALLENGE = f'Digest algorithm=SHA-256, realm="{REALM}", qop="auth", nonce="abc", opaque="xyz"'
SNWL_CHALLENGE = CHALLENGE + ", userhash=true"


def sha(x):
    return hashlib.sha256(x.encode()).hexdigest()


def digest_ok(header, method, user="u", password="p"):
    """서버 쪽 RFC 7616 검증(userhash 포함)."""
    f = s.parse_digest(header)
    expected_user = sha(f"{user}:{REALM}") if f.get("userhash") == "true" else user
    if f.get("username") != expected_user or f.get("nonce") != "abc" or f.get("opaque") != "xyz":
        return False
    ha1, ha2 = sha(f"{user}:{REALM}:{password}"), sha(f"{method}:{f['uri']}")
    return f["response"] == sha(f"{ha1}:abc:{f['nc']}:{f['cnonce']}:{f['qop']}:{ha2}")


class FakeFirewall:
    """NSa 3800 / SonicOS 8.2 실측 동작을 흉내 낸 모의 장비.

    - POST /auth: Digest(SHA-256) 요구. extended 범위 + 본문 snwl=true 일 때만 bearer_token 발급
    - 그 외 경로: Authorization: Bearer <토큰> 이 없으면 401 E_UNAUTHORIZED
    """

    def __init__(self, data=None, expire_first=False):
        self.calls = []
        self.data = data if data is not None else {"firmware_version": "8.2.0"}
        self.expire_first = expire_first
        self.token = TOKEN

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.calls.append((req.method, req.url.path))
        auth = req.headers.get("authorization", "")
        if req.url.path.endswith("/auth") and req.method == "POST":
            snwl = req.headers.get("x-snwl-api-scope") == "extended"
            if not auth.startswith("Digest "):
                # 웹 UI용 로그인(extended)은 챌린지를 전용 헤더로, userhash를 요구하며 보낸다
                if snwl:
                    return httpx.Response(401, headers={"X-Snwl-Authenticate": SNWL_CHALLENGE})
                return httpx.Response(401, headers={"WWW-Authenticate": CHALLENGE})
            if not digest_ok(auth, "POST") or (snwl and "userhash=true" not in auth):
                return httpx.Response(401, json={"status": {"info": [{"code": "E_UNAUTHORIZED", "auth_code": "API_AUTH_REMOTE_USER"}]}})
            info = {"code": "E_OK", "message": "Login as a user.", "read_only": "Yes"}
            body = json.loads(req.content or b"{}")
            if body.get("snwl") and req.headers.get("origin") != "https://fw":
                return httpx.Response(401)  # 웹 UI 로그인은 출처(Origin) 검사
            assert body.get("override") is False  # 다른 관리자 세션을 빼앗지 않음
            if req.headers.get("x-snwl-api-scope") == "extended" and body.get("snwl") is True:
                info["bearer_token"] = self.token
            return httpx.Response(200, json={"status": {"success": True, "info": [info]}})
        if auth != f"Bearer {self.token}":
            return httpx.Response(401, json={"status": {"info": [{"code": "E_UNAUTHORIZED"}]}})
        if self.expire_first:
            self.expire_first = False
            self.token = "tok-new"  # 서버 쪽에서 토큰 만료
            return httpx.Response(401, json={"status": {"info": [{"code": "E_UNAUTHORIZED"}]}})
        if req.method == "DELETE":
            return httpx.Response(200, json={})
        return httpx.Response(200, json=self.data)


def make(fw):
    http = httpx.Client(base_url="https://fw", transport=httpx.MockTransport(fw))
    return s.SonicWallClient(client=http, user="u", password="p")


def test_bearer_flow_and_redact():
    fw = FakeFirewall(data={"address_objects": [{"name": "a", "psk": "x", "shared_secret": ""}]})
    c = make(fw)
    out = s.render(c.get("address-objects/ipv4"))
    assert fw.calls[-1] == ("GET", "/api/sonicos/address-objects/ipv4")
    assert "***REDACTED***" in out and '"x"' not in out


def test_relogin_when_token_expires():
    fw = FakeFirewall(expire_first=True)
    assert make(fw).get("version") == {"firmware_version": "8.2.0"}
    assert fw.calls.count(("POST", "/api/sonicos/auth")) == 4  # (챌린지+Digest) x 2회 로그인


def test_missing_token_gives_clear_error():
    def h(req):
        if "authorization" not in req.headers:
            return httpx.Response(401, headers={"WWW-Authenticate": CHALLENGE})
        return httpx.Response(200, json={"status": {"info": [{"code": "E_OK", "message": "x"}]}})

    with pytest.raises(s.SonicWallError, match="bearer_token이 없습니다"):
        make(h).get("version")


def test_logout_sends_bearer():
    fw = FakeFirewall()
    c = make(fw)
    c.get("zones")
    c.close()
    assert fw.calls[-1] == ("DELETE", "/api/sonicos/auth")


@pytest.mark.parametrize("p", ["../etc/passwd", "auth", "export/current-config", "version?x=1", "administration"])
def test_blocked_paths(p):
    with pytest.raises(s.SonicWallError):
        s.validate_path(p)


def test_only_get_is_ever_sent():
    fw = FakeFirewall()
    c = make(fw)
    c.get("zones")
    methods = {m for m, _ in fw.calls}
    assert methods <= {"POST", "GET"}  # POST는 /auth 로그인 전용
    assert all(path.endswith("/auth") for m, path in fw.calls if m == "POST")


def test_login_failure_shows_server_reason():
    def h(req):
        return httpx.Response(401, headers={"WWW-Authenticate": "Basic realm=x"},
                              json={"status": {"info": [{"message": "Bad credentials"}]}})

    with pytest.raises(s.SonicWallError) as e:
        make(h).get("version")
    msg = str(e.value)
    assert "401" in msg and "Basic" in msg and "Bad credentials" in msg


def test_pin_match_and_mismatch(monkeypatch):
    fp = "ab" * 32
    monkeypatch.setattr(s, "server_cert_fingerprint", lambda h, p: fp)
    c = make(FakeFirewall())
    c._pin, c._host, c._port = s.normalize_fp(fp.upper()), "fw", 443
    assert c.get("version") == {"firmware_version": "8.2.0"}

    fw2 = FakeFirewall()
    c2 = make(fw2)
    c2._pin, c2._host, c2._port = "cd" * 32, "fw", 443
    with pytest.raises(s.SonicWallError, match="지문 불일치"):
        c2.get("version")
    assert fw2.calls == []  # 지문이 다르면 계정 정보를 보내지 않는다


def test_truncate_list():
    out = s.render({"items": list(range(500))}, limit=10)
    assert "500개 중 10개" in out


def test_never_enters_config_mode():
    fw = FakeFirewall()
    c = make(fw)
    c.get("zones")
    c.close()
    assert not any("config-mode" in path for _, path in fw.calls)


def test_login_failure_reports_plain_login_comparison():
    def h(req):
        auth = req.headers.get("authorization", "")
        if not auth:
            return httpx.Response(401, headers={"WWW-Authenticate": CHALLENGE})
        if req.method == "DELETE":
            return httpx.Response(200, json={})
        return httpx.Response(401 if req.content else 200, json={})  # snwl 로그인만 거부

    with pytest.raises(s.SonicWallError, match=r"일반 로그인\): HTTP 200"):
        make(h).get("version")


def test_challenge_summary_hides_nonce():
    r = httpx.Response(401, headers={"X-Snwl-Authenticate": CHALLENGE})
    out = s.challenge_summary(r)
    assert "SHA-256" in out and "abc" not in out and "xyz" not in out


def test_wrong_password_rejected_by_digest_check():
    fw = FakeFirewall()
    http = httpx.Client(base_url="https://fw", transport=httpx.MockTransport(fw))
    c = s.SonicWallClient(client=http, user="u", password="WRONG")
    with pytest.raises(s.SonicWallError, match="받은 Digest 챌린지: .*userhash=true") as e:
        c.get("version")
    assert "abc" not in str(e.value) and "xyz" not in str(e.value)  # nonce/opaque 비노출


def test_digest_without_userhash():
    req = httpx.Request("POST", "https://fw/api/sonicos/auth")
    a = s.SnwlDigestAuth("u", "p")
    hdr = a._build(req, s.parse_digest(CHALLENGE))
    assert 'username="u"' in hdr and "userhash" not in hdr and digest_ok(hdr, "POST")
