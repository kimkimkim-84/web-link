"""SonicWall(SonicOS 7/8, 8세대 포함) 읽기 전용 MCP 서버.

SonicOS REST API(/api/sonicos)를 감싸며 GET 요청만 보낸다.
설정 변경(POST/PUT/PATCH/DELETE, commit)은 코드 차원에서 불가능하다.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import ssl
import threading
from urllib.request import parse_http_list, parse_keqv_list
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

logging.getLogger("httpx").setLevel(logging.WARNING)  # 요청 로그에 주소가 남지 않게

API_BASE = "/api/sonicos"
# SonicOS 8.2 웹 UI와 같은 로그인 형식. 본문의 snwl=true 로 bearer_token이 발급된다.
# override=false: 다른 관리자의 세션/설정 모드를 빼앗지 않는다. (config-mode 진입은 하지 않음)
SNWL_HEADERS = {"X-Snwl-Api-Scope": "extended", "X-Snwl-Timer": "no-reset"}
LOGIN_BODY = {"override": False, "snwl": True}
MAX_CHARS = 60_000
SECRET_KEY = re.compile(r"pass(word)?|secret|psk|shared_key|private_key|token|community|^key$", re.I)
# 임의 조회 도구가 접근할 수 있는 경로. 인증/관리자/백업/설정 내보내기 계열은 제외.
ALLOWED_PREFIXES = (
    "version", "zones", "interfaces", "address-objects", "address-groups",
    "service-objects", "service-groups", "access-rules", "nat-policies",
    "route-policies", "vpn", "reporting", "user/status", "dhcp-server",
    "security-services", "high-availability", "licenses", "tsr",
)
PATH_OK = re.compile(r"^[A-Za-z0-9._~\-/{}]+$")


class SonicWallError(RuntimeError):
    pass


def redact(obj: Any) -> Any:
    """응답 JSON에서 비밀번호/PSK 등 민감 값을 가린다."""
    if isinstance(obj, dict):
        return {k: ("***REDACTED***" if SECRET_KEY.search(k) and v not in (None, "", False) else redact(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def validate_path(path: str) -> str:
    p = path.strip().lstrip("/")
    if p.startswith("api/sonicos/"):
        p = p[len("api/sonicos/"):]
    if ".." in p or not PATH_OK.match(p):
        raise SonicWallError(f"허용되지 않는 경로 형식: {path!r}")
    if not any(p == a or p.startswith(a + "/") for a in ALLOWED_PREFIXES):
        raise SonicWallError(f"허용 목록에 없는 경로: {path!r} (허용: {', '.join(ALLOWED_PREFIXES)})")
    return p


def parse_digest(header: str) -> dict[str, str]:
    """'Digest a="b", c=d' -> {"a": "b", "c": "d"}"""
    _, _, fields = header.partition(" ")
    return parse_keqv_list([f.strip() for f in parse_http_list(fields)])


DIGEST_HASHES = {"MD5": hashlib.md5, "SHA-256": hashlib.sha256, "SHA-512": hashlib.sha512}


class SnwlDigestAuth(httpx.Auth):
    """RFC 7616 Digest 인증(userhash 지원).

    SonicOS 8.2의 웹 UI용(snwl) 로그인은 챌린지를 WWW-Authenticate 대신 X-Snwl-Authenticate로
    보낸다(브라우저 로그인 팝업 방지). httpx 기본 DigestAuth는 이 헤더와 userhash를 지원하지 않는다.
    """

    def __init__(self, username: str, password: str) -> None:
        self._user, self._password = username, password
        self.challenge_info = ""  # 진단용: nonce/opaque 값을 뺀 챌린지 파라미터

    def auth_flow(self, request: httpx.Request):
        response = yield request
        if response.status_code != 401:
            return
        header = next((v for name in ("www-authenticate", "x-snwl-authenticate")
                       for v in response.headers.get_list(name) if v.lower().startswith("digest ")), None)
        if header is None:
            return
        params = parse_digest(header)
        self.challenge_info = ", ".join(f"{k}={'…' if k in ('nonce', 'opaque') else v}" for k, v in params.items())
        request.headers["Authorization"] = self._build(request, params)
        yield request

    def _build(self, request: httpx.Request, c: dict[str, str]) -> str:
        algorithm = c.get("algorithm", "MD5")
        base = algorithm.upper().removesuffix("-SESS")
        if base not in DIGEST_HASHES:
            raise SonicWallError(f"지원하지 않는 Digest 알고리즘: {algorithm}")

        def h(text: str) -> str:
            return DIGEST_HASHES[base](text.encode("utf-8")).hexdigest()

        realm, nonce = c.get("realm", ""), c.get("nonce", "")
        uri = request.url.raw_path.decode()
        cnonce, nc = os.urandom(16).hex(), "00000001"
        ha1 = h(f"{self._user}:{realm}:{self._password}")
        if algorithm.upper().endswith("-SESS"):
            ha1 = h(f"{ha1}:{nonce}:{cnonce}")
        ha2 = h(f"{request.method}:{uri}")
        qops = [q.strip() for q in c.get("qop", "").split(",") if q.strip()]
        if qops and "auth" not in qops:
            raise SonicWallError(f"지원하지 않는 qop: {c.get('qop')}")
        userhash = c.get("userhash", "").lower() == "true"
        fields = {
            "username": h(f"{self._user}:{realm}") if userhash else self._user,
            "realm": realm, "nonce": nonce, "uri": uri, "algorithm": algorithm,
            "response": h(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}") if qops else h(f"{ha1}:{nonce}:{ha2}"),
        }
        if "opaque" in c:
            fields["opaque"] = c["opaque"]
        if qops:
            fields.update(qop="auth", nc=nc, cnonce=cnonce)
        if userhash:
            fields["userhash"] = "true"
        bare = ("algorithm", "qop", "nc", "userhash")
        return "Digest " + ", ".join(f"{k}={v}" if k in bare else f'{k}="{v}"' for k, v in fields.items())


def challenge_summary(r: httpx.Response) -> str:
    """챌린지 헤더에서 방식/알고리즘만 추린다(nonce/opaque 값 제외)."""
    out = []
    for name in ("www-authenticate", "x-snwl-authenticate"):
        for v in r.headers.get_list(name):
            parts = [p for p in v.replace(",", " ").split() if not p.lower().startswith(("nonce", "opaque"))]
            out.append(f"{name}: {' '.join(parts)[:150]}")
    return "; ".join(out)


def normalize_fp(fp: str) -> str:
    return re.sub(r"[^0-9a-f]", "", fp.lower())


def server_cert_fingerprint(host: str, port: int) -> str:
    """서버 인증서(DER)의 SHA-256 지문. 검증 없이 인증서만 가져온다(로그인 정보는 보내지 않음)."""
    pem = ssl.get_server_certificate((host, port))
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


class SonicWallClient:
    """로그인(POST /auth)으로 bearer_token을 받아 GET만 수행하는 얇은 클라이언트."""

    def __init__(self, client: httpx.Client | None = None, user: str | None = None, password: str | None = None):
        self._pin: str | None = None
        self._token: str | None = None
        self._host = self._port = None
        self._lock = threading.Lock()
        self._user = user if user is not None else os.environ.get("SONICWALL_USER", "")
        self._password = password if password is not None else os.environ.get("SONICWALL_PASSWORD", "")
        self._logged_in = False
        if client is not None:
            self._http = client
            return
        host = os.environ.get("SONICWALL_HOST")
        if not host:
            raise SonicWallError("SONICWALL_HOST 환경변수가 필요합니다.")
        port = os.environ.get("SONICWALL_PORT", "443")
        verify: bool | str | ssl.SSLContext = os.environ.get("SONICWALL_CA_BUNDLE") or \
            os.environ.get("SONICWALL_VERIFY_TLS", "true").lower() != "false"
        pin = os.environ.get("SONICWALL_CERT_SHA256")
        if pin:
            # 자체서명 인증서: CA 검증 대신 지문 고정. 로그인 전에 지문이 다르면 중단한다.
            self._pin, self._host, self._port = normalize_fp(pin), host, int(port)
            if len(self._pin) != 64:
                raise SonicWallError("SONICWALL_CERT_SHA256은 SHA-256 지문(64자리 16진수)이어야 합니다.")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            verify = ctx
        self._http = httpx.Client(base_url=f"https://{host}:{port}", verify=verify, timeout=20.0)

    def _check_pin(self) -> None:
        if self._pin is None or self._host is None:
            return
        actual = server_cert_fingerprint(self._host, self._port)
        if actual != self._pin:
            raise SonicWallError(
                f"인증서 지문 불일치(중간자 공격 또는 인증서 교체 가능성). 기대={self._pin} 실제={actual}")

    def _base_headers(self) -> dict[str, str]:
        # 웹 UI 로그인(snwl)은 출처를 검사하므로 브라우저처럼 Origin/Referer를 보낸다.
        origin = str(self._http.base_url).rstrip("/")
        return {"Accept": "application/json", "Origin": origin, "Referer": origin + "/", **SNWL_HEADERS}

    def _headers(self) -> dict[str, str]:
        h = self._base_headers()
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    def _login(self) -> None:
        self._check_pin()  # 계정 정보를 보내기 전에 서버를 확인
        if not (self._user and self._password):
            raise SonicWallError("SONICWALL_USER / SONICWALL_PASSWORD 환경변수가 필요합니다.")
        self._token = None
        # SonicOS 8.2: 웹 UI와 같은 헤더/본문으로 로그인해야 bearer_token을 받고, 이후 요청은
        # Authorization: Bearer <토큰>으로 인증한다. 웹 UI는 이 로그인을 Basic으로 한다(실측:
        # Digest는 API_AUTH_REMOTE_USER로 거부됨). Basic이 거부되면 Digest로 대체한다.
        # Basic의 비밀번호는 TLS 안에서만, 인증서 지문 확인(_check_pin) 뒤에만 전송된다.
        headers = self._base_headers()
        url = f"{API_BASE}/auth"
        digest = SnwlDigestAuth(self._user, self._password)
        r = self._http.post(url, headers=headers, json=LOGIN_BODY, auth=(self._user, self._password))
        if r.status_code == 401:
            r = self._http.post(url, headers=headers, json=LOGIN_BODY, auth=digest)
        if r.status_code >= 400:
            hint = challenge_summary(r)
            raise SonicWallError(
                f"로그인 실패: HTTP {r.status_code}"
                + (f" | 챌린지: {hint}" if hint else "")
                + (f" | 받은 Digest 챌린지: {digest.challenge_info}" if digest.challenge_info else "")
                + (f" | 응답: {r.text[:300]}" if r.text else "")
                + f" | 응답 헤더: {sorted(r.headers.keys())}"
                + f" | 비교(본문/전용헤더 없는 일반 로그인): {self._plain_login_status()}")
        try:
            body = r.json()
        except ValueError:
            body = {}
        self.login_keys = sorted({k for k, _ in iter_items(body)})  # 진단용(키 이름만)
        token = find_key(body, "bearer_token")
        if not token:
            keys = sorted({k for k, _ in iter_items(body)})
            raise SonicWallError(f"로그인은 성공했지만 응답에 bearer_token이 없습니다. 응답 키: {keys}")
        self._token = str(token)
        self._logged_in = True

    def _plain_login_status(self) -> str:
        """진단용: 토큰 없는 일반 로그인이 되는지 확인하고 곧바로 로그아웃한다."""
        try:
            r = self._http.post(f"{API_BASE}/auth", auth=httpx.DigestAuth(self._user, self._password))
            if r.status_code < 400:
                self._http.delete(f"{API_BASE}/auth")
            return f"HTTP {r.status_code}"
        except httpx.HTTPError as e:
            return f"{type(e).__name__}"

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        p = validate_path(path)
        with self._lock:
            for attempt in (1, 2):
                if not self._logged_in:
                    self._login()
                r = self._http.get(f"{API_BASE}/{p}", params=params, headers=self._headers())
                if r.status_code == 401 and attempt == 1:  # 토큰 만료: 한 번 재로그인
                    self._logged_in = False
                    continue
                break
        if r.status_code >= 400:
            raise SonicWallError(f"GET /{p} 실패: HTTP {r.status_code} {r.text[:300]}")
        try:
            return r.json()
        except ValueError:
            return {"raw": r.text}

    def close(self) -> None:
        try:
            if self._logged_in:
                self._http.delete(f"{API_BASE}/auth", headers=self._headers())
        except httpx.HTTPError:
            pass
        finally:
            self._logged_in = False
            self._token = None
            self._http.close()


def iter_items(obj: Any):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k, v
            yield from iter_items(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from iter_items(v)


def find_key(obj: Any, key: str) -> Any:
    return next((v for k, v in iter_items(obj) if k == key and v), None)


_client: SonicWallClient | None = None


def client() -> SonicWallClient:
    global _client
    if _client is None:
        _client = SonicWallClient()
    return _client


def render(data: Any, limit: int = 100) -> str:
    data = redact(data)
    note = ""
    if isinstance(data, dict):
        for k, v in data.items():  # SonicOS는 {"address_objects":[...]} 같은 형태로 응답
            if isinstance(v, list) and len(v) > limit:
                data = {**data, k: v[:limit]}
                note = f"\n[주의] '{k}' {len(v)}개 중 {limit}개만 표시"
    elif isinstance(data, list) and len(data) > limit:
        note = f"\n[주의] {len(data)}개 중 {limit}개만 표시"
        data = data[:limit]
    text = json.dumps(data, ensure_ascii=False, indent=2)
    if len(text) > MAX_CHARS:
        text = text[:MAX_CHARS] + "\n...[잘림]"
    return text + note


def _tool(path: str, limit: int = 100) -> str:
    try:
        return render(client().get(path), limit)
    except (SonicWallError, httpx.HTTPError) as e:
        return f"오류: {e}"


mcp = FastMCP("sonicwall-readonly")


@mcp.tool()
def get_version() -> str:
    """SonicOS 버전/모델 정보를 조회한다."""
    return _tool("version")


@mcp.tool()
def list_zones() -> str:
    """보안 영역(Zone) 목록."""
    return _tool("zones")


@mcp.tool()
def list_interfaces(ip_version: str = "ipv4") -> str:
    """인터페이스 설정 목록. ip_version: ipv4 | ipv6."""
    return _tool(f"interfaces/{_ipv(ip_version)}")


@mcp.tool()
def list_address_objects(ip_version: str = "ipv4", limit: int = 100) -> str:
    """주소 객체 목록. ip_version: ipv4 | ipv6."""
    return _tool(f"address-objects/{_ipv(ip_version)}", limit)


@mcp.tool()
def list_service_objects(limit: int = 100) -> str:
    """서비스 객체 목록."""
    return _tool("service-objects", limit)


@mcp.tool()
def list_access_rules(ip_version: str = "ipv4", limit: int = 100) -> str:
    """방화벽 접근 규칙 목록. ip_version: ipv4 | ipv6."""
    return _tool(f"access-rules/{_ipv(ip_version)}", limit)


@mcp.tool()
def list_nat_policies(ip_version: str = "ipv4", limit: int = 100) -> str:
    """NAT 정책 목록. ip_version: ipv4 | ipv6."""
    return _tool(f"nat-policies/{_ipv(ip_version)}", limit)


@mcp.tool()
def list_route_policies(ip_version: str = "ipv4", limit: int = 100) -> str:
    """라우팅 정책 목록. ip_version: ipv4 | ipv6."""
    return _tool(f"route-policies/{_ipv(ip_version)}", limit)


@mcp.tool()
def sonicos_get(path: str, limit: int = 100) -> str:
    """허용 목록 내 임의 SonicOS API 경로를 GET으로 조회한다(읽기 전용).
    예: 'vpn/policies/ipv4/site-to-site', 'reporting/system/...'. 정확한 경로는
    장비의 HOME | API Swagger에서 확인."""
    return _tool(path, limit)


def _ipv(v: str) -> str:
    if v not in ("ipv4", "ipv6"):
        raise ValueError("ip_version은 ipv4 또는 ipv6")
    return v


def main() -> None:
    try:
        mcp.run()
    finally:
        if _client:
            _client.close()


if __name__ == "__main__":
    main()
