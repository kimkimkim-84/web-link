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
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

logging.getLogger("httpx").setLevel(logging.WARNING)  # 요청 로그에 주소가 남지 않게

API_BASE = "/api/sonicos"
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


def normalize_fp(fp: str) -> str:
    return re.sub(r"[^0-9a-f]", "", fp.lower())


def server_cert_fingerprint(host: str, port: int) -> str:
    """서버 인증서(DER)의 SHA-256 지문. 검증 없이 인증서만 가져온다(로그인 정보는 보내지 않음)."""
    pem = ssl.get_server_certificate((host, port))
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


class SonicWallClient:
    """세션 로그인(POST /auth) 후 GET만 수행하는 얇은 클라이언트."""

    def __init__(self, client: httpx.Client | None = None, user: str | None = None, password: str | None = None):
        self._pin: str | None = None
        self._auth = None
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

    def _login(self) -> None:
        self._check_pin()  # 계정 정보를 보내기 전에 서버를 확인
        if not (self._user and self._password):
            raise SonicWallError("SONICWALL_USER / SONICWALL_PASSWORD 환경변수가 필요합니다.")
        # SonicOS 8은 보통 Digest(SHA-256)를 요구한다. Digest를 먼저 시도하고, 서버가 Basic을
        # 요구하면 Basic으로 대체한다.
        digest = httpx.DigestAuth(self._user, self._password)
        r = self._http.post(f"{API_BASE}/auth", auth=digest)
        self._auth: httpx.Auth | tuple[str, str] | None = digest
        if r.status_code == 401 and "basic" in r.headers.get("www-authenticate", "").lower():
            self._auth = (self._user, self._password)
            r = self._http.post(f"{API_BASE}/auth", auth=self._auth)
        if r.status_code >= 400:
            hint = r.headers.get("www-authenticate", "")
            raise SonicWallError(
                f"로그인 실패: HTTP {r.status_code}"
                + (f" | WWW-Authenticate: {hint[:200]}" if hint else "")
                + (f" | 응답: {r.text[:300]}" if r.text else ""))
        self._logged_in = True

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        p = validate_path(path)
        with self._lock:
            for attempt in (1, 2):
                if not self._logged_in:
                    self._login()
                r = self._http.get(f"{API_BASE}/{p}", params=params, headers={"Accept": "application/json"})
                if r.status_code == 401 and self._auth is not None:
                    # 세션 쿠키가 없거나 만료: 요청 단위 인증으로 한 번 더 시도
                    r = self._http.get(f"{API_BASE}/{p}", params=params,
                                       headers={"Accept": "application/json"}, auth=self._auth)
                if r.status_code == 401 and attempt == 1:
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
                self._http.delete(f"{API_BASE}/auth")
        except httpx.HTTPError:
            pass
        finally:
            self._logged_in = False
            self._http.close()


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
