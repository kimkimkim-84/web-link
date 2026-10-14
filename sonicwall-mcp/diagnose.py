"""로그인 이후 401 원인 진단 v4 (경로/세션/헤더 영향 비교). GET + 로그인/로그아웃만 수행한다.

비밀번호·토큰·쿠키·nonce 값은 출력하지 않는다(길이만 표시). 출력 전체를 전달해도 된다.
사용: SONICWALL_* 환경변수 설정 후  python diagnose.py
"""
import re

import httpx

import sonicwall_mcp as s

PATHS = ["version", "zones", "access-rules/ipv4"]
JSON = {"Accept": "application/json"}
SENSITIVE = re.compile(r"token|bearer|jwt|sess|sid|key|secret|pass|auth(?!_code)|cookie|nonce|opaque", re.I)
TOKEN_HINT = re.compile(r"token|bearer|jwt|sess|sid", re.I)


def walk(obj, path=""):
    """(경로, 값) 목록. 값이 문자열/숫자/불리언인 잎 노드만."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk(v, f"{path}[{i}]")
    else:
        yield path, obj


def show(path, v):
    if SENSITIVE.search(path.split(".")[-1]) or (isinstance(v, str) and len(v) > 60):
        return f"<{type(v).__name__} 길이={len(str(v))}>"
    return repr(v)


def status_of(r):
    try:
        return r.status_code, (r.json().get("status", {}).get("info") or [{}])[0].get("code")
    except ValueError:
        return r.status_code, None


def main() -> None:
    c = s.SonicWallClient()
    h, user, pw = c._http, c._user, c._password
    c._check_pin()

    r = h.post(f"{s.API_BASE}/auth", auth=httpx.DigestAuth(user, pw))
    info = (r.json().get("status", {}).get("info") or [{}])[0]
    print("== 로그인 ==", r.status_code, {k: info.get(k) for k in ("code", "message", "auth_code", "read_only", "privilege")})

    def probe(label, path, creds=False, accept=True, ctype=False):
        headers = dict(JSON) if accept else {}
        if ctype:
            headers["Content-Type"] = "application/json"
        kw = {"auth": httpx.DigestAuth(user, pw)} if creds else {}
        g = h.get(f"{s.API_BASE}/{path}", headers=headers, **kw)
        extra = sorted(k for k in g.headers.keys() if k not in ("content-type", "content-length", "cache-control", "expires", "server", "x-content-type-options", "date"))
        print(f"  {label:<44} -> {status_of(g)}  추가 응답 헤더: {extra or '없음'}")

    print("\n== 로그인 직후 시험 (자격 증명 없음) ==")
    probe("GET /auth", "auth")
    probe("GET /version", "version")
    probe("GET /no-such-path-xyz (존재하지 않는 경로)", "no-such-path-xyz")
    print("\n== 요청마다 Digest ==")
    probe("GET /auth", "auth", creds=True)
    probe("GET /version", "version", creds=True)
    probe("GET /version (Accept 헤더 없이)", "version", creds=True, accept=False)
    probe("GET /version (+Content-Type: json)", "version", creds=True, ctype=True)
    probe("GET /no-such-path-xyz", "no-such-path-xyz", creds=True)
    probe("GET /zones", "zones", creds=True)
    print("\n== 로그아웃 ==", h.delete(f"{s.API_BASE}/auth").status_code)
    h.close()


if __name__ == "__main__":
    try:
        main()
    except (s.SonicWallError, httpx.HTTPError) as e:
        print("오류:", type(e).__name__, e)
