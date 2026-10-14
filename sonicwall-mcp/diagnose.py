"""로그인 이후 401 원인 진단 v2. 읽기 전용(GET + 로그인/로그아웃)만 수행한다.

비밀번호와 쿠키/nonce 값은 출력하지 않는다. 출력 전체를 개발 세션에 전달해도 된다.
사용: SONICWALL_* 환경변수 설정 후  python diagnose.py
"""
import httpx

import sonicwall_mcp as s

PATHS = ["version", "zones", "interfaces/ipv4", "address-objects/ipv4", "access-rules/ipv4"]
JSON = {"Accept": "application/json"}


def body(r: httpx.Response, n: int = 160) -> str:
    return " ".join(r.text.split())[:n]


def scheme(r: httpx.Response) -> str:
    """WWW-Authenticate에서 방식 이름/알고리즘만 추린다(nonce/opaque 제외)."""
    out = []
    for v in r.headers.get_list("www-authenticate"):
        out.append(" ".join(p for p in v.replace(",", " ").split()
                            if not p.lower().startswith(("nonce", "opaque"))))
    return "; ".join(out) or "(없음)"


def login(h, user, pw, **kw):
    r = h.post(f"{s.API_BASE}/auth", auth=httpx.DigestAuth(user, pw), **kw)
    info = (r.json().get("status", {}).get("info") or [{}])[0] if r.headers.get("content-type", "").startswith("application/json") else {}
    return r, info


def main() -> None:
    c = s.SonicWallClient()
    h, user, pw = c._http, c._user, c._password
    c._check_pin()

    print("== 1. 로그인 (Digest) ==")
    r, info = login(h, user, pw)
    print("상태:", r.status_code)
    print("계정 정보:", {k: info.get(k) for k in ("code", "auth_code", "read_only", "privilege", "model", "session_limit") if k in info})
    print("info 키 목록:", sorted(info.keys()))
    print("응답 헤더:", sorted(r.headers.keys()), "| 쿠키:", [ck.name for ck in h.cookies.jar] or "없음")

    print("\n== 2. 로그인 직후 GET (자격 증명 없이 = 세션 확인) ==")
    for p in PATHS:
        g = h.get(f"{s.API_BASE}/{p}", headers=JSON)
        print(f"  /{p}: {g.status_code} | 요구 방식: {scheme(g)}")

    print("\n== 3. 요청마다 Digest ==")
    for p in PATHS:
        g = h.get(f"{s.API_BASE}/{p}", headers=JSON, auth=httpx.DigestAuth(user, pw))
        print(f"  /{p}: {g.status_code} | {body(g)}")

    print("\n== 4. GET /auth (세션 상태 조회가 되는지) ==")
    g = h.get(f"{s.API_BASE}/auth", headers=JSON, auth=httpx.DigestAuth(user, pw))
    print(" ", g.status_code, "|", body(g))

    print("\n== 5. 로그아웃 ==")
    d = h.delete(f"{s.API_BASE}/auth")
    print(" ", d.status_code)
    h.close()


if __name__ == "__main__":
    try:
        main()
    except (s.SonicWallError, httpx.HTTPError) as e:
        print("오류:", type(e).__name__, e)
