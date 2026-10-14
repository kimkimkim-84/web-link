"""로그인 이후 401 원인 진단. 읽기 전용(GET + 로그인/로그아웃)만 수행한다.

비밀번호와 쿠키 값은 출력하지 않는다. 출력 전체를 개발 세션에 전달해도 된다.
사용: SONICWALL_* 환경변수 설정 후  python diagnose.py
"""
import httpx

import sonicwall_mcp as s


def body(r: httpx.Response, n: int = 400) -> str:
    return " ".join(r.text.split())[:n]


def main() -> None:
    c = s.SonicWallClient()
    h, user, pw = c._http, c._user, c._password
    c._check_pin()
    print("== 1. 로그인 (Digest) ==")
    r = h.post(f"{s.API_BASE}/auth", auth=httpx.DigestAuth(user, pw))
    print("상태:", r.status_code, "| 본문:", body(r))
    print("응답 헤더 이름:", sorted(r.headers.keys()))
    print("Set-Cookie 개수:", len(r.headers.get_list("set-cookie")))
    print("저장된 쿠키(이름/경로/secure):",
          [(ck.name, ck.path, ck.secure) for ck in h.cookies.jar] or "없음")

    def get(label, **kw):
        g = h.get(f"{s.API_BASE}/version", headers={"Accept": "application/json"}, **kw)
        print(f"{label}: 상태 {g.status_code} | {body(g, 250)}")

    print("\n== 2. GET /version 방식별 ==")
    get("a) 세션 쿠키만")
    get("b) 요청마다 Digest", auth=httpx.DigestAuth(user, pw))
    get("c) 요청마다 Basic", auth=(user, pw))
    print("\n== 3. 로그아웃 ==")
    d = h.delete(f"{s.API_BASE}/auth")
    print("상태:", d.status_code, "|", body(d, 200))
    h.close()


if __name__ == "__main__":
    try:
        main()
    except (s.SonicWallError, httpx.HTTPError) as e:
        print("오류:", type(e).__name__, e)
