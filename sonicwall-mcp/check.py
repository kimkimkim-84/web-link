"""Claude 없이 방화벽 연결을 점검하는 스크립트 (읽기 전용 GET만 수행).

사용: SONICWALL_HOST/USER/PASSWORD 환경변수를 설정한 뒤  python check.py
     로그인 후 조회가 401이면  python check.py --debug  (토큰/헤더 방식 비교, 토큰 값은 출력 안 함)
"""
import base64
import json
import sys

import httpx

import sonicwall_mcp as s

CHECKS = ["version", "zones", "interfaces/ipv4", "address-objects/ipv4", "access-rules/ipv4"]


# 웹 UI가 실제로 성공한 GET(읽기 전용). 토큰 자체가 유효한지 가리는 기준으로 쓴다.
GUI_PATH = "dynamic-file/getRTData.json?src=0&ipVerApps=2&ipVerBandwidth=2"


def code_of(r: httpx.Response):
    try:
        return r.status_code, (r.json().get("status", {}).get("info") or [{}])[0].get("code")
    except (ValueError, AttributeError):
        return r.status_code, r.headers.get("content-type", "")[:30]


CHROME_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")
TIME_CLAIMS = ("iat", "exp", "nbf", "auth_time")


def jwt_summary(tok: str) -> None:
    """JWT 헤더/페이로드의 항목 이름과 시간 정보만 출력한다(값·서명은 출력하지 않음)."""
    parts = tok.split(".")
    if len(parts) != 3:
        print("  JWT 아님")
        return
    for label, seg in (("헤더", parts[0]), ("페이로드", parts[1])):
        try:
            data = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
        except ValueError:
            print(f"  {label}: 해석 불가")
            continue
        shown = {}
        for k, v in data.items():
            if label == "헤더" and k in ("alg", "typ"):
                shown[k] = v
            elif k in TIME_CLAIMS and isinstance(v, (int, float)):
                shown[k] = v
            else:
                shown[k] = f"<{type(v).__name__}, 길이 {len(str(v))}>"
        print(f"  {label}: {shown}")
        if label == "페이로드" and isinstance(data.get("exp"), (int, float)) and isinstance(data.get("iat"), (int, float)):
            print(f"  유효기간(exp-iat): {data['exp'] - data['iat']}초")


BROWSER_GET = {  # 웹 UI의 GET 요청 헤더(캡처 기준). GET에는 Origin이 없다.
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
    "Connection": "keep-alive",
    "Sec-Ch-Ua": '"Google Chrome";v="155", "Chromium";v="155", "Not(A:Brand";v="24"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "User-Agent": CHROME_UA,
}


def trial(c, label: str, login_extra: dict[str, str], get_extra: dict[str, str], drop_origin_on_get=False) -> None:
    headers = {**c._base_headers(), **login_extra}
    r = c._http.post(f"{s.API_BASE}/auth", headers=headers, json=s.LOGIN_BODY, auth=(c._user, c._password))
    try:
        body = r.json()
    except ValueError:
        body = {}
    info = (body.get("status", {}).get("info") or [{}])[0] if isinstance(body, dict) else {}
    tok = s.find_key(body, "bearer_token") if r.status_code == 200 else None
    print(f"\n[{label}] 로그인 {r.status_code}, 토큰 {'있음' if tok else '없음'}")
    print("  로그인 응답:", {k: info.get(k) for k in ("code", "message", "auth_code", "read_only",
                                                   "privilege", "show_status", "security_warning") if k in info})
    if not tok:
        return
    h = {**c._base_headers(), **get_extra, "Authorization": f"Bearer {tok}"}
    if drop_origin_on_get:
        h.pop("Origin", None)
    for path in ("version", GUI_PATH):
        g = c._http.get(f"{s.API_BASE}/{path}", headers=h)
        print(f"  GET /{path.split('?')[0]:<32} -> {code_of(g)}")
    d = c._http.delete(f"{s.API_BASE}/auth", headers=h)
    print(f"  로그아웃 -> {code_of(d)}")


def debug() -> int:
    c = s.client()
    c._login()
    tok = c._token or ""
    print("로그인 응답 키:", c.login_keys)
    print(f"토큰 형태: 길이={len(tok)}, 공백포함={' ' in tok}, 점개수={tok.count('.')}, "
          f"'Bearer'로시작={tok.lower().startswith('bearer')}")
    print("JWT 분석:")
    jwt_summary(tok)
    c._http.delete(f"{s.API_BASE}/auth", headers=c._headers())

    trial(c, "기본", {}, {})
    trial(c, "브라우저 헤더 전체 흉내", {k: v for k, v in BROWSER_GET.items() if k != "Accept"},
          BROWSER_GET, drop_origin_on_get=True)
    c._logged_in = False
    c.close()
    return 0


def main() -> int:
    if "--debug" in sys.argv:
        try:
            return debug()
        except (s.SonicWallError, httpx.HTTPError) as e:
            print(f"[오류] {type(e).__name__}: {e}")
            return 1
    try:
        c = s.client()
    except s.SonicWallError as e:
        print(f"[설정 오류] {e}")
        return 2
    failed = 0
    for path in CHECKS:
        try:
            data = c.get(path)
            size = len(str(data))
            print(f"[OK]   GET /{path}  (응답 {size}자)")
            if path == "version":
                print(s.render(data))
        except (s.SonicWallError, httpx.HTTPError) as e:
            failed += 1
            print(f"[FAIL] GET /{path}  -> {type(e).__name__}: {e}")
    c.close()
    print("\n결과:", "모두 성공" if not failed else f"{failed}개 실패 (위 메시지를 개발 세션에 전달)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
