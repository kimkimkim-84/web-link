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


def same_conn(a: httpx.Response, b: httpx.Response):
    sa, sb = a.extensions.get("network_stream"), b.extensions.get("network_stream")
    return "알수없음" if sa is None or sb is None else sa is sb


def trial(c, label: str, extra: dict[str, str]) -> None:
    """extra 헤더를 로그인과 조회에 똑같이 붙여 시험한다. 같은 TCP 연결 재사용 여부도 표시."""
    headers = {**c._base_headers(), **extra}
    r = c._http.post(f"{s.API_BASE}/auth", headers=headers, json=s.LOGIN_BODY, auth=(c._user, c._password))
    tok = s.find_key(r.json(), "bearer_token") if r.status_code == 200 else None
    print(f"\n[{label}] 로그인 {r.status_code}, 토큰 {'있음' if tok else '없음'}, "
          f"응답 Connection 헤더={r.headers.get('connection')!r}, 응답 HTTP 버전={r.http_version}")
    if not tok:
        return
    h = {**headers, "Authorization": f"Bearer {tok}"}
    for path in ("version", GUI_PATH):
        g = c._http.get(f"{s.API_BASE}/{path}", headers=h)
        print(f"  GET /{path.split('?')[0]:<32} -> {code_of(g)}  같은연결={same_conn(g, r)}")
    c._http.delete(f"{s.API_BASE}/auth", headers=h)


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

    trial(c, "기본", {})
    trial(c, "keep-alive", {"Connection": "keep-alive"})
    trial(c, "keep-alive + 브라우저 User-Agent", {"Connection": "keep-alive", "User-Agent": CHROME_UA})
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
