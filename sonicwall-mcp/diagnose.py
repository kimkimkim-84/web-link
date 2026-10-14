"""로그인 이후 401 원인 진단 v3 (Bearer 토큰/세션 방식 탐색). GET + 로그인/로그아웃만 수행한다.

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

    for label in ("기본",):  # override는 다른 관리자의 설정 모드를 빼앗을 수 있어 사용하지 않는다
        print(f"== 로그인 ({label}) ==")
        r = h.post(f"{s.API_BASE}/auth", auth=httpx.DigestAuth(user, pw))
        print("상태:", r.status_code, "| 응답 헤더:", sorted(r.headers.keys()), "| 쿠키:", [k.name for k in h.cookies.jar] or "없음")
        leaves = []
        try:
            leaves = list(walk(r.json()))
        except ValueError:
            print("JSON 아님:", r.text[:120])
        for p, v in leaves:
            print(f"  {p} = {show(p, v)}")
        cands = [(p, v) for p, v in leaves if TOKEN_HINT.search(p.split('.')[-1]) and isinstance(v, str) and v]
        print("토큰 후보 필드:", [p for p, _ in cands] or "없음")
        for p, tok in cands:
            for name in ("Bearer",):
                g = h.get(f"{s.API_BASE}/version", headers={**JSON, "Authorization": f"{name} {tok}"})
                print(f"  → {p}를 '{name}'으로 GET /version: {status_of(g)}")
        print("  → 로그인 직후 자격 증명 없이 GET:", {p_: status_of(h.get(f'{s.API_BASE}/{p_}', headers=JSON)) for p_ in PATHS})
        h.delete(f"{s.API_BASE}/auth")
        print()
    h.close()


if __name__ == "__main__":
    try:
        main()
    except (s.SonicWallError, httpx.HTTPError) as e:
        print("오류:", type(e).__name__, e)
