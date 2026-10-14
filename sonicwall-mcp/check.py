"""Claude 없이 방화벽 연결을 점검하는 스크립트 (읽기 전용 GET만 수행).

사용: SONICWALL_HOST/USER/PASSWORD 환경변수를 설정한 뒤  python check.py
     로그인 후 조회가 401이면  python check.py --debug  (로그인 단계별 결과, 토큰 값은 출력 안 함)
"""
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


def debug() -> int:
    """로그인 단계(사용자 모드 → start-management → 재로그인)와 조회 결과를 보여준다. 토큰 값은 출력 안 함."""
    c = s.client()
    c._login()
    print("로그인 단계:", " → ".join(c.login_steps))
    print("마지막 로그인 응답 키:", c.login_keys)
    for path in ("version", GUI_PATH):
        g = c._http.get(f"{s.API_BASE}/{path}", headers=c._headers())
        print(f"GET /{path.split('?')[0]:<32} -> {code_of(g)}")
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
