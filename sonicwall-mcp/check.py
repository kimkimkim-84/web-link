"""Claude 없이 방화벽 연결을 점검하는 스크립트 (읽기 전용 GET만 수행).

사용: SONICWALL_HOST/USER/PASSWORD 환경변수를 설정한 뒤  python check.py
"""
import sys

import httpx

import sonicwall_mcp as s

CHECKS = ["version", "zones", "interfaces/ipv4", "address-objects/ipv4", "access-rules/ipv4"]


def main() -> int:
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
