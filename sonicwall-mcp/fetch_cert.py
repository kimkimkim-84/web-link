"""방화벽 인증서의 SHA-256 지문을 출력한다(로그인 정보는 보내지 않음).

사용:  python fetch_cert.py <호스트> [포트]
출력된 지문을 방화벽 화면(장치 > 설정 > 인증서)에 표시되는 지문과 대조한 뒤
SONICWALL_CERT_SHA256 환경변수에 설정한다.
"""
import sys

import sonicwall_mcp as s

host = sys.argv[1]
port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
fp = s.server_cert_fingerprint(host, port)
print("SHA-256:", ":".join(fp[i:i + 2] for i in range(0, 64, 2)).upper())
print("연속 형식:", fp)
