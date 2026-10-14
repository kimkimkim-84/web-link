# SonicWall 읽기 전용 MCP 서버

SonicWall 8세대(SonicOS 8) 방화벽의 REST API(`/api/sonicos`)를 Claude에 연결하는 MCP 서버.
**GET만 사용**하므로 Claude가 설정을 바꿀 수 없다. (인증용 `POST /auth`, 로그아웃 `DELETE /auth`만 예외)

## 작업 흐름 (클라우드 개발 세션 + 내 PC)
- **클라우드 세션**: 코드 수정/푸시만 담당. 내부망 방화벽에는 접근 불가.
- **내 PC(로컬 Claude Code)**: 방화벽 조회 담당. 등록된 `sonicwall` MCP가 여기서 동작.
1. PC에서 `.\update.ps1` 실행(최신 코드 받기) 후 Claude Code 재시작
2. 연결 점검(Claude 없이): 환경변수 설정 후 `python check.py`
   ```powershell
   $env:SONICWALL_HOST="<내부 IP>"; $env:SONICWALL_USER="mcp-readonly"; $env:SONICWALL_PASSWORD="<비밀번호>"
   python check.py
   ```
3. 오류가 나면 `check.py` 출력(비밀번호 제외)을 클라우드 세션에 붙여 수정 요청 → 푸시 → 1번 반복

## 안전장치
- 읽기 전용: 쓰기/commit 호출 코드가 없음
- 경로 허용 목록(`ALLOWED_PREFIXES`): 인증·관리자·설정내보내기 등은 조회 불가
- 응답의 password / secret / psk / token 등 민감 키는 `***REDACTED***` 처리
- 큰 응답은 항목 수(limit)와 글자 수로 잘라 컨텍스트 폭주 방지
- TLS 검증 기본 ON. 자체서명 인증서는 **지문 고정**(`SONICWALL_CERT_SHA256`)으로 처리하며, 지문이 다르면 계정 정보를 보내기 전에 중단(사설 CA는 `SONICWALL_CA_BUNDLE`)

## 인증 방식 (NSa 3800 / SonicOS 8.2 실측)
1. `POST /api/sonicos/auth` 를 웹 UI와 같은 형식으로 보낸다: `X-Snwl-Api-Scope: extended`, `X-Snwl-Timer: no-reset`, `Origin/Referer` 헤더 + 본문 `{"override": false, "snwl": true}`.
   인증은 웹 UI처럼 **Basic**(이 로그인에서 Digest는 `API_AUTH_REMOTE_USER`로 거부됨, 실측). 비밀번호는 인증서 지문 확인 후 TLS 안에서만 전송.
   `override: false` 이므로 다른 관리자의 세션/설정 모드를 빼앗지 않으며, `config-mode` 에는 들어가지 않는다.
2. 응답의 `bearer_token` 을 받아 이후 모든 요청에 `Authorization: Bearer <토큰>` 으로 사용
   - 로컬 계정(`mcp-readonly` 등)은 먼저 **사용자 모드**(`API_AUTH_USER_CAN_MGMT`)로 로그인되어 관리 API가 모두 401이다.
     웹 UI의 Manage 버튼과 같이 `POST /api/sonicos/start-management` → 재인증 요구(`API_AUTH_USER_REAUTH`) → 다시 로그인하면 관리 모드가 된다.
     이 전환은 세션 모드만 바꾸며 설정은 바꾸지 않는다.
3. 토큰 만료(401) 시 한 번 재로그인, 종료 시 `DELETE /auth` 로 로그아웃

세션 쿠키는 쓰지 않으며, 위 헤더 없이 로그인하면 토큰이 발급되지 않아 모든 조회가 401(E_UNAUTHORIZED)이 된다.

## 대상 환경
- 검증 장비: NSa 3800 / SonicOS 8.2.0-8009 (Gen 8) — check.py 5개 조회 성공 확인
- 로그인(`/auth`), `access-rules/ipv4`, `address-objects` 경로는 SonicWall 공식 API 문서(7.x 기준)와 일치함을 확인.
  8.2.2 전용 문서는 확인하지 못했으므로 첫 연결 시 `get_version`부터 호출해 검증할 것.
- 로그인 시 `override`(기존 관리자 세션 강제 종료)는 **사용하지 않음** — 운영 중 다른 관리자의 세션을 끊지 않기 위함.

## 1. 방화벽 준비
1. 장치 > 설정 > 관리(Administration) 에서 **SonicOS API 활성화** 및 **HTTP Basic 인증(RFC-2617) 허용**
   (메뉴 위치는 버전에 따라 다를 수 있음)
2. **읽기 전용 관리자 계정**(예: `mcp-readonly`)을 만들고, 이 서버에서만 접근하도록 관리 IP 제한

## 2. 설치 / 테스트
```bash
cd sonicwall-mcp
pip install -r requirements.txt
python -m pytest -q
cp .env.example .env   # 값 수정
```

## 3. Claude 연결
Claude Code:
```bash
claude mcp add sonicwall \
  -e SONICWALL_HOST=192.168.1.1 -e SONICWALL_USER=mcp-readonly -e SONICWALL_PASSWORD='***' \
  -- python /절대경로/sonicwall-mcp/sonicwall_mcp.py
```
Claude Desktop(`claude_desktop_config.json`):
```json
{"mcpServers": {"sonicwall": {
  "command": "python", "args": ["/절대경로/sonicwall-mcp/sonicwall_mcp.py"],
  "env": {"SONICWALL_HOST": "192.168.1.1", "SONICWALL_USER": "mcp-readonly", "SONICWALL_PASSWORD": "***"}
}}}
```

## 자체서명 인증서 (CERTIFICATE_VERIFY_FAILED)
```powershell
python fetch_cert.py <방화벽 IP>          # SHA-256 지문 출력
$env:SONICWALL_CERT_SHA256="<출력된 지문>"  # 방화벽 화면의 인증서 지문과 대조 후 설정
python check.py
```
Claude Code 등록 시에는 `-e SONICWALL_CERT_SHA256=<지문>`을 추가한다.

## 도구
`get_version`, `list_zones`, `list_interfaces`, `list_address_objects`, `list_service_objects`,
`list_access_rules`, `list_nat_policies`, `list_route_policies`, `sonicos_get`(허용 목록 내 임의 경로)

예시 질문: "any→any 허용 규칙 찾아줘", "사용 안 하는 주소 객체 후보 알려줘", "WAN 쪽 NAT 정책 요약해줘"

## 주의
- 엔드포인트 경로는 SonicOS 공개 API 문서를 기준으로 작성했고 **실제 장비로는 검증하지 못했다.**
  모델/펌웨어에 따라 다르면 장비의 HOME | API(Swagger)에서 경로를 확인해 `sonicos_get` 또는 코드를 수정할 것.
- 로그 조회/실시간 모니터링, 설정 변경(쓰기)은 의도적으로 제외했다. 필요하면 별도 승인 절차와 함께 추가 권장.
