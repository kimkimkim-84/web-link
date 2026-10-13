# SonicWall 읽기 전용 MCP 서버

SonicWall 8세대(SonicOS 8) 방화벽의 REST API(`/api/sonicos`)를 Claude에 연결하는 MCP 서버.
**GET만 사용**하므로 Claude가 설정을 바꿀 수 없다. (인증용 `POST /auth`, 로그아웃 `DELETE /auth`만 예외)

## 안전장치
- 읽기 전용: 쓰기/commit 호출 코드가 없음
- 경로 허용 목록(`ALLOWED_PREFIXES`): 인증·관리자·설정내보내기 등은 조회 불가
- 응답의 password / secret / psk / token 등 민감 키는 `***REDACTED***` 처리
- 큰 응답은 항목 수(limit)와 글자 수로 잘라 컨텍스트 폭주 방지
- TLS 검증 기본 ON (사설 CA는 `SONICWALL_CA_BUNDLE`)

## 1. 방화벽 준비
1. 관리 > 시스템 설정 > 관리자(Administration) 에서 **SonicOS API 활성화**(Basic 인증 허용)
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

## 도구
`get_version`, `list_zones`, `list_interfaces`, `list_address_objects`, `list_service_objects`,
`list_access_rules`, `list_nat_policies`, `list_route_policies`, `sonicos_get`(허용 목록 내 임의 경로)

예시 질문: "any→any 허용 규칙 찾아줘", "사용 안 하는 주소 객체 후보 알려줘", "WAN 쪽 NAT 정책 요약해줘"

## 주의
- 엔드포인트 경로는 SonicOS 공개 API 문서를 기준으로 작성했고 **실제 장비로는 검증하지 못했다.**
  모델/펌웨어에 따라 다르면 장비의 HOME | API(Swagger)에서 경로를 확인해 `sonicos_get` 또는 코드를 수정할 것.
- 로그 조회/실시간 모니터링, 설정 변경(쓰기)은 의도적으로 제외했다. 필요하면 별도 승인 절차와 함께 추가 권장.
