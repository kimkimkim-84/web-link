"""SonicWall 계정을 Windows 자격 증명 관리자에 저장한다(비밀번호는 화면에 표시되지 않음).

사용:  python save_password.py [항목이름]     (기본 항목이름: SonicWallMCP/API)
저장 후 MCP 등록 시 SONICWALL_PASSWORD 대신  -e SONICWALL_CRED_TARGET=<항목이름>  을 쓴다.
"""
import getpass
import sys

import win32cred

import sonicwall_mcp as s


def main() -> None:
    target = sys.argv[1] if len(sys.argv) > 1 else s.DEFAULT_CRED_TARGET
    user = input("SonicWall 계정명: ").strip()
    password = getpass.getpass("SonicWall 비밀번호 (입력이 표시되지 않습니다): ")
    if not user or not password:
        sys.exit("계정명과 비밀번호를 모두 입력하세요.")
    win32cred.CredWrite({
        "Type": win32cred.CRED_TYPE_GENERIC,
        "TargetName": target,
        "UserName": user,
        "CredentialBlob": password,
        "Persist": win32cred.CRED_PERSIST_LOCAL_MACHINE,
    }, 0)
    print(f"저장했습니다: '{target}' (계정 {user})")


if __name__ == "__main__":
    main()
