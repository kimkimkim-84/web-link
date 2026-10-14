# 최신 코드를 받고 의존성을 갱신한다. 사용: PowerShell에서  .\update.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
git pull
python -m pip install -q -r requirements.txt
Write-Host "업데이트 완료. Claude Code를 다시 시작해야 변경된 서버가 적용됩니다."
