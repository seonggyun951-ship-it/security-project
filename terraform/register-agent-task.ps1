# 로컬 에이전트를 윈도우 작업 스케줄러에 등록한다.
#
#   powershell -ExecutionPolicy Bypass -File register-agent-task.ps1
#
# 에이전트는 상주하면서 신청 적용(Terraform)과 보안 점검(Prowler)을 맡는다.
# 둘 다 노트북에 깔린 실행 파일이 필요해 클라우드로 옮길 수 없다. 그래서
# "노트북에 로그인하면 알아서 뜨는" 형태로 둔다.
#
# 로그온 트리거인 이유: 점검은 하루 한 번이면 되지만 그 하루가 언제인지는
# 노트북이 켜져 있느냐에 달렸다. 정해진 시각에 거는 것보다 켤 때 띄우는 편이
# 실제로 더 자주 돈다. 껐다 켠 사이에 밀린 것은 StartWhenAvailable이 따라잡는다.

$ErrorActionPreference = 'Stop'

# S4U로 등록하려면 관리자 권한이 필요하다. 일반 창에서 돌리면 Access denied만 나고
# 왜 안 되는지 알기 어려우므로 먼저 걸러낸다.
$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
  Write-Host '관리자 권한으로 실행해야 합니다.' -ForegroundColor Yellow
  Write-Host 'PowerShell을 관리자로 열고 다시 실행하세요.'
  exit 1
}

$dir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$name = 'security-console-agent'
$me   = "$env:USERDOMAIN\$env:USERNAME"

$action = New-ScheduledTaskAction -Execute "$dir\agent-service.cmd" -WorkingDirectory $dir

$trigger = New-ScheduledTaskTrigger -AtLogOn -User $me

# S4U — 내 세션이 아니라 세션 밖에서 돌린다.
#
# Interactive로 두면 cmd 창이 화면에 그대로 뜬다. 그 창은 닫으면 에이전트가 죽는데,
# 닫으면 안 되는 창이 종일 떠 있는 건 사고를 부른다. S4U면 창 자체가 없다.
# 자격증명은 비밀번호 없이 발급받으므로 저장할 것도 없다.
#
# 사용자 프로필 접근이 제한될까 걱정했지만 실제로는 문제없었다 —
# ~/.aws/credentials도 Prowler도 정상으로 읽는다(점검 완주 확인).
#
# RunLevel Limited — 관리자로 올릴 이유가 없다. Terraform도 Prowler도 사용자 권한으로 돈다.
$principal = New-ScheduledTaskPrincipal -UserId $me -LogonType S4U -RunLevel Limited

# IgnoreNew            — 이미 떠 있으면 또 띄우지 않는다
# AllowStartIfOnBatteries — 노트북이라 이걸 켜지 않으면 배터리일 때 아예 안 뜬다
# ExecutionTimeLimit 0  — 상주 프로세스라 시간 제한을 두면 도중에 잘린다
$settings = New-ScheduledTaskSettingsSet `
  -MultipleInstances IgnoreNew `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -ExecutionTimeLimit ([TimeSpan]::Zero) `
  -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) `
  -StartWhenAvailable

# 작업 스케줄러 목록에서 이 작업을 숨긴다.
# 콘솔 창을 숨기는 옵션이 아니다 — 이름 때문에 헷갈리기 쉬운데 창은 로그온 유형이 정한다.
$settings.Hidden = $true

Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings `
  -Description '보안 콘솔 로컬 에이전트 - 신청 적용(Terraform) + 보안 점검(Prowler)' `
  -Force | Out-Null

Write-Host "등록했습니다: $name"
Write-Host ''
Write-Host '  지금 실행:  Start-ScheduledTask -TaskName ' -NoNewline; Write-Host $name
Write-Host '  멈추기:     Stop-ScheduledTask  -TaskName ' -NoNewline; Write-Host $name
Write-Host '  상태:       Get-ScheduledTaskInfo -TaskName ' -NoNewline; Write-Host $name
Write-Host "  로그:       Get-Content '$dir\logs\agent.log' -Tail 30 -Encoding UTF8"
