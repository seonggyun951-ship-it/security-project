@echo off
rem 로컬 에이전트를 백그라운드 서비스처럼 띄운다.
rem
rem 에이전트는 상주하면서 신청 적용(Terraform)과 보안 점검(Prowler)을 맡는다.
rem 둘 다 노트북에 깔린 실행 파일이 필요해서 클라우드로 옮길 수 없다.
rem 그래서 "노트북이 켜지면 알아서 뜨는" 형태로 만든다.
rem
rem 작업 스케줄러 등록은 옆의 register-agent-task.ps1이 한다:
rem
rem   powershell -ExecutionPolicy Bypass -File register-agent-task.ps1
rem
rem 상태 확인:  schtasks /query /tn "security-console-agent"
rem 지금 실행:  schtasks /run   /tn "security-console-agent"
rem 멈추기:     schtasks /end   /tn "security-console-agent"

setlocal
cd /d "%~dp0"

if not exist logs mkdir logs

rem 뜰 때마다 직전 로그를 하나만 남기고 갈아끼운다.
rem 15초마다 폴링하므로 그냥 두면 로그가 끝없이 커진다.
if exist "logs\agent.log" move /y "logs\agent.log" "logs\agent.prev.log" >nul

rem PATH는 작업 스케줄러 환경에서 다를 수 있어 경로를 직접 적는다.
"C:\Program Files\nodejs\node.exe" agent.js >> "logs\agent.log" 2>&1
