# UTF-8 인코딩으로 실행되도록 설정
$PSDefaultParameterValues['*:Encoding'] = 'utf8'
Write-Host "=== Tunneler 클라이언트(Windows) 설치 (PowerShell) ===" -ForegroundColor Yellow

# --- 경로 및 이름 정의 ---
$InstallDir = Join-Path $env:LOCALAPPDATA "TunnelerClient"
$TaskName = "TunnelerClient"
$ConfigFile = Join-Path $InstallDir "config.txt"
$RunnerFile = Join-Path $InstallDir "runner.ps1"

# --- 1. 사전 조건 확인 ---
Write-Host "[1/4] 환경 확인 중..."
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { Write-Host "[에러] Python을 찾을 수 없습니다." -ForegroundColor Red; pause; exit 1 }
if (-not (Test-Path "$PSScriptRoot\client.py") -or -not (Test-Path "$PSScriptRoot\requirements.txt")) { Write-Host "[에러] client.py 또는 requirements.txt가 없습니다." -ForegroundColor Red; pause; exit 1 }

# --- 2. 설치 및 가상환경 준비 ---
Write-Host "[2/4] 설치 디렉터리 및 가상환경 준비 중..."
if (Test-Path $InstallDir) { Remove-Item -Path $InstallDir -Recurse -Force }
New-Item -ItemType Directory -Path $InstallDir | Out-Null
Copy-Item "$PSScriptRoot\client.py" -Destination $InstallDir
Copy-Item "$PSScriptRoot\requirements.txt" -Destination $InstallDir
python -m venv (Join-Path $InstallDir ".venv")
& (Join-Path $InstallDir ".venv\Scripts\pip.exe") install -r (Join-Path $InstallDir "requirements.txt") | Out-Null

# --- 3. 사용자 설정 입력 및 config.txt 생성 ---
Write-Host "[3/4] 클라이언트 설정 입력..."
$ServerHost = Read-Host "서버 주소 (예: example.com)"
$UseSsl = Read-Host "SSL 인증서(HTTPS) 사용 중인가요? [y/N]"
$Subdomain = Read-Host "서브도메인 (예: mybox)"
$Token = Read-Host "토큰(화이트리스트; 없으면 Enter)"
$HttpBase = Read-Host "HTTP 로컬 베이스(예: http://127.0.0.1:8000 없으면 Enter)"
$TcpMaps = Read-Host "TCP 매핑(예: ssh=127.0.0.1:22,db=127.0.0.1:5432) 없으면 Enter"
$UdpMaps = Read-Host "UDP 매핑(예: dns=127.0.0.1:53) 없으면 Enter"
$WsUrl = if ($UseSsl -eq 'y') { "wss://$ServerHost/_ws" } else { "ws://$ServerHost/_ws" }

# key=value 형태의 설정 파일 생성
$configContent = @"
WS_URL=$WsUrl
SUBDOMAIN=$Subdomain
TOKEN=$Token
HTTP_BASE=$HttpBase
TCP_MAPS=$TcpMaps
UDP_MAPS=$UdpMaps
"@
Set-Content -Path $ConfigFile -Value $configContent

# --- 4. runner.ps1 및 작업 스케줄러 등록 ---
Write-Host "[4/4] 자동 실행 서비스 등록 중..."
# runner.ps1 스크립트 내용 생성
$runnerContent = @"
`$InstallDir = "$InstallDir"
`$ConfigFile = Join-Path `$InstallDir "config.txt"
`$VenvPython = Join-Path `$InstallDir ".venv\Scripts\pythonw.exe"
`$ClientPy = Join-Path `$InstallDir "client.py"

# config.txt 읽어서 변수로 변환
`$Config = Get-Content -Path `$ConfigFile | ConvertFrom-StringData

# 실행할 인자(argument) 리스트 생성
`$ArgumentList = @(
    `$ClientPy,
    `$Config.WS_URL,
    `$Config.SUBDOMAIN,
    `$Config.TOKEN
)
if (`$Config.HTTP_BASE) { `$ArgumentList += "--http", `$Config.HTTP_BASE }
if (`$Config.TCP_MAPS) { (`$Config.TCP_MAPS -split ',').Trim() | ForEach-Object { `$ArgumentList += "--tcp", `$_ } }
if (`$Config.UDP_MAPS) { (`$Config.UDP_MAPS -split ',').Trim() | ForEach-Object { `$ArgumentList += "--udp", `$_ } }

# Python 클라이언트 실행
Start-Process -FilePath `$VenvPython -ArgumentList `$ArgumentList -NoNewWindow
"@
Set-Content -Path $RunnerFile -Value $runnerContent

# 작업 스케줄러 등록
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$RunnerFile`""
$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Principal = New-ScheduledTaskPrincipal -UserId (Get-CimInstance Win32_ComputerSystem).UserName -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null

Write-Host "`n=== 설치 완료 ===" -ForegroundColor Green
Write-Host "작업을 바로 시작합니다..."
Start-ScheduledTask -TaskName $TaskName
pause