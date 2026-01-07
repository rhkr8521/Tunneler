Write-Host "=== Tunneler 클라이언트(Windows) 제거 ===" -ForegroundColor Yellow

$InstallDir = Join-Path $env:LOCALAPPDATA "TunnelerClient"
$TaskName = "TunnelerClient"

# 1단계: 작업 스케줄러를 통해 정상 종료 시도
Write-Host "[1/4] 자동 시작 작업 중지 요청 중..."
Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

# 2단계 (NEW): client.py를 실행하는 모든 pythonw.exe 프로세스를 강제 종료하여 파일 잠금 해제
Write-Host "[2/4] 클라이언트 프로세스 강제 종료 중..."
Get-CimInstance -ClassName Win32_Process | Where-Object {
    $_.ExecutablePath -like "$InstallDir\*"
} | ForEach-Object {
    Write-Host " - 실행 중인 프로세스(PID: $($_.ProcessId))를 종료합니다."
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}

# 잠시 대기하여 프로세스 종료 완료 보장
Start-Sleep -Seconds 1

# 3단계: 작업 스케줄러에서 등록 해제
Write-Host "[3/4] 자동 시작 작업 등록 제거 중..."
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

# 4단계: 설치 파일 전체 삭제
Write-Host "[4/4] 설치 파일 삭제 중: $InstallDir"
if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
}

# 최종 확인
if (Test-Path $InstallDir) {
    Write-Host "[경고] 일부 파일/폴더를 삭제하지 못했습니다. PC를 재부팅한 후 폴더를 수동으로 삭제해 주세요." -ForegroundColor Yellow
} else {
    Write-Host "`n=== 제거 완료 ===" -ForegroundColor Green
}

pause