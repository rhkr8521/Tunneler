# UTF-8 인코딩
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

Write-Host "=== Tunneler 클라이언트 포트 매핑 재설정 ===" -ForegroundColor Yellow

# 경로
$InstallDir = Join-Path $env:LOCALAPPDATA "TunnelerClient"
$ConfigFile = Join-Path $InstallDir "config.txt"
$TaskName   = "TunnelerClient"

if (-not (Test-Path $ConfigFile)) {
    Write-Host "[에러] 설정 파일($ConfigFile)을 찾을 수 없습니다. 먼저 클라이언트를 설치하세요." -ForegroundColor Red
    pause; exit 1
}

# ---- 유틸 함수 ----
function Split-Maps([string]$s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return @() }
    return ($s -split '\s*,\s*' | Where-Object { $_ -ne '' })
}
function Join-Maps([string[]]$arr) {
    if ($null -eq $arr -or $arr.Count -eq 0) { return '' }
    return ($arr -join ',')
}
function Upsert-Maps([string[]]$arr, [string[]]$adds) {
    # 이름=호스트:포트 형태로 사전 병합(이름 기준으로 덮어쓰기)
    $dict = [ordered]@{}
    foreach ($it in $arr) {
        $kv = $it -split '=', 2
        if ($kv.Length -eq 2) { $dict[$kv[0].Trim()] = $kv[1].Trim() }
    }
    foreach ($add in $adds) {
        if ($add -notlike '*=*:*') { Write-Warning "잘못된 형식 무시: $add"; continue }
        $kv = $add -split '=', 2
        $dict[$kv[0].Trim()] = $kv[1].Trim()
    }
    return @($dict.Keys | ForEach-Object { "$_=$($dict[$_])" })
}
function Delete-Maps([string[]]$arr, [string[]]$delNames) {
    if ($null -eq $delNames -or $delNames.Count -eq 0) { return $arr }
    $del = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $delNames) { if ($n) { [void]$del.Add($n.Trim()) } }
    return @($arr | Where-Object { ($_.Split('=')[0]).Trim() -notin $del })
}

# ---- 설정 읽기(깊게) ----
# ConvertFrom-StringData는 key=value 파싱에 안전
$cfg = Get-Content -Raw -Path $ConfigFile | ConvertFrom-StringData

# 기존 문자열을 '반드시' 배열로 변환
$tcpList = Split-Maps $cfg.TCP_MAPS
$udpList = Split-Maps $cfg.UDP_MAPS

Write-Host "`n--- 현재 설정 ---"
Write-Host ("TCP 매핑: {0}" -f (Join-Maps $tcpList))
Write-Host ("UDP 매핑: {0}" -f (Join-Maps $udpList))
Write-Host "--------------------`n"

# ---- 입력 ----
$tcpAdd = Read-Host "추가/수정할 TCP 매핑 (쉼표로 구분, 예: s1=127.0.0.1:22,s2=127.0.0.1:25565)"
$tcpDel = Read-Host "삭제할 TCP 이름 (쉼표로 구분)"
$udpAdd = Read-Host "추가/수정할 UDP 매핑 (쉼표로 구분)"
$udpDel = Read-Host "삭제할 UDP 이름 (쉼표로 구분)"

$changed = $false

# 삭제
if (-not [string]::IsNullOrWhiteSpace($tcpDel)) {
    $delNames = ($tcpDel -split '\s*,\s*' | Where-Object { $_ })
    $tcpList  = Delete-Maps $tcpList $delNames
    $changed = $true
}
if (-not [string]::IsNullOrWhiteSpace($udpDel)) {
    $delNames = ($udpDel -split '\s*,\s*' | Where-Object { $_ })
    $udpList  = Delete-Maps $udpList $delNames
    $changed = $true
}

# 추가/수정
if (-not [string]::IsNullOrWhiteSpace($tcpAdd)) {
    $adds    = ($tcpAdd -split '\s*,\s*' | Where-Object { $_ })
    $tcpList = Upsert-Maps $tcpList $adds
    $changed = $true
}
if (-not [string]::IsNullOrWhiteSpace($udpAdd)) {
    $adds    = ($udpAdd -split '\s*,\s*' | Where-Object { $_ })
    $udpList = Upsert-Maps $udpList $adds
    $changed = $true
}

# ---- 저장 & 재시작 ----
if ($changed) {
    Write-Host "`n[OK] 설정이 변경되었습니다. 서비스를 업데이트하고 재시작합니다..."

    # 반드시 콤마로 조인해서 저장 (여기가 핵심)
    $newContent = @"
WS_URL=$($cfg.WS_URL)
SUBDOMAIN=$($cfg.SUBDOMAIN)
TOKEN=$($cfg.TOKEN)
HTTP_BASE=$($cfg.HTTP_BASE)
TCP_MAPS=$(Join-Maps $tcpList)
UDP_MAPS=$(Join-Maps $udpList)
"@

    # UTF-8(BOM) + CRLF로 저장
    Set-Content -Path $ConfigFile -Value $newContent -Encoding utf8

    # 예약 작업 재시작
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Write-Host " - 기존 작업 중지를 요청합니다..."
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

        Write-Host " - 실행 중인 클라이언트를 종료합니다..."
        Get-CimInstance -ClassName Win32_Process |
          Where-Object { $_.ExecutablePath -like "$InstallDir\*" } |
          ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Seconds 1

        Write-Host " - 새 설정으로 작업을 시작합니다..."
        Start-ScheduledTask -TaskName $TaskName
    } else {
        Write-Warning "예약 작업을 찾지 못했습니다. 먼저 설치 스크립트로 등록하세요."
    }

    Write-Host "`n=== 재설정 완료 ===" -ForegroundColor Green
} else {
    Write-Host "`n[정보] 변경된 내용이 없습니다."
}

pause
