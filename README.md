# Tunneler — 실시간 대시보드를 갖춘 리버스 터널러

사설망에서도 손쉽게 포트를 터널링하는 리버스 터널러 & 대시보드(실시간 대역폭·로그·IP/시간제한), 서버/클라이언트(리눅스·macOS·윈도우) 구현

---

사설망/방화벽 뒤의 PC(클라이언트)가 **서버로 WebSocket** 연결을 맺고, 서버가 **외부 포트(TCP/UDP)와 HTTP 프록시**를 자동 할당하여 외부에서 접근 가능하게 하는 터널러입니다.
관리자는 **웹 대시보드**로 실시간 상태(대역폭, 연결), 포트, 토큰/접근제어, 로그를 관리할 수 있습니다.

## ✨ 주요 기능

<img width="1286" height="1282" alt="image" src="https://github.com/user-attachments/assets/8f3750ab-c780-4c37-9df8-85862d681f8e" />


-   **멀티 프로토콜**: TCP / UDP / HTTP 프록시 지원
-   **자동 포트 할당**: 서버가 가용 포트를 자동으로 선택하여 클라이언트에 할당
-   **실시간 대시보드**: 전체/터널별 대역폭(MB/s), 활성 터널, 포트 현황, 로그 스트림 실시간 업데이트
-   **강력한 보안/제어**:
    -   토큰 기반 클라이언트 인증 (화이트리스트)
    -   대시보드 접근 IP 제한 (허용 목록)
    -   터널별 접근 IP/CIDR 차단
    -   전역 및 터널별 접속 허용 시간대 설정
-   **운영 편의성**:
    -   Nginx 리버스 프록시 및 방화벽(UFW/iptables) 규칙 자동 설정
    -   Let’s Encrypt를 이용한 HTTPS 자동 설정 (옵션)
    -   OS별 서비스 자동 시작 지원 (systemd, launchd, 작업 스케줄러)
-   **반응형 UI**: Tailwind 기반의 모바일 친화적 대시보드

## 🚀 작동 원리

```text
(외부 사용자) ── TCP/UDP/HTTP 요청 ──> [서버 (공개 IP)]
    │
    ├─ 서버 Listen (자동 할당 포트 / HTTP 프록시)
    │
    └─ WebSocket 터널 ───────────────> [클라이언트 (사설망 PC)]
                                         ├─ 로컬 TCP 서비스 (예: SSH, DB)
                                         └─ 로컬 UDP 서비스 (예: DNS, 게임)
```

1.  **클라이언트**가 서버의 `/_ws` 엔드포인트로 WebSocket 연결을 맺고, 원하는 포트 매핑을 서버에 등록합니다.
2.  **서버**는 설정된 범위 내에서 사용 가능한 포트를 찾아 TCP/UDP 리스너를 열고, 외부 요청을 WebSocket 터널을 통해 클라이언트로 전달합니다.
3.  **HTTP 프록시** 모드에서는 `subdomain.example.com`과 같은 호스트명으로 들어온 HTTP 요청을 해당 클라이언트가 지정한 로컬 HTTP 엔드포인트로 전달합니다.
4.  **대시보드**는 WebSocket을 통해 실시간 로그, 대역폭, 터널 상태를 표시하며, API를 통해 각종 정책과 토큰을 관리합니다.

### 📂 폴더 구조

```
.
├─ server/
│  ├─ server.py
│  ├─ requirements.txt
│  ├─ install_server.sh
│  └─ uninstall_server.sh
└─ client/
   ├─ ubuntu/
   │  ├─ client.py
   │  ├─ requirements.txt
   │  ├─ install_client_ubuntu.sh
   │  └─ uninstall_client_ubuntu.sh
   ├─ mac/
   │  ├─ client.py
   │  ├─ requirements.txt
   │  ├─ install_client_mac.sh
   │  └─ uninstall_client_mac.sh
   └─ windows/
      ├─ client.py
      ├─ requirements.txt
      ├─ install_client_windows.ps1
      └─ uninstall_client_windows.ps1
```

## 🛠️ 설치 방법

### 요구사항

-   **서버**
    -   Ubuntu 20.04+ (24.04 권장)
    -   공개 포트: `80`, `443`, 앱 포트(기본 `8080`), 터널링에 사용할 **TCP/UDP 포트 범위**
    -   Python 3.10+, Nginx (스크립트에서 자동 설치)
    -   도메인 및 DNS 설정 (와일드카드 서브도메인 사용 시 `*.example.com` 필요)
-   **클라이언트**
    -   Ubuntu/Debian, macOS, Windows 10+
    -   Python 3.10+ (OS별 설치 스크립트가 가상환경을 자동으로 구성)

### 1. 서버 설치 (Ubuntu)

1.  서버에 `server.py`, `requirements.txt`, `install_server.sh` 파일을 업로드합니다.
2.  아래 명령어를 실행하고 프롬프트에 따라 설정을 입력합니다.

    ```bash
    sudo bash install_server.sh
    ```
    -   **주요 입력 항목**: 도메인, 와일드카드 사용 여부, TCP/UDP 포트 범위, 토큰 화이트리스트, 대시보드 ID/비밀번호, Let's Encrypt 사용 여부

3.  **설치 확인**
    -   **대시보드 접속**: `http(s)://<도메인>/dashboard`
    -   **서비스 상태**: `sudo systemctl status tunneler-server -l`
    -   **실시간 로그**: `sudo journalctl -u tunneler-server -f`
    -   **헬스 체크**: `curl -fsS http://<도메인>/_health | jq .`

### 2. 클라이언트 설치

#### Ubuntu

1.  `client.py`, `requirements.txt`, `install_client_ubuntu.sh` 파일을 준비합니다.
2.  스크립트를 실행하고 프롬프트에 따라 설정을 입력합니다.
    ```bash
    bash install_client_ubuntu.sh
    ```
3.  **상태 확인**: `systemctl --user status tunneler-client -l`

#### macOS

1.  `client.py`, `requirements.txt`, `install_client_mac.sh` 파일을 준비합니다.
2.  스크립트를 실행합니다.
    ```bash
    bash install_client_mac.sh
    ```
3.  **로그 확인**: `sudo tail -f /var/log/tunneler/client.out.log`
4.  **수동 제어**: `/Library/TunnelerClient/start.sh` (시작), `/Library/TunnelerClient/stop.sh` (중지)

#### Windows

1.  `client.py`, `requirements.txt`와 `install_client_windows.ps1` 파일들을 준비합니다.
2.  `install_client_windows.ps1` 파일을 **관리자 권한으로 실행**합니다.
3.  설치된 파일은 `%LOCALAPPDATA%\TunnelerClient`에 저장되며, 로그온 시 자동 실행되도록 작업 스케줄러에 등록됩니다.
4.  **상태 확인**: 작업 스케줄러 앱에서 `TunnelerClient` 작업의 '마지막 실행 결과' 확인

## ⚙️ 사용법

### 대시보드

-   **실시간 대역폭**: 전체 및 터널별 업/다운로드 속도를 초 단위로 시각화합니다.
-   **활성 터널 관리**: 현재 연결된 터널과 할당된 포트를 확인하고, 원격으로 연결을 끊을 수 있습니다.
-   **토큰 관리**: 인증 토큰을 추가/삭제하고, 각 토큰의 마지막 사용 IP와 시간을 추적합니다.
-   **IP 제어**:
    -   대시보드에 접근할 수 있는 IP/CIDR 지정
    -   특정 터널의 공개 포트로 들어오는 외부 IP/CIDR 차단
-   **접속 허용 시간대**: `mon-fri 09:00~18:00` 형식으로 전역 또는 터널별 접속 가능 시간을 설정합니다.
-   **로그 뷰어**: 실시간 로그 스트림을 보거나, `server.log.YYYY-MM-DD` 형식의 이전 로그 파일을 열람할 수 있습니다.

### 포트 매핑 규칙

-   **형식**: `이름=로컬주소:포트`
-   **구분**: 여러 개를 등록할 경우 쉼표(`,`)로 구분합니다.
-   **예시**: `ssh=127.0.0.1:22,db=127.0.0.1:5432,game=192.168.0.5:25565`

## 🗑️ 제거 방법

-   **Ubuntu Server**: `sudo bash uninstall_server.sh` 스크립트를 실행합니다.
-   **Ubuntu Client**: `bash uninstall_client_ubuntu.sh` 스크립트를 실행합니다.
-   **macOS Client**: `bash uninstall_client_mac.sh` 스크립트를 실행합니다.
-   **Windows Client**: `uninstall_client_windows.ps1` 스크립트를 **관리자 권한으로 실행** 합니다.

## 💡 트러블슈팅

-   **클라이언트가 대시보드에 안 보일 때**: 각 OS별 로그 확인 명령어를 실행하여 `REGISTER` / `ASSIGNED` 메시지가 출력되는지 확인하세요. 토큰, IP 제한, 시간대 설정을 가장 먼저 점검해야 합니다.
-   **포트가 안 열릴 때**: 클라우드/호스팅 방화벽에서 설치 시 입력한 TCP/UDP 포트 범위를 허용했는지 확인하세요.
-   **HTTP 프록시 403/404**: `403`은 IP/시간대 제한, `404`는 해당 서브도메인으로 등록된 클라이언트가 없음을 의미합니다.

## 🔒 보안 권장사항

-   개발/테스트 목적이 아니라면 **토큰 화이트리스트를 절대로 비워두지 마세요.**
-   대시보드 비밀번호를 복잡하게 설정하고, **IP 차단 목록을 함께 사용**하여 접근을 최소화하세요.

---

## 라이선스 (License)

이 프로젝트는 다음과 같은 오픈소스 라이브러리를 사용하고 있습니다. 각 라이브러리의 라이선스 조항을 준수하기 위해 아래에 해당 라이선스 원문을 포함합니다.

### Apache License 2.0

`aiohttp`와 그 의존성 라이브러리인 `yarl`, `multidict`, `frozenlist` 등은 Apache License 2.0을 따릅니다.

<details>
<summary>Apache License 2.0 전문 보기</summary>

```
   Copyright 2024 Your Name or Company Name

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```

</details>

### MIT License

`aiohttp`의 의존성 라이브러리인 `attrs`는 MIT License를 따릅니다.

<details>
<summary>MIT License 전문 보기</summary>

```
Copyright (c) 2015-present Hynek Schlawack

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
</details>
