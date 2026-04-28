# 🛡️ Automated File Analysis & AI Report Tool

이 프로젝트는 의심스러운 파일(PDF, Excel, Image, EXE)과 이메일(EML)을 다각도로 분석하고, 그 결과를 AI(Gemini)와 연동하여 상세한 보안 분석 보고서를 자동 생성하는 도구입니다. 최근 **Docker 기반 환경**으로 마이그레이션되어 운영 체제와 무관하게 안전하고 일관된 격리 환경에서 분석이 가능해졌습니다.

## 📂 주요 기능 및 업데이트 사항

1.  **`file_analysis.py`**: 정적 분석 도구
    *   **다양한 포맷 지원**: PDF, Excel, Image(PNG/JPG), EXE(PE) 파일 분석.
    *   **도구 업데이트**: 기존 `peepdf`에서 호환성이 뛰어난 `pdf-parser`로 전환하여 객체 파싱을 강화했습니다.

2.  **`eml_analysis.py` & `ai_analysis.py`**: 일괄 자동화 및 AI 리포트
    *   **비동기 일괄 처리**: Python `asyncio`를 사용하여 폴더 내의 **모든 파일**을 동시에 빠르게 분석.
    *   **AI 리포트 생성**: 분석된 기술적 데이터를 취합하여 Gemini 모델(`gemini` CLI)을 통해 사람이 읽기 쉬운 한글 종합 리포트를 자동 생성.
    *   **동적 경로 대응**: 도커 컨테이너(`/app`) 환경 및 로컬 환경에서 충돌 없이 저장 디렉토리를 스스로 찾아가도록 구조가 개선되었습니다.

3.  **`extract_eml.py`**: EML 이메일 파일 전용 분석 도구
    *   **EML 파싱 및 추출**: 이메일 파일 본문, 헤더, 첨부파일을 식별하고 폴더별 추출.
    *   **심층 URL 추적**: 리다이렉션을 추적하여 원본 Landing URL과 최종 도착지 URL 모두 파악 및 추출.
    *   **URL 악성 검증**: 추출된 URL을 VirusTotal CLI 등과 연동하여 검사.

4.  **`auto_run.py` & `run_kali_shell.py`**: Docker 연동 및 워크플로우 자동화
    *   **원클릭 파이프라인 (`auto_run.py`)**: 구 메일 백업, `auto_login.py` 구동 후 자동으로 Kali Docker 컨테이너를 띄워 백그라운드 분석을 수행하고 컨테이너까지 정리합니다. (기존 SSH -> Docker 방식으로 완벽 대체)
    *   **쉬운 대화형 접속 (`run_kali_shell.py`)**: 긴 마운트 명령어 입력 없이 즉시 분석용 도커 컨테이너의 터미널(Bash) 모드로 진입하게 해줍니다.

---

## 🛠️ 사전 요구사항 (Prerequisites)

현재 프로젝트는 **Docker** 환경 사용을 강력히 권장합니다. 실행에 필요한 리눅스 패키지 및 파이썬 도구들은 모두 제공된 `Dockerfile`을 통해 이미지에 설치됩니다.

*   **Docker**: 필수 설치
*   **Docker 이미지 빌드**: 
    ```bash
    docker build -t kali-linux .
    ```
*   **주요 포함 도구 (컨테이너 내 자동 구성)**:
    *   `pdfid`, `pdf-parser`
    *   `oletools` (`olevba` 등)
    *   `exiftool`, `strings`, `sha256sum`, `vt`
    *   `gemini` (Gemini CLI)


---

## 🚀 사용 방법 (Usage)

### 1. 🌟 전체 파이프라인 원클릭 자동 실행 (`auto_run.py`)

**가장 권장하는 방식입니다.** 메일 수집부터 Docker 컨테이너 생성, 스크립트 구동, AI 분석 및 찌꺼기 컨테이너 정리까지 모든 과정을 윈도우 환경에서 파이썬 명령 한 줄로 자동 제어합니다.

```bash
python auto_run.py
```

### 2. 💻 수동 분석을 위한 Docker 쉘 접속 (`run_kali_shell.py`)

복잡한 `docker run -v ...` 볼륨 마운트 명령어 입력 없이, 곧바로 필요한 권한과 마운트 설정이 적용된 채로 분석용 Kali 컨테이너 터미널에 접속합니다.

```bash
python run_kali_shell.py
```
*터미널 안에서 `python3 eml_analysis.py -ai` 등 개별 스크립트를 테스트할 수 있으며, `exit` 입력 시 컨테이너는 깔끔하게 삭제됩니다.*

### 3. 개별 파일/EML 수동 상세 분석

컨테이너 내부 쉘 환경(또는 필수 패키지가 구비된 환경)에서 사용할 수 있는 개별 명령어입니다.

**단일 파일 (PDF/XLS/IMG 등) 분석 (`file_analysis.py`)**
```bash
# 기본 사용법 (자동 파일 형식 감지)
python3 file_analysis.py -file <파일명>

# 엑셀 파일 심층 분석 (Unzip & Recursive Grep 적용)
python3 file_analysis.py -file <파일명.xlsx> --deep
```

**이메일 파싱 및 추출 (`extract_eml.py`)**
```bash
# URL 추출 및 목록 생성 (urls.txt)
python3 extract_eml.py --list

# VirusTotal API를 통해 추출된 URL 분석
python3 extract_eml.py --url -apikey <YOUR_VT_API_KEY>
```

---

## 📝 산출물 예시 및 구조

*   **분석 리포트 (`analysis_result/`)**: `[날짜]_[파일명]_ai.md` 등의 형태로 최종 리포트 저장.
*   **원본 파일 백업 (`analyzed_eml/` -> `backup/`)**: 분석이 끝난 폴더와 파일들은 백업 폴더로 안전하게 정리됩니다.
*   **보안 설정 관리**: API Key 등 민감한 정보가 담긴 `config.ini` 및 `.gemini/` 폴더는 `.dockerignore`를 통해 이미지에 담기지 않으며, 실행 시점에만 안전하게 볼륨 마운트 방식으로 전달됩니다.

## ⚠️ 주의사항

*   Docker 환경에서 Gemini 분석을 원활하게 수행하려면 `.gemini` 폴더를 포함하여 로컬 인증 정보가 볼륨으로 마운트되어야 합니다. (제공된 `run_kali_shell.py`와 `auto_run.py`가 이를 자동으로 지원하므로 가급적 래퍼 스크립트를 사용해 주세요.)

