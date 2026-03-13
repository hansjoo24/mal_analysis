# 🛡️ Automated File Analysis & AI Report Tool

이 프로젝트는 의심스러운 파일(PDF, Excel, Image, EXE)을 다각도로 분석하고, 그 결과를 AI(Gemini)와 연동하여 상세한 보안 분석 보고서를 자동 생성하는 도구입니다.

## 📂 주요 기능 및 업데이트

1.  **`file_analysis.py`**: 정적 분석 도구
    *   **다양한 포맷 지원**: PDF, Excel, Image(PNG/JPG), EXE(PE) 파일 분석.
    *   **심층 분석 옵션 (`--deep`)**: Excel 파일(xlsx)의 압축을 풀고 내부 구조(매크로, 외부 링크, 스크립트 등)를 정밀 검사.
    *   **자동 감지**: 파일 확장자에 따른 자동 분석 모드 지원.

2.  **`ai_analysis.py`**: AI 자동화 래퍼 (Batch Processing)
    *   **비동기 일괄 처리**: Python `asyncio`를 사용하여 폴더 내의 **모든 파일**을 동시에 빠르게 분석.
    *   **AI 리포트 생성**: 분석된 기술적 데이터를 바탕으로 사람이 읽기 쉬운 한글 요약 보고서 생성.
    *   **자동 파일 정리**: 분석이 완료된 원본 파일은 `analyzed` 폴더로 자동 이동.

3.  **`extract_eml.py`**: EML 이메일 파일 전용 분석 도구
    *   **EML 파싱 및 추출**: 이메일 파일 내의 정보(본문, 첨부파일 등)를 파싱하고 폴더별로 정리.
    *   **URL 추출 및 악성 검증**: 이메일 본문 내 URL을 추출하고 VirusTotal과 연동하여 악성 여부 자동 검사.
    *   **리포트 자동 생성**: 추출된 이메일 정보와 VirusTotal 검사 결과를 취합하여 상세 리포트 생성.

---

## 🛠️ 사전 요구사항 (Prerequisites)

이 도구를 사용하기 위해 다음 환경이 구성되어 있어야 합니다.

*   **Python 3**: 메인 스크립트 실행
*   **Gemini CLI**: `gemini-cli` (AI 분석용)
*   **분석 도구 (Dependencies)**:
    *   `pdfid`, `peepdf` (PDF)
    *   `oletools`, `olevba` (Excel)
    *   `exiftool` (Image)
    *   `pefile` (EXE - Python 라이브러리)
    *   `strings`, `grep`, `file`, `unzip` (또는 내장 라이브러리)
    *   `sha256sum` (Hash)
    *   `vt` (VirusTotal CLI)

---

## 🚀 사용 방법 (Usage)

### 1. 개별 파일 상세 분석 (`file_analysis.py`)

단일 파일에 대해 기술적인 분석을 수행하고 결과를 출력합니다.

```bash
# 기본 사용법 (자동 파일 형식 감지)
python file_analysis.py -file <파일명>

# 엑셀 파일 심층 분석 (Unzip & Recursive Grep)
python file_analysis.py -file <파일명.xlsx> --deep
```

**주요 옵션:**
*   `-file`: 파일 형식을 자동 감지하여 분석합니다.
*   `--deep`, `-d`: (엑셀 전용) 압축 해제 후 내부 XML 및 파일들에 대해 정밀 검색(cmd, powershell, url 등)을 수행합니다.
*   `-out`: 로그 저장 경로 지정.

---

### 2. AI 일괄/단일 분석 (`ai_analysis.py`)

여러 파일을 한 번에 처리하거나, AI 분석 리포트를 받아보고 싶을 때 사용합니다.

#### A. 폴더 내 모든 파일 일괄 분석 (Batch Mode)
별도의 인자 없이 실행하면, **현재 디렉토리**에 있는 분석 대상 파일들을 자동으로 찾아 **병렬(비동기) 분석**을 시작합니다.

```bash
python ai_analysis.py
```

*   **동작 흐름**:
    1.  현재 폴더 스캔 (스크립트 제외)
    2.  `file_analysis.py` 실행 (엑셀일 경우 `--deep` 모드 자동 적용 등)
    3.  `gemini-cli`로 리포트 생성
    4.  결과물은 `analysis_result` 폴더(또는 지정 경로)에 저장
    5.  **완료된 원본 파일은 `./analyzed` 폴더로 이동**

#### B. 단일 파일 분석 (Single Mode)
특정 파일 하나만 분석하고 싶을 때 사용합니다.

```bash
python ai_analysis.py -file malicious_doc.xlsx
```

---

### 3. EML 파일 분석 (`extract_eml.py`)

의심스러운 EML(이메일) 파일에서 정보를 추출하고, 포함된 URL을 VirusTotal을 통해 분석하여 리포트를 자동 생성합니다.

```bash
# 기본 파싱 및 메일 정보 추출
python extract_eml.py --extract --info

# EML에서 URL만 추출하여 목록 생성 (urls.txt)
python extract_eml.py --list

# VirusTotal API를 통해 추출된 URL 분석
python extract_eml.py --url -apikey <YOUR_VT_API_KEY>

# 분석된 데이터를 바탕으로 최종 종합 리포트 생성
python extract_eml.py --report
```

**주요 옵션:**
*   `--extract`: EML 파일을 폴더별로 정리 및 복사합니다.
*   `--list`: EML에서 URL만 추출하여 `urls.txt`를 생성합니다. (VT 분석 안 함)
*   `--url`: `urls.txt`의 URL 목록을 VirusTotal로 분석합니다.
*   `--info`: 추출된 EML의 메일 정보(txt)를 생성합니다.
*   `--attach`: EML 파일 내의 첨부파일을 추출하여 `attachments` 폴더에 저장합니다.
*   `--report`: VT 분석 결과 JSON들을 취합하여 리포트(txt)를 생성합니다.
*   `-apikey <APIKEY>`: VirusTotal API Key를 지정합니다. (입력 시 `config.ini`보다 우선)
*   `-dir <DIR>`: 원본 EML 디렉토리를 설정합니다. (기본값: `./eml/`)

---

## 📝 산출물 예시

*   **분석 리포트 (`analysis_result/`)**: `[날짜]_[파일명]_analyis_result.md`
    *   포함 내용: 파일 정보, 감지된 위협(해시, 매크로, 문자열), AI 종합 의견, 원본 로그.
*   **이동된 원본 (`analyzed/`)**: 분석이 끝난 파일들이 안전하게 격리/이동됨.

## ⚠️ 주의사항

*   일괄 분석(`ai_analysis.py`) 실행 시, 현재 폴더의 파일 위치가 변경(이동)되므로 테스트 시 유의하세요.
*   `--deep` 옵션은 압축을 해제하므로 디스크 공간을 일시적으로 사용하며, 완료 후 자동 삭제됩니다.
