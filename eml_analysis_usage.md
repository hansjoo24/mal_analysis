# `eml_analysis.py` 사용법 및 옵션 안내

`eml_analysis.py`는 EML 형식의 이메일 파일에 대해 비동기(Async) 및 일괄(Batch) 처리를 지원하는 AI 기반 보안 분석 래퍼(Wrapper) 스크립트입니다. 원본 EML에서 본문, URL, 첨부파일 등을 추출한 뒤, 바이러스토탈(VirusTotal) 통신 및 각종 분석 스크립트를 연동하여 위협 여부를 점검하고 종합적인 마크다운(`.md`) 보고서를 생성합니다.

## 기본 사용법

명령줄(Terminal/CMD)에서 다음과 같이 실행할 수 있습니다.

```bash
python eml_analysis.py [옵션]
```

### 1. 단일 파일 분석
특정 EML 파일 하나만 분석할 때 사용합니다.
```bash
python eml_analysis.py -file sample.eml
```

### 2. 디렉토리 내 일괄 분석
옵션 없이 실행하거나 `-file`을 지정하지 않으면, 스크립트가 실행된 현재 디렉토리 안의 모든 `.eml` 파일을 찾아 일괄적으로 분석을 시도합니다.
```bash
python eml_analysis.py
```

### 3. 첨부파일 일괄 재분석
기존에 한 번 EML이 추출되어 `analyzed_eml` 하위에 저장된 폴더들을 훑으면서, 추출된 첨부파일들만 다시 심층 분석을 돌릴 때 사용합니다.
```bash
python eml_analysis.py -reanalyze-attachments
```

---

## 옵션 설명 (Options)

| 옵션 / 기본값 | 설명 |
| :--- | :--- |
| `-h`, `--help` | 프로그램의 도움말 메시지를 출력하고 종료합니다. |
| `-file FILENAME` | 분석할 대상 `EML` 파일의 경로를 지정합니다.<br>- 입력 예시: `-file ./suspicious.eml`<br>- 이 옵션을 생략하면 현재 작업 디렉토리 내의 모든 EML 파일을 대상으로 다중 처리를 수행합니다. |
| `-out OUTPUT_DIR` | 최종 AI EML 분석 보고서(`.md`)가 저장될 디렉토리 경로를 지정합니다.<br>- 기본값: `/mnt/hgfs/Suspicious_File/analysis_result/` |
| `-apikey APIKEY` | VirusTotal(바이러스토탈) 검사에 사용할 API Key를 입력합니다.<br>- 입력 시 `config.ini` 파일에 저장된 설정값보다 이 옵션값이 최우선으로 적용됩니다. |
| `-reanalyze-attachments` | 새로운 EML 파일 분석 사이클을 돌리는 대신, 이전에 추출해둔 폴더(`analyzed_eml/`) 내부의 모든 **첨부파일만 다시 전체 재분석**할 때 사용되는 플래그입니다. |

---

## 프로그램 동작 흐름 (워크플로우)

`eml_analysis.py`는 내부적으로 다음과 같은 절차로 자동화된 분석을 수행합니다.

1. **임시 처리 디렉토리 준비**:
   - `temp_파일명_processing` 구조를 만들어 타겟 파일을 복사하여 안전하게 처리 환경을 세팅합니다.
2. **이메일 정보 및 아티팩트 추출 (`extract_eml.py` 연동)**:
   - 본문 텍스트 압축 해제 및 파싱
   - 이메일 내 포함된 URL 리스트업
   - EML 헤더 정보(SPF, DKIM, 발신자, 수신자 등) 추출
   - 파일 첨부물(Attachments) 분리 및 저장
3. **URL 악성 여부 분석**:
   - 추출된 URL을 `VirusTotal` API로 검색하여 악성 검사 보고서(`url_analyze_result.txt`)를 생성합니다.
4. **첨부파일 개별 분석 (`file_analysis.py` 연동)**:
   - 추출된 각각의 첨부파일의 타입을 판별(`detect_file_type`)합니다.
   - 각 파일 타입에 맞는 심층 분석 로직(`run_analysis_on_file`)을 수행하고 결과를 `파일명_file_analysis.txt`로 기록합니다.
5. **분석 데이터 취합 및 로깅**:
   - 추출 메일 정보, VirusTotal 결과, 첨부파일 분석 결과를 하나의 컨텍스트로 취합합니다.
   - 현재는 AI 연동이 테스트 모드(주석 처리)로 되어 있어, 프롬프트 전송 대신 취합된 **데이터 원문 정보**를 기반으로 보고서(`.md`) 텍스트가 조립됩니다.
6. **최종 보고서 생성 및 파일 정리**:
   - 조립된 최종 보고서는 `-out` 옵션으로 지정한 경로(기본: `analysis_result/`)에 `YYMMDD_파일명_eml_analysis_result.md` 형태로 저장됩니다.
   - 처리가 끝난 원본 EML 파일은 중복 분석 방지를 위해 원본 위치의 `analyzed/` 라는 별도 폴더로 이동됩니다. 
   - 사용했던 모든 임시 폴더들은 자동으로 초기화(삭제) 및 정리됩니다.
