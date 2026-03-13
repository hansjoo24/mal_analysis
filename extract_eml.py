#!/usr/bin/env python3
"""
EML Analyzer & URL VirusTotal Scanner (Refactored)
- 기능별 선택적 실행 및 덮어쓰기 지원
- config.ini 연동을 통한 API Key 관리 지원
"""

import os
import re
import json
import time
import email
import zipfile
import email.policy
import shutil
import requests
import argparse
import configparser
from email.header import decode_header
from base64 import urlsafe_b64encode
from urllib.parse import urlparse, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- 설정 및 경로 ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EML_DIR = os.path.join(SCRIPT_DIR, "eml")
OUTPUT_BASE_DIR = os.path.join(SCRIPT_DIR, "analyzed_eml")
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.ini")

# URL 추출을 위한 정규표현식 (수정: 끝에 붙은 불필요한 HTML 태그 < 등은 포함시키지 않음)
URL_PATTERN = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+(?<![<>"\'\s])'

# 필터링 제외 키워드 및 확장자
EXCLUDE_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', 
    '.woff', '.woff2', '.ttf', '.eot', '.otf', '.ico', '.webp'
}
EXCLUDE_DOMAINS = {
    'w3.org', 'schemas.microsoft.com', 'schemas.openxmlformats.org', 'purl.org',
    'xmlsoft.org', 'fonts.googleapis.com', 'fonts.gstatic.com',
    'img2.stibee.com', 'resource.stibee.com', 'stibee.com'
}
EXCLUDE_KEYWORDS = ['/editor/icon/', '/v2/open/', '/v2/thumb/']

# 최종 목적지 화이트리스트 (신뢰할 수 있는 도메인)
TRUSTED_DOMAINS = {
    'naver.com', 'lawtimes.co.kr', 'facebook.com', 'google.com', 'daum.net', 'kakao.com',
    'instagram.com', 'twitter.com', 'youtube.com', 'linkedin.com', 'apple.com', 'microsoft.com'
}

def sanitize_name(name):
    """파일명으로 사용할 수 없는 문자를 제거합니다."""
    return re.sub(r'[<>:"/\\|?*]', '_', name).strip(' .')

def decode_mime_header(header_value):
    """MIME 인코딩된 헤더 값을 디코딩합니다."""
    if not header_value:
        return "N/A"
    decoded_parts = decode_header(header_value)
    result = []
    for part, charset in decoded_parts:
        if isinstance(part, bytes):
            charset = charset or 'utf-8'
            try:
                result.append(part.decode(charset, errors='replace'))
            except Exception:
                result.append(part.decode('utf-8', errors='replace'))
        else:
            result.append(str(part))
    return ''.join(result)

def extract_urls(msg):
    """메일 본문(Text, HTML)에서 URL을 추출합니다."""
    urls = set()
    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type in ["text/plain", "text/html"]:
            try:
                payload = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')
                found = re.findall(URL_PATTERN, payload)
                urls.update(found)
                if content_type == "text/html":
                    attr_urls = re.findall(r'(?:href|src)=["\'](http[s]?://.*?)["\']', payload)
                    urls.update(attr_urls)
            except Exception as e:
                print(f"  [!] URL 추출 중 오류: {e}")
    return sorted(list(urls))

def get_final_destination(url):
    """URL의 리다이렉트를 추적하여 최종 도착 주소를 반환합니다."""
    try:
        # HEAD 요청으로 리다이렉트만 추적 (본문 제외하여 속도 향상)
        # allow_redirects=True로 설정하면 최종 URL까지 추적함
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.url
    except Exception:
        # 실패 시 원본 URL 반환
        return url

def filter_and_deduplicate_urls(urls):
    """3단계 URL 필터링: 사전 필터 -> 병렬 리다이렉트 추적 -> 최종 도메인 화이트리스트"""
    # 1단계: 문자열 사전 필터 (네트워크 요청 없음)
    initial_filtered = []
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        # 제외 도메인 체크
        if any(ex_dom in domain for ex_dom in EXCLUDE_DOMAINS):
            continue
        # 제외 확장자 체크
        ext = os.path.splitext(path)[1]
        if ext in EXCLUDE_EXTENSIONS:
            continue
        # 제외 키워드 체크
        if any(word in url for word in EXCLUDE_KEYWORDS):
            continue
            
        initial_filtered.append(url)

    if not initial_filtered:
        return []

    # 2단계/3단계: 병렬 리다이렉트 추적 및 최종 도메인 필터링
    print(f"    [*] 3단계 필터링 진행 중 ({len(initial_filtered)}개 URL, 병렬)...")
    
    final_filtered_results = []
    seen_pure_urls = set()
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(get_final_destination, url): url for url in initial_filtered}
        
        for future in as_completed(future_to_url):
            original_url = future_to_url[future]
            try:
                final_target_url = future.result()
                
                # 중복 체크를 위해 쿼리/프래그먼트 제거
                parsed_final = urlparse(final_target_url)
                pure_url = urlunparse((parsed_final.scheme, parsed_final.netloc, parsed_final.path, '', '', ''))
                
                # 3단계: 최종 목적지 도메인이 화이트리스트(TRUSTED)에 있는지 확인
                final_domain = parsed_final.netloc.lower()
                if any(trusted_dom in final_domain for trusted_dom in TRUSTED_DOMAINS):
                    continue
                
                # 순수 URL 기준 중복 체크
                if pure_url not in seen_pure_urls:
                    seen_pure_urls.add(pure_url)
                    final_filtered_results.append(original_url)
            except Exception as e:
                print(f"    [!] 오류 ({original_url[:30]}): {e}")
                final_filtered_results.append(original_url)
                
    return sorted(final_filtered_results)

def get_vt_analysis(url, api_key, re_analyze=False):
    """VirusTotal API v3를 사용하여 URL을 검사합니다."""
    if not api_key or api_key == "YOUR_VIRUSTOTAL_API_KEY":
        return {"error": "API Key not configured"}, {}

    vt_url = "https://www.virustotal.com/api/v3/urls"
    url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": api_key}
    
    try:
        # re_analyze가 True면 분석 요청(POST)을 먼저 보냄
        if re_analyze:
            requests.post(f"{vt_url}/{url_id}/analyse", headers=headers)

        response = requests.get(f"{vt_url}/{url_id}", headers=headers)
        
        # Rate limit 헤더 파싱
        rate_limits = {
            "hourly": response.headers.get("x-tool-request-rate-limit", "Unknown"),
            "daily": response.headers.get("x-day-request-rate-limit", "Unknown"),
            "monthly": response.headers.get("x-month-request-rate-limit", "Unknown")
        }
        
        if response.status_code == 200:
            return response.json(), rate_limits
        elif response.status_code == 404:
            post_response = requests.post(vt_url, headers=headers, data={"url": url})
            
            # Post 응답에 대한 Rate limit 업데이트
            rate_limits["hourly"] = post_response.headers.get("x-tool-request-rate-limit", rate_limits["hourly"])
            rate_limits["daily"] = post_response.headers.get("x-day-request-rate-limit", rate_limits["daily"])
            rate_limits["monthly"] = post_response.headers.get("x-month-request-rate-limit", rate_limits["monthly"])
            
            if post_response.status_code == 200:
                return post_response.json(), rate_limits
            else:
                return {"error": f"VT API Error (POST): {post_response.status_code}", "detail": post_response.text}, rate_limits
        else:
            return {"error": f"VT API Error (GET): {response.status_code}", "detail": response.text}, rate_limits
    except Exception as e:
        return {"error": str(e)}, {}

def load_vt_api_key():
    """config.ini 파일에서 VirusTotal API Key를 로드합니다."""
    if not os.path.exists(CONFIG_FILE):
        return None
    
    try:
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE)
        if 'virusTotal' in config and 'api_key' in config['virusTotal']:
            # 따옴표가 포함되어 있을 수 있으므로 제거
            return config['virusTotal']['api_key'].strip('"').strip("'")
    except Exception as e:
        print(f"[!] config.ini 로드 실패: {e}")
    return None

def cmd_extract(eml_dir, output_base):
    """1. EML 파일을 각 폴더로 복사합니다."""
    print(f"[*] 모드: extract (EML 파일 정리)")
    if not os.path.exists(eml_dir):
        print(f"  [!] EML 디렉토리가 없습니다: {eml_dir}")
        return

    eml_files = [f for f in os.listdir(eml_dir) if f.lower().endswith('.eml')]
    for eml_file in eml_files:
        src_path = os.path.join(eml_dir, eml_file)
        
        # 파일명이 너무 긴 경우 잘라서 사용 (폴더명 및 대상 파일명 모두 적용)
        # 윈도우/리눅스 파일 시스템에서 경로 제한이 걸리지 않도록 30글자 + 해시 8글자로 축소
        base_name = os.path.splitext(eml_file)[0]
        folder_name = sanitize_name(base_name)
        if len(folder_name) > 30:
            import hashlib
            short_hash = hashlib.md5(eml_file.encode('utf-8')).hexdigest()[:8]
            folder_name = f"{folder_name[:30]}..._{short_hash}"
            
        target_dir = os.path.join(output_base, folder_name)
        os.makedirs(target_dir, exist_ok=True)
        
        # 대상 파일 이름도 동일하게 줄여서 복사
        dest_eml_name = f"{folder_name}.eml"
        dest_path = os.path.join(target_dir, dest_eml_name)
        if os.path.exists(dest_path):
            print(f"  [-] {dest_eml_name} 이미 존재함. 덮어쓰기 위해 삭제 후 복사.")
            os.remove(dest_path)
        
        shutil.copy2(src_path, dest_path)
        print(f"  [+] 복사 완료: {eml_file[:30]}... -> {target_dir}")

def cmd_analyze_urls(output_base, api_key):
    """2. 각 폴더의 urls.txt 파일을 읽어 VirusTotal 분석을 수행합니다."""
    print(f"[*] 모드: url (URL VirusTotal 분석)")
    if not api_key:
        print(f"  [!] VirusTotal API Key가 설정되지 않았습니다. (config.ini 또는 -apikey 확인)")
        return
    if not os.path.exists(output_base):
        print(f"  [!] 분석 폴더가 없습니다: {output_base}")
        return

    for folder_name in sorted(os.listdir(output_base)):
        folder_path = os.path.join(output_base, folder_name)
        if not os.path.isdir(folder_path): continue
        
        # url_none.txt 가 있으면 분석 건너뜀
        url_none_path = os.path.join(folder_path, "url_none.txt")
        if os.path.exists(url_none_path):
            print(f"  [-] 분석 생략: {folder_name} (url_none.txt 존재 - 추출된 URL 없음)")
            continue
            
        # urls_filtered.txt 우선, 없으면 urls.txt
        urls_txt_path = os.path.join(folder_path, "urls_filtered.txt")
        if not os.path.exists(urls_txt_path):
            urls_txt_path = os.path.join(folder_path, "urls.txt")
            
        if not os.path.exists(urls_txt_path):
            print(f"  [-] URL 파일 없음: {folder_name} (먼저 --list 실행 필요)")
            continue
            
        print(f"  [*] 분석 중: {folder_name} ({os.path.basename(urls_txt_path)} 기반)")
        
        try:
            with open(urls_txt_path, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            if not urls:
                print(f"    [-] 분석할 URL이 없습니다.")
                continue

            cycle = 1
            while True:
                urls_to_analyze = []
                analysis_count = 0
                
                for url in urls:
                    safe_url_name = sanitize_name(url.replace("://", "_").replace("/", "_"))[:100]
                    json_path = os.path.join(folder_path, f"{safe_url_name}.json")
                    
                    skip_analysis = False
                    is_analysis = False
                    
                    if os.path.exists(json_path):
                        try:
                            with open(json_path, 'r', encoding='utf-8') as f_json:
                                existing_data = json.load(f_json)
                                data_type = existing_data.get("data", {}).get("type")
                                
                                # 분석 중(analysis)이거나, url 타입인데 탐지 결과가 0(incomplete)인 경우 재조회
                                is_incomplete_url = False
                                if data_type == "url":
                                    stats = existing_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                                    total_detections = sum([
                                        stats.get("malicious", 0),
                                        stats.get("suspicious", 0),
                                        stats.get("undetected", 0),
                                        stats.get("harmless", 0)
                                    ])
                                    # 모든 탐지 결과가 0이면 아직 분석이 덜 된 것으로 간주
                                    if total_detections == 0:
                                        is_incomplete_url = True

                                if data_type == "analysis" or is_incomplete_url:
                                    analysis_count += 1
                                    is_analysis = True
                                    skip_analysis = False # 다시 분석 필요
                                    
                                    # 너무 오래된 빈 결과면 명시적으로 재분석 요청 고려 (Optional)
                                    # 여기서는 일단 단순 대기/재조회만 수행
                                else:
                                    skip_analysis = True
                                    if cycle == 1:
                                        print(f"    [-] 분석 생략 (완료된 결과 유지): {url[:40]}...")
                        except:
                            pass # 파일 읽기 실패 시 재분석
                            
                    if not skip_analysis:
                        urls_to_analyze.append((url, json_path, is_analysis))
                        
                if not urls_to_analyze:
                    if cycle > 1:
                        print(f"    [+] 모든 URL 분석이 완료되었습니다.")
                    break
                    
                print(f"    [*] [Cycle {cycle}] 현재 대기중인 URL {analysis_count}개 / 전체 조사 대상 URL {len(urls)}개 / 미완료 종합 {len(urls_to_analyze)}개")
                
                # 1번째 사이클이 아닐 경우(재조회 시) 10초 대기 처리
                if cycle > 1 and analysis_count > 0:
                    print(f"    [⏳] 10초 대기 후 상태 업데이트를 확인합니다 (최대 10회 재시도)...")
                    time.sleep(10)
                    
                    # 무한 루프 방지를 위한 장치 (예: 10 사이클 이상이면 중단)
                    if cycle > 10:
                        print(f"    [!] 최대 재시도 횟수 초과. 현재까지의 결과를 저장하고 종료합니다.")
                        break

                for url, json_path, is_analysis in urls_to_analyze:
                    if is_analysis:
                        print(f"    [+] VT 상태 재조회: {url[:40]}...")
                    else:
                        print(f"    [+] VT 분석(초기): {url[:40]}...")
                        
                    vt_data, rate_limits = get_vt_analysis(url, api_key)
                    
                    if rate_limits and cycle == 1:
                        # 첫 사이클에만 사용량 출력
                        daily_limit = rate_limits.get('daily', 'Unknown')
                        hourly_limit = rate_limits.get('hourly', 'Unknown')
                        
                        if daily_limit != 'Unknown' and daily_limit != '':
                            print(f"        └─ [API 사용량] 시간당: {hourly_limit} | 일일: {daily_limit}")
                    
                    with open(json_path, 'w', encoding='utf-8') as f_json:
                        json.dump(vt_data, f_json, indent=4, ensure_ascii=False)
                        
                cycle += 1
        except Exception as e:
            print(f"    [!] 오류 발생: {e}")

def cmd_generate_list(output_base):
    """4. 각 폴더의 EML 파일을 기반으로 URL 리스트(urls.txt)를 생성합니다."""
    print(f"[*] 모드: list (URL 리스트 추출)")
    if not os.path.exists(output_base):
        print(f"  [!] 분석 폴더가 없습니다: {output_base}")
        return

    for folder_name in sorted(os.listdir(output_base)):
        folder_path = os.path.join(output_base, folder_name)
        if not os.path.isdir(folder_path): continue
        
        eml_files = [f for f in os.listdir(folder_path) if f.lower().endswith('.eml')]
        if not eml_files: continue
        
        eml_path = os.path.join(folder_path, eml_files[0])
        print(f"  [*] URL 추출 중: {folder_name}")
        
        try:
            with open(eml_path, 'rb') as f:
                msg = email.message_from_binary_file(f, policy=email.policy.default)
            urls = extract_urls(msg)
            
            # 1. 원본 urls.txt 저장
            urls_txt_path = os.path.join(folder_path, "urls.txt")
            with open(urls_txt_path, 'w', encoding='utf-8') as f_urls:
                f_urls.write('\n'.join(urls) + '\n')
            
            # 2. 필터링된 urls_filtered.txt 또는 url_none.txt 저장
            filtered_urls = filter_and_deduplicate_urls(urls)
            filtered_txt_path = os.path.join(folder_path, "urls_filtered.txt")
            url_none_path = os.path.join(folder_path, "url_none.txt")
            
            # 이전 파일들 정리 (재실행 시 꼬이지 않도록)
            if os.path.exists(filtered_txt_path): os.remove(filtered_txt_path)
            if os.path.exists(url_none_path): os.remove(url_none_path)
            
            if filtered_urls:
                with open(filtered_txt_path, 'w', encoding='utf-8') as f_furls:
                    f_furls.write('\n'.join(filtered_urls) + '\n')
            else:
                with open(url_none_path, 'w', encoding='utf-8') as f_none:
                    f_none.write('No URLs found after filtering.\n')
                
            print(f"    [+] URL 리스트 저장 완료: 원본({len(urls)}) / 필터링({len(filtered_urls)})")
        except Exception as e:
            print(f"    [!] 오류 발생: {e}")

def cmd_generate_info(output_base):
    """3. 각 폴더의 EML 파일을 기반으로 info 파일을 생성합니다."""
    print(f"[*] 모드: info (메일 정보 추출)")
    if not os.path.exists(output_base):
        print(f"  [!] 분석 폴더가 없습니다: {output_base}")
        return

    for folder_name in sorted(os.listdir(output_base)):
        folder_path = os.path.join(output_base, folder_name)
        if not os.path.isdir(folder_path): continue
        
        eml_files = [f for f in os.listdir(folder_path) if f.lower().endswith('.eml')]
        if not eml_files: continue
        
        eml_path = os.path.join(folder_path, eml_files[0])
        info_path = os.path.join(folder_path, f"{folder_name}_info.txt")
        print(f"  [*] 정보 생성: {folder_name}")
        
        try:
            with open(eml_path, 'rb') as f:
                msg = email.message_from_binary_file(f, policy=email.policy.default)
            
            sender = decode_mime_header(msg.get("From"))
            subject = decode_mime_header(msg.get("Subject"))
            
            # SPF 정보 추출 (Received-SPF 우선, 없으면 Authentication-Results)
            spf_info = "없음"
            received_spf = msg.get_all("Received-SPF")
            if received_spf:
                spf_info = " / ".join([val.replace("\n", " ").replace("\t", " ") for val in received_spf])
            else:
                auth_results = msg.get("Authentication-Results", "")
                if auth_results:
                    spf_match = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
                    if spf_match:
                        spf_info = spf_match.group(1)
            
            # DKIM 정보 추출 (DKIM-Signature 원본 유지)
            dkim_info = "없음"
            dkim_signatures = msg.get_all("DKIM-Signature")
            if dkim_signatures:
                dkim_info = "\n".join([f"DKIM-Signature: {sig.strip()}" for sig in dkim_signatures])
            else:
                auth_results = msg.get("Authentication-Results", "")
                if auth_results:
                    dkim_match = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
                    if dkim_match:
                        dkim_info = dkim_match.group(1)

            with open(info_path, 'w', encoding='utf-8') as f_info:
                f_info.write(f"- 메일 송신자 주소\n{sender}\n\n")
                f_info.write(f"- 메일 제목\n{subject}\n\n")
                f_info.write(f"- SPF\n{spf_info}\n\n")
                f_info.write(f"- DKIM 서명 정보\n{dkim_info}\n")
            print(f"    [+] {info_path} 저장 완료")
        except Exception as e:
            print(f"    [!] 오류 발생: {e}")

def cmd_generate_report(output_base):
    """5. 각 폴더의 VT JSON 결과들을 분석하여 통합 리포트(url_analyze_result.txt)를 생성합니다."""
    print(f"[*] 모드: report (VT 분석 결과 리포트 생성)")
    if not os.path.exists(output_base):
        print(f"  [!] 분석 폴더가 없습니다: {output_base}")
        return

    for folder_name in sorted(os.listdir(output_base)):
        folder_path = os.path.join(output_base, folder_name)
        if not os.path.isdir(folder_path): continue
        
        json_files = [f for f in os.listdir(folder_path) if f.lower().endswith('.json')]
        if not json_files: continue
        
        report_path = os.path.join(folder_path, "url_analyze_result.txt")
        print(f"  [*] 리포트 생성 중: {folder_name}")
        
        results = []
        for json_file in sorted(json_files):
            json_path = os.path.join(folder_path, json_file)
            try:
                with open(json_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # VT 결과 구조 확인
                if data.get("data", {}).get("type") == "url":
                    attr = data["data"]["attributes"]
                    url = attr.get("url")
                    final_url = attr.get("last_final_url", url)
                    stats = attr.get("last_analysis_stats", {})
                    
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                    
                    if malicious >= 1:
                        risk = "🚨 위험"
                    else:
                        risk = "✅ 안전"
                    
                    results.append(f"[{risk}] {url}\n    - 최종 목적지: {final_url}\n    - 탐지 결과: Malicious({malicious}), Suspicious({suspicious}), Harmless({harmless}), Undetected({undetected})")
                elif data.get("data", {}).get("type") == "analysis":
                    results.append(f"[⏳ 분석 진행 중] {json_file}\n    - 상세 정보가 아직 업데이트되지 않았습니다.")
                else:
                    results.append(f"[?] 알 수 없는 데이터 형식: {json_file}")
            except Exception as e:
                results.append(f"[!] 파일 처리 오류 ({json_file}): {e}")
        
        if results:
            with open(report_path, 'w', encoding='utf-8') as f_report:
                f_report.write(f"=== {folder_name} URL 분석 리포트 ===\n\n")
                f_report.write("\n\n".join(results) + "\n")
            print(f"    [+] {report_path} 저장 완료")

def cmd_extract_attachments(output_base):
    """6. 각 폴더의 EML 파일에서 첨부파일을 추출합니다."""
    print(f"[*] 모드: attach (첨부파일 추출)")
    if not os.path.exists(output_base):
        print(f"  [!] 분석 폴더가 없습니다: {output_base}")
        return

    for folder_name in sorted(os.listdir(output_base)):
        folder_path = os.path.join(output_base, folder_name)
        if not os.path.isdir(folder_path): continue
        
        eml_files = [f for f in os.listdir(folder_path) if f.lower().endswith('.eml')]
        if not eml_files: continue
        
        eml_path = os.path.join(folder_path, eml_files[0])
        
        try:
            with open(eml_path, 'rb') as f:
                msg = email.message_from_binary_file(f, policy=email.policy.default)
            
            attach_dir = os.path.join(folder_path, "attachments")
            has_attachment = False
            
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                    
                filename = part.get_filename()
                if not filename:
                    continue
                
                if not has_attachment:
                    os.makedirs(attach_dir, exist_ok=True)
                    has_attachment = True
                    print(f"  [*] 첨부파일 추출 중: {folder_name}")
                
                filename = decode_mime_header(filename)
                
                # 파일명 안전하게 포맷팅하되 확장자는 최대한 보존하도록 수정 (점 유지)
                safe_filename = re.sub(r'[<>:"/\\|?*]', '_', filename).strip(' ')
                if not safe_filename:
                    safe_filename = "unknown_attachment"
                    
                filepath = os.path.join(attach_dir, safe_filename)
                
                # 파일이 이미 존재하면 건너뜀
                base_name, target_ext = os.path.splitext(safe_filename)
                if os.path.exists(filepath):
                    print(f"    [-] 건너뜀 (이미 존재함): {os.path.basename(filepath)}")
                    continue
                
                with open(filepath, 'wb') as f_out:
                    payload = part.get_payload(decode=True)
                    if payload:
                        f_out.write(payload)
                
                print(f"    [+] 저장 완료: {os.path.basename(filepath)}")
                
                # 만약 방금 저장한 파일이 ZIP 파일이라면 압축 해제 수행
                if target_ext.lower() == '.zip':
                    # 압축 풀 디렉토리 (ZIP 파일명과 동일하게 하위 폴더 생성)
                    unzip_dir = os.path.join(attach_dir, base_name)
                    os.makedirs(unzip_dir, exist_ok=True)
                    print(f"    [*] ZIP 파일 감지됨. 압축 해제 중: {base_name}.zip -> {unzip_dir}/")
                    try:
                        with zipfile.ZipFile(filepath, 'r') as zip_ref:
                            zip_ref.extractall(unzip_dir)
                        print(f"    [+] 압축 해제 완료: {base_name}.zip")
                    except Exception as e:
                        print(f"    [!] 압축 해제 실패 ({base_name}.zip): {e}")
                
        except Exception as e:
            print(f"    [!] 첨부파일 추출 오류 ({folder_name}): {e}")

def main():
    parser = argparse.ArgumentParser(description="EML Analyzer Refactored (Extract/List/URL/Info) with config.ini support")
    parser.add_argument("--extract", action="store_true", help="EML 파일을 폴더별로 정리 및 복사")
    parser.add_argument("--list", action="store_true", help="EML에서 URL만 추출하여 urls.txt 생성 (VT 분석 안 함)")
    parser.add_argument("--url", action="store_true", help="urls.txt의 URL 목록을 VirusTotal로 분석")
    parser.add_argument("--info", action="store_true", help="추출된 EML의 메일 정보(txt) 생성")
    parser.add_argument("--report", action="store_true", help="VT 분석 결과 JSON들을 취합하여 리포트(txt) 생성")
    parser.add_argument("--attach", action="store_true", help="EML 파일에서 첨부파일을 추출 (attachments 폴더 생성)")
    parser.add_argument("-apikey", help="VirusTotal API Key (입력 시 config.ini보다 우선)")
    parser.add_argument("-dir", default=EML_DIR, help="원본 EML 디렉토리 (기본: ./eml/)")
    
    args = parser.parse_args()
    
    if not (args.extract or args.url or args.info or args.list or args.report or args.attach):
        parser.print_help()
        return

    os.makedirs(OUTPUT_BASE_DIR, exist_ok=True)

    # API Key 결정 (인자 우선, 없으면 config.ini)
    vt_api_key = args.apikey if args.apikey else load_vt_api_key()

    if args.extract:
        cmd_extract(args.dir, OUTPUT_BASE_DIR)
    
    if args.list:
        cmd_generate_list(OUTPUT_BASE_DIR)
    
    if args.url:
        cmd_analyze_urls(OUTPUT_BASE_DIR, vt_api_key)
        
    if args.info:
        cmd_generate_info(OUTPUT_BASE_DIR)
        
    if args.attach:
        cmd_extract_attachments(OUTPUT_BASE_DIR)
        
    if args.report:
        cmd_generate_report(OUTPUT_BASE_DIR)

if __name__ == "__main__":
    main()
