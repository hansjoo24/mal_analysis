#!/usr/bin/env python3

import argparse
import subprocess
import sys
import os
import datetime
import shutil
import asyncio
import hashlib
import re
import concurrent.futures

# 파일 분석 시 sys.stdout 리다이렉션 충돌 방지 및 병렬 I/O 가속을 위한 멀티프로세스 풀
process_pool = concurrent.futures.ProcessPoolExecutor(max_workers=5)

# extract_eml.py 등 외부 모듈 임포트
try:
    from extract_eml import (
        cmd_extract,
        cmd_generate_list,
        cmd_analyze_urls,
        cmd_generate_info,
        cmd_extract_attachments,
        cmd_generate_report,
        load_vt_api_key
    )
    from file_analysis import (
        run_analysis_on_file,
        detect_file_type
    )
except ImportError as e:
    print(f"\033[91m[!] 필수 모듈을 찾을 수 없습니다: {e}\033[0m")
    sys.exit(1)

# 분석 결과가 최종 저장될 디렉토리 경로
output_path = "/mnt/hgfs/Suspicious_File/analysis_result/"
# EML 추출물을 임시/중간 저장할 베이스 디렉토리
eml_output_base = "/mnt/hgfs/Suspicious_File/analyzed_eml/"

# AI 분석용 공통 프롬프트
AI_ANALYSIS_PROMPT = """
- 이 내용은 이메일 파일(.eml)의 자동 분석 결과야. 다음의 형식을 지켜 이 파일에 대한 종합 보안 분석 결과를 한글로 작성해줘. 
# 1. 분석 개요
- 이메일 제목 : 
- 분석 일시 : 

# 2. 메일 평판 분석 결과
- 메일의 송신자 정보, SPF 인증 정보, DKIM 서명 정보를 확인하여 평판을 분석하고 신뢰할 수 있는지 판단해줘. 
### 1) 정상 / 악성 이메일 확률 분류 (정상 확률 n% / 악성 확률 n%)
### 2) 기업/도메인 평판 (DKIM 서명 도메인이 알려진 도메인인지, 송신자 기업 정보 등 구체적 서술)
### 3) SPF/DKIM 인증 정보 분석 종합

# 3. 본문 내 URL 분석 결과
- 같이 제공된 URL(Virus Total API) 분석 결과를 확인하고 해당 메일에 악성 링크가 포함되어 있는지 작성해줘. 
### 1) 정상 / 악성 링크 포함 여부 설명

# 4. 첨부파일 분석 결과
- 첨부된 파일 목록(추출 결과)을 보고 의심스러운 파일 확장자(.exe, .zip, .js, 임의의 문서 등)가 포함되어 있는지, 어떤 위협이 있을 수 있는지 간략히 작성해줘.
### 1) 첨부파일 목록 및 위험도 평가

# 5. 최종 결론
- 해당 이메일이 스피어피싱 또는 악성 스팸일 확률에 대한 종합적인 설명과 최종 권고사항 작성
"""

async def run_command_async(cmd_list, input_data=None):
    """
    서브프로세스 명령어를 비동기적으로 실행합니다.
    반환값: (returncode, stdout, stderr)
    """
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd_list,
            stdin=asyncio.subprocess.PIPE if input_data else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate(input=input_data.encode() if input_data else None)
        return process.returncode, stdout.decode().strip(), stderr.decode().strip()
    except Exception as e:
        return -1, "", str(e)

def generate_summary_text(folder_path, folder_name):
    """
    지정된 폴더에서 info.txt, url_analyze_result.txt, attachments 분석 결과를
    읽어와서 총합 텍스트를 구성하여 반환합니다.
    """
    # 1. info.txt
    info_text = ""
    info_file = os.path.join(folder_path, f"{folder_name}_info.txt")
    if os.path.exists(info_file):
        with open(info_file, 'r', encoding='utf-8') as f:
            info_text = f.read().strip()
    else:
        for f_name in os.listdir(folder_path):
            if f_name.endswith("info.txt"):
                with open(os.path.join(folder_path, f_name), 'r', encoding='utf-8') as f:
                    info_text = f.read().strip()
                break

    # 2. url_analyze_result.txt
    url_text = "eml 내부 url 없음"
    url_file = os.path.join(folder_path, "url_analyze_result.txt")
    if os.path.exists(url_file):
        with open(url_file, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if content:
                url_text = content

    # 3. 첨부파일 분석 결과
    attach_texts = []
    attach_dir = os.path.join(folder_path, "attachments")
    if os.path.exists(attach_dir):
        for root, _, files in os.walk(attach_dir):
            for f_name in files:
                if f_name.endswith("_file_analysis.txt"):
                    with open(os.path.join(root, f_name), 'r', encoding='utf-8') as f:
                        attach_texts.append(f"--- 파일명: {f_name} 분석 결과 ---\n{f.read().strip()}")
    
    if attach_texts:
        attachments_info = "\n\n".join(attach_texts)
    else:
        attachments_info = "첨부파일 없음"

    summary_content = f"""===========================
[이메일 정보]
{info_text}
===========================
[본문 내 URL 분석 결과]
{url_text}
===========================
[첨부파일 분석 결과]
{attachments_info}
===========================
"""
    return summary_content

async def analyze_eml_file_async(target_file, output_dir_base, vt_api_key, semaphore):
    async with semaphore:
        target_abs_path = os.path.abspath(target_file)
        filename = os.path.basename(target_abs_path)
        # 확장자를 제외한 파일명 (폴더명으로 쓰임)
        base_name, _ = os.path.splitext(filename)
        
        if not os.path.exists(target_abs_path):
            print(f"\033[91m[!] File not found: {target_file}\033[0m")
            return

        # 출력 디렉토리 확인/생성
        os.makedirs(output_dir_base, exist_ok=True)
        os.makedirs(eml_output_base, exist_ok=True)

        print(f"\n{'='*60}")
        print(f"[*] [START] Analyzing EML: {filename}")
        print(f"{'='*60}")
        
        # 길이가 너무 길어 에러가 발생하지 않도록 짧은 해시 사용
        short_hash = hashlib.md5(target_abs_path.encode('utf-8')).hexdigest()[:8]
        
        # 1. 파일명 길이 제한 적용 (추출된 결과물 경로 오류 방지용)
        # 윈도우/리눅스 파일 시스템에서 경로 제한이 걸리지 않도록 30글자 + 해시 8글자로 대폭 축소
        safe_folder_name = re.sub(r'[<>:"/\\|?*]', '_', base_name).strip(' .')
        if len(safe_folder_name) > 30:
            safe_folder_name = f"{safe_folder_name[:30]}..._{short_hash}"
        temp_target_dir = os.path.join(os.path.dirname(target_abs_path), f"temp_{short_hash}_proc")
        os.makedirs(temp_target_dir, exist_ok=True)
        
        temp_eml_path = os.path.join(temp_target_dir, filename)
        await asyncio.to_thread(shutil.copy2, target_abs_path, temp_eml_path)
        
        temp_eml_output_base = os.path.join(os.path.dirname(target_abs_path), f"temp_{short_hash}_out")
        os.makedirs(temp_eml_output_base, exist_ok=True)
        
        try:
            # extract_eml 파이프라인 수동 스케쥴링
            # 주의: temp_eml_output_base 아래에 safe_folder_name 폴더가 생성됨
            print(f"  [-] Extracting EML contents...")
            cmd_extract(temp_target_dir, temp_eml_output_base)
            print(f"  [-] Generating URL list...")
            cmd_generate_list(temp_eml_output_base)
            print(f"  [-] Extracting attachments...")
            cmd_extract_attachments(temp_eml_output_base)
            print(f"  [-] Generating Email Info...")
            cmd_generate_info(temp_eml_output_base)
            print(f"  [-] Analyzing URLs via VirusTotal...")
            cmd_analyze_urls(temp_eml_output_base, vt_api_key)
            print(f"  [-] Generating VT Report...")
            cmd_generate_report(temp_eml_output_base)
            
            # 2. 결과 텍스트 읽어오기 및 AI에게 전달할 종합 Context 문자열 구성
            # extract_eml이 생성한 실제 폴더명 찾기
            actual_folder_list = os.listdir(temp_eml_output_base)
            if not actual_folder_list:
                print(f"\033[91m[!] [{filename}] 추출된 폴더를 찾을 수 없습니다.\033[0m")
                return
            
            # 단일 EML을 분석하므로 폴더는 1개만 생성되었어야 함
            actual_folder_name = actual_folder_list[0]
            extracted_folder = os.path.join(temp_eml_output_base, actual_folder_name)
            
            # --- 2.1 첨부파일 개별 분석 (file_analysis.py 연동) ---
            attach_dir = os.path.join(extracted_folder, "attachments")
            if os.path.exists(attach_dir):
                files_to_analyze = []
                for root, _, files in os.walk(attach_dir):
                    for f in files:
                        if not f.endswith("_file_analysis.txt"):
                            files_to_analyze.append(os.path.join(root, f))
                
                if files_to_analyze:
                    print(f"  [-] Analyzing {len(files_to_analyze)} attachments in {attach_dir}...")
                    for af_path in files_to_analyze:
                        af = os.path.basename(af_path)
                        rel_path = os.path.relpath(af_path, attach_dir)
                        f_type = detect_file_type(af_path)
                        
                        if f_type:
                            print(f"    [-] Running file_analysis on: {rel_path} ({f_type})")
                            loop = asyncio.get_running_loop()
                            analysis_res = await loop.run_in_executor(process_pool, run_analysis_on_file, af_path, f_type, True)
                            if analysis_res:
                                safe_name, _ = os.path.splitext(af)
                                res_file_path = os.path.join(os.path.dirname(af_path), f"{safe_name}_file_analysis.txt")
                                with open(res_file_path, 'w', encoding='utf-8') as out_f:
                                    out_f.write(analysis_res)

            # generate_summary_text를 사용하여 내용 취합
            ai_input_data = generate_summary_text(extracted_folder, actual_folder_name)
            
            # 3. 임시 폴더에서 최종 폴더(eml_output_base)로 결과물 이동 이동
            final_extracted_folder = os.path.join(eml_output_base, actual_folder_name)
            if os.path.exists(final_extracted_folder):
                await asyncio.to_thread(shutil.rmtree, final_extracted_folder)
            await asyncio.to_thread(shutil.move, extracted_folder, final_extracted_folder)
            
        finally:
            # 임시 처리 디렉토리 정리
            if os.path.exists(temp_target_dir):
                await asyncio.to_thread(shutil.rmtree, temp_target_dir)
            if os.path.exists(temp_eml_output_base):
                await asyncio.to_thread(shutil.rmtree, temp_eml_output_base)

        # 4. Generate _summary.txt for AI Prompt Context
        summary_out_file = os.path.join(final_extracted_folder, f"{actual_folder_name}_summary.txt")
        with open(summary_out_file, 'w', encoding='utf-8') as f:
            f.write(ai_input_data)
        print(f"  [+] Saved AI context summary to: {os.path.basename(summary_out_file)}")

        return actual_folder_name

    # 분석 완료, 원본 EML 파일은 그대로 폴더에 유지

async def reanalyze_all_attachments_async():
    """기존에 분석된 analyzed_eml 폴더들을 순회하며 모든 첨부파일을 (재)분석합니다."""
    print(f"[*] Starting batch re-analysis of attachments in: {eml_output_base}")
    
    if not os.path.exists(eml_output_base):
        print(f"\033[91m[!] Directory not found: {eml_output_base}\033[0m")
        return

    for folder_name in sorted(os.listdir(eml_output_base)):
        folder_path = os.path.join(eml_output_base, folder_name)
        if not os.path.isdir(folder_path):
            continue
            
        attach_dir = os.path.join(folder_path, "attachments")
        if not os.path.exists(attach_dir):
            continue
            
        print(f"\n[*] Folder: {folder_name}")
        found_files = 0
        
        for root, _, files in os.walk(attach_dir):
            for file in files:
                if file.endswith("_file_analysis.txt"):
                    continue
                    
                target = os.path.join(root, file)
                f_type = detect_file_type(target)
                if f_type:
                    found_files += 1
                    rel_path = os.path.relpath(target, attach_dir)
                    print(f"  [-] Processing: {rel_path} ({f_type})")
                    loop = asyncio.get_running_loop()
                    analysis_res = await loop.run_in_executor(process_pool, run_analysis_on_file, target, f_type, True)
                    if analysis_res:
                        safe_name, _ = os.path.splitext(file)
                        res_file_path = os.path.join(root, f"{safe_name}_file_analysis.txt")
                        with open(res_file_path, 'w', encoding='utf-8') as out_f:
                            out_f.write(analysis_res)
                        print(f"    [+] Saved: {os.path.basename(res_file_path)}")
        
        if found_files == 0:
            print("  [-] No supported attachments found.")
            
    print("\n[*] Attachment re-analysis completed.")

async def preprocess_for_ai_async():
    """analyzed_eml 폴더 내의 분석 결과들을 모아 AI 분석용 총합 파일을 생성합니다."""
    print(f"[*] Starting AI preprocessing in: {eml_output_base}")
    if not os.path.exists(eml_output_base):
        print(f"\033[91m[!] Directory not found: {eml_output_base}\033[0m")
        return

    for folder_name in sorted(os.listdir(eml_output_base)):
        folder_path = os.path.join(eml_output_base, folder_name)
        if not os.path.isdir(folder_path):
            continue
            
        print(f"\n[*] Preprocessing Folder: {folder_name}")
        
        # 신규 추가된 텍스트 병합 함수 사용
        summary_content = generate_summary_text(folder_path, folder_name)
        out_file = os.path.join(folder_path, f"{folder_name}_summary.txt")
        with open(out_file, 'w', encoding='utf-8') as f:
            f.write(summary_content)
        print(f"  [+] Saved AI summary: {os.path.basename(out_file)}")

    print("\n[*] AI preprocessing completed.")

async def _process_single_ai_analysis(folder_path, folder_name, summary_file, prompt, semaphore, output_dir_base):
    async with semaphore:
        print(f"  [*] Running AI analysis for: {folder_name}")
        
        with open(summary_file, 'r', encoding='utf-8') as f:
            summary_content = f.read()

        cmd_ai = ["gemini-cli", AI_ANALYSIS_PROMPT]
        ret_code_ai, ai_stdout, ai_stderr = await run_command_async(cmd_ai, input_data=summary_content)
        
        if ret_code_ai != 0:
            print(f"\033[91m  [!] gemini-cli failed for {folder_name}: {ai_stderr}\033[0m")
            return
            
        ai_md_file = os.path.join(folder_path, f"{folder_name}_ai.md")
        
        final_content = f"""# AI 종합 보안 분석 결과
{ai_stdout}

---

# 원본 분석 데이터
```text
{summary_content}
```
"""
        with open(ai_md_file, 'w', encoding='utf-8') as f:
            f.write(final_content)
        print(f"  [+] AI analysis saved to {os.path.basename(ai_md_file)}")

        # /analysis_result 디렉토리로 복사
        os.makedirs(output_dir_base, exist_ok=True)
        date_str = datetime.datetime.now().strftime("%y%m%d")
        dest_filename = f"{date_str}_{folder_name}_ai.md"
        if len(dest_filename) > 200:
            short_hash = hashlib.md5(folder_name.encode('utf-8')).hexdigest()[:8]
            dest_filename = f"{date_str}_{folder_name[:150]}_{short_hash}_ai.md"
            
        dest_path = os.path.join(output_dir_base, dest_filename)
        await asyncio.to_thread(shutil.copy2, ai_md_file, dest_path)
        print(f"  [+] Copied to analysis_result: {dest_filename}")


async def run_ai_analysis_async(output_dir_base=output_path, target_folders=None):
    """_summary.txt 파일들을 기반으로 gemini-cli를 실행하여 AI 분석 결과를 파일 상단에 추가합니다."""
    print(f"\n[*] Starting AI analysis phase in: {eml_output_base}")
    if not os.path.exists(eml_output_base):
        print(f"\033[91m[!] Directory not found: {eml_output_base}\033[0m")
        return

    found_any_summary = False
    tasks = []
    
    # 동시 실행 수를 5개로 제한하기 위해 세마포어 사용
    semaphore = asyncio.Semaphore(5)
    
    folders_to_scan = sorted(os.listdir(eml_output_base)) if target_folders is None else target_folders

    for folder_name in folders_to_scan:
        folder_path = os.path.join(eml_output_base, folder_name)
        if not os.path.isdir(folder_path):
            continue
            
        summary_file = os.path.join(folder_path, f"{folder_name}_summary.txt")
        if not os.path.exists(summary_file):
            continue
            
        found_any_summary = True
        tasks.append(asyncio.create_task(_process_single_ai_analysis(folder_path, folder_name, summary_file, AI_ANALYSIS_PROMPT, semaphore, output_dir_base)))

    if not found_any_summary:
        print("\033[91m[!] 경고: 분석을 진행할 _summary.txt 파일을 찾을 수 없습니다. (전처리 안됨)\033[0m")
        return

    print(f"[*] Found {len(tasks)} summary files. Running AI analysis concurrently (max 5 at a time)...")
    await asyncio.gather(*tasks)

    print("\n[*] All AI analysis tasks completed.")

async def main_async():
    parser = argparse.ArgumentParser(description="AI EML Analysis Wrapper (Batch & Async)")
    parser.add_argument("-file", dest="filename", help="Target EML file for analysis. If omitted, scans directory specified by -path.")
    parser.add_argument("-path", dest="eml_path", default="./eml", help="Directory containing EML files to analyze. Defaults to ./eml")
    parser.add_argument("-out", dest="output_dir", default=output_path, help="Directory to save AI analysis result")
    parser.add_argument("-apikey", help="VirusTotal API Key (입력 시 config.ini보다 우선)")
    parser.add_argument("-reanalyze-attachments", action="store_true", help="Re-analyze all extracted attachments in existing folders")
    parser.add_argument("-preprocess", action="store_true", help="analyzed_eml 폴더 안의 분석된 파일들을 모아 AI 전처리용 총합 파일(.txt) 생성 (테스트용 옵션)")
    parser.add_argument("-ai", action="store_true", help="_summary.txt 파일들을 기반으로 gemini-cli를 실행하여 AI 분석 결과를 파일 상단에 추가 (테스트용 옵션)")
    
    args = parser.parse_args()
    
    # API Key 설정
    vt_api_key = args.apikey if args.apikey else load_vt_api_key()
    
    # 첨부파일 일괄 재분석 모드
    if args.reanalyze_attachments:
        await reanalyze_all_attachments_async()
        return

    # AI 전처리 파일 생성 모드
    if args.preprocess:
        await preprocess_for_ai_async()
        return

    # AI 분석 모드
    if args.ai:
        await run_ai_analysis_async(args.output_dir)
        return

    tasks = []
    
    # EML 파일 분석 동시 실행 수를 10개로 제한하기 위해 세마포어(Semaphore) 사용
    eml_semaphore = asyncio.Semaphore(10)

    if args.filename:
        if args.filename.lower().endswith('.eml'):
            tasks.append(asyncio.create_task(analyze_eml_file_async(args.filename, args.output_dir, vt_api_key, eml_semaphore)))
        else:
            print(f"\033[91m[!] {args.filename} is not an .eml file. This script only processes EML files.\033[0m")
            return
    else:
        # 일괄 처리 모드 (지정된 경로 또는 기본 ./eml)
        target_dir = args.eml_path
        if not os.path.exists(target_dir):
            print(f"\033[91m[!] Directory not found: {target_dir}\033[0m")
            return
            
        print(f"[*] Scanning directory: {target_dir}")
        
        ignored_files = ["ai_analysis.py", "file_analysis.py", ".DS_Store"]
        ignored_extensions = [".md", ".py", ".pyc"]
        
        for f in sorted(os.listdir(target_dir)):
            full_path = os.path.join(target_dir, f)
            
            # 파일이 아니거나 .eml 형식이 아니면 건너뜀
            if not os.path.isfile(full_path) or not f.lower().endswith('.eml'):
                continue
                
            tasks.append(asyncio.create_task(analyze_eml_file_async(full_path, args.output_dir, vt_api_key, eml_semaphore)))

    if not tasks:
        print("[*] No files to analyze.")
        return

    print(f"[*] Starting batch extraction and summary phase for {len(tasks)} files...")
    # 동시성 제한 없이 asyncio.gather로 빠르게 일괄 처리 (내부적으로 semaphore로 10개만 실행)
    results = await asyncio.gather(*tasks)
    print("\n[*] All initial extraction and summary tasks completed.")
    
    # AI 별도 비동기 실행 (모든 대상 파일에 대한 분석 후 _summary.txt 생성 완료 시점)
    if not args.preprocess and not args.reanalyze_attachments:
        processed_folders = [r for r in results if r]
        await run_ai_analysis_async(args.output_dir, target_folders=processed_folders)
        
    print("\n[*] EML Pipeline completely finished.")

def main():
    try:
        if sys.platform == 'win32':
             # 윈도우 환경에서 비동기 서브프로세스 실행을 위한 이벤트 루프 정책 설정
             # 파이썬 3.8+ 윈도우에서는 ProactorEventLoop가 기본이지만 명시적으로 설정
             asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\033[91m\n[!] Analysis interrupted by user.\033[0m")
    except Exception as e:
        print(f"\033[91m[!] Unexpected error: {e}\033[0m")

if __name__ == "__main__":
    main()