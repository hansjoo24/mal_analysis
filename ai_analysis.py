#!/usr/bin/env python3

import argparse
import subprocess
import sys
import os
import datetime
import shutil
import asyncio

# 분석 결과가 저장될 디렉토리 경로
output_path = "/mnt/hgfs/Suspicious_File/analysis_result/" 

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

async def analyze_file_async(target_file, output_dir_base):
    # 나중에 안전하게 이동하기 위해 절대 경로가 필요합니다.
    target_abs_path = os.path.abspath(target_file)
    filename = os.path.basename(target_abs_path)
    
    if not os.path.exists(target_abs_path):
        print(f"[!] File not found: {target_file}")
        return

    # 출력 디렉토리 확인/생성
    if not os.path.exists(output_dir_base):
        try:
            os.makedirs(output_dir_base)
        except OSError as e:
            print(f"[!] Could not create output directory: {e}")
            return

    # Define the prompt
    prompt = """
- 이 내용은 파일의 분석 명령어를 실행한 결과이고, 다음의 형식을 지켜 이 파일에 대한 분석 결과를 한글로 생성해줘. 
# 1. 분석 개요
- 분석 파일명 : 
- 분석 도구 : 
- 분석 일시

# 2. 해시분석 결과
# 3. 파일 분석 결과
- 명령어 실행 결과 원문의 중요한 부분만 요약해서 보여주고, 구체적 분석 결과를 써줘  
# 4. 최종 결론
- 해당 파일이 정상일 확률 / 악성일 확률과 그에 대한 설명 작성
# 5. 추가 분석 제안(분석 결과가 확실한 경우 생략 가능)
"""
    
    python_exe = sys.executable
    # file_analysis.py가 이 스크립트와 같은 디렉토리에 있다고 가정하거나,
    # 이전의 하드코딩된 경로를 사용합니다. 
    # 스크립트 위치를 기반으로 경로를 찾는 것이 더 안정적입니다.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_analysis_script = os.path.join(script_dir, "file_analysis.py")
    if not os.path.exists(file_analysis_script):
        # Fallback to the hardcoded path if relative fails for some reason
        file_analysis_script = "/mnt/hgfs/Suspicious_File/file_analysis.py"

    print(f"[*] [START] Analyzing: {filename}")
    
    # 1. file_analysis.py 실행
    # -file 옵션(자동 감지)을 사용합니다.
    cmd_analysis = [python_exe, file_analysis_script, "-file", target_abs_path] 
    
    ret_code, analysis_stdout, analysis_stderr = await run_command_async(cmd_analysis)
    
    if ret_code != 0:
        print(f"[!] [{filename}] file_analysis.py failed: {analysis_stderr}")
        return

    # 2. gemini-cli 실행
    cmd_ai = ["gemini-cli", prompt]
    ret_code_ai, ai_stdout, ai_stderr = await run_command_async(cmd_ai, input_data=analysis_stdout)

    if ret_code_ai != 0:
        print(f"[!] [{filename}] gemini-cli failed: {ai_stderr}")
        return
        
    final_result = ai_stdout
    
    # 원본 출력 결과 추가
    final_result += "\n\n---\n# 분석원문 \n\n"
    final_result += "```\n" + analysis_stdout + "\n```"

    # 3. 보고서 저장
    date_str = datetime.datetime.now().strftime("%y%m%d")
    base_name_no_ext = os.path.splitext(filename)[0]
    output_filename = f"{date_str}_{base_name_no_ext}_analyis_result.md"
    report_path = os.path.join(output_dir_base, output_filename)
    
    try:
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(final_result)
        print(f"[+] [{filename}] Report saved to: {report_path}")
    except IOError as e:
        print(f"[!] [{filename}] Failed to write report: {e}")
        return

    # 4. 처리된 파일을 'analyzed' 디렉토리로 이동
    # 분석이 성공적으로 실행되었을 때만 이동
    analyzed_dir = os.path.join(os.path.dirname(target_abs_path), "analyzed")
    if not os.path.exists(analyzed_dir):
        os.makedirs(analyzed_dir, exist_ok=True)
        
    try:
        shutil.move(target_abs_path, os.path.join(analyzed_dir, filename))
        print(f"[-] [{filename}] Moved to: {analyzed_dir}")
    except Exception as e:
        print(f"[!] [{filename}] Failed to move file: {e}")

async def main_async():
    parser = argparse.ArgumentParser(description="AI Analysis Wrapper (Batch & Async)")
    parser.add_argument("-file", dest="filename", help="Target file for analysis (Optional). If omitted, scans current directory.")
    parser.add_argument("-out", dest="output_dir", default=output_path, help="Directory to save analysis result")
    
    args = parser.parse_args()
    
    tasks = []
    
    if args.filename:
        # 단일 파일 모드
        tasks.append(analyze_file_async(args.filename, args.output_dir))
    else:
        # 일괄 처리 모드 (현재 디렉토리)
        current_dir = os.getcwd()
        print(f"[*] Scanning directory: {current_dir}")
        
        ignored_files = ["ai_analysis.py", "file_analysis.py", ".DS_Store"]
        ignored_extensions = [".md", ".py", ".pyc"]
        
        for f in os.listdir(current_dir):
            full_path = os.path.join(current_dir, f)
            
            # 디렉토리는 건너뜀
            if not os.path.isfile(full_path):
                continue
                
            # 스크립트 자체나 이미 알려진 제외 파일들은 건너뜀
            if f in ignored_files or f.startswith('.'):
                continue
                
            # 확장자를 기준으로 결과 파일이나 스크립트는 건너뜀
            _, ext = os.path.splitext(f)
            if ext.lower() in ignored_extensions:
                continue

            tasks.append(analyze_file_async(full_path, args.output_dir))

    if not tasks:
        print("[*] No files to analyze.")
        return

    print(f"[*] Starting batch analysis for {len(tasks)} files...")
    # 동시성 제한 없이 asyncio.gather로 빠르게 일괄 처리 (요청사항 반영)
    await asyncio.gather(*tasks)
    print("\n[*] All analysis tasks completed.")

def main():
    try:
        if sys.platform == 'win32':
             # 윈도우 환경에서 비동기 서브프로세스 실행을 위한 이벤트 루프 정책 설정
             # 파이썬 3.8+ 윈도우에서는 ProactorEventLoop가 기본이지만 명시적으로 설정
             asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n[!] Analysis interrupted by user.")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

if __name__ == "__main__":
    main()