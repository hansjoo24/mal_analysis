#!/usr/bin/env python3

import argparse
import subprocess
import json
import os
import sys
import datetime
import pefile

# 실행 결과가 저장될 내부 버퍼 역할
import io
import contextlib

def run_command(command, description):
    print(f"\n{'='*60}")
    print(f"[+] Running: {description}")
    print(f"    Command: {command}")
    print(f"{'='*60}\n")

    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        if result.stdout:
            print(result.stdout)
        
        if result.stderr:
            # pdf-parser 등의 도구가 도움말이나 경고를 stderr로 뱉는 경우가 있어 출력함
            print(f"[!] Output (stderr):\n{result.stderr}")

    except Exception as e:
        print(f"[!] Execution Failed: {e}")

def analyze_pdf(target_file):
    """
    PDF 파일 분석을 수행하는 함수입니다.
    pdfid, peepdf, strings 도구를 사용하여 분석합니다.
    """
    # Step 1: pdfid
    cmd1 = f"pdfid '{target_file}'"
    run_command(cmd1, "PDFID Analysis")

    # Step 2: pdf-parser
    cmd2 = f"echo 'tree' | python2 /usr/local/bin/peepdf -if '{target_file}'" 
    run_command(cmd2, "Pee-pdf Stats Analysis")

    # Step 3: strings & grep
    # 정규식 패턴 앞에 r을 붙여서 Raw String으로 처리 (SyntaxWarning 해결)
    pattern = r'"http|https|www\.|\.exe|\.js|\.zip"'
    
    # 파일명에 따옴표 추가
    cmd3 = f"strings '{target_file}' | grep -Ei {pattern}"
    run_command(cmd3, "Suspicious Strings Extraction")

def analyze_xls(target_file, deep_analysis=False):
    """
    엑셀(XLS, XLSX) 파일 분석을 수행하는 함수입니다.
    기본적인 파일 확인 후, ZIP 구조(XLSX)인 경우 압축을 해제하여
    내부 XML 및 설정 파일에서 매크로 유무, 의심스러운 키워드, 외부 링크를 정밀 분석합니다.
    """
    import zipfile
    import shutil
    
    # Step 1: file 명령어 실행 (파일 포맷 확인)
    cmd1 = f"file '{target_file}'"
    run_command(cmd1, "File Type Verification")

    # Step 2: olevba 실행 (매크로 분석)
    # VBA 매크로가 포함되어 있는지 전문 도구로 1차 확인
    cmd2 = f"olevba '{target_file}'"
    run_command(cmd2, "OLEVBA Macro Analysis")

    # Step 3: Unzip & Deep Analysis (for OpenXML formats like .xlsx, .xlsm)
    if zipfile.is_zipfile(target_file):
        print(f"\n{'='*60}")
        print(f"[+] Running: Deep Analysis (Unzip & Inspect)")
        print(f"{'='*60}\n")
        
        # 임시 디렉토리 생성
        temp_dir = f"temp_unzip_{os.path.basename(target_file)}"
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        os.makedirs(temp_dir)
        
        try:
            print(f"[*] Unzipping '{target_file}' to '{temp_dir}'...")
            with zipfile.ZipFile(target_file, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            # 3-1. 매크로(Macro) 존재 여부 확인 (vbaProject.bin)
            vba_bin_path = os.path.join(temp_dir, "xl", "vbaProject.bin")
            if os.path.exists(vba_bin_path):
                print("\n[!] 'xl/vbaProject.bin' FOUND: This file contains VBA Macros.")
            else:
                print("\n[*] 'xl/vbaProject.bin' NOT FOUND: No standard internal macro binary detected.")

            # 3-2. 위험한 키워드 검색 (Grep)
            # 검색 키워드: cmd, powershell, .exe, http, https, external (외부 연결 등)
            # -r: recursive, -i: ignore case, -E: extended regex, -n: line number
            print("\n[*] Searching for suspicious keywords (cmd, powershell, exe, http, etc.) in extracted files:")
            grep_pattern = r"cmd|powershell|\.exe|http://|https://|external"
            cmd_grep = f"grep -rniE '{grep_pattern}' '{temp_dir}'"
            
            run_command(cmd_grep, f"Grep Recursive Search in {temp_dir}")
            
        except Exception as e:
            print(f"[!] Deep Analysis Failed: {e}")
        finally:
            # Clean up
            if os.path.exists(temp_dir):
                print(f"[*] Cleaning up temporary directory: {temp_dir}")
                shutil.rmtree(temp_dir)
                
    else:
        # ZIP 형식이 아닌 경우 (Old .xls binary format)
        print("\n[*] File is not a ZIP archive (likely legacy .xls). Skipping Unzip analysis.")
        
        # 기존 strings 방식 유지
        # 탐지할 키워드: http, ftp, tcp, udp, powershell, cmd.exe, vbs, exe, bat
        pattern = r"'http|ftp|tcp|udp|powershell|cmd.exe|vbs|exe|bat'"
        cmd3 = f"strings '{target_file}' | grep -iE {pattern}"
        run_command(cmd3, "Suspicious Strings Extraction (Legacy XLS)")

def analyze_img(target_file):
    """
    이미지 파일 분석을 수행하는 함수입니다.
    file, exiftool, strings 도구를 사용하여 분석합니다.
    """
    # Step 1: file 명령어 실행 (파일 포맷 확인)
    cmd1 = f"file '{target_file}'"
    run_command(cmd1, "File Type Verification")

    # Step 2: exiftool 실행 (메타데이터 분석)
    cmd2 = f"exiftool '{target_file}'"
    run_command(cmd2, "ExifTool Metadata Analysis")

    # Step 3: strings & grep 실행 (악성 문자열 탐지)
    # 탐지할 키워드: html, script, zip, pk.., <svg
    pattern = r"'html|script|zip|pk..|<svg'"
    cmd3 = f"strings '{target_file}' | grep -Ei {pattern}"
    run_command(cmd3, "Suspicious Strings Extraction (Image)")

def analyze_hash(target_file):
    """
    파일의 해시를 계산하고 VirusTotal 정보를 조회하는 함수입니다.
    sha256sum, vt 도구를 사용합니다.
    """
    print(f"\n{'='*60}")
    print(f"[+] Running: Hash & VirusTotal Analysis")
    print(f"{'='*60}\n")

    try:
        # Step 1: Calculate SHA256 Hash
        # sha256sum output format: "<hash> <filename>"
        # Windows certutil or similar might be needed if sha256sum isn't available, 
        # but following instructions to use sha256sum.
        
        # Using subprocess directly to get clean output for variable usage
        hash_cmd = f"sha256sum '{target_file}'"
        hash_output = subprocess.getoutput(hash_cmd)
        
        if "not found" in hash_output.lower() or "'" in hash_output and "is not recognized" in hash_output:
             print("[!] sha256sum command not found or failed.")
             return

        file_hash = hash_output.split()[0]
        print(f"[*] Calculated SHA256: {file_hash}")

        # Step 2: Query VirusTotal
        vt_cmd = f"vt file {file_hash} --format json"
        print(f"[*] Querying VirusTotal for hash: {file_hash}...")
        
        vt_output = subprocess.getoutput(vt_cmd)
        
        # Step 3: Raw JSON Output
        try:
            vt_data = json.loads(vt_output)
            print(f"\n[+] VirusTotal raw JSON:")
            print(json.dumps(vt_data, indent=4, ensure_ascii=False))
        except json.JSONDecodeError:
            print("[!] Failed to parse VirusTotal JSON output.")
            print(f"Raw Output: {vt_output[:200]}...") # Print first 200 chars

    except Exception as e:
        print(f"[!] Hash Analysis Failed: {e}")

def analyze_exe(target_file):
    """
    EXE 파일 분석을 수행하는 함수입니다.
    pefile을 사용하여 헤더, 섹션, 임포트 정보를 분석하고 strings로 악성 문자열을 탐지합니다.
    """
    print(f"\n{'='*60}")
    print(f"[+] Running: PE Analysis (pefile)")
    print(f"{'='*60}\n")

    try:
        pe = pefile.PE(target_file)
        
        # 1. Basic Information
        print(f"[*] Basic Information:")
        print(f"    Machine: {hex(pe.FILE_HEADER.Machine)}")
        print(f"    TimeDateStamp: {pe.FILE_HEADER.TimeDateStamp} ({datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)})")
        print(f"    Subsystem: {hex(pe.OPTIONAL_HEADER.Subsystem)}")
        print(f"    EntryPoint: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        print(f"    ImageBase: {hex(pe.OPTIONAL_HEADER.ImageBase)}")

        # 2. Sections & Entropy
        print(f"\n[*] Sections:")
        print(f"    {'Name':<10} {'Virtual Addr':<15} {'Raw Size':<10} {'Entropy':<10}")
        print(f"    {'-'*10} {'-'*15} {'-'*10} {'-'*10}")
        
        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').strip('\\x00')
            # pefile SectionStructure usually has get_entropy()
            try:
                entropy = section.get_entropy()
            except AttributeError:
                # Fallback if get_entropy is missing (older pefile)
                entropy = 0.0
            
            print(f"    {name:<10} {hex(section.VirtualAddress):<15} {section.SizeOfRawData:<10} {entropy:.4f}")
            if entropy > 7.0:
                print(f"    [!] High Entropy detected in {name} (possible packing/encryption)")

        # 3. Suspicious Imports
        print(f"\n[*] Suspicious Imports Check:")
        suspicious_apis = [
            'VirtualAlloc', 'VirtualProtect', 'CreateRemoteThread', 'WriteProcessMemory',
            'InternetOpen', 'URLDownloadToFile', 'ShellExecute', 'RegOpenKey',
            'GetProcAddress', 'LoadLibrary'
        ]
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            found_suspicious = False
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        if any(s_api in func_name for s_api in suspicious_apis):
                            print(f"    [!] Suspicious API Found: {func_name} ({dll_name})")
                            found_suspicious = True
            if not found_suspicious:
                 print("    No specific suspicious APIs found from the watchlist.")
        else:
             print("    No Imports found (possibly packed or simple native).")

    except Exception as e:
        print(f"[!] PE Analysis Failed: {e}")

    # 4. Strings Analysis
    # 정규식: IP, URL, PDB, EXE, DLL
    pattern = r'"http|https|\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|\\.pdb|\\.exe|\\.dll"'
    cmd_strings = f"strings '{target_file}' | grep -Ei {pattern}"
    run_command(cmd_strings, "Suspicious Strings Extraction (EXE)")

def analyze_doc(target_file, deep_analysis=False):
    """
    Word (DOC, DOCX) 파일 분석을 수행하는 함수입니다.
    기본적인 매크로(olevba) 확인 후, ZIP 구조(DOCX)인 경우 압축을 해제하여
    내부 XML 등에서 매크로(vbaProject.bin) 및 외부 연결 링크 등을 정밀 분석합니다.
    """
    import zipfile
    import shutil
    
    # Step 1: file 명령어 실행 (파일 포맷 확인)
    cmd1 = f"file '{target_file}'"
    run_command(cmd1, "File Type Verification")

    # Step 2: olevba 실행 (매크로 분석)
    cmd2 = f"olevba '{target_file}'"
    run_command(cmd2, "OLEVBA Macro Analysis")

    # Step 3: Unzip & Deep Analysis (for OpenXML formats like .docx, .docm)
    if zipfile.is_zipfile(target_file):
        print(f"\n{'='*60}")
        print(f"[+] Running: Deep Analysis (Unzip & Inspect) for Word Document")
        print(f"{'='*60}\n")
        
        temp_dir = f"temp_unzip_{os.path.basename(target_file)}"
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        os.makedirs(temp_dir)
        
        try:
            print(f"[*] Unzipping '{target_file}' to '{temp_dir}'...")
            with zipfile.ZipFile(target_file, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            # 3-1. 매크로 존재 여부 확인 (word/vbaProject.bin)
            vba_bin_path = os.path.join(temp_dir, "word", "vbaProject.bin")
            if os.path.exists(vba_bin_path):
                print("\n[!] 'word/vbaProject.bin' FOUND: This file contains VBA Macros.")
            else:
                print("\n[*] 'word/vbaProject.bin' NOT FOUND: No standard internal macro binary detected.")

            # 3-2. OLE Object 유무 탐지
            embeddings_dir = os.path.join(temp_dir, "word", "embeddings")
            if os.path.exists(embeddings_dir) and os.listdir(embeddings_dir):
                print(f"\n[!] 'word/embeddings' FOUND: Document contains embedded objects ({len(os.listdir(embeddings_dir))} files).")
                for ef in os.listdir(embeddings_dir):
                    print(f"    - {ef}")

            # 3-3. 위험한 키워드 검색 (Grep)
            print("\n[*] Searching for suspicious keywords (cmd, powershell, exe, http, etc.) in extracted files:")
            grep_pattern = r"cmd|powershell|\.exe|http://|https://|external"
            cmd_grep = f"grep -rniE '{grep_pattern}' '{temp_dir}'"
            
            run_command(cmd_grep, f"Grep Recursive Search in {temp_dir}")
            
        except Exception as e:
            print(f"[!] Deep Analysis Failed: {e}")
        finally:
            if os.path.exists(temp_dir):
                print(f"[*] Cleaning up temporary directory: {temp_dir}")
                shutil.rmtree(temp_dir)
    else:
        print("\n[*] File is not a ZIP archive (likely legacy .doc). Skipping Unzip analysis.")
        pattern = r"'http|ftp|tcp|udp|powershell|cmd.exe|vbs|exe|bat'"
        cmd3 = f"strings '{target_file}' | grep -iE {pattern}"
        run_command(cmd3, "Suspicious Strings Extraction (Legacy DOC)")

def analyze_ppt(target_file):
    """
    PPT/PPTX 파일 분석을 수행하는 함수입니다.
    olevba를 사용하여 매크로를 분석하고, strings로 악성 문자열을 탐지합니다.
    """

    # Step 1: file 명령어 실행 (파일 포맷 확인)
    cmd1 = f"file '{target_file}'"
    run_command(cmd1, "File Type Verification")

    # Step 2: olevba 실행 (매크로 분석)
    # VBA 매크로가 포함되어 있는지 전문 도구로 1차 확인
    cmd2 = f"olevba '{target_file}'"
    run_command(cmd2, "OLEVBA Macro Analysis")

    # Step 3: Strings Analysis
    # 기존 strings 방식
    pattern = r"'http|ftp|tcp|udp|powershell|cmd.exe|vbs|exe|bat'"
    cmd3 = f"strings '{target_file}' | grep -iE {pattern}"
    run_command(cmd3, "Suspicious Strings Extraction")

def detect_file_type(target_file):
    """
    파일 확장자를 기반으로 파일 타입을 자동으로 감지합니다.
    """
    _, ext = os.path.splitext(target_file)
    ext = ext.lower()
    
    if ext in ['.pdf']:
        return 'pdf'
    elif ext in ['.xls', '.xlsx', '.xlsm']:
        return 'xls'
    elif ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.jfif']:
        return 'img'
    elif ext in ['.exe', '.dll', '.sys', '.ocx']:
        return 'exe'
    elif ext in ['.ppt', '.pptx', '.pptm', '.potx', '.pps', '.ppsx']:
        return 'ppt'
    elif ext in ['.doc', '.docx', '.docm', '.dot', '.dotx']:
        return 'doc'
    return None

def run_analysis_on_file(target_file, file_type, deep_analysis=False):
    """
    단일 파일에 대해 분석을 실행하고 결과 터미널 출력을 캡처하여 문자열로 반환합니다.
    에러 발생 시 None을 반환합니다.
    """
    if not os.path.exists(target_file):
        print(f"[!] File not found: {target_file}")
        return None

    # 출력을 캡처하기 위한 StringIO 객체 생성
    captured_output = io.StringIO()
    
    try:
        with contextlib.redirect_stdout(captured_output):
            print(f"[*] Analysis started at: {datetime.datetime.now()}")
            print(f"[*] Starting analysis for: {target_file} ({file_type})")
            
            # Common Step: Hash Analysis
            analyze_hash(target_file)

            if file_type == 'pdf':
                analyze_pdf(target_file)
            elif file_type == 'xls':
                analyze_xls(target_file, deep_analysis)
            elif file_type == 'img':
                analyze_img(target_file)
            elif file_type == 'exe':
                analyze_exe(target_file)
            elif file_type == 'ppt':
                analyze_ppt(target_file)
            elif file_type == 'doc':
                analyze_doc(target_file, deep_analysis)
                
        # 캡처된 문자열 반환
        return captured_output.getvalue()
    except Exception as e:
        print(f"[!] Analysis failed for {target_file}: {e}")
        return None
    finally:
        captured_output.close()

def main():
    parser = argparse.ArgumentParser(description="Automated File Analysis Tool (PDF & XLS & Image)")
    
    # 상호 배타적인 인자 그룹 생성 (-pdf, -xls, -img 중 하나만 사용 가능)
    # 일괄 처리를 위해 required=True를 제거함
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-pdf", dest="pdf_filename", help="Path to the suspicious PDF file")
    group.add_argument("-xls", dest="xls_filename", help="Path to the suspicious Excel file")
    group.add_argument("-ppt", dest="ppt_filename", help="Path to the suspicious PowerPoint file")
    group.add_argument("-doc", dest="doc_filename", help="Path to the suspicious Word Document file")
    group.add_argument("-img", dest="img_filename", help="Path to the suspicious Image file")
    group.add_argument("-exe", dest="exe_filename", help="Path to the suspicious EXE file")
    group.add_argument("-file", dest="generic_filename", help="Path to any suspicious file (auto-detect)")
    
    parser.add_argument("-out", dest="output_dir", default=".", help="Directory to save analysis result (when running standalone)")
    parser.add_argument("--deep", "-d", dest="deep_analysis", action="store_true", help="Enable deep analysis (Unzip & Recursive Grep for Excel files)")

    args = parser.parse_args()
    
    # 출력 디렉토리 확인/생성
    if not os.path.exists(args.output_dir):
        try:
            os.makedirs(args.output_dir)
        except OSError as e:
            print(f"[!] Could not create output directory: {e}")
            sys.exit(1)

    # 1. 특정 파일이 지정된 경우 (기존 모드)
    target_file = None
    file_type = None

    if args.pdf_filename:
        target_file = args.pdf_filename
        file_type = 'pdf'
    elif args.xls_filename:
        target_file = args.xls_filename
        file_type = 'xls'
    elif args.img_filename:
        target_file = args.img_filename
        file_type = 'img'
    elif args.exe_filename:
        target_file = args.exe_filename
        file_type = 'exe'
    elif args.ppt_filename:
        target_file = args.ppt_filename
        file_type = 'ppt'
    elif args.doc_filename:
        target_file = args.doc_filename
        file_type = 'doc'
    elif args.generic_filename:
        target_file = args.generic_filename
        file_type = detect_file_type(target_file)
        if not file_type:
            print(f"[!] Unsupported file extension for: {target_file}")
            sys.exit(1)

    if target_file:
        res = run_analysis_on_file(target_file, file_type, args.deep_analysis)
        if res:
            date_str = datetime.datetime.now().strftime("%y%m%d")
            base_name = os.path.splitext(os.path.basename(target_file))[0]
            log_filename = f"{date_str}_{base_name}_instruction_output.md"
            log_full_path = os.path.join(args.output_dir, log_filename)
            with open(log_full_path, 'w', encoding='utf-8') as f:
                f.write(res)
            print(f"[*] Report saved to {log_full_path}")
    else:
        # 2. 인자가 없는 경우: 현재 디렉토리 일괄 분석 (추가된 기능)
        current_dir = os.getcwd()
        print(f"[*] Batch Mode: Scanning directory: {current_dir}")
        
        # 제외 대상
        ignored_files = ["file_analysis.py", "ai_analysis.py", "auto_login.py", "extract_attachments.py", "extract_eml.py", "qr_reader.py"]
        
        files_to_analyze = []
        for f in os.listdir(current_dir):
            full_path = os.path.join(current_dir, f)
            if not os.path.isfile(full_path):
                continue
            if f in ignored_files or f.startswith('.'):
                continue
            
            f_type = detect_file_type(f)
            if f_type:
                files_to_analyze.append((full_path, f_type))
        
        if not files_to_analyze:
            print("[*] No supported files found for batch analysis.")
            return

        print(f"[*] Found {len(files_to_analyze)} files to analyze.")
        for target, f_type in files_to_analyze:
            print(f"[*] Processing: {os.path.basename(target)}...")
            res = run_analysis_on_file(target, f_type, args.deep_analysis)
            if res:
                date_str = datetime.datetime.now().strftime("%y%m%d")
                base_name = os.path.splitext(os.path.basename(target))[0]
                log_filename = f"{date_str}_{base_name}_instruction_output.md"
                log_full_path = os.path.join(args.output_dir, log_filename)
                with open(log_full_path, 'w', encoding='utf-8') as f:
                    f.write(res)
                print(f"[*] Report saved to {log_full_path}")
        
        print("\n[*] Batch analysis completed.")

if __name__ == "__main__":
    main()