#!/usr/bin/env python3
"""
EML Attachment Extractor
EML 파일에서 첨부파일을 자동으로 추출하여 각 EML 파일명별 폴더에 저장합니다.
Python 내장 email 모듈을 사용하므로 추가 패키지가 필요 없습니다.
"""

import os
import sys
import email
import email.policy
import argparse
import re
from email.header import decode_header


# 기본 경로 설정 (스크립트 위치 기준)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_EML_DIR = os.path.join(SCRIPT_DIR, "eml")
DEFAULT_OUTPUT_DIR = os.path.join(SCRIPT_DIR, "attachfiles")


def sanitize_filename(filename):
    """파일명에서 OS에서 허용하지 않는 문자를 제거합니다."""
    # Windows 금지 문자 제거
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # 앞뒤 공백 및 점 제거
    filename = filename.strip(' .')
    # 너무 긴 파일명 자르기 (Windows 제한)
    if len(filename) > 150:
        name, ext = os.path.splitext(filename)
        filename = name[:150] + ext
    return filename


def decode_mime_header(header_value):
    """MIME 인코딩된 헤더 값을 디코딩합니다."""
    if not header_value:
        return ""
    decoded_parts = decode_header(header_value)
    result = []
    for part, charset in decoded_parts:
        if isinstance(part, bytes):
            charset = charset or 'utf-8'
            try:
                result.append(part.decode(charset, errors='replace'))
            except (LookupError, UnicodeDecodeError):
                result.append(part.decode('utf-8', errors='replace'))
        else:
            result.append(part)
    return ''.join(result)


def extract_attachments(eml_path, output_base_dir):
    """
    단일 EML 파일에서 첨부파일을 추출합니다.
    EML 파일명으로 폴더를 생성하고 그 안에 첨부파일을 저장합니다.
    
    Returns: (추출된 첨부파일 수, 생성된 폴더 경로)
    """
    eml_filename = os.path.basename(eml_path)
    eml_name_no_ext = os.path.splitext(eml_filename)[0]
    folder_name = sanitize_filename(eml_name_no_ext)

    # EML 파일 파싱
    try:
        with open(eml_path, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=email.policy.default)
    except Exception as e:
        print(f"  [!] Failed to parse: {e}")
        return 0, None

    # 첨부파일 추출
    attachment_count = 0
    output_dir = None

    for part in msg.walk():
        content_disposition = str(part.get("Content-Disposition", ""))
        
        # 첨부파일인지 확인
        if "attachment" in content_disposition or "inline" in content_disposition:
            filename = part.get_filename()
            if filename:
                filename = decode_mime_header(filename)
                filename = sanitize_filename(filename)
            else:
                # 파일명이 없는 경우 Content-Type에서 추출 시도
                ext = part.get_content_type().split('/')[-1]
                filename = f"attachment_{attachment_count + 1}.{ext}"
            
            # Content-Disposition이 없어도 파일명이 있는 경우도 체크
            if not filename:
                continue

            # 출력 폴더 생성 (첫 번째 첨부파일 발견 시)
            if output_dir is None:
                output_dir = os.path.join(output_base_dir, folder_name)
                os.makedirs(output_dir, exist_ok=True)

            # 파일 저장
            filepath = os.path.join(output_dir, filename)
            
            # 동일 파일명 충돌 방지
            if os.path.exists(filepath):
                name, ext = os.path.splitext(filename)
                counter = 1
                while os.path.exists(filepath):
                    filepath = os.path.join(output_dir, f"{name}_{counter}{ext}")
                    counter += 1

            try:
                payload = part.get_payload(decode=True)
                if payload:
                    with open(filepath, 'wb') as f:
                        f.write(payload)
                    attachment_count += 1
                    print(f"  [+] Saved: {filename} ({len(payload):,} bytes)")
            except Exception as e:
                print(f"  [!] Failed to save {filename}: {e}")

    return attachment_count, output_dir


def main():
    parser = argparse.ArgumentParser(description="EML Attachment Extractor")
    parser.add_argument("-dir", dest="eml_dir", default=DEFAULT_EML_DIR,
                        help=f"Directory containing .eml files (default: ./eml/)")
    parser.add_argument("-out", dest="output_dir", default=DEFAULT_OUTPUT_DIR,
                        help=f"Output directory for attachments (default: ./attachfiles/)")
    
    args = parser.parse_args()

    eml_dir = os.path.abspath(args.eml_dir)
    output_dir = os.path.abspath(args.output_dir)

    if not os.path.isdir(eml_dir):
        print(f"[!] EML directory not found: {eml_dir}")
        sys.exit(1)

    # EML 파일 스캔
    eml_files = [f for f in os.listdir(eml_dir) if f.lower().endswith('.eml')]
    
    if not eml_files:
        print(f"[*] No .eml files found in: {eml_dir}")
        return

    print(f"[*] Found {len(eml_files)} EML file(s) in: {eml_dir}")
    print(f"[*] Output directory: {output_dir}")
    print(f"{'='*60}\n")

    total_attachments = 0
    files_with_attachments = 0

    for eml_file in sorted(eml_files):
        eml_path = os.path.join(eml_dir, eml_file)
        print(f"[*] Processing: {eml_file}")
        
        count, folder = extract_attachments(eml_path, output_dir)
        
        if count > 0:
            print(f"  [*] {count} attachment(s) extracted → {folder}")
            total_attachments += count
            files_with_attachments += 1
        else:
            print(f"  [-] No attachments found.")
        print()

    # 요약
    print(f"{'='*60}")
    print(f"[*] Summary:")
    print(f"    Total EML files processed: {len(eml_files)}")
    print(f"    Files with attachments: {files_with_attachments}")
    print(f"    Total attachments extracted: {total_attachments}")
    print(f"    Output location: {output_dir}")


if __name__ == "__main__":
    main()
