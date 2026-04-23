import os
import shutil
import email
import email.policy
from email.header import decode_header
import argparse

def decode_mime_header(header_value):
    """MIME 인코딩된 헤더 값을 디코딩합니다."""
    if not header_value:
        return ""
    try:
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
    except Exception:
        return str(header_value)

def has_html_attachment(eml_path):
    """EML 파일에 .html 또는 .htm 첨부파일이 있는지 확인합니다."""
    try:
        with open(eml_path, 'rb') as f:
            # policy=email.policy.default를 사용하면 파일명을 더 쉽게 가져올 수 있습니다.
            msg = email.message_from_binary_file(f, policy=email.policy.default)
        
        for part in msg.walk():
            # 1. 파일명이 직접 정의된 경우 확인
            filename = part.get_filename()
            if filename:
                filename = decode_mime_header(filename)
                if filename.lower().endswith(('.html', '.htm')):
                    return True
            
            # 2. Content-Disposition에서 filename 파라미터 확인 (get_filename()이 놓칠 때를 대비)
            cd = part.get("Content-Disposition", "")
            if cd:
                if 'filename' in cd.lower() and ('.html' in cd.lower() or '.htm' in cd.lower()):
                    return True

            # 3. Content-Type에서 name 파라미터 확인
            ct = part.get("Content-Type", "")
            if ct:
                if 'name=' in ct.lower() and ('.html' in ct.lower() or '.htm' in ct.lower()):
                    return True
                    
        return False
    except Exception as e:
        print(f"  [!] Error processing {eml_path}: {e}")
        return False

def main():
    source_dirs = ["backup", "_backup"]
    dest_dir = "eml_html"

    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)
        print(f"[*] Created destination directory: {dest_dir}")

    found_files = []
    
    for source_dir in source_dirs:
        if not os.path.exists(source_dir):
            print(f"[!] Source directory '{source_dir}' does not exist. Skipping...")
            continue
            
        print(f"[*] Scanning '{source_dir}' recursively for EML files with HTML attachments...")

        for root, dirs, files in os.walk(source_dir):
            for file in files:
                if file.lower().endswith('.eml'):
                    eml_path = os.path.join(root, file)
                    if has_html_attachment(eml_path):
                        found_files.append(eml_path)
                        print(f"  [+] Found: {file}")

    if not found_files:
        print("[!] No EML files with HTML/HTM attachments found in the specified source.")
        return

    print(f"\n[*] Copying {len(found_files)} files to '{dest_dir}'...")
    for eml_path in found_files:
        filename = os.path.basename(eml_path)
        dest_path = os.path.join(dest_dir, filename)
        
        # 파일명 충돌 방지
        base, ext = os.path.splitext(filename)
        counter = 1
        while os.path.exists(dest_path):
            dest_path = os.path.join(dest_dir, f"{base}_{counter}{ext}")
            counter += 1
            
        try:
            shutil.copy2(eml_path, dest_path)
            print(f"  [+] Copied: {filename}")
        except Exception as e:
            print(f"  [-] Failed to copy {filename}: {e}")

    print(f"\n[*] Successfully finished. Total files copied: {len(found_files)}")
    print(f"[*] Check results in: {os.path.abspath(dest_dir)}")

if __name__ == "__main__":
    main()
