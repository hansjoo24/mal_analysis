import os
import shutil
import email
import email.policy
from email.header import decode_header
import sys

# Configure stdout to handle utf-8 to avoid cp949 encoding errors
if sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

def decode_mime_header(header_value):
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
    try:
        with open(eml_path, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=email.policy.default)
        
        for part in msg.walk():
            filename = part.get_filename()
            if filename:
                filename = decode_mime_header(filename)
                if filename.lower().endswith(('.html', '.htm')):
                    return True
            
            cd = part.get("Content-Disposition", "")
            if cd:
                if 'filename' in cd.lower() and ('.html' in cd.lower() or '.htm' in cd.lower()):
                    return True

            ct = part.get("Content-Type", "")
            if ct:
                if 'name=' in ct.lower() and ('.html' in ct.lower() or '.htm' in ct.lower()):
                    return True
                    
        return False
    except Exception as e:
        return False

def main():
    source_dir = r"c:\Users\한승주\Desktop\Suspicious_File"
    dest_dir = os.path.join(source_dir, "eml_html")

    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)
        print(f"[*] Created destination directory: {dest_dir}")

    found_files = []
    
    print(f"[*] Scanning recursively for EML files with HTML attachments...")

    for root, dirs, files in os.walk(source_dir):
        # Skip the destination directory itself to avoid moving files that are already there
        if os.path.abspath(root) == os.path.abspath(dest_dir):
            continue
            
        for file in files:
            if file.lower().endswith('.eml'):
                eml_path = os.path.join(root, file)
                if has_html_attachment(eml_path):
                    found_files.append((eml_path, file))

    if not found_files:
        print("[!] No EML files with HTML/HTM attachments found in the specified source.")
        return

    print(f"\n[*] Moving {len(found_files)} files to '{dest_dir}'...")
    moved_count = 0
    for eml_path, filename in found_files:
        dest_path = os.path.join(dest_dir, filename)
        
        # Avoid overwriting existing files in destination
        base, ext = os.path.splitext(filename)
        counter = 1
        while os.path.exists(dest_path):
            dest_path = os.path.join(dest_dir, f"{base}_{counter}{ext}")
            counter += 1
            
        try:
            shutil.move(eml_path, dest_path)
            moved_count += 1
        except Exception as e:
            print(f"  [-] Failed to move {filename}: {e}")

    print(f"\n[*] Successfully finished. Total files moved: {moved_count}")
    print(f"[*] Check results in: {os.path.abspath(dest_dir)}")

if __name__ == "__main__":
    main()
