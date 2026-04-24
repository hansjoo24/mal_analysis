import os
import email
from email import policy
import shutil

def is_html_attachment(part):
    # Check filename first
    fn = part.get_filename()
    if fn and fn.lower().endswith(('.html', '.htm')):
        return True
    
    # Check Content-Type and Content-Disposition strings
    ct = part.get("Content-Type", "")
    cd = part.get("Content-Disposition", "")
    
    # Needs to be an attachment or have a filename that implies html
    if 'attachment' in cd.lower() and ('.html' in ct.lower() or '.htm' in ct.lower() or '.html' in cd.lower() or '.htm' in cd.lower()):
        return True
        
    return False

def main():
    src_dir = r"c:\Users\한승주\Desktop\Suspicious_File\eml"
    dest_dir = r"c:\Users\한승주\Desktop\Suspicious_File\eml_html"
    
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)
        print(f"[*] Created destination directory: {dest_dir}")
    else:
        print(f"[*] Destination directory exists: {dest_dir}")
    
    if not os.path.exists(src_dir):
        print(f"[!] Source directory does not exist: {src_dir}")
        return

    count = 0
    eml_files = [f for f in os.listdir(src_dir) if f.lower().endswith('.eml')]
    
    for file in eml_files:
        eml_path = os.path.join(src_dir, file)
        try:
            with open(eml_path, 'rb') as f:
                msg = email.message_from_binary_file(f, policy=policy.default)
            
            found = False
            for part in msg.walk():
                # We skip multipart containers themselves
                if part.get_content_maintype() == 'multipart':
                    continue
                
                if is_html_attachment(part):
                    found = True
                    break
            
            if found:
                dest_path = os.path.join(dest_dir, file)
                # Handle duplicate names if we were scanning multiple directories
                idx = 1
                base_name, ext = os.path.splitext(file)
                while os.path.exists(dest_path):
                    # Check if it's identical before renaming? 
                    # For simple copying, let's just make it unique
                    dest_path = os.path.join(dest_dir, f"{base_name}_{idx}{ext}")
                    idx += 1
                
                shutil.move(eml_path, dest_path)
                print(f"  [+] Moved: {file} -> eml_html/")
                count += 1
        except Exception as e:
            print(f"  [!] Error processing {file}: {e}")

    print(f"\n[*] Total files moved: {count}")

if __name__ == "__main__":
    main()
