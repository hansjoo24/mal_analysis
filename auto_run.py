import os
import shutil
import glob
import subprocess
import sys
from datetime import datetime

def cleanup_files():
    # 파일들을 정리하는 프로세스
    answer = input("\n[?] 파일 정리 프로세스를 실행하시겠습니까? (y/n): ")
    if answer.lower() != 'y':
        print("[*] 파일 정리를 건너뜁니다.\n")
        return

    print("[*] 파일 정리를 시작합니다...")
    base_dir = os.path.dirname(os.path.abspath(__file__))

    # 1. eml 폴더의 .eml 파일 삭제
    eml_dir = os.path.join(base_dir, "eml")
    if os.path.exists(eml_dir):
        eml_files = glob.glob(os.path.join(eml_dir, "*.eml"))
        for f in eml_files:
            try:
                os.remove(f)
                print(f"  [삭제] {os.path.basename(f)}")
            except Exception as e:
                print(f"  [오류] {os.path.basename(f)} 일괄 삭제 실패: {e}")

    # 2. analyzed_eml 의 폴더들을 backup 으로 이동
    analyzed_eml_dir = os.path.join(base_dir, "analyzed_eml")
    backup_dir = os.path.join(base_dir, "backup")
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)

    if os.path.exists(analyzed_eml_dir):
        for item in os.listdir(analyzed_eml_dir):
            item_path = os.path.join(analyzed_eml_dir, item)
            if os.path.isdir(item_path):
                dest_path = os.path.join(backup_dir, item)
                try:
                    target_dest = dest_path
                    counter = 1
                    # 같은 이름의 폴더가 backup 안에 있을 수 있으므로 처리
                    while os.path.exists(target_dest):
                        target_dest = f"{dest_path}_{counter}"
                        counter += 1
                    shutil.move(item_path, target_dest)
                    print(f"  [이동] {item} -> backup/")
                except Exception as e:
                    print(f"  [오류] {item} 이동 실패: {e}")

    # 2.5 eml_bank 의 폴더들을 backup 으로 이동
    eml_bank_dir = os.path.join(base_dir, "eml_bank")
    if os.path.exists(eml_bank_dir):
        for item in os.listdir(eml_bank_dir):
            item_path = os.path.join(eml_bank_dir, item)
            if os.path.isdir(item_path):
                dest_path = os.path.join(backup_dir, item)
                try:
                    target_dest = dest_path
                    counter = 1
                    # 같은 이름의 폴더가 backup 안에 있을 수 있으므로 처리
                    while os.path.exists(target_dest):
                        target_dest = f"{dest_path}_{counter}"
                        counter += 1
                    shutil.move(item_path, target_dest)
                    print(f"  [이동] {item} -> backup/ (from eml_bank)")
                except Exception as e:
                    print(f"  [오류] {item} 이동 실패: {e}")

    # 3. analysis_result 내의 파일을 현재 'YYMM' 폴더로 이동 (예: 2604)
    analysis_result_dir = os.path.join(base_dir, "analysis_result")
    current_yymm = datetime.now().strftime("%y%m")
    target_date_dir = os.path.join(analysis_result_dir, current_yymm)

    if os.path.exists(analysis_result_dir):
        if not os.path.exists(target_date_dir):
            os.makedirs(target_date_dir)
            
        for item in os.listdir(analysis_result_dir):
            item_path = os.path.join(analysis_result_dir, item)
            # 폴더가 아닌 파일만 이동
            if os.path.isfile(item_path):
                dest_path = os.path.join(target_date_dir, item)
                try:
                    # 중복 파일일 경우 덮어쓰기 위해 기존 파일 삭제
                    if os.path.exists(dest_path):
                        os.remove(dest_path)
                    shutil.move(item_path, dest_path)
                    print(f"  [이동] {item} -> {current_yymm}/")
                except Exception as e:
                    print(f"  [오류] {item} 파일 이동 실패: {e}")

    print("[+] 파일 정리가 완료되었습니다.\n")

def run_local_autologin():
    print("[*] 로컬 환경에서 auto_login.py를 실행합니다...")
    try:
        result = subprocess.run([sys.executable, "auto_login.py"])
        if result.returncode == 0:
            print("[+] auto_login.py 실행을 성공적으로 완료했습니다.\n")
        else:
            print(f"[-] auto_login.py 실행 중 문제가 발생했습니다. (Exit status: {result.returncode})\n")
    except Exception as e:
        print(f"[-] auto_login.py 실행 중 예외가 발생했습니다: {e}\n")

def main():

     # 1. 파일 정리 프로세스 수행 여부 확인 및 진행
    cleanup_files()

    # 2. auto_login.py 실행 (Window Local)
    run_local_autologin()   

    # 3. SSH 접속 및 eml_analysis.py 명령어 실행 (Kali VM)
    command = [
        "ssh",
        "-t", # 가상 터미널 할당 (인터랙티브 프로그램 실행 시 필요할 수 있음)
        "kali@192.168.31.131",
        "cd /mnt/hgfs/Suspicious_File && python eml_analysis.py"
    ]
    
    print("[*] Kali VM에 접속하여 eml_analysis.py를 실행합니다...")
    print(f"[*] Command: {' '.join(command)}\n")
    
    try:
        # subprocess.run을 사용하여 실시간으로 출력을 터미널에 표시
        result = subprocess.run(command)
        
        if result.returncode == 0:
            print("\n[+] 스크립트 실행이 성공적으로 완료되었습니다.")
        else:
            print(f"\n[-] 스크립트 실행 중 문제가 발생했습니다. (Exit status: {result.returncode})")
            
    except FileNotFoundError:
        print("[-] ssh 명령어를 찾을 수 없습니다. Windows에 OpenSSH 클라이언트가 설치되어 있는지 확인해주세요.")
    except Exception as e:
        print(f"[-] 예외가 발생했습니다: {e}")

if __name__ == "__main__":
    main()
