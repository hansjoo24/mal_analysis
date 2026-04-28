import os
import subprocess

#리눅스 쉘에 직접 접속하는 스크립트!

def main():
    # 현재 스크립트가 있는 디렉토리 및 .gemini 폴더 경로
    base_dir = os.path.dirname(os.path.abspath(__file__))
    gemini_dir = os.path.join(base_dir, ".gemini")

    # Docker 터미널 접속 명령어
    command = [
        "docker", "run", "--rm", "-it",
        "-v", f"{base_dir}:/app",
        "-v", f"{gemini_dir}:/root/.gemini",
        "-w", "/app",
        "kali-linux",
        "/bin/bash"
    ]

    print("=" * 60)
    print("[*] Kali Linux 도커 컨테이너 쉘(Shell)에 접속합니다...")
    print("=" * 60)
    print("💡 사용 팁:")
    print("  - 여기서 자유롭게 리눅스 명령어나 파이썬 스크립트를 실행해 볼 수 있습니다.")
    print("  - 작업을 마치고 빠져나오시려면 'exit'를 입력하세요.")
    print("=" * 60 + "\n")

    try:
        # 터미널 상호작용을 위해 subprocess.run 사용
        subprocess.run(command)
        print("\n[+] 컨테이너 접속이 종료되고 자동으로 컨테이너가 삭제되었습니다.")
        
    except FileNotFoundError:
        print("\n[-] docker 명령어를 찾을 수 없습니다. Docker 데스크톱이 켜져 있는지 확인해주세요.")
    except KeyboardInterrupt:
        print("\n\n[*] 강제 종료되었습니다.")
    except Exception as e:
        print(f"\n[-] 예외가 발생했습니다: {e}")

if __name__ == "__main__":
    main()
