#!/usr/bin/env python3
"""
mail.shinhan.com 자동 로그인 스크립트
- Selenium: 브라우저 자동화 (로그인 + 2차 인증 입력)
- IMAP: Gmail에서 2차 인증코드 자동 읽기
"""

# Windows cp949 인코딩 문제 방지
import os
os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"
import re
import sys
import time
import email
import imaplib
import configparser
from datetime import datetime, timedelta

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import (
        TimeoutException, NoSuchElementException, WebDriverException
    )
except ImportError:
    print("[!] selenium이 설치되어 있지 않습니다.")
    print("    실행: pip install selenium")
    sys.exit(1)

try:
    from selenium.webdriver.chrome.service import Service as ChromeService
    from webdriver_manager.chrome import ChromeDriverManager
    HAS_WEBDRIVER_MANAGER = True
except ImportError:
    from selenium.webdriver.chrome.service import Service as ChromeService
    HAS_WEBDRIVER_MANAGER = False


# ─────────────────────────────────────────────
# 설정 로드
# ─────────────────────────────────────────────
def load_config(config_path=None):
    """config.ini 파일에서 설정을 로드합니다."""
    if config_path is None:
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")
    
    if not os.path.exists(config_path):
        print(f"[!] 설정 파일을 찾을 수 없습니다: {config_path}")
        print("    config.ini 파일을 생성하고 계정 정보를 입력해주세요.")
        sys.exit(1)
    
    config = configparser.ConfigParser()
    config.read(config_path, encoding="utf-8")
    return config


# ─────────────────────────────────────────────
# Gmail IMAP: 2차 인증코드 읽기
# ─────────────────────────────────────────────
def get_verification_code(config):
    """
    Gmail IMAP에 접속하여 최신 인증코드 메일에서 코드를 추출합니다.
    최대 max_wait_seconds 동안 poll_interval_seconds 간격으로 폴링합니다.
    """
    gmail_email = config.get("gmail_imap", "email")
    app_password = config.get("gmail_imap", "app_password")
    imap_server = config.get("gmail_imap", "imap_server", fallback="imap.gmail.com")
    sender_filter = config.get("gmail_imap", "sender_filter", fallback="shinhan")
    code_pattern = config.get("gmail_imap", "code_pattern", fallback=r"\d{6}")
    max_wait = config.getint("gmail_imap", "max_wait_seconds", fallback=60)
    poll_interval = config.getint("gmail_imap", "poll_interval_seconds", fallback=5)
    
    # 로그인 시도 시각 기록 (이전 메일 무시용)
    search_after = datetime.now() - timedelta(minutes=2)
    
    print(f"[*] Gmail IMAP 접속 중... ({gmail_email})")
    
    elapsed = 0
    while elapsed < max_wait:
        try:
            # IMAP 서버 접속
            mail = imaplib.IMAP4_SSL(imap_server)
            mail.login(gmail_email, app_password)
            mail.select("INBOX")
            
            # 최근 메일 검색 (날짜 기준)
            date_str = search_after.strftime("%d-%b-%Y")
            search_criteria = f'(SINCE "{date_str}" FROM "{sender_filter}")'
            
            status, message_ids = mail.search(None, search_criteria)
            
            if status == "OK" and message_ids[0]:
                ids = message_ids[0].split()
                # 가장 최근 메일부터 확인 (역순)
                for msg_id in reversed(ids):
                    status, msg_data = mail.fetch(msg_id, "(RFC822)")
                    if status != "OK":
                        continue
                    
                    raw_email = msg_data[0][1]
                    msg = email.message_from_bytes(raw_email)
                    
                    # 메일 수신 시간 확인
                    msg_date = email.utils.parsedate_to_datetime(msg["Date"])
                    if msg_date.replace(tzinfo=None) < search_after:
                        continue
                    
                    # 메일 본문에서 인증코드 추출
                    body = _get_email_body(msg)
                    if body:
                        match = re.search(code_pattern, body)
                        if match:
                            code = match.group(0)
                            print(f"[+] 인증코드 발견: {code}")
                            mail.logout()
                            return code
            
            mail.logout()
            
        except imaplib.IMAP4.error as e:
            print(f"[!] IMAP 오류: {e}")
            print("    Gmail 앱 비밀번호를 확인해주세요.")
            return None
        except Exception as e:
            print(f"[!] 메일 확인 중 오류: {e}")
        
        elapsed += poll_interval
        if elapsed < max_wait:
            remaining = max_wait - elapsed
            print(f"[*] 인증코드 메일 대기 중... ({elapsed}s / {max_wait}s, 남은 시간: {remaining}s)")
            time.sleep(poll_interval)
    
    print(f"[!] {max_wait}초 동안 인증코드 메일을 수신하지 못했습니다.")
    return None


def _get_email_body(msg):
    """이메일 메시지에서 텍스트 본문을 추출합니다."""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                try:
                    body = part.get_payload(decode=True).decode("utf-8", errors="replace")
                    break
                except Exception:
                    continue
            elif content_type == "text/html":
                try:
                    body = part.get_payload(decode=True).decode("utf-8", errors="replace")
                except Exception:
                    continue
    else:
        try:
            body = msg.get_payload(decode=True).decode("utf-8", errors="replace")
        except Exception:
            pass
    return body


# ─────────────────────────────────────────────
# Selenium: 브라우저 자동화
# ─────────────────────────────────────────────
def create_driver(config):
    """Selenium WebDriver를 생성합니다."""
    browser_type = config.get("browser", "browser_type", fallback="chrome")
    headless = config.getboolean("browser", "headless", fallback=False)
    timeout = config.getint("browser", "page_load_timeout", fallback=30)
    
    if browser_type.lower() == "chrome":
        options = webdriver.ChromeOptions()
        if headless:
            options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1280,900")
        # SSL 인증서 오류 무시 (사내망 등)
        options.add_argument("--ignore-certificate-errors")
        options.add_experimental_option("excludeSwitches", ["enable-logging"])
        options.add_experimental_option("detach", True)  # 브라우저 유지 옵션
        
        # 다운로드 디렉토리 설정
        download_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "eml")
        os.makedirs(download_dir, exist_ok=True)
        prefs = {
            "profile.default_content_setting_values.automatic_downloads": 1,
            "download.default_directory": download_dir,
            "download.prompt_for_download": False,
            "download.directory_upgrade": True,
            "safebrowsing.enabled": True
        }
        options.add_experimental_option("prefs", prefs)
        
        try:
            if HAS_WEBDRIVER_MANAGER:
                driver_path = ChromeDriverManager().install()
                # webdriver-manager가 chromedriver가 아닌 다른 파일을 반환할 수 있음
                import pathlib
                p = pathlib.Path(driver_path)
                if p.name != "chromedriver.exe" and p.name != "chromedriver":
                    # 같은 디렉토리에서 chromedriver.exe 찾기
                    for f in p.parent.glob("chromedriver*"):
                        if f.suffix in (".exe", "") and "THIRD_PARTY" not in f.name:
                            driver_path = str(f)
                            break
                service = ChromeService(executable_path=driver_path)
                driver = webdriver.Chrome(service=service, options=options)
            else:
                driver = webdriver.Chrome(options=options)
        except Exception as e:
            print(f"[!] ChromeDriver 자동 설치 실패: {e}")
            print("[*] 시스템 기본 ChromeDriver로 시도합니다...")
            driver = webdriver.Chrome(options=options)
    
    elif browser_type.lower() == "edge":
        from selenium.webdriver.edge.service import Service as EdgeService
        options = webdriver.EdgeOptions()
        if headless:
            options.add_argument("--headless=new")
        options.add_argument("--ignore-certificate-errors")
        options.add_experimental_option("detach", True)  # 브라우저 유지 옵션
        driver = webdriver.Edge(options=options)
    
    else:
        print(f"[!] 지원하지 않는 브라우저: {browser_type}")
        sys.exit(1)
    
    driver.set_page_load_timeout(timeout)
    driver.implicitly_wait(10)
    return driver


def login_shinhan_mail(config):
    """
    mail.shinhan.com에 자동 로그인합니다.
    1단계: ID/PW 입력 → 로그인 클릭
    2단계: Gmail에서 2차 인증코드 읽기
    3단계: 인증코드 입력 → 최종 로그인
    """
    url = config.get("shinhan_mail", "url")
    username = config.get("shinhan_mail", "username")
    password = config.get("shinhan_mail", "password")
    
    id_selector = config.get("shinhan_mail", "id_selector", fallback="#userId")
    pw_selector = config.get("shinhan_mail", "pw_selector", fallback="#userPw")
    login_btn_selector = config.get("shinhan_mail", "login_btn_selector", fallback="#loginBtn")
    otp_input_selector = config.get("shinhan_mail", "otp_input_selector", fallback="#otpNo")
    otp_submit_selector = config.get("shinhan_mail", "otp_submit_selector", fallback="#otpBtn")
    login_success_selector = config.get("shinhan_mail", "login_success_selector", fallback=".mail-list")
    
    # 계정 정보 확인
    if username == "your_id" or password == "your_password":
        print("[!] config.ini에 실제 계정 정보를 입력해주세요.")
        sys.exit(1)
    
    driver = None
    try:
        # ─── Step 1: 로그인 페이지 접속 ───
        print(f"[*] 브라우저 시작...")
        driver = create_driver(config)
        
        print(f"[*] {url} 접속 중...")
        driver.get(url)
        time.sleep(3)  # 페이지 로딩 대기
        
        print(f"[*] 현재 URL: {driver.current_url}")
        print(f"[*] 페이지 제목: {driver.title}")
        
        # ─── Step 2: ID/PW 입력 ───
        print(f"[*] ID 입력 중... (셀렉터: {id_selector})")
        try:
            id_field = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, id_selector))
            )
            id_field.clear()
            id_field.send_keys(username)
        except TimeoutException:
            print(f"[!] ID 입력 필드를 찾을 수 없습니다. 셀렉터를 확인해주세요: {id_selector}")
            _print_page_debug(driver)
            return False
        
        print(f"[*] Password 입력 중... (셀렉터: {pw_selector})")
        try:
            pw_field = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, pw_selector))
            )
            pw_field.clear()
            pw_field.send_keys(password)
        except TimeoutException:
            print(f"[!] PW 입력 필드를 찾을 수 없습니다. 셀렉터를 확인해주세요: {pw_selector}")
            _print_page_debug(driver)
            return False
        
        # ─── Step 3: 로그인 실행 ───
        # 방법 1: PW 필드에서 Enter 키 전송 (가장 자연스러운 방식)
        print("[*] 로그인 실행 중... (Enter 키 전송)")
        pw_field.send_keys(Keys.RETURN)
        
        print("[*] 로그인 요청 전송. 페이지 전환 대기 중...")
        time.sleep(5)  # 페이지 전환 대기 (넉넉하게)
        
        # 로그인 후 에러 메시지 확인
        print(f"[*] 로그인 후 URL: {driver.current_url}")
        
        # Alert 팝업 확인
        try:
            alert = driver.switch_to.alert
            alert_text = alert.text
            print(f"[!] Alert 메시지: {alert_text}")
            alert.accept()
        except Exception:
            pass
        
        # 에러 메시지 요소 확인 (일반적인 로그인 에러 패턴)
        error_selectors = [".error", ".alert", ".err-msg", ".login-error", 
                          "[class*='error']", "[class*='alert']", "[class*='warn']"]
        for es in error_selectors:
            try:
                err_el = driver.find_element(By.CSS_SELECTOR, es)
                if err_el.text.strip():
                    print(f"[!] 에러 메시지 감지: {err_el.text.strip()}")
            except Exception:
                continue
        
        # ─── Step 4: 2차 인증코드 입력 필드 확인 ───
        # OTP 입력 필드가 나타나는지 확인 (15초 대기)
        try:
            otp_field = WebDriverWait(driver, 15).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, otp_input_selector))
            )
            print("[*] 2차 인증 입력 화면 감지!")
        except TimeoutException:
            print("[*] 기본 OTP 셀렉터로 감지 실패. 페이지 구조를 분석합니다...")
            print(f"[*] 현재 URL: {driver.current_url}")
            
            # /twoFactorAuth 페이지인 경우 → OTP 필드를 다양한 방법으로 찾기
            if "twoFactor" in driver.current_url or "otp" in driver.current_url.lower():
                print("[*] 2차 인증 페이지 감지! OTP 입력 필드를 탐색합니다...")
                _print_page_debug(driver)
                
                # 다양한 셀렉터로 OTP 입력 필드 탐색
                otp_candidates = [
                    otp_input_selector,
                    "input[type='text']",
                    "input[type='number']",
                    "input[type='tel']",
                    "input[name*='otp']",
                    "input[name*='code']",
                    "input[name*='auth']",
                    "input[id*='otp']",
                    "input[id*='code']",
                    "input[id*='auth']",
                    "input[placeholder*='인증']",
                    "input[placeholder*='코드']",
                ]
                otp_field = None
                for candidate in otp_candidates:
                    try:
                        found = driver.find_elements(By.CSS_SELECTOR, candidate)
                        if found:
                            otp_field = found[0]
                            print(f"[+] OTP 입력 필드 발견! (셀렉터: {candidate})")
                            break
                    except Exception:
                        continue
                
                if otp_field is None:
                    print("[!] OTP 입력 필드를 찾을 수 없습니다.")
                    print("[*] 위 디버그 정보에서 input 요소를 확인하고 config.ini의 otp_input_selector를 수정해주세요.")
                    return False
            else:
                # URL이 변경되었는지 확인 (2FA가 아닌 다른 페이지)
                if driver.current_url != url and driver.current_url != url + "/login":
                    print("[+] URL이 변경되었습니다. 로그인 성공으로 추정됩니다.")
                    return True
                
                # 로그인 성공 여부 확인
                try:
                    WebDriverWait(driver, 5).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, login_success_selector))
                    )
                    print("[+] 로그인 성공! (2차 인증 불필요)")
                    return True
                except TimeoutException:
                    print("[!] 2차 인증도 없고, 로그인도 안 됨. 페이지를 확인해주세요.")
                    _print_page_debug(driver)
                    return False
        
        # ─── Step 5: 메일 인증 모드 선택 + 인증코드 발송 ───
        # 메일 인증 라디오 버튼 선택
        try:
            mail_auth_radio = driver.find_element(By.CSS_SELECTOR, "#authMode_mail")
            if not mail_auth_radio.is_selected():
                driver.execute_script("arguments[0].click();", mail_auth_radio)
                print("[*] 메일 인증 모드 선택 완료")
                time.sleep(1)
        except Exception:
            print("[*] 인증 모드 라디오 버튼을 찾을 수 없습니다. 기본 모드를 사용합니다.")
        
        # 인증코드 발송 버튼 찾기 및 클릭
        send_btn_selectors = [
            "button", "input[type='submit']", "input[type='button']",
            "a[class*='btn']", "[class*='send']", "[class*='request']",
            "[onclick*='send']", "[onclick*='auth']",
        ]
        send_clicked = False
        for sel in send_btn_selectors:
            try:
                btns = driver.find_elements(By.CSS_SELECTOR, sel)
                for btn in btns:
                    btn_text = btn.text.strip() if btn.text else ""
                    btn_value = btn.get_attribute("value") or ""
                    if any(kw in (btn_text + btn_value) for kw in ["발송", "전송", "요청", "send", "인증"]):
                        driver.execute_script("arguments[0].click();", btn)
                        print(f"[*] 인증코드 발송 버튼 클릭: '{btn_text or btn_value}'")
                        send_clicked = True
                        break
            except Exception:
                continue
            if send_clicked:
                break
        
        if not send_clicked:
            # 모든 버튼/링크를 출력하여 디버깅
            print("[!] 인증코드 발송 버튼을 찾을 수 없습니다.")
            try:
                all_clickable = driver.find_elements(By.CSS_SELECTOR, "button, input[type='submit'], input[type='button'], a")
                print(f"[DEBUG] 클릭 가능한 요소 {len(all_clickable)}개:")
                for idx, el in enumerate(all_clickable[:10]):
                    el_tag = el.tag_name
                    el_text = el.text.strip()[:50] if el.text else ""
                    el_id = el.get_attribute("id") or ""
                    el_class = el.get_attribute("class") or ""
                    el_value = el.get_attribute("value") or ""
                    print(f"  [{idx}] <{el_tag}> id={el_id}, class={el_class[:30]}, text='{el_text}', value='{el_value}'")
            except Exception:
                pass
        
        time.sleep(3)  # 인증코드 발송 대기
        
        # ─── Step 6: Gmail에서 인증코드 읽기 ───
        print("[*] Gmail에서 인증코드 읽기 시작...")
        verification_code = get_verification_code(config)
        
        if not verification_code:
            print("[!] 인증코드를 가져오지 못했습니다.")
            print("[*] 수동으로 인증코드를 입력해주세요:")
            verification_code = input(">>> 인증코드: ").strip()
            if not verification_code:
                print("[!] 인증코드가 입력되지 않았습니다. 종료합니다.")
                return False
        
        # ─── Step 6: 인증코드 입력 + 제출 ───
        print(f"[*] 인증코드 입력 중: {verification_code}")
        otp_field.clear()
        otp_field.send_keys(verification_code)
        
        print("[*] 인증 제출 버튼 검색...")
        submit_clicked = False
        
        # 1차: config.ini 셀렉터로 시도
        try:
            otp_submit = driver.find_element(By.CSS_SELECTOR, otp_submit_selector)
            driver.execute_script("arguments[0].click();", otp_submit)
            print(f"[*] OTP 제출 버튼 클릭 (셀렉터: {otp_submit_selector})")
            submit_clicked = True
        except Exception:
            pass
        
        # 2차: 키워드로 버튼/링크 검색 (발송 버튼과 혼동 방지)
        if not submit_clicked:
            for sel in ["button", "input[type='submit']", "input[type='button']", "a[class*='btn']", "a"]:
                try:
                    btns = driver.find_elements(By.CSS_SELECTOR, sel)
                    for btn in btns:
                        btn_text = btn.text.strip() if btn.text else ""
                        btn_value = btn.get_attribute("value") or ""
                        combined = btn_text + btn_value
                        # "요청"이나 "발송"이 포함된 건 발송 버튼이므로 제외
                        if any(skip in combined for skip in ["요청", "발송", "전송"]):
                            continue
                        if any(kw in combined for kw in ["확인", "로그인", "submit", "confirm", "login"]):
                            driver.execute_script("arguments[0].click();", btn)
                            print(f"[*] OTP 제출 버튼 클릭: '{btn_text or btn_value}'")
                            submit_clicked = True
                            break
                except Exception:
                    continue
                if submit_clicked:
                    break
        
        # 3차: form submit 또는 Enter 키
        if not submit_clicked:
            try:
                form = driver.find_element(By.TAG_NAME, "form")
                driver.execute_script("arguments[0].submit();", form)
                print("[*] Form submit으로 제출합니다.")
            except Exception:
                print("[*] Enter 키로 제출합니다.")
                otp_field.send_keys(Keys.RETURN)
        
        time.sleep(1)  # 인증 처리 대기 (팝업이 바로 뜨므로 짧게)
        
        # ─── Step 7: 인증 완료 팝업 처리 ───
        # 1차: JavaScript Alert 확인
        popup_handled = False
        try:
            WebDriverWait(driver, 3).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            print(f"[+] Alert 팝업 감지: '{alert.text}'")
            alert.accept()
            popup_handled = True
            time.sleep(3)
        except (TimeoutException, Exception):
            pass
        
        # 2차: 커스텀 모달 팝업 (HTML 기반)
        if not popup_handled:
            print("[*] 커스텀 팝업 확인 중...")
            time.sleep(1)
            
            # 팝업/오버레이 컨테이너 셀렉터 (일반적인 UI 프레임워크들)
            popup_selectors = [
                # SweetAlert
                ".swal2-popup", ".swal2-container", ".swal-overlay",
                # Bootstrap Modal  
                ".modal.show", ".modal.in", ".modal[style*='display: block']",
                # 일반적인 커스텀 팝업
                "[class*='popup']", "[class*='layer']", "[class*='modal']",
                "[class*='dialog']", "[class*='overlay']", "[class*='dim']",
                "[class*='alert'][class*='box']",
                "[role='dialog']", "[role='alertdialog']",
                # display:block 또는 visibility:visible 된 요소
                ".popup", ".layer", ".modal", ".dialog", ".overlay",
            ]
            
            popup_container = None
            for ps in popup_selectors:
                try:
                    elements = driver.find_elements(By.CSS_SELECTOR, ps)
                    for el in elements:
                        if el.is_displayed():
                            popup_container = el
                            print(f"[+] 팝업 컨테이너 발견: {ps}")
                            break
                except Exception:
                    continue
                if popup_container:
                    break
            
            if popup_container:
                # 팝업 내 모든 클릭 가능 요소 탐색
                try:
                    popup_btns = popup_container.find_elements(By.CSS_SELECTOR, 
                        "button, a, input[type='button'], input[type='submit'], [class*='btn']")
                    print(f"[*] 팝업 내 클릭 가능 요소: {len(popup_btns)}개")
                    for idx, pb in enumerate(popup_btns):
                        try:
                            pb_text = pb.text.strip()
                            pb_id = pb.get_attribute("id") or ""
                            pb_class = pb.get_attribute("class") or ""
                            print(f"  [{idx}] text='{pb_text}', id={pb_id}, class={pb_class[:40]}")
                            if pb.is_displayed() and any(kw in pb_text for kw in ["확인", "OK", "닫기"]):
                                try:
                                    pb.click()
                                except Exception:
                                    driver.execute_script("arguments[0].click();", pb)
                                print(f"[+] 팝업 확인 버튼 클릭: '{pb_text}'")
                                popup_handled = True
                                time.sleep(1)
                                break
                        except Exception:
                            continue
                except Exception as e:
                    print(f"[*] 팝업 버튼 탐색 실패: {e}")
            
            # 컨테이너를 못 찾은 경우: 페이지 전체에서 새로 보이는 '확인' 버튼 찾기
            if not popup_handled:
                print("[*] 전체 페이지에서 보이는 '확인' 버튼 탐색...")
                all_visible = driver.find_elements(By.CSS_SELECTOR, 
                    "button, a, input[type='button'], input[type='submit'], [class*='btn'], span")
                visible_confirms = []
                for el in all_visible:
                    try:
                        if el.is_displayed():
                            t = el.text.strip()
                            el_id = el.get_attribute("id") or ""
                            el_class = el.get_attribute("class") or ""
                            el_tag = el.tag_name
                            if t:
                                visible_confirms.append({
                                    "element": el, "text": t, "id": el_id, 
                                    "class": el_class, "tag": el_tag
                                })
                    except Exception:
                        continue
                
                print(f"[DEBUG] 보이는 텍스트 요소 {len(visible_confirms)}개:")
                for idx, vc in enumerate(visible_confirms):
                    print(f"  [{idx}] <{vc['tag']}> text='{vc['text'][:30]}', id={vc['id']}, class={vc['class'][:40]}")
                
                # 정확히 "확인"만 포함된 버튼 찾기 (OTP 확인이 아닌 팝업 확인)
                for vc in visible_confirms:
                    if vc["text"] == "확인":
                        # OTP 제출 때 이미 클릭한 버튼과 다른지 확인
                        driver.execute_script("arguments[0].click();", vc["element"])
                        print(f"[+] 확인 버튼 클릭: <{vc['tag']}> id={vc['id']}, class={vc['class'][:30]}")
                        popup_handled = True
                        break
        
        if popup_handled:
            # URL 변경 대기 (최대 10초)
            print("[*] 페이지 전환 대기 중...")
            for _ in range(20):
                time.sleep(0.5)
                if "twoFactorAuth" not in driver.current_url:
                    print(f"[+] URL 변경 감지: {driver.current_url}")
                    break
        else:
            print("[*] 팝업이 감지되지 않았습니다.")
        
        # ─── Step 7: 로그인 완료 확인 ───
        try:
            WebDriverWait(driver, 15).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, login_success_selector))
            )
            print("[+] ✅ 로그인 성공!")
            print(f"[+] 최종 URL: {driver.current_url}")
            return driver
        except TimeoutException:
            print("[*] 로그인 성공 요소를 확인할 수 없습니다.")
            print(f"[*] 현재 URL: {driver.current_url}")
            print(f"[*] 페이지 제목: {driver.title}")
            # URL 변화로 성공 여부 추정
            if "mailCommon.do" in driver.current_url:
                print("[+] 메일함 URL 감지. 로그인 성공!")
                return driver
            if "twoFactorAuth" not in driver.current_url and "login" not in driver.current_url:
                print("[+] 인증 페이지를 벗어남. 로그인 성공으로 추정.")
                return driver
            return None
    
    except WebDriverException as e:
        print(f"[!] 브라우저 오류: {e}")
        return None
    except Exception as e:
        print(f"[!] 예상치 못한 오류: {e}")
        return None


def _print_page_debug(driver):
    """디버깅용: 현재 페이지의 주요 요소를 출력합니다."""
    print("\n[DEBUG] === 페이지 디버그 정보 ===")
    print(f"  URL: {driver.current_url}")
    print(f"  Title: {driver.title}")
    
    # input 요소 목록 출력
    try:
        inputs = driver.find_elements(By.TAG_NAME, "input")
        print(f"  발견된 input 요소: {len(inputs)}개")
        for idx, inp in enumerate(inputs[:10]):
            inp_id = inp.get_attribute("id") or "(없음)"
            inp_name = inp.get_attribute("name") or "(없음)"
            inp_type = inp.get_attribute("type") or "(없음)"
            inp_placeholder = inp.get_attribute("placeholder") or "(없음)"
            print(f"    [{idx}] id={inp_id}, name={inp_name}, type={inp_type}, placeholder={inp_placeholder}")
    except Exception:
        pass
    
    # button 요소 목록 출력
    try:
        buttons = driver.find_elements(By.TAG_NAME, "button")
        print(f"  발견된 button 요소: {len(buttons)}개")
        for idx, btn in enumerate(buttons[:5]):
            btn_id = btn.get_attribute("id") or "(없음)"
            btn_text = btn.text.strip() or "(빈 텍스트)"
            print(f"    [{idx}] id={btn_id}, text={btn_text}")
    except Exception:
        pass
    
    # iframe 목록 출력
    try:
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            print(f"  ⚠️ iframe 발견: {len(iframes)}개 (iframe 내부 요소 접근 시 switch_to.frame 필요)")
            for idx, iframe in enumerate(iframes):
                iframe_id = iframe.get_attribute("id") or "(없음)"
                iframe_src = iframe.get_attribute("src") or "(없음)"
                print(f"    [{idx}] id={iframe_id}, src={iframe_src[:80]}")
    except Exception:
        pass
    
    print("[DEBUG] ==============================\n")


# ─────────────────────────────────────────────
# EML 첨부파일 다운로드
# ─────────────────────────────────────────────
def download_eml_attachments(driver):
    """
    로그인 후 받은편지함에서 모든 메일을 확인하고,
    첨부파일 중 .eml 확장자를 가진 파일을 모두 다운로드합니다.
    
    신한 메일 구조:
    - 메일 목록: table.mail_list > tr (id=Inbox_XXXX)
    - 안 읽은 메일: tr.read_no
    - 첨부파일 목록: #attachListWrap > li
    - EML 아이콘: .ic_file.ic_eml
    - 다운로드 클릭: span[evt-rol="download-attach"]
    """
    print("\n" + "="*50)
    print("  [자동화] 받은편지함 EML 첨부파일 다운로드")
    print("="*50)
    
    download_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "eml")
    os.makedirs(download_dir, exist_ok=True)
    
    time.sleep(3)  # 페이지 완전 로딩 대기
    
    # 메일 행 수집 (모든 메일 - Inbox_XXXX ID를 가진 tr)
    mail_rows = driver.find_elements(By.CSS_SELECTOR, "tr[id^='Inbox_']")
    total_mails = len(mail_rows)
    print(f"\n[*] 받은편지함 메일 개수: {total_mails}")
    
    if total_mails == 0:
        print("[-] 처리할 메일이 없습니다.")
        return
    
    # 각 메일의 ID를 미리 수집 (DOM이 변경되므로)
    mail_ids = []
    for row in mail_rows:
        mid = row.get_attribute("id")
        if mid:
            mail_ids.append(mid)
    
    downloaded_count = 0
    skipped_count = 0
    
    for idx, mail_id in enumerate(mail_ids):
        print(f"\n[*] --- 메일 {idx+1}/{len(mail_ids)} (ID: {mail_id}) ---")
        
        # 메일 행 재탐색 (DOM이 변경될 수 있으므로)
        try:
            row = driver.find_element(By.CSS_SELECTOR, f"#{mail_id}")
        except Exception:
            print(f"[!] 메일 행을 찾을 수 없습니다: {mail_id}")
            continue
        
        # 메일 제목 추출
        try:
            link = row.find_element(By.TAG_NAME, "a")
            title = link.text.strip()[:60]
            print(f"[*] 제목: {title}")
        except Exception:
            title = "(제목 없음)"
            print(f"[*] 제목을 가져올 수 없습니다.")
        
        # 메일 클릭 (본문으로 이동)
        try:
            link = row.find_element(By.TAG_NAME, "a")
            driver.execute_script("arguments[0].click();", link)
            time.sleep(3)  # 본문 로딩 대기
        except Exception as e:
            print(f"[!] 메일 클릭 실패: {e}")
            continue
        
        # 첨부파일 목록 확인
        eml_found = False
        try:
            attach_wrap = driver.find_elements(By.CSS_SELECTOR, "#attachListWrap li")
            if not attach_wrap:
                print("[-] 첨부파일 없음. 목록으로 돌아갑니다.")
            else:
                print(f"[*] 첨부파일 {len(attach_wrap)}개 발견")
                
                for aidx, attach_li in enumerate(attach_wrap):
                    try:
                        # EML 파일 여부 확인 (아이콘 또는 파일명으로)
                        is_eml = False
                        
                        # 1차: .ic_eml 클래스로 확인
                        try:
                            attach_li.find_element(By.CSS_SELECTOR, ".ic_eml")
                            is_eml = True
                        except Exception:
                            pass
                        
                        # 2차: 파일명으로 확인
                        if not is_eml:
                            try:
                                name_span = attach_li.find_element(By.CSS_SELECTOR, 'span[evt-rol="download-attach"]')
                                fname = name_span.text.strip().lower()
                                if fname.endswith(".eml"):
                                    is_eml = True
                            except Exception:
                                pass
                        
                        # 파일명 가져오기
                        try:
                            name_span = attach_li.find_element(By.CSS_SELECTOR, 'span[evt-rol="download-attach"]')
                            filename = name_span.text.strip()
                        except Exception:
                            filename = f"unknown_{mail_id}_{aidx}" + (".eml" if is_eml else ".dat")
                        
                        if is_eml:
                            print(f"[+] EML 파일 발견: {filename}")
                        else:
                            print(f"[+] 일반 첨부파일 발견: {filename}")
                        
                        # 기존 파일 목록 스냅샷
                        before_files = set(os.listdir(download_dir))
                        
                        # 다운로드 클릭
                        try:
                            name_span = attach_li.find_element(By.CSS_SELECTOR, 'span[evt-rol="download-attach"]')
                            driver.execute_script("arguments[0].click();", name_span)
                            print("[*] 다운로드 요청 전송 완료")
                        except Exception as e:
                            print(f"[!] 다운로드 클릭 실패: {e}")
                            continue
                        
                        # 다운로드 완료 대기 (최대 30초)
                        download_complete = False
                        downloaded_filename = None
                        for wait in range(30):
                            time.sleep(1)
                            current_files = set(os.listdir(download_dir))
                            new_files = current_files - before_files
                            
                            # 다운로드 중 파일 확인
                            is_downloading = any(
                                f.endswith(".crdownload") or f.endswith(".tmp") 
                                for f in current_files
                            )
                            
                            if new_files and not is_downloading:
                                for nf in new_files:
                                    # EML인 경우 EML 파일만 인정
                                    if is_eml and not nf.lower().endswith(".eml"):
                                        continue
                                    downloaded_filename = nf
                                    if is_eml:
                                        downloaded_count += 1
                                        eml_found = True
                                    print(f"[SUCCESS] 다운로드 완료: {nf}")
                                    download_complete = True
                                    break
                            
                            if download_complete:
                                break
                        
                        if not download_complete:
                            # 팝업 처리 (다운로드 확인 팝업이 뜰 수 있음)
                            try:
                                popup = driver.find_element(By.CSS_SELECTOR, "[class*='popup']")
                                if popup.is_displayed():
                                    confirm_btns = popup.find_elements(By.CSS_SELECTOR, "button, a, [class*='btn']")
                                    for cb in confirm_btns:
                                        if "확인" in (cb.text or "") or "저장" in (cb.text or ""):
                                            driver.execute_script("arguments[0].click();", cb)
                                            print("[*] 다운로드 팝업 확인 클릭")
                                            time.sleep(3)
                                            break
                            except Exception:
                                pass
                            
                            # 재확인
                            current_files = set(os.listdir(download_dir))
                            new_files = current_files - before_files
                            for nf in new_files:
                                if is_eml and not nf.lower().endswith(".eml"):
                                    continue
                                downloaded_filename = nf
                                if is_eml:
                                    downloaded_count += 1
                                    eml_found = True
                                print(f"[SUCCESS] 다운로드 완료: {nf}")
                                download_complete = True
                                break
                            
                            if not download_complete:
                                print(f"[!] 다운로드 시간 초과: {filename}")
                        
                        # EML이 아닌 첨부파일의 경우 폴더 생성 및 이동
                        if download_complete and not is_eml and downloaded_filename:
                            import shutil
                            eml_bank_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "eml_bank")
                            
                            # 폴더명에 사용할 수 없는 문자 제거
                            safe_title = re.sub(r'[\\/*?:"<>|]', "_", title).strip()
                            if not safe_title:
                                safe_title = f"mail_{mail_id}"
                            
                            target_dir = os.path.join(eml_bank_dir, safe_title)
                            os.makedirs(target_dir, exist_ok=True)
                            
                            src_path = os.path.join(download_dir, downloaded_filename)
                            dst_path = os.path.join(target_dir, downloaded_filename)
                            
                            try:
                                # 파일 덮어쓰기 방지
                                if os.path.exists(dst_path):
                                    base, ext = os.path.splitext(downloaded_filename)
                                    dst_path = os.path.join(target_dir, f"{base}_{int(time.time())}{ext}")
                                shutil.move(src_path, dst_path)
                                print(f"[*] 일반 첨부파일을 {target_dir} 이동 완료")
                            except Exception as e:
                                print(f"[!] 파일 이동 실패: {e}")
                    except Exception as e:
                        print(f"[!] 첨부파일 처리 오류: {e}")
                        continue
        except Exception as e:
            print(f"[!] 첨부파일 목록 확인 실패: {e}")
        
        if not eml_found:
            skipped_count += 1
        
        # 목록으로 돌아가기
        print("[*] 메일 목록으로 돌아가기...")
        try:
            # '목록' 버튼 찾기
            list_btn = None
            btns = driver.find_elements(By.CSS_SELECTOR, "a, button")
            for btn in btns:
                try:
                    t = btn.text.strip() if btn.text else ""
                    evt = btn.get_attribute("evt-rol") or ""
                    if "목록" in t or "list" in evt.lower():
                        list_btn = btn
                        break
                except Exception:
                    continue
            
            if list_btn:
                driver.execute_script("arguments[0].click();", list_btn)
                print("[+] 목록 버튼 클릭")
            else:
                driver.back()
                print("[*] 브라우저 Back 사용")
            
            time.sleep(3)  # 목록 로딩 대기
            
            # 목록 페이지 확인 (state=1)
            if "state=1" not in driver.current_url:
                print("[*] 목록 URL이 아닙니다. 새로고침...")
                driver.get("https://mail.shinhan.com/mail/mail/mailCommon.do?state=1")
                time.sleep(5)
        except Exception as e:
            print(f"[!] 목록 복귀 오류: {e}. 새로고침합니다.")
            driver.get("https://mail.shinhan.com/mail/mail/mailCommon.do?state=1")
            time.sleep(5)
    
    # 결과 요약
    print("\n" + "="*50)
    print(f"  [결과] 전체 메일: {len(mail_ids)}개")
    print(f"  [결과] 다운로드한 EML: {downloaded_count}개")
    print(f"  [결과] EML 없는 메일: {skipped_count}개")
    print(f"  [결과] 저장 위치: {download_dir}")
    print("="*50)


# ─────────────────────────────────────────────
# 메인 실행
# ─────────────────────────────────────────────
def main():
    print("=" * 50)
    print("  mail.shinhan.com 자동 로그인")
    print("  Selenium + Gmail IMAP 2FA")
    print("=" * 50)
    print()
    
    config = load_config()
    
    # 설정 확인 출력
    print(f"[*] 대상 URL: {config.get('shinhan_mail', 'url')}")
    print(f"[*] 사용자 ID: {config.get('shinhan_mail', 'username')}")
    print(f"[*] Gmail: {config.get('gmail_imap', 'email')}")
    print(f"[*] 브라우저: {config.get('browser', 'browser_type', fallback='chrome')}")
    print(f"[*] Headless: {config.get('browser', 'headless', fallback='False')}")
    print()
    
    driver = login_shinhan_mail(config)
    
    if driver:
        print("\n[SUCCESS] 자동 로그인이 완료되었습니다!")
        
        # EML 첨부파일 다운로드
        try:
            download_eml_attachments(driver)
        except Exception as e:
            print(f"[!] EML 다운로드 중 오류: {e}")
        
        print("\n[*] 다운로드가 완료되었습니다. 브라우저를 유지한 채 다음 단계를 진행합니다.")
    else:
        print("\n[FAIL] 로그인에 실패했습니다. config.ini 설정을 확인해주세요.")
        print("   특히 CSS 셀렉터가 실제 페이지 구조와 맞는지 확인이 필요합니다.")
        print("   브라우저 개발자 도구(F12)로 요소의 ID, Name을 확인하세요.")


if __name__ == "__main__":
    main()
