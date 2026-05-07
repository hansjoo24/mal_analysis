import os
import email
import email.policy
import re
import html

eml_path = r"C:\Users\Administrator\.gemini\antigravity\playground\mal_analysis\본문이미지악성메일\4월 송금 전표 7559.eml"

def test_url_extraction(eml_path):
    print(f"Testing URL extraction for: {eml_path}")
    
    with open(eml_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)
        
    url_pattern = re.compile(r'https?://[^\s<>"\')]+', re.IGNORECASE)
    
    for part in msg.walk():
        content_type = part.get_content_type()
        print(f"Part type: {content_type}")
        if content_type in ('text/plain', 'text/html'):
            try:
                body = part.get_content()
            except Exception as e:
                print(f"get_content() failed: {e}")
                raw_body = part.get_payload(decode=True)
                if raw_body:
                    body = raw_body.decode('utf-8', errors='ignore')
                else:
                    body = ""
                    
            if isinstance(body, str) and body:
                print(f"Body length: {len(body)}")
                # Print a small snippet to see encoding issues
                print(f"Body snippet: {repr(body[:200])}")
                body = html.unescape(body)
                found = url_pattern.findall(body)
                print(f"URLs found: {found}")
                print("-" * 40)

if __name__ == "__main__":
    test_url_extraction(eml_path)
