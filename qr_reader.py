#!/usr/bin/env python3

import cv2
import sys
import os
from pyzbar.pyzbar import decode

def read_qr_code(image_path):
    # 파일 존재 여부 확인
    if not os.path.exists(image_path):
        print(f"Error: 파일을 찾을 수 없습니다: {image_path}")
        return

    # 이미지 읽기
    image = cv2.imread(image_path)
    if image is None:
        print(f"Error: 이미지를 읽을 수 없습니다: {image_path}")
        return

    # QR 코드 디코딩
    decoded_objects = decode(image)

    if not decoded_objects:
        print("QR 코드를 찾을 수 없습니다.")
        return

    print(f"총 {len(decoded_objects)}개의 QR 코드를 발견했습니다:\n")
    for idx, obj in enumerate(decoded_objects, 1):
        # 데이터 디코딩 (utf-8)
        data = obj.data.decode('utf-8')
        qr_type = obj.type
        
        print(f"[{idx}] 타입: {qr_type}")
        print(f"    내용: {data}")
        print("-" * 30)

def main():
    if len(sys.argv) < 2:
        print("사용법: python3 qr_reader.py <이미지_파일_경로>")
        sys.exit(1)

    image_path = sys.argv[1]
    read_qr_code(image_path)

if __name__ == "__main__":
    main()
