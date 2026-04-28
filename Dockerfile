# 1. 베이스 이미지를 반드시 Kali로 변경 (도구들이 이미 상점에 등록되어 있음)
FROM kalilinux/kali-rolling

WORKDIR /app

# 2. 기업 보안망 에러 방지 (https를 http로 강제 전환)
RUN sed -i 's/https/http/g' /etc/apt/sources.list || true && \
    if [ -f /etc/apt/sources.list.d/kali.sources ]; then \
        sed -i 's/https/http/g' /etc/apt/sources.list.d/kali.sources; \
    fi

# 3. 필수 패키지 설치 (python2는 제외하고, exiftool 명칭 수정)
RUN apt-get -o "Acquire::https::Verify-Peer=false" update && \
    apt-get -o "Acquire::https::Verify-Peer=false" install -y \
    python3 python3-pip python3-venv \
    file binutils libimage-exiftool-perl coreutils \
    pdfid pdf-parser \
    wget curl git unzip \
    nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# 4. Python 분석 라이브러리 설치
RUN pip3 install --no-cache-dir --break-system-packages \
    requests pefile oletools


# 5. Gemini CLI
RUN npm install -g @google/gemini-cli

# 6. VirusTotal CLI 설치
RUN wget --no-check-certificate https://github.com/VirusTotal/vt-cli/releases/download/0.14.0/Linux64.zip -O /tmp/vt.zip && \
    unzip /tmp/vt.zip -d /tmp && \
    mv /tmp/vt /usr/local/bin/vt && \
    chmod +x /usr/local/bin/vt && \
    rm -rf /tmp/vt*

# 7. 코드 복사 및 실행 권한 부여
COPY . /app
RUN chmod +x *.py 2>/dev/null || true

CMD ["/bin/bash"]