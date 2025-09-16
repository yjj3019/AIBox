#!/bin/bash

python3 -m venv venv
source venv/bin/activate

# path of backup file
DIR="/tmp"
# date at run time
DATE=`date +%Y%m%d`
# Backup log file settings
BACKUPLOG=$DIR/security_$DATE.txt

function send(){
        tee -a $BACKUPLOG
}

# no proxy
export no_proxy="localhost, 127.0.0.1, 172.21.135.113"


# --- 스크립트 설명 ---
# 이 스크립트는 AI 전문가 시스템 백엔드 서버를 Linux 환경에서 실행합니다.
# 1. Python 가상 환경(venv)을 생성하고 활성화합니다.
# 2. requirements.txt에 명시된 필수 패키지를 설치합니다.
# 3. gunicorn WSGI 서버를 사용하여 Flask 애플리케이션을 실행합니다.

export LLM_URL="http://x.x.x.x:4000" # 여기에 LLM 서버 URL을 입력하세요. 예: http://192.168.1.10:8080
export MODEL="xxxx"   # 여기에 사용할 모델 이름을 입력하세요. 예: mistral-7b-instruct-v0.2.Q4_K_M.gguf
export TOKEN="xxxx"   # LLM 서버에 토큰이 필요하면 여기에 입력하세요. (선택 사항)

# waitress 서버 실행 (기존 app.py와 호환)
/usr/bin//python3.6  /data/iso/AIBox/security.py --llm-url "$LLM_URL" --model "$MODEL" --token "$TOKEN" | send
