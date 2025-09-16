#!/bin/bash

# no proxy
export no_proxy="localhost, 127.0.0.1, 172.21.135.113"


# --- 스크립트 설명 ---
# 이 스크립트는 AI 전문가 시스템 백엔드 서버를 Linux 환경에서 실행합니다.
# 1. Python 가상 환경(venv)을 생성하고 활성화합니다.
# 2. requirements.txt에 명시된 필수 패키지를 설치합니다.
# 3. gunicorn WSGI 서버를 사용하여 Flask 애플리케이션을 실행합니다.

# --- 사용자 설정 변수 ---
HOST="0.0.0.0"
PORT="5000"
# 워커 수: (2 * CPU 코어 수) + 1 공식을 따르는 것을 권장합니다.
# nproc 명령어로 코어 수를 확인할 수 있습니다. 예: WORKERS=$((2 * $(nproc) + 1))
WORKERS=4
LLM_URL="http:/x.x.x.x:4000" # 여기에 LLM 서버 URL을 입력하세요. 예: http://192.168.1.10:8080
MODEL="xxxxxx"   # 여기에 사용할 모델 이름을 입력하세요. 예: mistral-7b-instruct-v0.2.Q4_K_M.gguf
TOKEN="xxxxxx"   # LLM 서버에 토큰이 필요하면 여기에 입력하세요. (선택 사항)

# --- 필수 변수 확인 ---
if [ -z "$LLM_URL" ] || [ -z "$MODEL" ]; then
    echo "오류: LLM_URL과 MODEL 변수를 스크립트 내에 설정해야 합니다."
    echo "예시: "
    echo "LLM_URL=\"http://<your-llm-server-ip>:<port>\""
    echo "MODEL=\"<your-model-name>\""
    exit 1
fi

echo "--- AI 전문가 시스템 서버 시작 ---"

# 1. Python 가상 환경 설정
if [ ! -d "venv" ]; then
    echo "Python 가상 환경(venv)을 생성합니다..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "가상 환경 생성에 실패했습니다. python3-venv 패키지가 설치되어 있는지 확인하세요."
        exit 1
    fi
fi

echo "가상 환경을 활성화합니다..."
source venv/bin/activate

# 2. 의존성 패키지 설치
#echo "requirements.txt로부터 패키지를 설치합니다..."
#pip install -r requirements.txt

# 3. Gunicorn으로 Flask 앱 실행
echo "Gunicorn 서버를 시작합니다..."
echo "주소: http://$HOST:$PORT"
echo "워커 수: $WORKERS"
echo "LLM 서버: $LLM_URL"
echo "사용 모델: $MODEL"

# gunicorn 실행: app 모듈(app.py) 안에 있는 app 객체를 실행
# --llm-url, --model, --token 등의 인자는 app.py에서 직접 처리하지 않고,
# 여기서는 gunicorn으로 앱을 실행하는 데 집중합니다.
# app.py는 실행될 때 환경 변수나 설정 파일에서 이 값들을 읽도록 수정하는 것이 좋습니다.
# 하지만 현재 app.py는 argparse를 사용하므로, gunicorn으로 직접 인자를 넘길 수 없습니다.
# 대신, app.py를 직접 실행하여 waitress를 사용하도록 합니다.
# (또는 gunicorn을 사용하려면 app.py의 설정 로딩 방식을 변경해야 합니다.)

# 여기서는 기존 app.py 구조를 최대한 활용하기 위해 python app.py를 직접 실행합니다.
# Gunicorn을 사용하려면 app.py의 설정 로딩 방식을 수정해야 합니다. (예: 환경 변수 사용)
echo "-------------------------------------------"
echo "기존 AIBox_search.py 구조를 유지하기 위해 waitress 서버를 실행합니다."
echo "gunicorn을 사용하려면 AIBox_search.py의 설정 로딩 방식을 변경해야 합니다."
echo "서버 중지: Ctrl+C"

# waitress 서버 실행 (기존 AIBox_search.py와 호환)
#python3 AIBox_search.py --llm-url "$LLM_URL" --model "$MODEL" ${TOKEN:+--token "$TOKEN"} --host "$HOST" --port "$PORT"
#python3 AIBox_server_updated.py --llm-url "$LLM_URL" --model "$MODEL" ${TOKEN:+--token "$TOKEN"} --host "$HOST" --port "$PORT"
python3 AIBox_search_api.py --llm-url "$LLM_URL" --model "$MODEL" ${TOKEN:+--token "$TOKEN"} --host "$HOST" --port "$PORT"

# Gunicorn 실행 예시 (app.py 수정 필요)
# export LLM_URL=$LLM_URL
# export MODEL=$MODEL
# export TOKEN=$TOKEN
# gunicorn --bind $HOST:$PORT --workers $WORKERS app:app
