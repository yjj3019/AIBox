#!/bin/bash

# --- 스크립트 설명 ---
# 이 스크립트는 AIBox 백엔드 서버를 Linux 환경에서 안정적으로 실행합니다.
# 1. Python 가상 환경(venv)을 생성하고 활성화합니다.
# 2. requirements.txt에 명시된 필수 패키지를 설치합니다.
# 3. waitress WSGI 서버를 사용하여 Flask 애플리케이션을 실행합니다.

set -e # 오류 발생 시 스크립트 중단

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
VENV_DIR="${SCRIPT_DIR}/.venv"

echo "--- AIBox 서버 실행 스크립트 시작 ---"

# 1. 가상 환경 설정
if [ ! -d "$VENV_DIR" ]; then
    echo "Python 가상 환경(venv)을 생성합니다..."
    python3 -m venv "$VENV_DIR"
else
    echo "기존 가상 환경(venv)을 사용합니다."
fi

source "${VENV_DIR}/bin/activate"
echo "가상 환경이 활성화되었습니다."

# 2. 필수 패키지 설치
echo "필수 패키지를 설치합니다 (requirements.txt)..."
pip install --upgrade pip
pip install -r "${SCRIPT_DIR}/requirements.txt"
echo "패키지 설치가 완료되었습니다."

# 3. AIBox 서버 실행ㅣㅣㅣㅣ
# 서버 실행에 필요한 환경 변수를 여기에 설정할 수 있습니다.
# 예: export LLM_URL="http://your-llm-server:8080"
export AIBOX_PASSWORD="aibox_admin" # [수정] 비밀번호를 환경 변수로 설정합니다.

# [BUG FIX] 시스템의 python3 대신, 활성화된 가상 환경(venv) 내의 python을 사용하여 서버를 실행합니다.
# 이렇게 하면 가상 환경에 설치된 라이브러리(openpyxl 등)를 정상적으로 임포트할 수 있습니다.
echo "AIBox 서버를 시작합니다..."
# [수정] 더 이상 사용하지 않는 --password 인자를 제거합니다.
/usr/bin/python "${SCRIPT_DIR}/AIBox_Server.py"

echo "--- AIBox 서버가 종료되었습니다. ---"