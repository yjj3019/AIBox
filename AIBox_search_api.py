import argparse
import getpass
import sys
import json
import os
import uuid
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import logging
from collections import OrderedDict
from waitress import serve

# --- 로깅 설정 ---
class HealthCheckFilter(logging.Filter):
    def filter(self, record):
        # '/api/health' 경로에 대한 액세스 로그 필터링
        return 'GET /api/health HTTP/1.1' not in record.getMessage()

log = logging.getLogger('werkzeug')
log.addFilter(HealthCheckFilter())
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Flask 앱 초기화 ---
app = Flask(__name__)
CORS(app)

# --- 전역 변수 ---
CONFIG = {}
PROMPTS = OrderedDict()
LEARNING_DATA_FILE = 'learning_data.json'
PROMPTS_FILE = 'prompts.json'
SERVER_INSTANCE_ID = str(uuid.uuid4())

# --- 함수 정의 ---
def initialize_prompts():
    """prompts.json 파일에서 프롬프트를 로드하거나 기본값으로 생성합니다."""
    global PROMPTS
    # 기본 프롬프트 내용은 기존과 동일하므로 생략합니다.
    default_prompts = OrderedDict([
        ("시스템 문제 해결 전문가 프롬프트", "...")
    ])
    try:
        if os.path.exists(PROMPTS_FILE):
            with open(PROMPTS_FILE, 'r', encoding='utf-8') as f:
                PROMPTS = OrderedDict(json.load(f))
            logging.info(f"'{PROMPTS_FILE}'에서 프롬프트를 성공적으로 로드했습니다.")
        else:
            PROMPTS = default_prompts
            with open(PROMPTS_FILE, 'w', encoding='utf-8') as f:
                json.dump(list(PROMPTS.items()), f, ensure_ascii=False, indent=4)
            logging.info(f"기본 프롬프트로 '{PROMPTS_FILE}' 파일을 생성했습니다.")
    except Exception as e:
        logging.error(f"프롬프트 파일 처리 중 오류 발생: {e}", exc_info=True)
        PROMPTS = default_prompts

def call_llm(prompt, system_message):
    """LLM 서버에 API 요청을 보내고 응답을 반환합니다."""
    headers = {'Content-Type': 'application/json'}
    if CONFIG.get("token"):
        headers['Authorization'] = f'Bearer {CONFIG["token"]}'

    payload = {
        "model": CONFIG["model"],
        "messages": [
            {"role": "system", "content": system_message},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 4096,
        "temperature": 0.2,
    }

    response = requests.post(f'{CONFIG["llm_url"]}/v1/chat/completions', headers=headers, json=payload, timeout=180)
    response.raise_for_status()
    return response.json()['choices'][0]['message']['content']

# --- API 엔드포인트 ---

@app.route('/api/health')
def health_check():
    return jsonify({"status": "ok", "instance_id": SERVER_INSTANCE_ID})

@app.route('/api/config', methods=['GET'])
def get_config():
    return jsonify({"model": CONFIG.get("model", "N/A")})

@app.route('/api/prompts', methods=['GET'])
def get_prompts():
    prompt_list = [{"key": key, "value": value} for key, value in PROMPTS.items()]
    return jsonify(prompt_list)

@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    prompt_key = data.get('prompt_key')
    user_query = data.get('user_query')

    if not all([prompt_key, user_query, prompt_key in PROMPTS]):
        return jsonify({"error": "잘못된 요청입니다."}), 400

    try:
        template = PROMPTS[prompt_key]
        meta_prompt_system = "You are a helpful assistant that constructs a detailed and professional final prompt for another AI expert..."
        meta_prompt_user = f"Template: {template}\n\nUser Query: {user_query}\n\nCompleted Prompt:"

        final_prompt = call_llm(meta_prompt_user, meta_prompt_system)

        final_system_message = "You are an expert assistant. Your responses must be in Korean and formatted using Markdown."
        final_answer = call_llm(final_prompt, final_system_message)

        return jsonify({"answer": final_answer, "question": user_query})
    except requests.exceptions.RequestException as e:
        logging.error(f"Request Error: {e}")
        return jsonify({"error": f"LLM 서버에 연결할 수 없습니다: {e}"}), 503
    except Exception as e:
        logging.error(f"분석 중 서버 오류 발생: {e}", exc_info=True)
        return jsonify({"error": "분석 중 내부 서버 오류가 발생했습니다."}), 500

# --- 추가된 기능 ---
@app.route('/api/verify-password', methods=['POST'])
def verify_password():
    """프롬프트 편집을 위한 비밀번호를 확인합니다."""
    password_attempt = request.get_json().get('password')
    if password_attempt and password_attempt == CONFIG.get("password"):
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "error": "비밀번호가 올바르지 않습니다."}), 401

@app.route('/api/update-prompts', methods=['POST'])
def update_prompts():
    """클라이언트로부터 받은 프롬프트로 업데이트하고 파일에 저장합니다."""
    global PROMPTS
    data = request.get_json()
    password = data.get('password')
    updated_prompts_list = data.get('prompts')

    if not password or password != CONFIG.get("password"):
        return jsonify({"success": False, "error": "비밀번호가 올바르지 않습니다."}), 401

    if not isinstance(updated_prompts_list, list):
        return jsonify({"success": False, "error": "잘못된 데이터 형식입니다."}), 400

    try:
        PROMPTS = OrderedDict([(item['key'], item['value']) for item in updated_prompts_list])

        with open(PROMPTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(list(PROMPTS.items()), f, ensure_ascii=False, indent=4)

        logging.info(f"프롬프트가 성공적으로 업데이트되고 '{PROMPTS_FILE}'에 저장되었습니다.")
        return jsonify({"success": True, "message": "프롬프트가 성공적으로 업데이트되었습니다."})
    except Exception as e:
        logging.error(f"프롬프트 업데이트 중 오류 발생: {e}", exc_info=True)
        return jsonify({"success": False, "error": "서버에서 프롬프트를 업데이트하는 중 오류가 발생했습니다."}), 500

@app.route('/api/learn', methods=['POST'])
def learn_from_feedback():
    """사용자 피드백을 학습 데이터 파일에 저장합니다."""
    data = request.get_json()
    question = data.get('question')
    original_answer = data.get('original_answer')
    feedback_answer = data.get('feedback_answer')

    if not all([question, original_answer, feedback_answer]):
        return jsonify({"error": "필수 피드백 데이터가 누락되었습니다."}), 400

    new_entry = {
        "question": question,
        "original_answer": original_answer,
        "learned_answer": feedback_answer
    }

    try:
        learning_data = []
        if os.path.exists(LEARNING_DATA_FILE):
            with open(LEARNING_DATA_FILE, 'r', encoding='utf-8') as f:
                try:
                    learning_data = json.load(f)
                except json.JSONDecodeError:
                    learning_data = []

        learning_data.append(new_entry)

        with open(LEARNING_DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(learning_data, f, ensure_ascii=False, indent=4)

        logging.info(f"새로운 학습 데이터를 저장했습니다: {question[:50]}...")
        return jsonify({"success": True, "message": "피드백이 성공적으로 저장되었습니다."})
    except Exception as e:
        logging.error(f"학습 데이터 저장 중 오류 발생: {e}", exc_info=True)
        return jsonify({"error": "피드백 저장 중 서버 오류가 발생했습니다."}), 500

# --- 서버 실행 ---
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="AI Expert System API Server for Nginx Reverse Proxy")
    parser.add_argument('--llm-url', required=True, help='LLM 서버의 전체 URL')
    parser.add_argument('--model', required=True, help='사용할 LLM 모델 이름')
    parser.add_argument('--token', default=None, help='LLM 서버 API 토큰 (선택 사항)')
    parser.add_argument('--host', default='127.0.0.1', help='API 서버 호스트 주소 (Nginx와 내부 통신용)')
    parser.add_argument('--port', type=int, default=5000, help='API 서버 포트')
    args = parser.parse_args()

    initialize_prompts()

    # 비밀번호 설정 (기존 로직과 동일)
    try:
        password = getpass.getpass("프롬프트 편집용 비밀번호를 설정하세요: ")
        if not password:
            password = 's-core'
            logging.warning("비밀번호가 입력되지 않아 기본값 's-core'로 설정됩니다.")
    except Exception:
        password = 's-core'
        logging.warning("비밀번호를 읽는 데 실패하여 기본값 's-core'로 설정됩니다.")

    CONFIG.update({
        "llm_url": args.llm_url.rstrip('/'),
        "model": args.model,
        "token": args.token,
        "password": password
    })

    logging.info(f"--- AI Expert API Server starting on http://{args.host}:{args.port} ---")
    logging.info("This server should be run behind an Nginx reverse proxy.")
    serve(app, host=args.host, port=args.port)
