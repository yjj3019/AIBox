#!/usr/bin/env python3

# -*- coding: utf-8 -*-
# ==============================================================================
# Unified AI Server (v5.0 - Stable Release)
# ------------------------------------------------------------------------------
# 기능:
# 1. AI 채팅 분석 (스트리밍)
# 2. LLM 서버의 사용 가능 모델 목록 조회 기능 (--list-models)
# 3. sosreport 분석 (파일 업로드, 상태 관리)
# 4. 스케줄러 (Python 하위 버전 호환성 문제 해결)
# 5. security.py 연동 API (개별 CVE 분석, 요약 생성)
# 6. cve_report.html 연동 API (종합 CVE 리포트 생성)
# 7. 관리자 페이지 (프롬프트, 스케줄 관리)
# 8. LLM 채팅 엔드포인트 자동 확인 기능 추가
# 9. [수정] CVE 리포트 API를 POST 방식으로 변경하여 404 오류 근본 해결
#
# 실행:
#   - 서버 시작: python AIBox_Server.py --llm-url [LLM_CHAT_API_URL] --model [MODEL_NAME]
#   - 모델 목록 조회: python AIBox_Server.py --llm-url [LLM_BASE_URL] --list-models
# ==============================================================================

# --- 1. 라이브러리 임포트 ---
import argparse
import json
import os
import sys
import uuid
import time
import threading
import subprocess
import logging
import logging.handlers
from collections import OrderedDict
import traceback
import atexit
import re

from flask import Flask, request, jsonify, Response, send_from_directory
from flask_cors import CORS
import requests
from werkzeug.utils import secure_filename
from waitress import serve
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore

# --- 2. 로깅 및 Flask 앱 설정 ---
class HealthCheckFilter(logging.Filter):
    def filter(self, record):
        is_health_check = 'GET /api/health' in record.getMessage()
        return not is_health_check

log = logging.getLogger('werkzeug')
log.addFilter(HealthCheckFilter())
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# --- 3. 전역 변수 및 설정 ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG = {}
PROMPTS = {}
PROMPTS_FILE = os.path.join(SCRIPT_DIR, 'prompts.json')
LEARNING_DATA_FILE = os.path.join(SCRIPT_DIR, 'learning_data.json')
SERVER_INSTANCE_ID = str(uuid.uuid4())
PROMPT_SEPARATOR = "\n---USER_TEMPLATE---\n"
PROMPT_FILE_MTIME = 0
PROMPT_LOCK = threading.Lock()
# Note: These paths are hardcoded for a specific environment.
UPLOAD_FOLDER = '/data/iso/AIBox/upload'
OUTPUT_FOLDER = '/data/iso/AIBox/output'
SOS_ANALYZER_SCRIPT = "/data/iso/AIBox/sos_analyzer.py"
scheduler = None

# 보이지 않는 제어 문자를 제거하기 위한 정규식
CONTROL_CHAR_REGEX = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024 * 1024 # 100 GB

# --- 4. 핵심 헬퍼 함수 ---

def sanitize_value(value):
    """문자열에서 잠재적으로 문제를 일으킬 수 있는 제어 문자를 제거합니다."""
    if isinstance(value, str):
        return CONTROL_CHAR_REGEX.sub('', value)
    return value

def sanitize_loaded_json(data):
    """JSON 객체를 재귀적으로 탐색하며 모든 문자열 값을 정제합니다."""
    if isinstance(data, dict):
        return OrderedDict((k, sanitize_loaded_json(v)) for k, v in data.items())
    elif isinstance(data, list):
        return [sanitize_loaded_json(item) for item in data]
    else:
        return sanitize_value(data)

def resolve_chat_endpoint(llm_url, token):
    if llm_url.endswith(('/v1/chat/completions', '/api/chat')):
        logging.info(f"Provided LLM URL '{llm_url}' is already a full endpoint.")
        return llm_url

    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    
    base_url = llm_url.rstrip('/')
    logging.info(f"Probing for LLM API type at base URL: {base_url}")

    try:
        openai_test_url = f"{base_url}/v1/models"
        response = requests.head(openai_test_url, headers=headers, timeout=3)
        if response.status_code < 500:
            resolved_url = f"{base_url}/v1/chat/completions"
            logging.info(f"OpenAI-compatible API detected. Using endpoint: {resolved_url}")
            return resolved_url
    except requests.exceptions.RequestException:
        logging.info("OpenAI-compatible probe failed. Trying next type.")

    try:
        ollama_test_url = f"{base_url}/api/tags"
        response = requests.head(ollama_test_url, headers=headers, timeout=3)
        if response.status_code < 500:
            resolved_url = f"{base_url}/api/chat"
            logging.info(f"Ollama API detected. Using endpoint: {resolved_url}")
            return resolved_url
    except requests.exceptions.RequestException:
        logging.info("Ollama probe failed.")

    return None

def list_available_models(llm_url, token):
    print(f"Fetching available models from the server at {llm_url}...")
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'

    try:
        base_url = llm_url.split('/v1/')[0].split('/api/')[0]
        models_endpoint = f"{base_url.rstrip('/')}/v1/models"
        
        print(f"--> Trying OpenAI-compatible endpoint: {models_endpoint}")
        response = requests.get(models_endpoint, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        models = sorted([m.get('id') for m in data.get('data', []) if m.get('id')])
        if models:
            print("\n--- Available Models (OpenAI format) ---")
            for model_id in models:
                print(f"  - {model_id}")
            return
    except requests.exceptions.RequestException as e:
        print(f"    [INFO] Could not connect to OpenAI-compatible endpoint: {e}")
    except (json.JSONDecodeError, KeyError) as e:
        print(f"    [INFO] Failed to parse response from OpenAI-compatible endpoint: {e}")

    try:
        base_url = llm_url.split('/api/')[0]
        models_endpoint = f"{base_url.rstrip('/')}/api/tags"

        print(f"--> Trying Ollama-compatible endpoint: {models_endpoint}")
        response = requests.get(models_endpoint, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        models = sorted([m.get('name') for m in data.get('models', []) if m.get('name')])
        if models:
            print("\n--- Available Models (Ollama format) ---")
            for model_name in models:
                print(f"  - {model_name}")
            return
    except requests.exceptions.RequestException as e:
        print(f"    [INFO] Could not connect to Ollama-compatible endpoint: {e}")
    except (json.JSONDecodeError, KeyError) as e:
        print(f"    [INFO] Failed to parse response from Ollama-compatible endpoint: {e}")

    print("\n[ERROR] Could not retrieve any models. Please verify your --llm-url and ensure the server is running.")

def make_request_generic(method, url, **kwargs):
    try:
        kwargs.setdefault('timeout', 20)
        response = requests.request(method, url, **kwargs)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        logging.error(f"Generic request failed for {url}: {e}")
        return None

def call_llm_blocking(system_message, user_message):
    headers = {'Content-Type': 'application/json'}
    if CONFIG.get("token"): headers['Authorization'] = f'Bearer {CONFIG["token"]}'
    
    llm_endpoint_url = CONFIG["llm_url"]
    payload = {"model": CONFIG["model"], "messages": [{"role": "system", "content": system_message}, {"role": "user", "content": user_message}], "max_tokens": 4096, "temperature": 0.1, "stream": False}
    try:
        response = requests.post(llm_endpoint_url, headers=headers, json=payload, timeout=180)
        response.raise_for_status()
        result = response.json()
        
        content = result.get('choices', [{}])[0].get('message', {}).get('content')
        if content is None: content = result.get('message', {}).get('content')
        return content

    except requests.exceptions.RequestException as e:
        return f"Error: LLM 서버 연결 실패. (Endpoint: {llm_endpoint_url}, Details: {e})"
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        return f"Error: LLM 응답을 파싱할 수 없습니다. (Details: {e})"

def call_llm_stream(system_message, user_message):
    headers = {'Content-Type': 'application/json'}
    if CONFIG.get("token"): headers['Authorization'] = f'Bearer {CONFIG["token"]}'
    
    llm_endpoint_url = CONFIG["llm_url"]
    payload = {"model": CONFIG["model"], "messages": [{"role": "system", "content": system_message}, {"role": "user", "content": user_message}], "max_tokens": 8192, "temperature": 0.2, "stream": True}
    try:
        response = requests.post(llm_endpoint_url, headers=headers, json=payload, timeout=180, stream=True)
        response.raise_for_status()
        
        for line in response.iter_lines():
            if not line: continue
            decoded_line = line.decode('utf-8')
            json_str = decoded_line
            if decoded_line.startswith('data: '):
                json_str = decoded_line[len('data: '):].strip()
            if json_str == '[DONE]': break

            if json_str:
                try:
                    data = json.loads(json_str)
                    content = data.get('choices', [{}])[0].get('delta', {}).get('content')
                    if content is None: content = data.get('message', {}).get('content')
                    if content: yield content
                except (json.JSONDecodeError, KeyError, IndexError):
                    pass
                    
    except requests.exceptions.RequestException as e:
        yield (f"\n\n**Error:** LLM 서버 연결 실패.\n- Endpoint: {llm_endpoint_url}\n- Details: {e}")
    except Exception as e:
        yield f"\n\n**Error:** 스트리밍 중 알 수 없는 오류 발생: {e}"

def initialize_and_monitor_prompts():
    def load_prompts(force_reload=False):
        global PROMPTS, PROMPT_FILE_MTIME
        try:
            current_mtime = os.path.getmtime(PROMPTS_FILE)
            if not force_reload and current_mtime == PROMPT_FILE_MTIME:
                return

            with PROMPT_LOCK:
                if not force_reload and current_mtime == PROMPT_FILE_MTIME:
                    return
                
                logging.info(f"Attempting to reload prompts from '{PROMPTS_FILE}'.")
                
                with open(PROMPTS_FILE, 'rb') as f:
                    raw_data = f.read()
                
                try:
                    content = raw_data.decode('utf-8-sig')
                except UnicodeDecodeError:
                    content = raw_data.decode('utf-8', errors='ignore')

                start_brace_index = content.find('{')
                end_brace_index = content.rfind('}')

                if start_brace_index == -1 or end_brace_index == -1 or end_brace_index < start_brace_index:
                    raise json.JSONDecodeError("Could not find valid JSON object boundaries '{{...}}'.", content, 0)

                json_content = content[start_brace_index : end_brace_index + 1]

                loaded_json = json.loads(json_content, object_pairs_hook=OrderedDict)
                PROMPTS = sanitize_loaded_json(loaded_json)
                
                PROMPT_FILE_MTIME = current_mtime
                logging.info(f"Successfully sanitized and reloaded prompts from '{PROMPTS_FILE}'.")

        except FileNotFoundError:
            logging.warning(f"Prompt file not found at '{PROMPTS_FILE}'. A default will be created.")
            pass
        except json.JSONDecodeError as e:
            logging.critical(f"CRITICAL: Failed to parse JSON from '{PROMPTS_FILE}'. The file is likely corrupted. Error: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred while loading prompts: {e}", exc_info=True)

    default_prompts = OrderedDict([("시스템 문제 해결 전문가", {"system_message": "당신은 20년 경력의 RHCA입니다...", "user_template": "질문: {user_query}"})])
    if not os.path.exists(PROMPTS_FILE) or os.path.getsize(PROMPTS_FILE) == 0:
        with open(PROMPTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(default_prompts, f, ensure_ascii=False, indent=4)
    
    load_prompts(force_reload=True)
    
    def monitor_loop():
        while True:
            time.sleep(5)
            load_prompts()

    monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
    monitor_thread.start()

def setup_scheduler():
    global scheduler
    jobstores = {'default': SQLAlchemyJobStore(url=f'sqlite:///{os.path.join(SCRIPT_DIR, "jobs.sqlite")}')}
    scheduler = BackgroundScheduler(jobstores=jobstores, timezone='Asia/Seoul')
    
    logger = logging.getLogger('scheduler')
    logger.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler(CONFIG["scheduler_log_file"], maxBytes=1024*1024, backupCount=5)
    logger.addHandler(handler)

    try:
        scheduler.start()
        logging.info("APScheduler 시작 완료.")
        jobs_loaded = sync_jobs_from_file()
        logging.info(f"파일에서 {jobs_loaded}개의 스케줄 작업을 로드했습니다.")
    except Exception as e:
        logging.error(f"APScheduler 시작 실패: {e}", exc_info=True)
    atexit.register(lambda: scheduler.shutdown())

def run_scheduled_script(script_path):
    """
    Executes a shell script and logs its output.
    This function is now compatible with older Python versions (3.6+).
    """
    log = logging.getLogger('scheduler')
    log.info(f"Attempting to execute script: {script_path}")
    
    if not os.path.isfile(script_path):
        log.error(f"Script execution failed: File not found at '{script_path}'")
        return

    try:
        process = subprocess.Popen(
            ['/bin/bash', script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True, # For Python < 3.7 compatibility
            encoding='utf-8'
        )
        
        stdout, stderr = process.communicate()
        
        log.info(f"Script '{script_path}' finished with exit code {process.returncode}.")
        if stdout:
            log.info(f"[stdout] for {script_path}:\n{stdout.strip()}")
        if stderr:
            log.warning(f"[stderr] for {script_path}:\n{stderr.strip()}")
            
    except Exception as e:
        log.error(f"An exception occurred while trying to run script '{script_path}': {e}", exc_info=True)


def sync_jobs_from_file():
    schedule_file = CONFIG.get("schedule_file")
    if not os.path.isfile(schedule_file): return 0
    try:
        with open(schedule_file, 'r', encoding='utf-8') as f: schedules = json.load(f)
    except Exception: return 0
    
    current_job_ids = {job.id for job in scheduler.get_jobs()}
    desired_job_ids = {s['script'] for s in schedules}
    
    for job_id in current_job_ids - desired_job_ids:
        scheduler.remove_job(job_id)
        
    for schedule in schedules:
        hour, minute = schedule['time'].split(':')
        scheduler.add_job(run_scheduled_script, 'cron', args=[schedule['script']], id=schedule['script'], hour=hour, minute=minute, replace_existing=True)
    return len(schedules)

# --- 5. 웹 페이지 및 API 라우팅 ---
@app.before_request
def log_request_info():
    if '/api/health' not in request.path:
        logging.info(f"Request ===> Path: {request.path}, Method: {request.method}, From: {request.remote_addr}")

@app.route('/')
def route_index_user(): return send_from_directory(SCRIPT_DIR, 'user.html')
@app.route('/admin')
def route_admin(): return send_from_directory(SCRIPT_DIR, 'admin.html')
@app.route('/cve')
def route_cve(): return send_from_directory(SCRIPT_DIR, 'cve_report.html')
@app.route('/cron')
def route_cron(): return send_from_directory(SCRIPT_DIR, 'cron.html')
@app.route('/output/<path:filename>')
def route_output(filename): return send_from_directory(app.config['OUTPUT_FOLDER'], filename)

@app.route('/api/health', methods=['GET'])
def api_health(): return jsonify({"status": "ok", "instance_id": SERVER_INSTANCE_ID})

@app.route('/api/config', methods=['GET'])
def api_config(): return jsonify({"model": CONFIG.get("model", "N/A")})

@app.route('/api/verify-password', methods=['POST'])
def api_verify_password():
    if request.json.get('password') == CONFIG.get("password"):
        return jsonify({"success": True})
    return jsonify({"success": False}), 401

@app.route('/api/prompts', methods=['GET'])
def api_get_prompts():
    with PROMPT_LOCK:
        try:
            data_to_send = [
                {"key": k, "value": f"{v.get('system_message', '')}{PROMPT_SEPARATOR}{v.get('user_template', '')}"}
                for k, v in PROMPTS.items()
            ]
            json_string = json.dumps(data_to_send, ensure_ascii=False)
            return Response(json_string, mimetype='application/json; charset=utf-8')
        except Exception as e:
            logging.error(f"Error while creating prompts response: {e}")
            return jsonify({"error": "Failed to serialize prompts"}), 500

@app.route('/api/update-prompts', methods=['POST'])
def api_update_prompts():
    data = request.json
    if data.get('password') != CONFIG.get("password"): return jsonify({"error": "Unauthorized"}), 401
    try:
        prompts_to_save = OrderedDict()
        for key, value in data.get('prompts', {}).items():
            parts = value.split(PROMPT_SEPARATOR, 1)
            prompts_to_save[key] = {"system_message": parts[0], "user_template": parts[1] if len(parts) > 1 else ""}
        with PROMPT_LOCK:
            with open(PROMPTS_FILE, 'w', encoding='utf-8') as f:
                json.dump(prompts_to_save, f, ensure_ascii=False, indent=4)
        return jsonify({"success": True})
    except Exception as e:
        logging.error(f"Error while updating prompts: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    data = request.json
    prompt_key, user_query = data.get('prompt_key'), data.get('user_query')
    with PROMPT_LOCK:
        prompt_config = PROMPTS.get(prompt_key, {})
    
    system_msg = prompt_config.get('system_message', '').replace('{user_query}', user_query)
    user_msg = prompt_config.get('user_template', '{user_query}').replace('{user_query}', user_query)
    
    return Response(call_llm_stream(system_msg, user_msg), mimetype='text/plain; charset=utf-8')

@app.route('/api/learn', methods=['POST'])
def api_learn():
    data = request.json
    try:
        current_data = []
        if os.path.exists(LEARNING_DATA_FILE):
            with open(LEARNING_DATA_FILE, 'r', encoding='utf-8') as f: current_data = json.load(f)
        current_data.append(data)
        with open(LEARNING_DATA_FILE, 'w', encoding='utf-8') as f: json.dump(current_data, f, ensure_ascii=False, indent=4)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/cve/analyze', methods=['POST'])
def api_cve_analyze_for_script():
    cve_data = request.json
    prompt = f"[CVE Data]\n{json.dumps(cve_data, indent=2, ensure_ascii=False)}\n\n[Task]\nAnalyze and return JSON with keys: 'threat_tags', 'affected_components', 'concise_summary', 'selection_reason'."
    system_prompt = "You are an RHEL security analyst. Return only a single, valid JSON object."
    response_str = call_llm_blocking(system_prompt, prompt)
    try:
        match = re.search(r'\{.*\}', response_str, re.DOTALL)
        if match:
            return jsonify(json.loads(match.group(0)))
        else:
            raise ValueError("No JSON object found in LLM response")
    except (json.JSONDecodeError, AttributeError, ValueError) as e:
        logging.error(f"Failed to parse LLM JSON response for CVE analyze: {e}\nResponse was: {response_str}")
        return jsonify({"error": "LLM response parsing failed"}), 500

@app.route('/api/cve/executive_summary', methods=['POST'])
def api_cve_summary_for_script():
    top_cves = request.json.get('top_cves', [])
    prompt = f"[Vulnerabilities]\n{json.dumps(top_cves, indent=2, ensure_ascii=False)}\n\n[Task]\nWrite a professional Executive Summary in Korean."
    summary = call_llm_blocking("You are a cybersecurity expert.", prompt)
    return Response(summary.replace("\n", "<br>") if summary else "", mimetype='text/html')

# [수정] 404 오류의 근본적 해결을 위해 API 통신 방식을 POST로 변경
@app.route('/api/cve/report', methods=['POST'])
def api_cve_report_for_html():
    """
    Handles CVE report generation.
    Receives CVE ID in the JSON body of a POST request.
    This method is more robust than using dynamic URL paths.
    """
    data = request.get_json()
    if not data or 'cve_id' not in data:
        return jsonify({"error": "cve_id must be provided in the request body"}), 400
    
    cve_id = data['cve_id']
    logging.info(f"Received report request for CVE: {cve_id}")

    rh_data = {}
    response = make_request_generic('get', f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json")
    if response: rh_data = response.json()
    
    prompt = f"Generate a comprehensive security report for {cve_id}.\n[Baseline Data]\n{json.dumps(rh_data, indent=2) if rh_data else 'N/A'}\n\n[Instructions]\nAnalyze, web search for recent info/PoCs, and generate a Korean Markdown report with sections: '### 1. 위협 개요', '### 2. 주요 위협 및 영향도', '### 3. 권고 조치 및 완화 방안'."
    summary = call_llm_blocking("You are an elite cybersecurity analyst.", prompt)
    
    # 병합 후 반환
    final_data = rh_data.copy()
    final_data["comprehensive_summary"] = summary
    return jsonify(final_data)


@app.route('/api/upload', methods=['POST'])
def api_upload():
    file = request.files.get('sosreportFile')
    if not file: return jsonify({"error": "No file part."}), 400
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    analysis_id = filename.replace('.tar.xz', '')
    command = ["python3", SOS_ANALYZER_SCRIPT, "--llm-url", CONFIG["llm_url"], "--model", CONFIG["model"], file_path]
    if CONFIG.get("token"): command.extend(["--api-token", CONFIG["token"]])
    subprocess.Popen(command)
    return jsonify({"message": "Analysis started.", "analysis_id": analysis_id})

@app.route('/api/status/<analysis_id>', methods=['GET'])
def api_status(analysis_id):
    if os.path.exists(os.path.join(app.config['OUTPUT_FOLDER'], f"{analysis_id}_report.html")):
        return jsonify({"status": "complete"})
    return jsonify({"status": "running"})

@app.route('/api/reports', methods=['GET'])
def api_list_reports():
    files = [f for f in os.listdir(OUTPUT_FOLDER) if f.endswith('_report.html')]
    return jsonify(sorted(files, key=lambda f: os.path.getmtime(os.path.join(OUTPUT_FOLDER, f)), reverse=True))

@app.route('/api/schedules', methods=['GET'])
def api_get_schedules():
    schedule_file = CONFIG.get("schedule_file")
    if not os.path.isfile(schedule_file): return jsonify([])
    with open(schedule_file, 'r', encoding='utf-8') as f: return jsonify(json.load(f))

@app.route('/api/schedules', methods=['POST'])
def api_update_schedules():
    data = request.json
    if data.get('password') != CONFIG.get("password"): return jsonify({"error": "Unauthorized"}), 401
    with open(CONFIG.get("schedule_file"), 'w', encoding='utf-8') as f: json.dump(data.get('schedules', []), f, indent=4)
    sync_jobs_from_file()
    return jsonify({"success": True})

@app.route('/api/schedules/execute', methods=['POST'])
def api_execute_schedule():
    data = request.json
    if data.get('password') != CONFIG.get("password"): return jsonify({"error": "Unauthorized"}), 401
    script_path = data.get('script')
    threading.Thread(target=run_scheduled_script, args=(script_path,)).start()
    return jsonify({"success": True, "message": f"Execution started for {script_path}"})

@app.route('/api/logs/scheduler', methods=['GET', 'DELETE'])
def api_scheduler_logs():
    """
    Handles scheduler logs:
    - GET: Returns the last 100 lines of the log.
    - DELETE: Clears the entire log file.
    """
    log_file = CONFIG.get("scheduler_log_file")

    if request.method == 'DELETE':
        if not request.json or request.json.get('password') != CONFIG.get("password"):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            if os.path.isfile(log_file):
                with open(log_file, 'w') as f:
                    f.truncate(0)
                logging.info(f"Scheduler log file '{log_file}' was cleared by user request.")
            return jsonify({"success": True, "message": "Logs cleared successfully."})
        except Exception as e:
            logging.error(f"Failed to clear log file '{log_file}': {e}", exc_info=True)
            return jsonify({"error": "Failed to clear logs"}), 500

    if not os.path.isfile(log_file):
        return jsonify([])
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            return jsonify(f.readlines()[-100:])
    except Exception as e:
        logging.error(f"Could not read scheduler log file '{log_file}': {e}")
        return jsonify({"error": "Could not read log file"}), 500


# --- 7. 서버 실행 ---
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Unified AI Server",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--llm-url', help='Full URL for LLM server API (e.g., http://host/api/chat or http://host/v1)')
    parser.add_argument('--model', help='LLM model name (required unless --list-models is used)')
    parser.add_argument('--list-models', action='store_true', help='List available models from the LLM server and exit')
    
    parser.add_argument('--token', default=None, help='API token for the LLM server, if required')
    parser.add_argument('--password', default='s-core', help='Password for admin functions')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind the server to')
    parser.add_argument('--port', type=int, default=5000, help='Port to run the server on')
    parser.add_argument('--schedule-file', default='./schedule.json', help='Path to the schedule JSON file')
    parser.add_argument('--scheduler-log-file', default='./scheduler.log', help='Path to the scheduler log file')
    args = parser.parse_args()

    if args.list_models:
        if not args.llm_url:
            print("[ERROR] The --llm-url argument is required to list models.", file=sys.stderr)
            sys.exit(1)
        list_available_models(args.llm_url, args.token)
        sys.exit(0)

    if not args.llm_url or not args.model:
        parser.error("The --llm-url and --model arguments are required to start the server.")

    CONFIG.update(vars(args))
    
    original_llm_url = CONFIG['llm_url']
    resolved_llm_url = resolve_chat_endpoint(original_llm_url, CONFIG.get('token'))
    
    if resolved_llm_url:
        CONFIG['llm_url'] = resolved_llm_url
    else:
        logging.warning(f"Could not automatically determine API type for '{original_llm_url}'. Using the URL as is. If you see connection errors, please provide the full chat completions endpoint (e.g., http://host:port/v1/chat/completions).")

    CONFIG["schedule_file"] = os.path.abspath(args.schedule_file)
    CONFIG["scheduler_log_file"] = os.path.abspath(args.scheduler_log_file)
    
    initialize_and_monitor_prompts()
    setup_scheduler()

    logging.info(f"--- Unified AI Server starting on http://{args.host}:{args.port} ---")
    logging.info(f"Using LLM model '{args.model}' via endpoint '{CONFIG['llm_url']}'")
    serve(app, host=args.host, port=args.port)

