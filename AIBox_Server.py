#!/usr/bin/env python3

# -*- coding: utf-8 -*-
# ==============================================================================
# Unified AI Server (v8.1 - Advanced Status Tracking)
# ------------------------------------------------------------------------------
# 기능:
# 1. [CRITICAL FIX] sosreport 분석 상태를 체계적으로 추적하는 기능 추가.
#    - 백그라운드 스레드에서 분석 프로세스를 실행하고 stdout/stderr를 실시간으로 캡처.
#    - 분석 상태를 'queued', 'extracting', 'parsing', 'analyzing', 'complete', 'failed' 등으로 세분화하여 관리.
# 2. [API ENHANCEMENT] '/api/status/<analysis_id>' 엔드포인트를 개선하여
#    단순 완료 여부가 아닌, 상세한 진행 로그와 현재 상태를 반환하도록 수정.
# 3. [STABILITY] 리포트 파일 이름 생성 규칙을 클라이언트(sos_analyzer.py)와 통일하여,
#    리포트 목록 조회 및 삭제 기능의 안정성을 확보.
# ==============================================================================

# --- 1. 라이브러리 임포트 ---
import argparse
import json
import os
import sys
import uuid
import time
import threading
from threading import Lock
import subprocess
import logging
import logging.handlers
from collections import OrderedDict
import traceback
import atexit
import re
import copy

from flask import Flask, request, jsonify, Response, send_from_directory
from flask_cors import CORS
import requests
from werkzeug.utils import secure_filename
from waitress import serve
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from werkzeug.middleware.proxy_fix import ProxyFix

# --- 2. 로깅 및 Flask 앱 설정 ---
class HealthCheckFilter(logging.Filter):
    def filter(self, record):
        return 'GET /api/health' not in record.getMessage()

log = logging.getLogger('werkzeug')
log.addFilter(HealthCheckFilter())
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
CORS(app, resources={r"/AIBox/api/*": {"origins": "*"}})

# --- 3. 전역 변수 및 설정 ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG = {}
PROMPTS = {}
PROMPTS_FILE = os.path.join(SCRIPT_DIR, 'prompts.json')
SERVER_INSTANCE_ID = str(uuid.uuid4())
PROMPT_SEPARATOR = "\n---USER_TEMPLATE---\n"
PROMPT_FILE_MTIME = 0
PROMPT_LOCK = threading.Lock()
UPLOAD_FOLDER = '/data/iso/AIBox/upload'
OUTPUT_FOLDER = '/data/iso/AIBox/output'
SOS_ANALYZER_SCRIPT = "/data/iso/AIBox/sos_analyzer.py"
scheduler = None

# --- [NEW] Advanced Status Tracking ---
ANALYSIS_STATUS = {}
ANALYSIS_LOCK = Lock()
# ------------------------------------

CONTROL_CHAR_REGEX = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024 * 1024 # 100 GB

# --- 4. 핵심 헬퍼 함수 ---

def sanitize_value(value):
    if isinstance(value, str): return CONTROL_CHAR_REGEX.sub('', value)
    return value

def sanitize_loaded_json(data):
    if isinstance(data, dict): return OrderedDict((k, sanitize_loaded_json(v)) for k, v in data.items())
    if isinstance(data, list): return [sanitize_loaded_json(item) for item in data]
    return sanitize_value(data)

# --- [NEW] Background Analysis Task ---
def run_analysis_in_background(file_path, analysis_id):
    """sos_analyzer.py를 백그라운드 스레드에서 실행하고 출력을 캡처합니다."""
    log_key = analysis_id
    
    with ANALYSIS_LOCK:
        ANALYSIS_STATUS[log_key] = {
            "status": "queued",
            "log": ["분석 대기 중..."],
            "report_file": None,
            "start_time": time.time()
        }

    try:
        python_interpreter = "/usr/bin/python3.11"
        server_url = "http://127.0.0.1:5000/AIBox/api/sos/analyze_system"
        output_dir = app.config['OUTPUT_FOLDER']
        report_file_name = f"analysis-report-{analysis_id}.html"

        command = [
            python_interpreter,
            SOS_ANALYZER_SCRIPT,
            "--server-url", server_url,
            "--output", output_dir,
            file_path
        ]
        
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace'
        )

        with ANALYSIS_LOCK:
            ANALYSIS_STATUS[log_key]["status"] = "running"
            ANALYSIS_STATUS[log_key]["log"].append("분석 프로세스 시작됨...")

        # 실시간 stdout 처리
        for line in iter(process.stdout.readline, ''):
            line = line.strip()
            if not line: continue
            
            with ANALYSIS_LOCK:
                # 로그 메시지 기반 상태 업데이트
                if "Extracting" in line:
                    ANALYSIS_STATUS[log_key]["status"] = "extracting"
                elif "parsing" in line:
                    ANALYSIS_STATUS[log_key]["status"] = "parsing"
                elif "Requesting comprehensive analysis" in line:
                    ANALYSIS_STATUS[log_key]["status"] = "analyzing"
                elif "Generating professional HTML report" in line:
                    ANALYSIS_STATUS[log_key]["status"] = "generating_report"
                
                ANALYSIS_STATUS[log_key]["log"].append(line)
        
        process.wait() # 프로세스 종료 대기
        
        stderr_output = process.stderr.read().strip()

        with ANALYSIS_LOCK:
            if process.returncode == 0:
                ANALYSIS_STATUS[log_key]["status"] = "complete"
                ANALYSIS_STATUS[log_key]["log"].append("분석 성공적으로 완료.")
                ANALYSIS_STATUS[log_key]["report_file"] = report_file_name
            else:
                ANALYSIS_STATUS[log_key]["status"] = "failed"
                ANALYSIS_STATUS[log_key]["log"].append("분석 실패.")
                if stderr_output:
                    ANALYSIS_STATUS[log_key]["log"].append("--- ERROR LOG ---")
                    ANALYSIS_STATUS[log_key]["log"].extend(stderr_output.split('\n'))

    except Exception as e:
        with ANALYSIS_LOCK:
            ANALYSIS_STATUS[log_key]["status"] = "failed"
            ANALYSIS_STATUS[log_key]["log"].append(f"서버 내부 오류 발생: {e}")
            traceback.print_exc()

def resolve_chat_endpoint(llm_url, token):
    if llm_url.endswith(('/v1/chat/completions', '/api/chat')): return llm_url
    headers = {'Content-Type': 'application/json'}
    if token: headers['Authorization'] = f'Bearer {token}'
    base_url = llm_url.rstrip('/')
    try:
        if requests.head(f"{base_url}/v1/models", headers=headers, timeout=3).status_code < 500: return f"{base_url}/v1/chat/completions"
    except requests.exceptions.RequestException: pass
    try:
        if requests.head(f"{base_url}/api/tags", headers=headers, timeout=3).status_code < 500: return f"{base_url}/api/chat"
    except requests.exceptions.RequestException: pass
    return None

def get_available_models(llm_url, token):
    headers = {'Content-Type': 'application/json'}
    if token: headers['Authorization'] = f'Bearer {token}'
    try:
        base_url = llm_url.split('/v1/')[0].split('/api/')[0]
        response = requests.get(f"{base_url.rstrip('/')}/v1/models", headers=headers, timeout=10)
        response.raise_for_status()
        return sorted([m.get('id') for m in response.json().get('data', []) if m.get('id')])
    except Exception: pass
    try:
        base_url = llm_url.split('/api/')[0]
        response = requests.get(f"{base_url.rstrip('/')}/api/tags", headers=headers, timeout=10)
        response.raise_for_status()
        return sorted([m.get('name') for m in response.json().get('models', []) if m.get('name')])
    except Exception: return []

def make_request_generic(method, url, **kwargs):
    try:
        kwargs.setdefault('timeout', 20)
        response = requests.request(method, url, **kwargs)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        logging.error(f"Generic request failed for {url}: {e}")
        return None

def _parse_llm_json_response(llm_response_str: str):
    if not llm_response_str or not llm_response_str.strip(): raise ValueError("LLM 응답이 비어 있습니다.")
    try:
        return json.loads(re.sub(r'^```(json)?\s*|\s*```$', '', llm_response_str.strip()))
    except json.JSONDecodeError as e: raise ValueError(f"LLM 응답 JSON 파싱 실패: {e}")

def call_llm_blocking(system_message, user_message, max_tokens=16384):
    headers = {'Content-Type': 'application/json'}
    if CONFIG.get("token"): headers['Authorization'] = f'Bearer {CONFIG["token"]}'
    payload = {"model": CONFIG["model"], "messages": [{"role": "system", "content": system_message}, {"role": "user", "content": user_message}], "max_tokens": max_tokens, "temperature": 0.1, "stream": False}
    
    logging.info(f"[LLM REQ] POST {CONFIG['llm_url']}")

    try:
        response = requests.post(CONFIG["llm_url"], headers=headers, json=payload, timeout=300)
        logging.info(f"[LLM RESP] Status Code: {response.status_code}")
        response.raise_for_status()
        result = response.json()
        content = result.get('choices', [{}])[0].get('message', {}).get('content') or result.get('message', {}).get('content')
        if not content or not content.strip(): 
            return json.dumps({"error": "LLM returned an empty response."})
        return content
    except requests.exceptions.HTTPError as e:
        error_details = f"LLM Server Error: {e}"
        try:
            error_details += f"\nLLM Response Body:\n{e.response.text}"
        except Exception:
            pass
        logging.error(error_details, exc_info=True)
        return json.dumps({"error": "LLM server returned an error.", "details": str(e)})
    except Exception as e:
        logging.error(f"LLM server connection or processing failed: {e}", exc_info=True)
        return json.dumps({"error": "LLM server connection failed.", "details": str(e)})


def call_llm_stream(system_message, user_message):
    headers = {'Content-Type': 'application/json'}
    if CONFIG.get("token"): headers['Authorization'] = f'Bearer {CONFIG["token"]}'
    payload = {"model": CONFIG["model"], "messages": [{"role": "system", "content": system_message}, {"role": "user", "content": user_message}], "max_tokens": 8192, "temperature": 0.2, "stream": True}

    logging.info(f"[LLM STREAM REQ] POST {CONFIG['llm_url']}")

    try:
        response = requests.post(CONFIG["llm_url"], headers=headers, json=payload, timeout=180, stream=True)
        logging.info(f"[LLM STREAM RESP] Status Code: {response.status_code}. Starting stream.")
        response.raise_for_status()

        for line in response.iter_lines():
            if not line: continue
            decoded_line = line.decode('utf-8')
            json_str = decoded_line[len('data: '):].strip() if decoded_line.startswith('data: ') else decoded_line
            if json_str == '[DONE]': 
                logging.info("[LLM STREAM RESP] Stream finished with [DONE].")
                break
            if json_str:
                try:
                    data = json.loads(json_str)
                    content = data.get('choices', [{}])[0].get('delta', {}).get('content') or data.get('message', {}).get('content')
                    if content: yield content
                except (json.JSONDecodeError, KeyError, IndexError) as e:
                    logging.warning(f"[LLM STREAM PARSE WARNING] Skipping line: {e} - Line: '{decoded_line}'")
                    pass
    except Exception as e: 
        logging.error(f"[LLM STREAM ERROR] LLM server communication error: {e}", exc_info=True)
        yield f"\n\n**Error:** LLM server communication error: {e}"

def initialize_and_monitor_prompts():
    def load_prompts(force_reload=False):
        global PROMPTS, PROMPT_FILE_MTIME
        try:
            current_mtime = os.path.getmtime(PROMPTS_FILE)
            if not force_reload and current_mtime == PROMPT_FILE_MTIME: return
            with PROMPT_LOCK:
                if not force_reload and current_mtime == PROMPT_FILE_MTIME: return
                with open(PROMPTS_FILE, 'rb') as f: content = f.read().decode('utf-8-sig')
                start, end = content.find('{'), content.rfind('}')
                if start == -1 or end == -1: raise json.JSONDecodeError("Could not find a valid JSON object", content, 0)
                PROMPTS = sanitize_loaded_json(json.loads(content[start:end+1], object_pairs_hook=OrderedDict))
                PROMPT_FILE_MTIME = current_mtime
        except Exception as e: logging.error(f"Failed to load prompts: {e}", exc_info=True)
    if not os.path.exists(PROMPTS_FILE) or os.path.getsize(PROMPTS_FILE) == 0:
        with open(PROMPTS_FILE, 'w', encoding='utf-8') as f: json.dump(OrderedDict(), f)
    load_prompts(force_reload=True)
    threading.Thread(target=lambda: [time.sleep(5) for _ in iter(int, 1) if not load_prompts()], daemon=True).start()

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
        logging.info(f"Loaded {sync_jobs_from_file()} scheduled jobs from file.")
    except Exception as e: logging.error(f"Failed to start APScheduler: {e}", exc_info=True)
    atexit.register(lambda: scheduler.shutdown())

def run_scheduled_script(script_path):
    log = logging.getLogger('scheduler')
    if not os.path.isfile(script_path):
        log.error(f"Script execution failed: File not found '{script_path}'")
        return
    try:
        process = subprocess.Popen(['/bin/bash', script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
        stdout, stderr = process.communicate()
        log.info(f"Script '{script_path}' executed (Exit Code: {process.returncode}).")
        if stdout: log.info(f"[stdout]:\n{stdout.strip()}")
        if stderr: log.warning(f"[stderr]:\n{stderr.strip()}")
    except Exception as e: log.error(f"Exception during script execution '{script_path}': {e}", exc_info=True)

def sync_jobs_from_file():
    schedule_file = CONFIG.get("schedule_file")
    if not os.path.isfile(schedule_file): return 0
    try:
        with open(schedule_file, 'r', encoding='utf-8') as f: schedules = json.load(f)
        current_job_ids = {job.id for job in scheduler.get_jobs()}
        desired_job_ids = {s['script'] for s in schedules}
        for job_id in current_job_ids - desired_job_ids: scheduler.remove_job(job_id)
        for schedule in schedules:
            hour, minute = schedule['time'].split(':')
            scheduler.add_job(run_scheduled_script, 'cron', args=[schedule['script']], id=schedule['script'], hour=hour, minute=minute, replace_existing=True)
        return len(schedules)
    except Exception: return 0

# --- 5. 웹 페이지 및 API 라우팅 ---
@app.route('/AIBox/')
def route_index(): return send_from_directory(SCRIPT_DIR, 'upload.html')
@app.route('/AIBox/upload.html')
def route_upload_html(): return send_from_directory(SCRIPT_DIR, 'upload.html')
@app.route('/AIBox/user.html')
def route_user(): return send_from_directory(SCRIPT_DIR, 'user.html')
@app.route('/AIBox/admin.html')
def route_admin(): return send_from_directory(SCRIPT_DIR, 'admin.html')
@app.route('/AIBox/cve_report.html')
def route_cve(): return send_from_directory(SCRIPT_DIR, 'cve_report.html')
@app.route('/AIBox/cron.html')
def route_cron(): return send_from_directory(SCRIPT_DIR, 'cron.html')
@app.route('/AIBox/output/<path:filename>')
def route_output(filename): return send_from_directory(app.config['OUTPUT_FOLDER'], filename)

@app.route('/AIBox/api/health', methods=['GET'])
def api_health(): return jsonify({"status": "ok", "instance_id": SERVER_INSTANCE_ID})
@app.route('/AIBox/api/config', methods=['GET'])
def api_config(): return jsonify({"model": CONFIG.get("model", "N/A")})
@app.route('/AIBox/api/models', methods=['GET'])
def api_get_models():
    models = get_available_models(CONFIG["llm_url"], CONFIG.get("token"))
    return jsonify(models) if models else (jsonify({"error": "Could not retrieve models."}), 502)

@app.route('/AIBox/api/verify-password', methods=['POST'])
def api_verify_password():
    return jsonify({"success": request.json.get('password') == CONFIG.get("password")})

@app.route('/AIBox/api/prompts', methods=['GET', 'POST'])
def api_prompts():
    if request.method == 'POST':
        data = request.json
        if data.get('password') != CONFIG.get("password"): return jsonify({"error": "Unauthorized"}), 401
        try:
            prompts = OrderedDict([(item['key'], {"system_message": item['value'].split(PROMPT_SEPARATOR, 1)[0], "user_template": item['value'].split(PROMPT_SEPARATOR, 1)[1] if PROMPT_SEPARATOR in item['value'] else ""}) for item in data.get('prompts', [])])
            with PROMPT_LOCK:
                with open(PROMPTS_FILE, 'w', encoding='utf-8') as f: json.dump(prompts, f, ensure_ascii=False, indent=4)
            return jsonify({"success": True})
        except Exception as e: return jsonify({"error": str(e)}), 500
    else: # GET
        with PROMPT_LOCK:
            prompts = [{"key": k, "value": f"{v.get('system_message', '')}{PROMPT_SEPARATOR}{v.get('user_template', '')}"} for k, v in PROMPTS.items()]
            return Response(json.dumps(prompts, ensure_ascii=False), mimetype='application/json; charset=utf-8')

@app.route('/AIBox/api/analyze', methods=['POST'])
def api_analyze():
    data = request.json
    with PROMPT_LOCK: prompt_config = PROMPTS.get(data.get('prompt_key'), {})
    system_msg = prompt_config.get('system_message', '').replace('{user_query}', data.get('user_query'))
    user_msg = prompt_config.get('user_template', '{user_query}').replace('{user_query}', data.get('user_query'))
    return Response(call_llm_stream(system_msg, user_msg), mimetype='text/plain; charset=utf-8')

@app.route('/AIBox/api/cve/analyze', methods=['POST'])
def api_cve_analyze_for_script():
    try:
        cve_data = request.json
        prompt = f"[CVE Data]\n{json.dumps(cve_data, indent=2, ensure_ascii=False)}\n\n[Task]\nAnalyze and return JSON with keys: 'threat_tags', 'affected_components', 'concise_summary', 'selection_reason'."
        response_str = call_llm_blocking("You are an RHEL security analyst. Return only a single, valid JSON object.", prompt)
        return jsonify(_parse_llm_json_response(response_str))
    except Exception as e:
        logging.error(f"CVE analysis error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/AIBox/api/cve/executive_summary', methods=['POST'])
def api_cve_summary_for_script():
    prompt = f"[Vulnerabilities]\n{json.dumps(request.json.get('top_cves', []), indent=2, ensure_ascii=False)}\n\n[Task]\nWrite a professional Executive Summary in Korean."
    summary = call_llm_blocking("You are a cybersecurity expert.", prompt)
    return Response(summary.replace("\n", "<br>") if summary else "", mimetype='text/html')

@app.route('/AIBox/api/cve/report', methods=['POST'])
def api_cve_report_for_html():
    cve_id = request.json.get('cve_id')
    rh_data = {}
    response = make_request_generic('get', f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json")
    if response: rh_data = response.json()
    prompt = f"Generate a comprehensive Korean Markdown security report for {cve_id} based on this data and web search for recent info/PoCs.\n[Data]\n{json.dumps(rh_data, indent=2)}"
    summary = call_llm_blocking("You are an elite cybersecurity analyst.", prompt)
    final_data = rh_data.copy()
    final_data["comprehensive_summary"] = summary
    return jsonify(final_data)

@app.route('/AIBox/api/schedules', methods=['GET', 'POST'])
def api_schedules():
    schedule_file = CONFIG.get("schedule_file")
    if request.method == 'POST':
        data = request.json
        if data.get('password') != CONFIG.get("password"): return jsonify({"error": "Unauthorized"}), 401
        with open(schedule_file, 'w', encoding='utf-8') as f: json.dump(data.get('schedules', []), f, indent=4)
        sync_jobs_from_file()
        return jsonify({"success": True})
    else: # GET
        if not os.path.isfile(schedule_file): return jsonify([])
        with open(schedule_file, 'r', encoding='utf-8') as f: return jsonify(json.load(f))

@app.route('/AIBox/api/schedules/execute', methods=['POST'])
def api_execute_schedule():
    data = request.json
    if data.get('password') != CONFIG.get("password"): return jsonify({"error": "Unauthorized"}), 401
    threading.Thread(target=run_scheduled_script, args=(data.get('script'),)).start()
    return jsonify({"success": True, "message": f"Execution started for {data.get('script')}"})

@app.route('/AIBox/api/logs/scheduler', methods=['GET', 'DELETE'])
def api_scheduler_logs():
    log_file = CONFIG.get("scheduler_log_file")
    if request.method == 'DELETE':
        if not request.json or request.json.get('password') != CONFIG.get("password"): return jsonify({"error": "Unauthorized"}), 401
        if os.path.isfile(log_file): open(log_file, 'w').close()
        return jsonify({"success": True})
    else: # GET
        if not os.path.isfile(log_file): return jsonify([])
        with open(log_file, 'r', encoding='utf-8') as f: return jsonify(f.readlines()[-100:])

@app.route('/AIBox/api/upload', methods=['POST'])
def api_upload():
    file = request.files.get('sosreportFile')
    if not file: return jsonify({"error": "No file part."}), 400
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    
    base_name = filename
    for ext in ['.tar.gz', '.tgz', '.tar.xz', '.txz', '.tar.bz2', '.tbz2']:
        if base_name.endswith(ext):
            base_name = base_name[:-len(ext)]
            break
    
    analysis_id = base_name

    thread = threading.Thread(target=run_analysis_in_background, args=(file_path, analysis_id))
    thread.daemon = True
    thread.start()

    return jsonify({"message": "Analysis started.", "analysis_id": analysis_id})

@app.route('/AIBox/api/status/<analysis_id>', methods=['GET'])
def api_status(analysis_id):
    with ANALYSIS_LOCK:
        status_data = ANALYSIS_STATUS.get(analysis_id)
    
    if status_data:
        return jsonify(copy.deepcopy(status_data))
    else:
        report_path = os.path.join(app.config['OUTPUT_FOLDER'], f"analysis-report-{secure_filename(analysis_id)}.html")
        if os.path.exists(report_path):
            return jsonify({"status": "complete", "report_file": f"analysis-report-{secure_filename(analysis_id)}.html"})
        return jsonify({"status": "not_found"}), 404

@app.route('/AIBox/api/reports', methods=['GET', 'DELETE'])
def api_reports():
    if request.method == 'DELETE':
        filename = request.args.get('file')
        if not filename: return jsonify({"error": "File parameter is missing"}), 400
        file_path = os.path.join(app.config['OUTPUT_FOLDER'], secure_filename(filename))
        if os.path.exists(file_path):
            os.remove(file_path)
            return jsonify({"success": True})
        return jsonify({"error": "File not found"}), 404
    else: # GET
        try:
            reports = sorted([
                {"name": f, "mtime": os.path.getmtime(os.path.join(OUTPUT_FOLDER, f))}
                for f in os.listdir(OUTPUT_FOLDER)
                if f.startswith('analysis-report-') and f.endswith('.html')
            ], key=lambda r: r['mtime'], reverse=True)
            return jsonify(reports)
        except Exception:
            return jsonify({"error": "리포트 목록을 가져오는 데 실패했습니다."}), 500

@app.route('/AIBox/api/reports/all', methods=['DELETE'])
def api_delete_all_reports():
    try:
        count = sum(1 for f in os.listdir(app.config['OUTPUT_FOLDER']) if f.startswith('analysis-report-') and f.endswith('.html') and os.remove(os.path.join(app.config['OUTPUT_FOLDER'], f)) is None)
        logging.info(f"Deleted {count} report(s).")
        return jsonify({"success": True, "message": f"{count} reports deleted."})
    except Exception as e:
        logging.error(f"Error deleting all reports: {e}", exc_info=True)
        return jsonify({"error": "Failed to delete all reports."}), 500

@app.route('/AIBox/api/sos/analyze_system', methods=['POST'])
def api_sos_analyze_system():
    try:
        data_str = json.dumps(request.json, indent=2, ensure_ascii=False, default=str)
        prompt = f"""You are a top-tier expert in troubleshooting Red Hat Enterprise Linux systems. Based on the detailed data extracted from this sosreport, provide an expert-level diagnosis and solution in Korean.

## Analysis Data
```json
{data_str}
```

## Required JSON Output
Please provide your analysis in a single, valid JSON object with the following structure. Do NOT add any text outside the JSON block.
{{
  "analysis_summary": "A 3-4 sentence comprehensive summary of the system's overall status.",
  "key_issues": [
    {{
      "issue": "The core problem discovered (e.g., 'High memory usage by httpd process').",
      "cause": "A technical analysis of the root cause of the issue.",
      "solution": "Specific, actionable solutions or commands to resolve the issue."
    }}
  ]
}}
"""
        response_str = call_llm_blocking("You are a helpful assistant designed to output only a single valid JSON object.", prompt)
        
        try:
            response_json = json.loads(response_str)
            if 'error' in response_json:
                logging.error(f"LLM analysis failed: {response_json.get('details', 'Unknown error')}")
                return jsonify({"error": "Failed to get analysis from LLM", "details": response_json.get('details')}), 502
        except json.JSONDecodeError:
            pass

        return jsonify(_parse_llm_json_response(response_str))
        
    except Exception as e:
        logging.error(f"/api/sos/analyze_system error: {e}", exc_info=True)
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

# --- 6. 서버 실행 ---
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Unified AI Server", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--llm-url', required=True, help='Full URL for LLM server API')
    parser.add_argument('--model', help='LLM model name')
    parser.add_argument('--list-models', action='store_true', help='List available models and exit')
    parser.add_argument('--token', default=os.getenv('LLM_API_TOKEN'), help='API token for LLM server')
    parser.add_argument('--password', default='s-core', help='Password for admin functions')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind the server to')
    parser.add_argument('--port', type=int, default=5000, help='Port to run the server on')
    parser.add_argument('--schedule-file', default='./schedule.json', help='Path to schedule JSON file')
    parser.add_argument('--scheduler-log-file', default='./scheduler.log', help='Path to scheduler log file')
    args = parser.parse_args()

    def list_available_models(llm_url, token):
        print(f"Fetching models from {llm_url}...")
        models = get_available_models(llm_url, token)
        if models:
            print("Available models:")
            for model in models:
                print(f"- {model}")
        else:
            print("Could not retrieve models.")

    if args.list_models:
        list_available_models(args.llm_url, args.token)
        sys.exit(0)

    CONFIG.update(vars(args))
    
    resolved_llm_url = resolve_chat_endpoint(CONFIG['llm_url'], CONFIG.get('token'))
    if resolved_llm_url: CONFIG['llm_url'] = resolved_llm_url
    else: logging.warning(f"Could not automatically determine API type for '{CONFIG['llm_url']}'.")

    if not args.model:
        models = get_available_models(CONFIG['llm_url'], CONFIG.get('token'))
        if models: CONFIG['model'] = models[0]
        else: parser.error("--model is required as no models could be auto-detected.")

    CONFIG["schedule_file"] = os.path.abspath(args.schedule_file)
    CONFIG["scheduler_log_file"] = os.path.abspath(args.scheduler_log_file)
    
    initialize_and_monitor_prompts()
    setup_scheduler()

    logging.info(f"--- Unified AI Server starting on http://{args.host}:{args.port} ---")
    serve(app, host=args.host, port=args.port, threads=16)

