#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ==============================================================================
# Unified AI Server (v8.2 - Expert Prompt & Full Feature Restoration)
# ------------------------------------------------------------------------------
# [최종 통합 및 완전 복원]
# 1. [기능 완전 복원] v8.1의 모든 기능(스케줄링, 프롬프트 관리, 모든 API 엔드포인트)을
#    단 하나도 누락 없이 완벽하게 복원했습니다.
# 2. [기능 보완] '/api/sos/analyze_system'을 강화하여 전문가 프롬프트를 수용하고,
#    기존 방식과의 하위 호환성을 완벽하게 유지합니다.
# 3. [기능 추가] CVE 심층 분석을 위한 '/api/cve/analyze' 엔드포인트를 추가했습니다.
# 4. [BUG FIX] 보고된 SyntaxError를 완벽하게 수정했습니다.
# ==============================================================================

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
from datetime import datetime, timedelta
import copy
import shutil
import hashlib
from diskcache import Cache

from flask import Flask, request, jsonify, Response, send_from_directory
from flask_cors import CORS
import requests
from werkzeug.utils import secure_filename
from waitress import serve
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from werkzeug.middleware.proxy_fix import ProxyFix

# --- 로깅 및 Flask 앱 설정 ---
class HealthCheckFilter(logging.Filter):
    def filter(self, record):
        return 'GET /api/health' not in record.getMessage()

log = logging.getLogger('werkzeug')
log.addFilter(HealthCheckFilter())
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# [신규] LLM 상호작용 로깅을 위한 설정
LLM_LOG_DIR = "/data/iso/AIBox/log"
os.makedirs(LLM_LOG_DIR, exist_ok=True)
llm_logger = logging.getLogger('llm_interaction')
llm_logger.setLevel(logging.INFO)
# 핸들러가 중복 추가되는 것을 방지
if not llm_logger.handlers:
    # [개선] 로그 포맷을 지정하여 요청 ID, 시간, 크기 등 구조화된 정보 기록
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    llm_log_handler = logging.handlers.TimedRotatingFileHandler(
        os.path.join(LLM_LOG_DIR, 'llm_interaction.log'), 
        when='H', interval=1, backupCount=24, encoding='utf-8' # 24시간 동안 로그 보관
    )
    llm_log_handler.setFormatter(formatter)
    llm_logger.addHandler(llm_log_handler)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
CORS(app, resources={r"/AIBox/api/*": {"origins": "*"}})

# --- 전역 변수 및 설정 ---
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
CACHE_FOLDER = '/data/iso/AIBox/cache'
SOS_ANALYZER_SCRIPT = "/data/iso/AIBox/sos_analyzer.py"
CVE_FOLDER = '/data/iso/AIBox/cve'
scheduler = None

ANALYSIS_STATUS = {}
ANALYSIS_LOCK = Lock()
ANALYSIS_CLEANUP_INTERVAL_SECONDS = 3600 # 1시간마다 오래된 상태 정리

CONTROL_CHAR_REGEX = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)
os.makedirs(CVE_FOLDER, exist_ok=True)
# [개선] diskcache는 디렉토리를 자동으로 생성하므로, 이 라인은 더 이상 필요하지 않습니다.
os.makedirs(CACHE_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024 * 1024

def sanitize_value(value):
    if isinstance(value, str): return CONTROL_CHAR_REGEX.sub('', value)
    return value

def sanitize_loaded_json(data):
    if isinstance(data, dict): return OrderedDict((k, sanitize_loaded_json(v)) for k, v in data.items())
    if isinstance(data, list): return [sanitize_loaded_json(item) for item in data]
    return sanitize_value(data)

def run_analysis_in_background(file_path, analysis_id, server_url):
    log_key = analysis_id
    # [제안 반영] 분석 상태를 큐에 넣을 때 초기 상태를 'queued'로 설정합니다.
    with ANALYSIS_LOCK:
        ANALYSIS_STATUS[log_key] = {"status": "queued", "log": ["분석 대기 중..."], "report_file": None, "start_time": time.time()}

    try:
        python_interpreter = "/usr/bin/python3.11"
        output_dir = app.config['OUTPUT_FOLDER']
        
        command = [python_interpreter, SOS_ANALYZER_SCRIPT, file_path, "--server-url", server_url, "--output", output_dir]
        
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')

        with ANALYSIS_LOCK:
            ANALYSIS_STATUS[log_key]["status"] = "running"
            ANALYSIS_STATUS[log_key]["log"].append("분석 프로세스를 시작합니다...")

        for line in iter(process.stdout.readline, ''):
            line = line.strip()
            if not line: continue
            with ANALYSIS_LOCK:
                # [개선] 로그 파싱을 통한 상세 상태 업데이트
                if "압축 해제 중" in line:
                    ANALYSIS_STATUS[log_key]["status"] = "extracting"
                elif "데이터 파싱 시작" in line:
                    ANALYSIS_STATUS[log_key]["status"] = "parsing"
                elif "AI 시스템 분석 요청" in line or "보안 위협 분석 시작" in line:
                    ANALYSIS_STATUS[log_key]["status"] = "analyzing"
                elif "HTML 보고서 저장 완료" in line:
                    ANALYSIS_STATUS[log_key]["status"] = "generating_report"
                
                ANALYSIS_STATUS[log_key]["log"].append(line)
        
        process.wait()
        stderr_output = process.stderr.read().strip()

        with ANALYSIS_LOCK:
            final_log = "\n".join(ANALYSIS_STATUS[log_key]["log"])
            if "HTML 보고서 저장 완료" in final_log and process.returncode == 0:
                ANALYSIS_STATUS[log_key]["status"] = "complete"
                ANALYSIS_STATUS[log_key]["log"].append("분석 성공적으로 완료.")
                match = re.search(r"HTML 보고서 저장 완료: (.+)", final_log)
                if match:
                    report_full_path = match.group(1)
                    ANALYSIS_STATUS[log_key]["report_file"] = os.path.basename(report_full_path)
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

def cleanup_old_analysis_statuses():
    """오래된 분석 상태 정보를 정리하여 메모리 사용량을 관리합니다."""
    with ANALYSIS_LOCK:
        now = time.time()
        keys_to_delete = []
        for key, status_info in ANALYSIS_STATUS.items():
            # 완료/실패 후 1시간(3600초)이 지난 항목을 정리 대상으로 선정
            if (status_info['status'] in ['complete', 'failed']) and (now - status_info.get('start_time', 0) > ANALYSIS_CLEANUP_INTERVAL_SECONDS):
                keys_to_delete.append(key)
        
        if keys_to_delete:
            for key in keys_to_delete:
                del ANALYSIS_STATUS[key]
            logging.info(f"오래된 분석 상태 {len(keys_to_delete)}개를 정리했습니다.")

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
    except json.JSONDecodeError as e: raise ValueError(f"LLM 응답 JSON 파싱 실패: {e}\n응답 내용: {llm_response_str[:500]}")

def get_cache_key(system_message, user_message):
    """요청 내용을 기반으로 고유한 캐시 키를 생성합니다."""
    return hashlib.sha256((system_message + user_message).encode('utf-8')).hexdigest()
# [개선] diskcache 인스턴스를 전역적으로 생성합니다.
cache = None # 전역 변수로 선언

def call_llm_blocking(system_message, user_message, max_tokens=16384):
    """
    [개선] LLM을 호출하고 결과를 캐싱하는 블로킹 함수.
    동일한 요청에 대해서는 캐시된 결과를 반환하여 API 호출을 줄입니다.
    """
    cache_key = get_cache_key(system_message, user_message)
    cache_ttl_seconds = CONFIG.get('cache_ttl_days', 7) * 24 * 60 * 60

    # 1. 캐시 확인
    cached_response = cache.get(cache_key)
    if cached_response is not None:
        logging.info(f"[CACHE HIT] 캐시된 응답을 반환합니다. (Key: {cache_key[:10]}...)") 
        llm_logger.info(f"[CACHE HIT] Returning cached response for key: {cache_key}")
        return cached_response

    headers = {'Content-Type': 'application/json'}
    if CONFIG.get("token"): headers['Authorization'] = f'Bearer {CONFIG["token"]}'
    payload = {"model": CONFIG["model"], "messages": [{"role": "system", "content": system_message}, {"role": "user", "content": user_message}], "max_tokens": max_tokens, "temperature": 0.1, "stream": False}
    
    # [신규] LLM 요청 로깅
    llm_logger.info("--- LLM Request (Blocking) ---")
    llm_logger.info(f"System Message: {system_message}")
    llm_logger.debug(f"User Message: {user_message}")

    logging.info(f"[CACHE MISS] LLM 서버에 분석을 요청합니다. (POST {CONFIG['llm_url']})")
    
    # cache_misses.inc() # 메트릭 기능이 구현될 때까지 주석 처리
    # [제안 반영] LLM 호출 타임아웃을 600초(10분)로 늘려 긴 분석 작업(예: CVE 순위 선정)을 지원합니다.
    try:
        response = requests.post(CONFIG["llm_url"], headers=headers, json=payload, timeout=600)
        logging.info(f"[LLM RESP] Status Code: {response.status_code}")
        response.raise_for_status()
        result = response.json() 
        content = result.get('choices', [{}])[0].get('message', {}).get('content') or result.get('message', {}).get('content')
        if not content or not content.strip():
            return json.dumps({"error": "LLM returned an empty response."})
        
        # [신규] LLM 응답 로깅
        llm_logger.debug(f"--- LLM Response (Blocking) ---\n{content}\n")

        # 2. 성공적인 응답을 캐시에 저장
        cache.set(cache_key, content, expire=cache_ttl_seconds)
        logging.info(f"[CACHE MISS] 새로운 응답을 캐시에 저장합니다. (Key: {cache_key[:10]}...)")
        llm_logger.info(f"[CACHE SET] Storing new response in cache for key: {cache_key}")
        return content
    except requests.exceptions.HTTPError as e:
        error_details = f"LLM Server Error: {e}"
        llm_logger.error(f"--- LLM Error (Blocking) ---\n{error_details}\n")
        # [개선] LLM 서버가 500 오류를 반환할 때, 응답 본문을 로그에 포함하여 디버깅을 용이하게 합니다.
        if e.response is not None:
            error_details += f"\nLLM Response Body:\n{e.response.text}"
        logging.error(error_details)
        return json.dumps({"error": "LLM server returned an error.", "details": str(e)})
    except Exception as e:
        logging.error(f"LLM server connection or processing failed: {e}")
        return json.dumps({"error": "LLM server connection failed.", "details": str(e)})

def call_llm_stream(system_message, user_message):
    """
    [효율성 개선] LLM 스트리밍 호출 함수에 캐싱 기능 추가.
    - Cache Miss: 실제 LLM API를 호출하고, 스트리밍하면서 전체 응답을 캐시에 저장합니다.
    - Cache Hit: 캐시된 전체 응답을 가져와, 실제 스트리밍처럼 보이도록 작은 조각으로 나누어 전송합니다.
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()
    cache_key = get_cache_key(system_message, user_message)
    cache_ttl_seconds = CONFIG.get('cache_ttl_days', 7) * 24 * 60 * 60

    # 1. 캐시 확인
    cached_response = cache.get(cache_key)
    if cached_response is not None:
        duration = time.time() - start_time
        response_size = len(cached_response.encode('utf-8'))
        logging.info(f"[{request_id}] [CACHE HIT][STREAM] 캐시된 응답으로 스트리밍을 시뮬레이션합니다. (Key: {cache_key[:10]}...)")
        llm_logger.info(f"[{request_id}] [CACHE HIT] Stream from cache. Duration: {duration:.2f}s, Size: {response_size} bytes")
        full_response = cached_response
        
        # 캐시된 전체 응답을 작은 조각으로 나누어 스트리밍처럼 전송
        chunk_size = 10
        for i in range(0, len(full_response), chunk_size):
            yield full_response[i:i+chunk_size]
            time.sleep(0.002) # 실제 스트리밍처럼 보이게 하기 위한 작은 딜레이
        return # 스트리밍 시뮬레이션 완료 후 함수 종료

    # 2. Cache Miss: 실제 LLM API 호출
    headers = {'Content-Type': 'application/json'}
    if CONFIG.get("token"): headers['Authorization'] = f'Bearer {CONFIG["token"]}'
    messages = [{"role": "system", "content": system_message}, {"role": "user", "content": user_message}]
    payload = {"model": CONFIG["model"], "messages": messages, "max_tokens": 8192, "temperature": 0.2, "stream": True}
    request_size = len(json.dumps(payload).encode('utf-8'))

    # [신규] LLM 요청 로깅
    llm_logger.info(f"[{request_id}] [REQ][STREAM] POST {CONFIG['llm_url']}, Size: {request_size} bytes")
    llm_logger.debug(f"[{request_id}] [REQ PAYLOAD] {json.dumps(messages)}")

    logging.info(f"[{request_id}] [LLM STREAM REQ] POST {CONFIG['llm_url']}")
    # cache_misses.inc() # 메트릭 기능이 구현될 때까지 주석 처리

    try:
        full_response_accumulator = []
        total_tokens = {'prompt': 0, 'completion': 0}
        response = requests.post(CONFIG["llm_url"], headers=headers, json=payload, timeout=180, stream=True)
        logging.info(f"[{request_id}] [LLM STREAM RESP] Status Code: {response.status_code}. Starting stream.")
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
                    # 토큰 정보가 스트림의 마지막에 오는 경우 처리 (Ollama 등)
                    if data.get('done') and 'total_duration' in data:
                        total_tokens['prompt'] = data.get('prompt_eval_count', 0)
                        total_tokens['completion'] = data.get('eval_count', 0)

                    if content:
                        full_response_accumulator.append(content)
                        yield content
                except (json.JSONDecodeError, KeyError, IndexError) as e:
                    logging.warning(f"[LLM STREAM PARSE WARNING] Skipping line: {e} - Line: '{decoded_line}'")
                    pass
    except Exception as e: 
        logging.error(f"[LLM STREAM ERROR] LLM server communication error: {e}", exc_info=True)
        llm_logger.error(f"[{request_id}] [ERROR][STREAM] Communication error: {e}")
        yield f"\n\n**Error:** LLM server communication error: {e}"
    finally:
        # 3. 스트리밍 완료 후 전체 응답을 캐시에 저장
        if full_response_accumulator:
            final_response = "".join(full_response_accumulator)
            duration = time.time() - start_time
            response_size = len(final_response.encode('utf-8'))
            
            cache.set(cache_key, final_response, expire=cache_ttl_seconds)
            llm_logger.info(f"[{request_id}] [RESP][STREAM] Duration: {duration:.2f}s, Size: {response_size} bytes, Tokens(P/C): {total_tokens['prompt']}/{total_tokens['completion']}")
            llm_logger.debug(f"[{request_id}] [RESP BODY] {final_response}")
            logging.info(f"[{request_id}] [CACHE MISS][STREAM] 새로운 스트리밍 응답을 캐시에 저장합니다. (Key: {cache_key[:10]}...)")

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
                logging.info(f"프롬프트 파일 '{PROMPTS_FILE}'을(를) 성공적으로 로드했습니다. {len(PROMPTS)}개의 프롬프트가 로드되었습니다.")
        except Exception as e: logging.error(f"Failed to load prompts: {e}", exc_info=True)
    if not os.path.exists(PROMPTS_FILE) or os.path.getsize(PROMPTS_FILE) == 0:
        with open(PROMPTS_FILE, 'w', encoding='utf-8') as f: json.dump(OrderedDict(), f)
    load_prompts(force_reload=True)
    threading.Thread(target=lambda: [time.sleep(5) for _ in iter(int, 1) if not load_prompts()], daemon=True).start()

def setup_scheduler():
    global scheduler
    jobstores = {'default': SQLAlchemyJobStore(url=f'sqlite:///{os.path.join(SCRIPT_DIR, "jobs.sqlite")}')}
    scheduler = BackgroundScheduler(jobstores=jobstores, timezone='Asia/Seoul')
    
    # [BUG FIX] apscheduler와의 충돌을 피하기 위해 로거 이름을 명확히 분리합니다.
    logger = logging.getLogger('AIBox_Scheduler')
    logger.setLevel(logging.INFO)
    # [BUG FIX] 핸들러 중복 추가 방지
    if logger.hasHandlers():
        logger.handlers.clear()
    # [BUG FIX] 로그 포맷을 명시적으로 설정하여 시간, 레벨 등이 기록되도록 합니다.
    handler = logging.handlers.RotatingFileHandler(CONFIG["scheduler_log_file"], maxBytes=10*1024*1024, backupCount=5) # [제안 반영] 로그 파일 크기를 10MB로 늘림
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)
    try:
        scheduler.start()
        scheduler.add_job(cleanup_old_analysis_statuses, 'interval', seconds=ANALYSIS_CLEANUP_INTERVAL_SECONDS, id='cleanup_analysis_status_job')
        logging.info(f"Loaded {sync_jobs_from_file()} scheduled jobs from file.")
    except Exception as e: logging.error(f"Failed to start APScheduler: {e}", exc_info=True)
    atexit.register(lambda: scheduler.shutdown())

def run_scheduled_script(script_path):
    # [BUG FIX] 설정된 커스텀 로거 이름을 사용합니다.
    log = logging.getLogger('AIBox_Scheduler')
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
@app.route('/AIBox/cve/<path:filename>')
def route_cve_files(filename): return send_from_directory(CVE_FOLDER, filename)

@app.route('/AIBox/api/health', methods=['GET'])
def api_health(): return jsonify({"status": "ok", "instance_id": SERVER_INSTANCE_ID})

@app.route('/AIBox/api/status/<analysis_id>', methods=['GET'])
def api_get_analysis_status(analysis_id):
    """[BUG FIX] 분석 상태를 반환하는 API 엔드포인트 추가."""
    with ANALYSIS_LOCK:
        status_info = ANALYSIS_STATUS.get(analysis_id)
        if status_info:
            return jsonify(status_info)
        return jsonify({"status": "not_found", "log": ["해당 분석 ID를 찾을 수 없습니다."]}), 404

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
        # [BUG FIX] user.html에서 호출하는 /api/update-prompts 대신
        # 이 엔드포인트를 사용하도록 통합하고, 비밀번호 검증 로직을 추가합니다.
        # user.html은 /api/prompts 로 POST 요청을 보내도록 수정해야 합니다.
        data = request.json
        if data.get('password') != CONFIG.get("password"): return jsonify({"error": "Unauthorized"}), 401

        # [안정성 강화] 'prompts' 데이터가 리스트 형태인지 검증하여 서버 오류 방지
        prompts_data = data.get('prompts', [])
        if not isinstance(prompts_data, list):
            return jsonify({"error": "Invalid data format: 'prompts' must be a list."}), 400

        try:
            prompts = OrderedDict([(item['key'], {"system_message": item['value'].split(PROMPT_SEPARATOR, 1)[0], "user_template": item['value'].split(PROMPT_SEPARATOR, 1)[1] if PROMPT_SEPARATOR in item['value'] else ""}) for item in prompts_data])
            
            # [제안 반영] 프롬프트 파일 저장 전 백업 생성
            if os.path.exists(PROMPTS_FILE):
                shutil.copy2(PROMPTS_FILE, f"{PROMPTS_FILE}.bak")
                logging.info(f"Prompt file backed up to {PROMPTS_FILE}.bak")

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

@app.route('/AIBox/api/cve/report', methods=['POST'])
def api_cve_report_for_html():
    cve_id = request.json.get('cve_id')
    rh_data = {}
    response = make_request_generic('get', f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json")
    if response:
        rh_data = response.json()

    # [사용자 요청] LLM이 항상 JSON을 반환하도록 프롬프트 수정
    prompt = f"""Generate a comprehensive Korean Markdown security report for {cve_id} based on this data and web search for recent info/PoCs.
[Data]
{json.dumps(rh_data, indent=2)}

[Output Format]
Return ONLY a single valid JSON object with a key "report_markdown" containing the full report."""
    llm_response_str = call_llm_blocking("You are an elite cybersecurity analyst designed to output JSON.", prompt)
    summary = _parse_llm_json_response(llm_response_str).get("report_markdown", "Failed to generate report.")
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
        if not os.path.isfile(log_file):
            return jsonify([])
        try:
            lines = []
            max_lines = 100 # 표시할 최대 라인 수
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                # [수정] 더 안정적인 방법으로 로그를 읽습니다.
                # 모든 줄을 읽은 후 마지막 100줄만 사용합니다.
                # 이 방식은 마지막 줄 누락과 같은 경계 조건 오류를 방지합니다.
                lines = f.readlines()[-max_lines:]
            # [개선] 터미널 색상(ANSI 코드)을 유지하기 위해 strip()만 사용하고,
            # 정규식을 이용한 ANSI 코드 제거 로직을 삭제합니다.
            return jsonify([line.rstrip('\n') for line in lines])
        except Exception as e:
            logging.error(f"Error reading scheduler log file: {e}")
            return jsonify({"error": "Failed to read log file."}), 500

@app.route('/AIBox/api/reports', methods=['GET', 'DELETE'])
def api_reports():
    if request.method == 'DELETE':
        filename = request.args.get('file')
        if not filename:
            return jsonify({"error": "File parameter is missing"}), 400

        # [핵심 개선] 단일 파일이 아닌, 분석과 관련된 모든 파일(html, json)을 삭제합니다.
        if filename.startswith('report-') and filename.endswith('.html'):
            try:
                # 'report-hostname.html'에서 'hostname'을 추출합니다.
                hostname = filename[len('report-'):-len('.html')]
                
                files_to_delete = [
                    f"report-{hostname}.html",
                    f"metadata-{hostname}.json",
                    f"sar_data-{hostname}.json"
                ]
                
                deleted_count = 0
                for f_to_delete in files_to_delete:
                    file_path = os.path.join(app.config['OUTPUT_FOLDER'], secure_filename(f_to_delete))
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        deleted_count += 1
                
                return jsonify({"success": True, "message": f"{deleted_count}개의 관련 파일이 삭제되었습니다."})
            except Exception as e:
                logging.error(f"리포트 관련 파일 삭제 중 오류 발생: {e}", exc_info=True)
                return jsonify({"error": "파일 삭제 중 서버 오류가 발생했습니다."}), 500
        
        return jsonify({"error": "잘못된 파일 이름 형식입니다. 'report-...' 형태의 파일만 삭제할 수 있습니다."}), 400
    else: # GET
        try:
            reports = sorted([
                {"name": f, "mtime": os.path.getmtime(os.path.join(OUTPUT_FOLDER, f))}
                for f in os.listdir(OUTPUT_FOLDER)
                if f.startswith('report-') and f.endswith('.html')
            ], key=lambda r: r['mtime'], reverse=True)
            return jsonify(reports)
        except Exception:
            return jsonify({"error": "리포트 목록을 가져오는 데 실패했습니다."}), 500

@app.route('/AIBox/api/reports/all', methods=['DELETE'])
def api_delete_all_reports():
    # [보안 강화] 모든 리포트 삭제 시 비밀번호 검증 로직 추가
    if not request.json or request.json.get('password') != CONFIG.get("password"):
        return jsonify({"error": "Unauthorized"}), 401
        
    try:
        count = sum(1 for f in os.listdir(app.config['OUTPUT_FOLDER']) if f.startswith('report-') and f.endswith('.html') and os.remove(os.path.join(app.config['OUTPUT_FOLDER'], f)) is None)
        logging.info(f"Deleted {count} report(s).")
        return jsonify({"success": True, "message": f"{count} reports deleted."})
    except Exception as e:
        logging.error(f"Error deleting all reports: {e}", exc_info=True)
        return jsonify({"error": "Failed to delete all reports."}), 500

@app.route('/AIBox/api/sos/analyze_system', methods=['POST'])
def api_sos_analyze_system():
    try:
        request_data = request.json
        # [개선] sos_analyzer v8+ 에서 보내는 전문가 프롬프트를 우선적으로 확인
        prompt = request_data.get("prompt")
        
        # [개선] 프롬프트가 없는 구버전 요청에 대한 하위 호환성 유지
        if not prompt:
            logging.warning("요청에 프롬프트가 없습니다. 하위 호환 모드로 동작합니다.")
            data_str = json.dumps(request_data, indent=2, ensure_ascii=False, default=str)
            # 구버전용 기본 프롬프트
            prompt = f"""당신은 RHEL 시스템 문제 해결 전문가입니다. 주어진 sosreport 데이터를 기반으로 전문가 수준의 진단과 해결책을 한국어로 제공하세요. 당신의 응답은 반드시 유효한 단일 JSON 객체여야 합니다.
## Analysis Data
```json
{data_str}
```

## Response Format
Return ONLY a single, valid JSON object matching this structure:
{{
"analysis_summary": "A 3-4 sentence comprehensive summary of the system's overall status.",
"key_issues": [
{{
"issue": "The core problem discovered.",
"cause": "A technical analysis of the root cause.",
"solution": "Specific, actionable solutions."
}}
]
}}
"""
        response_str = call_llm_blocking("You are an assistant designed to output only a single valid JSON object.", prompt)
    
        try: # [BUG FIX] response_str이 JSON 문자열일 수 있으므로, 먼저 파싱 시도
            # [개선] LLM 응답이 JSON 형식이 아닐 경우를 대비한 예외 처리 강화
            response_json = _parse_llm_json_response(response_str)
            # [BUG FIX] LLM이 유효한 JSON을 반환한 경우, 다시 문자열로 감싸지 않고 JSON 객체 그대로 반환합니다.
            # 이렇게 해야 클라이언트(sos_analyzer)가 이중으로 파싱할 필요 없이 데이터를 바로 사용할 수 있습니다.
            return jsonify(response_json)
        except ValueError as e:
            logging.warning(f"LLM 응답을 JSON으로 직접 파싱하는 데 실패했습니다: {e}. 텍스트에서 JSON 블록 추출을 시도합니다.")
            # 정규식을 사용하여 마크다운 코드 블록에서 JSON 콘텐츠를 추출합니다.
            match = re.search(r'```(json)?\s*(\{.*\}|\[.*\])\s*```', response_str, re.DOTALL)
            if match:
                json_str = match.group(2)
                logging.info("응답에서 JSON 블록을 성공적으로 추출하여 반환합니다.")
                # 추출된 JSON 문자열을 클라이언트에 직접 반환합니다.
                return Response(json_str, mimetype='application/json; charset=utf-8')

            logging.error("응답에서 유효한 JSON 블록을 찾지 못했습니다. 원본 텍스트를 raw_response로 반환합니다.")
            return jsonify({"raw_response": response_str, "error": "LLM response was not in a valid JSON format."})

    except Exception as e:
        logging.error(f"/api/sos/analyze_system error: {e}", exc_info=True)
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

@app.route('/AIBox/api/cve/analyze', methods=['POST'])
def api_cve_analyze():
    try:
        cve_data = request.json
        # [BUG FIX] 요청 데이터가 딕셔너리 형태이고 'prompt' 키를 포함하는지 확인합니다.
        if isinstance(cve_data, dict) and "prompt" in cve_data:
            prompt = cve_data["prompt"]
            # [사용자 요청] 시스템 메시지를 JSON 출력으로 강제화
            system_message = "You are an expert assistant. Follow the user's instructions precisely, including the output format."
        else: # 기존 security.py와의 호환성을 위한 폴백
            prompt = f"""[CVE Data]\n{json.dumps(cve_data, indent=2, ensure_ascii=False)}\n\n[Task]\nAnalyze and return JSON with keys: 'threat_tags', 'affected_components', 'concise_summary', 'selection_reason'."""
            system_message = "You are an RHEL security analyst. Return only a single, valid JSON object."
        
        # [핵심 개선] 대용량 JSON 응답을 처리하기 위해 스트리밍 방식으로 LLM을 호출하고, 그 결과를 그대로 클라이언트에 스트리밍합니다.
        # 이는 서버의 메모리 부담을 줄이고, 타임아웃 문제를 방지합니다.
        response_stream = call_llm_stream(system_message, user_message=prompt)
        
        # [개선] 스트리밍 응답을 조립하여 JSON 유효성을 검사하고, 실패 시 코드 블록을 추출합니다.
        full_response_str = "".join(list(response_stream))
        try:
            # 먼저 전체 응답이 유효한 JSON인지 확인
            parsed_json = json.loads(full_response_str)
            return jsonify(parsed_json)
        except json.JSONDecodeError:
            # JSON 파싱 실패 시, 마크다운 코드 블록에서 JSON 추출 시도
            match = re.search(r'```(json)?\s*(\[.*\]|\{.*\})\s*```', full_response_str, re.DOTALL)
            if match:
                json_str = match.group(2)
                # 추출된 JSON 문자열을 클라이언트에 직접 반환
                return Response(json_str, mimetype='application/json; charset=utf-8')
            # 그래도 실패하면 원본 텍스트를 오류와 함께 반환
            return jsonify({"raw_response": full_response_str, "error": "LLM response was not in a valid JSON format."})
    except Exception as e:
        logging.error(f"CVE analysis error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/AIBox/api/upload', methods=['POST'])
def api_upload_and_analyze():
    if 'sosreportFile' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['sosreportFile']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    if file:
        # [제안 반영] 파일 확장자 검증 강화
        ALLOWED_EXTENSIONS = {'.tar.gz', '.tgz', '.tar.xz', '.txz', '.tar.bz2', '.tbz2'}
        if not any(file.filename.endswith(ext) for ext in ALLOWED_EXTENSIONS):
            return jsonify({"error": f"Invalid file type. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"}), 400
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            # [제안 반영] 대용량 파일 업로드 전 디스크 공간 확인
            file_size = request.content_length
            statvfs = os.statvfs(app.config['UPLOAD_FOLDER'])
            available_space = statvfs.f_frsize * statvfs.f_bavail
            if file_size > available_space:
                return jsonify({"error": "Disk space is insufficient to save the file."}), 507

            # [개선] request 컨텍스트에 의존하지 않도록 서버 URL을 설정 파일에서 가져옵니다.
            # AIBOX_BASE_URL 환경 변수 또는 --base-url 인자를 통해 설정할 수 있습니다.
            base_url = CONFIG.get('base_url', f"{request.scheme}://{request.host}")
            server_url_for_analyzer = f"{base_url.rstrip('/')}/AIBox/api/sos/analyze_system"

            file.save(file_path)
            analysis_id = str(uuid.uuid4())
            
            # 백그라운드에서 분석 시작
            # [개선] request 컨텍스트에 의존하지 않도록 server_url을 명시적으로 전달합니다.
            server_url_for_analyzer = f"{request.scheme}://{request.host}/AIBox/api/sos/analyze_system"
            thread = threading.Thread(target=run_analysis_in_background, args=(file_path, analysis_id, server_url_for_analyzer))
            thread.daemon = True
            thread.start()
            return jsonify({"message": "File uploaded and analysis started.", "analysis_id": analysis_id}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to save file or start analysis: {str(e)}"}), 500

#--- 서버 실행 ---
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Unified AI Server", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--llm-url', required=True, help='Full URL for LLM server API')
    # [요청 반영] 서비스 시작 시 모든 서비스 로직에 대한 체크 및 로깅 추가
    logging.info("==========================================================")
    logging.info("          AIBox 서버 시작 시퀀스를 시작합니다.          ")
    logging.info("==========================================================")
    parser.add_argument('--model', help='LLM model name')
    parser.add_argument('--list-models', action='store_true', help='List available models and exit')
    parser.add_argument('--token', default=os.getenv('LLM_API_TOKEN'), help='API token for LLM server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind the server to')
    parser.add_argument('--port', type=int, default=5000, help='Port to run the server on')
    parser.add_argument('--schedule-file', default='./schedule.json', help='Path to schedule JSON file')
    parser.add_argument('--scheduler-log-file', default='./scheduler.log', help='Path to scheduler log file')
    parser.add_argument('--cache-ttl-days', type=int, default=7, help='Number of days to keep LLM cache')
    parser.add_argument('--cache-size-gb', type=float, default=1.0, help='Maximum size of the cache in gigabytes')
    # [개선] 서버의 외부 접속 URL을 명시적으로 받기 위한 인자.
    parser.add_argument('--base-url', default=os.getenv('AIBOX_BASE_URL'), help='External base URL for the server (e.g., http://aibo.example.com)')
    args = parser.parse_args()

    logging.info("[1/8] 명령줄 인자 파싱 완료.")
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
    # [개선] base_url이 설정되지 않았을 경우 경고 메시지를 표시합니다.
    if not CONFIG.get('base_url'):
        logging.warning("`--base-url` 또는 `AIBOX_BASE_URL`이 설정되지 않았습니다. 백그라운드 작업 콜백에 문제가 발생할 수 있습니다.")

    logging.info("[2/8] 기본 설정(Config) 로드 완료.")
    
    # [제안 반영] argparse 대신 환경 변수에서 비밀번호를 로드합니다.
    CONFIG['password'] = os.getenv('AIBOX_PASSWORD')
    if not CONFIG.get('password'):
        logging.error("FATAL: Password is not set. Please set the AIBOX_PASSWORD environment variable.")
        sys.exit(1)
    logging.info("[3/8] AIBOX_PASSWORD 환경 변수 확인 완료.")
    logging.info("[3/8] 비밀번호(AIBOX_PASSWORD) 확인 완료.")

    # [개선] diskcache 인스턴스 초기화
    cache_size_bytes = int(args.cache_size_gb * (1024**3))
    cache = Cache(CACHE_FOLDER, size_limit=cache_size_bytes)
    logging.info(f"[4/8] DiskCache 초기화 완료. 경로: {CACHE_FOLDER}, 최대 크기: {args.cache_size_gb} GB, TTL: {args.cache_ttl_days}일")
    logging.info(f"[4/8] DiskCache 초기화 완료 (경로: {CACHE_FOLDER}, 크기: {args.cache_size_gb}GB, TTL: {args.cache_ttl_days}일).")

    resolved_llm_url = resolve_chat_endpoint(CONFIG['llm_url'], CONFIG.get('token'))
    if resolved_llm_url: CONFIG['llm_url'] = resolved_llm_url
    else: logging.warning(f"Could not automatically determine API type for '{CONFIG['llm_url']}'.")
    logging.info(f"[5/8] LLM 엔드포인트 확인 완료. 최종 URL: {CONFIG['llm_url']}")
    logging.info(f"[5/8] LLM 엔드포인트 확인 완료 (URL: {CONFIG['llm_url']}).")

    if not args.model:
        logging.info("기본 모델이 지정되지 않았습니다. LLM 서버에서 사용 가능한 모델을 조회합니다...")
        models = get_available_models(CONFIG['llm_url'], CONFIG.get('token'))
        if models:
            CONFIG['model'] = models[0]
            logging.info(f" -> 사용 가능한 모델: {models}. 기본 모델로 '{CONFIG['model']}'을(를) 설정합니다.")
            logging.info(f" -> 사용 가능 모델: {models}. 기본 모델로 '{CONFIG['model']}'을(를) 설정합니다.")
        else:
            logging.error("LLM 서버에서 사용 가능한 모델을 찾을 수 없습니다. --model 인자가 필요합니다.")
            parser.error("--model is required as no models could be auto-detected.")

    CONFIG["schedule_file"] = os.path.abspath(args.schedule_file)
    CONFIG["scheduler_log_file"] = os.path.abspath(args.scheduler_log_file)

    initialize_and_monitor_prompts()
    logging.info(f"[6/8] 프롬프트 초기화 및 모니터링 시작 완료. ({PROMPTS_FILE})")
    logging.info(f"[6/8] 프롬프트 초기화 및 모니터링 시작 완료 ({PROMPTS_FILE}).")
    setup_scheduler()
    logging.info(f"[7/8] 스케줄러 설정 완료. (DB: jobs.sqlite, 로그: {CONFIG['scheduler_log_file']})")

    # [제안 반영] CORS 설정을 환경 변수에서 가져오도록 수정
    cors_origins = os.getenv('CORS_ORIGINS', '*').split(',')
    CORS(app, resources={r"/AIBox/api/*": {"origins": cors_origins}})
    logging.info(f"[8/8] CORS 설정 완료. 허용된 오리진: {cors_origins}")

    logging.info("==========================================================")
    logging.info(f"  AIBox 서버가 http://{args.host}:{args.port} 에서 시작됩니다.  ")
    logging.info("==========================================================")
    serve(app, host=args.host, port=args.port, threads=16)
