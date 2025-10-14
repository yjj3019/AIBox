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
import psutil
import shutil
import hashlib
from diskcache import Cache
from typing import List, Dict, Any, Generator
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, request, jsonify, Response, send_from_directory
from flask_cors import CORS
import requests
from werkzeug.utils import secure_filename
from waitress import serve
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from werkzeug.middleware.proxy_fix import ProxyFix

# [개선] 토큰 기반 청크 분할을 위한 tiktoken 라이브러리 추가
try:
    import tiktoken
    IS_TIKTOKEN_AVAILABLE = True
except ImportError:
    IS_TIKTOKEN_AVAILABLE = False

# [사용자 요청] 서버 측 Excel 생성을 위해 openpyxl 라이브러리 추가
try:
    from openpyxl.writer.excel import save_virtual_workbook
    IS_OPENPYXL_AVAILABLE = True
except ImportError:
    IS_OPENPYXL_AVAILABLE = False
    IS_TIKTOKEN_AVAILABLE = False

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
RULES_FOLDER = '/data/iso/AIBox/rules'
SOS_ANALYZER_SCRIPT = "/data/iso/AIBox/sos_analyzer.py"
CVE_FOLDER = '/data/iso/AIBox/cve'
scheduler = None

ANALYSIS_STATUS = {}
ANALYSIS_LOCK = Lock()
ANALYSIS_CLEANUP_INTERVAL_SECONDS = 3600 # 1시간마다 오래된 상태 정리

# [사용자 요청] LLM 동시 요청 수를 제한하여 서버 과부하를 방지합니다.
# os.cpu_count()를 기반으로 설정하되, 최소 1개, 최대 4개로 제한합니다.
MAX_CONCURRENT_LLM_REQUESTS = max(1, min((os.cpu_count() or 1) // 2, 4))
llm_semaphore = threading.Semaphore(MAX_CONCURRENT_LLM_REQUESTS)

CONTROL_CHAR_REGEX = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)
os.makedirs(CVE_FOLDER, exist_ok=True)
os.makedirs(RULES_FOLDER, exist_ok=True)
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

class LLMChunker:
    """
    [신규] LLM 요청을 위한 데이터 청킹(chunking) 유틸리티 클래스.
    tiktoken을 사용하여 토큰 수를 계산하고, 컨텍스트 창 크기에 맞춰 데이터를 분할합니다.
    """
    def __init__(self, max_tokens: int = 120000):
        self.max_tokens = max_tokens
        self.tokenizer = None
        if IS_TIKTOKEN_AVAILABLE:
            try:
                self.tokenizer = tiktoken.get_encoding("cl100k_base")
            except Exception as e:
                logging.warning(f"tiktoken 로딩 실패: {e}. 문자 길이 기반으로 폴백합니다.")

    def get_token_count(self, text: str) -> int:
        """주어진 텍스트의 토큰 수를 계산합니다."""
        if self.tokenizer:
            return len(self.tokenizer.encode(text))
        # 토크나이저가 없을 경우, 대략적으로 1토큰 = 2.5자로 계산하여 안전 마진을 둡니다.
        return len(text) // 2

    def split_data(self, data: Any, base_prompt_tokens: int) -> Generator[Any, None, None]:
        """
        주어진 데이터를 LLM의 컨텍스트 창에 맞게 여러 청크로 분할합니다.
        리스트, 딕셔너리, 문자열 형태의 데이터를 지원합니다.
        """
        available_tokens = self.max_tokens - base_prompt_tokens - 500  # 500 토큰의 안전 마진

        if isinstance(data, str):
            if self.get_token_count(data) > available_tokens:
                logging.warning(f"데이터(문자열)가 너무 커서 분할합니다. (토큰: {self.get_token_count(data)})")
                # 문자열을 문단 단위로 분할 (간단한 예시)
                paragraphs = data.split('\n\n')
                current_chunk = ""
                for p in paragraphs:
                    if self.get_token_count(current_chunk + p) > available_tokens and current_chunk:
                        yield current_chunk; current_chunk = ""
                    current_chunk += p + "\n\n"
                if current_chunk: yield current_chunk
            else:
                yield data
        elif isinstance(data, list):
            current_chunk, current_tokens = [], 0
            for item in data:
                item_str = json.dumps(item, ensure_ascii=False, default=str)
                item_tokens = self.get_token_count(item_str)
                if current_chunk and current_tokens + item_tokens > available_tokens:
                    yield current_chunk; current_chunk, current_tokens = [], 0
                current_chunk.append(item); current_tokens += item_tokens
            if current_chunk: yield current_chunk
        elif isinstance(data, dict):
            current_chunk, current_tokens = {}, 0
            for key, value in data.items():
                item_str = json.dumps({key: value}, ensure_ascii=False, default=str)
                item_tokens = self.get_token_count(item_str)
                if current_chunk and current_tokens + item_tokens > available_tokens:
                    yield current_chunk; current_chunk, current_tokens = {}, 0
                current_chunk[key] = value; current_tokens += item_tokens
            if current_chunk: yield current_chunk
        else:
            yield data

def run_analysis_in_background(file_path, analysis_id, server_url):
    log_key = analysis_id
    # [제안 반영] 분석 상태를 큐에 넣을 때 초기 상태를 'queued'로 설정합니다.
    with ANALYSIS_LOCK:
        ANALYSIS_STATUS[log_key] = {"status": "queued", "log": ["분석 대기 중..."], "report_file": None, "start_time": time.time()}

    try:
        python_interpreter = "/usr/bin/python3.11"
        output_dir = app.config['OUTPUT_FOLDER']
        # [BUG FIX] sos_analyzer.py를 호출하는 방식을 수정합니다.
        # Python 인터프리터를 명시하고, 모든 인자(--server-url, --output, tar_path)를
        # 명령줄 인자로 전달하여 'unrecognized arguments' 오류를 해결합니다.
        command = [
            python_interpreter, SOS_ANALYZER_SCRIPT,
            "--server-url", server_url,
            "--output", output_dir,
            file_path
        ]
        
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')

        with ANALYSIS_LOCK:
            ANALYSIS_STATUS[log_key]["status"] = "running"
            ANALYSIS_STATUS[log_key]["log"].append("분석 프로세스를 시작합니다...")

        for line in iter(process.stdout.readline, ''):
            line = line.strip()
            if not line: continue
            with ANALYSIS_LOCK:
                # [개선] sos_analyzer.py의 표준화된 로그 포맷("[STEP]")을 파싱하여 상태 업데이트
                if "[STEP] EXTRACTING" in line:
                    ANALYSIS_STATUS[log_key]["status"] = "extracting"
                elif "[STEP] PARSING" in line:
                    ANALYSIS_STATUS[log_key]["status"] = "parsing"
                elif "[STEP] ANALYZING" in line:
                    ANALYSIS_STATUS[log_key]["status"] = "analyzing"
                elif "[STEP] GENERATING_REPORT" in line:
                    ANALYSIS_STATUS[log_key]["status"] = "generating_report"
                
                ANALYSIS_STATUS[log_key]["log"].append(line)
        
        process.wait()
        stderr_output = process.stderr.read().strip()

        with ANALYSIS_LOCK:
            # [핵심 개선] 분석 프로세스의 성공/실패를 더 명확하게 판단합니다.
            # 1. 프로세스 종료 코드가 0 (성공)인지 확인합니다.
            # 2. 로그에 'HTML 보고서 저장 완료' 메시지가 있는지 확인합니다.
            # 두 조건이 모두 충족되어야 최종 성공으로 처리합니다.
            final_log = "\n".join(ANALYSIS_STATUS[log_key].get("log", []))
            is_success = process.returncode == 0 and "HTML 보고서 저장 완료" in final_log

            if is_success:
                ANALYSIS_STATUS[log_key]["status"] = "complete"
                ANALYSIS_STATUS[log_key]["log"].append("분석 성공적으로 완료.")
                match = re.search(r"HTML 보고서 저장 완료: (.+)", final_log)
                if match:
                    report_full_path = match.group(1)
                    ANALYSIS_STATUS[log_key]["report_file"] = os.path.basename(report_full_path)
            else:
                ANALYSIS_STATUS[log_key]["status"] = "failed"
                ANALYSIS_STATUS[log_key]["log"].append(f"분석 실패 (종료 코드: {process.returncode}).")
                if stderr_output:
                    ANALYSIS_STATUS[log_key]["log"].append("--- ERROR LOG ---")
                    ANALYSIS_STATUS[log_key]["log"].extend(stderr_output.split('\n'))

    except Exception as e:
        with ANALYSIS_LOCK:
            ANALYSIS_STATUS[log_key]["status"] = "failed"
            ANALYSIS_STATUS[log_key]["log"].append(f"서버 내부 오류 발생: {e}")
            traceback.print_exc()
    finally:
        # [사용자 요청] 분석이 성공하든 실패하든, 완료 후에는 원본 sosreport 파일을 삭제하여 디스크 공간을 확보합니다.
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logging.info(f"분석 완료 후 업로드된 sosreport 파일 삭제: {file_path}")
        except OSError as e:
            # 파일 삭제 실패가 전체 프로세스에 영향을 주지 않도록 오류만 기록합니다.
            logging.error(f"업로드된 sosreport 파일 삭제 실패 '{file_path}': {e}")


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

def log_server_status():
    """[신규] 서버의 현재 부하 상태를 주기적으로 로깅합니다."""
    with ANALYSIS_LOCK:
        running_analyses = sum(1 for status in ANALYSIS_STATUS.values() if status['status'] == 'running')
    
    # psutil을 사용하여 현재 프로세스의 메모리 사용량 확인
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    mem_usage_mb = mem_info.rss / (1024 * 1024)

    logging.info(
        f"[SERVER STATUS] Active Threads: {threading.active_count()}, "
        f"Running Analyses: {running_analyses}, "
        f"LLM Concurrency: {MAX_CONCURRENT_LLM_REQUESTS - llm_semaphore._value}/{MAX_CONCURRENT_LLM_REQUESTS}, "
        f"Memory Usage: {mem_usage_mb:.2f} MB"
    )

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
        logging.info(f"[CACHE HIT] 캐시된 응답(객체)을 반환합니다. (Key: {cache_key[:10]}...)")
        llm_logger.info(f"[CACHE HIT] Returning cached response for key: {cache_key}")
        return cached_response

    # 2. Cache Miss: LLM 호출
    logging.info(f"[CACHE MISS] LLM 서버에 분석을 요청합니다. (Key: {cache_key[:10]}...)")
    raw_response_str = _call_llm_single_blocking(system_message, user_message, max_tokens, cache_key)

    # 3. LLM 응답 파싱 및 객체 변환
    # [BUG FIX] LLM 응답 파싱 실패 시, 클라이언트가 AttributeError를 일으키지 않도록
    #           항상 일관된 JSON 객체 형식으로 오류를 반환합니다.
    try:
        # [BUG FIX] LLM이 생성한 JSON 문자열 내의 이스케이프되지 않은 줄 바꿈 문자를 보정합니다.
        corrected_str = _correct_json_string(raw_response_str)
        final_object = _parse_llm_json_response(corrected_str)
        # [BUG FIX] 파싱은 성공했으나 결과가 문자열인 경우, 이를 JSON 객체로 감싸줍니다.
        if isinstance(final_object, str):
            final_object = {"analysis_report": final_object}
    except ValueError as e:
        logging.error(f"최종 LLM 응답 파싱 실패: {e}")
        final_object = {"error": "Final LLM response parsing failed", "details": str(e), "raw_response": raw_response_str}

    # 4. 성공적인 응답(객체)을 캐시에 저장
    if isinstance(final_object, dict) and 'error' not in final_object:
        cache.set(cache_key, final_object, expire=cache_ttl_seconds)
        logging.info(f"[CACHE SET] 새로운 응답을 캐시에 저장합니다. (Key: {cache_key[:10]}...)")

    return final_object

def _call_llm_single_blocking(system_message, user_message, max_tokens=16384, cache_key=None):
    """단일 LLM 호출을 처리하는 내부 블로킹 함수."""
    # [구조적 오류 수정] 이 함수는 이제 항상 문자열을 반환합니다. (성공 시 LLM 응답, 실패 시 오류 JSON 문자열)
    headers = {'Content-Type': 'application/json'}
    if CONFIG.get("token"): headers['Authorization'] = f'Bearer {CONFIG["token"]}'
    payload = {"model": CONFIG["model"], "messages": [{"role": "system", "content": system_message}, {"role": "user", "content": user_message}], "max_tokens": max_tokens, "temperature": 0.1, "stream": False}
    
    # [신규] LLM 요청 로깅
    llm_logger.info("--- LLM Request (Blocking) ---")
    llm_logger.info(f"System Message: {system_message}")
    llm_logger.debug(f"User Message: {user_message}")
    
    # cache_misses.inc() # 메트릭 기능이 구현될 때까지 주석 처리
    # [제안 반영] LLM 호출 타임아웃을 600초(10분)로 늘려 긴 분석 작업(예: CVE 순위 선정)을 지원합니다.
    try:
        response = requests.post(CONFIG["llm_url"], headers=headers, json=payload, timeout=600)
        logging.info(f"[LLM RESP] Status Code: {response.status_code}")
        response.raise_for_status()
        result = response.json() 
        content = result.get('choices', [{}])[0].get('message', {}).get('content') or result.get('message', {}).get('content')
        if not content or not content.strip():
            return json.dumps({"error": "LLM이 빈 응답을 반환했습니다."})
        
        # [신규] LLM 응답 로깅
        llm_logger.debug(f"--- LLM Response (Blocking) ---\n{content}\n")

        # [구조적 오류 수정] 보정된 '문자열'을 반환합니다. 파싱은 상위 호출자에서 수행합니다.
        # [BUG FIX] LLM이 생성한 JSON 문자열 내의 이스케이프되지 않은 줄 바꿈 문자를 보정합니다.
        return content
    except requests.exceptions.HTTPError as e:
        error_details = f"LLM Server Error: {e}"
        llm_logger.error(f"--- LLM Error (Blocking) ---\n{error_details}\n")
        # [개선] LLM 서버가 500 오류를 반환할 때, 응답 본문을 로그에 포함하여 디버깅을 용이하게 합니다.
        if e.response is not None:
            error_details += f"\nLLM Response Body:\n{e.response.text}"
        logging.error(error_details)        
        return json.dumps({"error": "LLM server returned an error.", "details": str(e), "raw_response": e.response.text if e.response else ""})
    except Exception as e:
        logging.error(f"LLM server connection or processing failed: {e}")
        return json.dumps({"error": "LLM server connection failed.", "details": str(e)})

def _correct_json_string(text: str) -> str:
    """
    [신규] LLM이 생성한 JSON 문자열 내의 이스케이프되지 않은 줄 바꿈 문자를 보정합니다.
    문자열 리터럴 내부에 있는 줄 바꿈 문자(\n)만 \\n으로 치환합니다.
    """
    in_string = False
    escaped_text = ""
    for i, char in enumerate(text):
        if char == '"':
            # 문자열 리터럴의 시작 또는 끝을 토글합니다. (이스케이프된 따옴표는 무시)
            if i == 0 or text[i-1] != '\\':
                in_string = not in_string
        elif char == '\n' and in_string:
            escaped_text += '\\n' # 문자열 내의 줄 바꿈 문자를 이스케이프합니다.
            continue
        escaped_text += char
    return escaped_text

def _parse_llm_json_response(llm_response_str: str):
    """
    [신규] LLM 응답 문자열에서 JSON 객체를 안정적으로 파싱합니다.
    - JSON 코드 블록(```json ... ```)을 처리합니다.
    - 코드 블록이 없는 경우, 문자열에서 유효한 JSON 부분을 찾습니다.
    """
    try:
        # [BUG FIX] LLM 응답이 문자열이 아닌 경우를 처리합니다.
        if not isinstance(llm_response_str, str) or not llm_response_str.strip():
            raise ValueError("LLM 응답이 비어 있거나 문자열이 아닙니다.")

        # [BUG FIX] re.DOTALL 플래그를 사용하여 여러 줄에 걸친 JSON 블록을 찾습니다.
        match = re.search(r'```(?:json)?\s*(\{.*\}|\[.*\])\s*```', llm_response_str, re.DOTALL)
        if match:
            json_str = match.group(1)
        else:
            # 코드 블록이 없는 경우, 응답에서 첫 '{' 또는 '[' 부터 마지막 '}' 또는 ']' 까지를 JSON으로 간주합니다.
            start = llm_response_str.find('{')
            if start == -1: start = llm_response_str.find('[')
            end = llm_response_str.rfind('}')
            if end == -1: end = llm_response_str.rfind(']')
            if start != -1 and end != -1:
                json_str = llm_response_str[start:end+1]
            else:
                raise ValueError(f"응답에서 유효한 JSON 형식(객체 또는 배열)을 찾을 수 없습니다.")

        return json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"LLM 응답 JSON 파싱 실패: {e}\n응답 내용: {llm_response_str[:500]}")

def call_llm_stream(system_message, user_message):
    """
    [효율성 개선] LLM 스트리밍 호출 함수에 캐싱 기능 추가.
    - Cache Miss: 실제 LLM API를 호출하고, 스트리밍하면서 전체 응답을 캐시에 저장합니다.
    - Cache Hit: 캐시된 전체 응답을 가져와, 실제 스트리밍처럼 보이도록 작은 조각으로 나누어 전송합니다.
    """
    # [개선] LLM 동시 요청이 꽉 찼을 경우 대기 상태임을 로깅합니다.
    if llm_semaphore.get_value() == 0:
        logging.info(f"[LLM QUEUE] LLM 동시 요청이 최대치({MAX_CONCURRENT_LLM_REQUESTS})에 도달하여 대기합니다...")

    # [사용자 요청] 세마포를 사용하여 동시 LLM 요청 수를 제어합니다.
    with llm_semaphore:
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
        scheduler.add_job(cleanup_old_analysis_statuses, 'interval', seconds=ANALYSIS_CLEANUP_INTERVAL_SECONDS, id='cleanup_analysis_status_job', replace_existing=True)
        scheduler.add_job(log_server_status, 'interval', minutes=1, id='log_server_status_job', replace_existing=True) # [신규] 1분마다 서버 상태 로깅
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
@app.route('/AIBox/rules.html')
def route_rules_html(): return send_from_directory(SCRIPT_DIR, 'rules.html')
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
            prompts_list = [{"key": k, "value": f"{v.get('system_message', '')}{PROMPT_SEPARATOR}{v.get('user_template', '')}"} for k, v in PROMPTS.items()]
        return Response(json.dumps(prompts_list, ensure_ascii=False), mimetype='application/json; charset=utf-8')

@app.route('/AIBox/api/rules', methods=['GET', 'POST'])
def api_rules():
    """[신규] YAML 규칙 파일을 관리하기 위한 API 엔드포인트."""
    import yaml
    
    if request.method == 'POST':
        data = request.json
        if data.get('password') != CONFIG.get("password"):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            # 1. 모든 기존 .yaml 파일을 삭제 (또는 백업)
            for f in os.listdir(RULES_FOLDER):
                if f.endswith('.yaml'):
                    os.remove(os.path.join(RULES_FOLDER, f))
            
            # 2. 프론트엔드에서 받은 데이터로 새 파일들을 작성
            for file_data in data.get('data', []):
                filename = secure_filename(file_data.get('filename'))
                rules = file_data.get('rules', [])
                if not filename.endswith('.yaml'): continue
                
                file_path = os.path.join(RULES_FOLDER, filename)
                with open(file_path, 'w', encoding='utf-8') as f:
                    yaml.dump(rules, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
            
            return jsonify({"success": True, "message": "규칙이 성공적으로 저장되었습니다."})
        except Exception as e:
            logging.error(f"Error processing /api/rules POST request: {e}", exc_info=True)
            return jsonify({"error": str(e)}), 500
    
    else: # GET
        rule_files_data = []
        for filename in sorted(os.listdir(RULES_FOLDER)):
            if filename.endswith('.yaml'):
                try:
                    file_path = os.path.join(RULES_FOLDER, filename)
                    with open(file_path, 'r', encoding='utf-8') as f:
                        rules = yaml.safe_load(f) or []
                    rule_files_data.append({"filename": filename, "rules": rules})
                except Exception as e:
                    logging.error(f"Error reading or parsing rule file {filename}: {e}")
        return jsonify(rule_files_data)

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
        # [기능 복원] 개별 리포트 삭제 기능 로직을 복원합니다.
        filename = request.args.get('file')
        if not filename:
            return jsonify({"error": "File parameter is missing"}), 400

        if filename.startswith('report-') and filename.endswith('.html'):
            try:
                hostname = filename[len('report-'):-len('.html')]
                output_folder = app.config['OUTPUT_FOLDER']
                
                # 호스트네임을 포함하는 모든 관련 파일(html, json 등)을 찾습니다.
                files_to_delete = [f for f in os.listdir(output_folder) if hostname in f]
                
                for f_to_delete in files_to_delete:
                    file_path = os.path.join(output_folder, f_to_delete)
                    if os.path.exists(file_path):
                        os.remove(file_path)
                
                return jsonify({"success": True, "message": f"{len(files_to_delete)}개의 관련 파일이 삭제되었습니다."})
            except Exception as e:
                return jsonify({"error": f"파일 삭제 중 오류 발생: {e}"}), 500
        return jsonify({"error": "잘못된 파일 이름 형식입니다."}), 400
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
        # [개선] 단순히 report-*.html 파일만 삭제하는 대신, output 디렉토리의 모든 파일을 삭제합니다.
        output_folder = app.config['OUTPUT_FOLDER']
        count = 0
        for filename in os.listdir(output_folder):
            file_path = os.path.join(output_folder, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                    count += 1
            except Exception as e:
                logging.error(f"전체 리포트 삭제 중 '{file_path}' 파일 삭제 실패: {e}")
        logging.info(f"모든 리포트 및 관련 파일 {count}개를 삭제했습니다.")
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
        # [근본 대책] call_llm_blocking은 이제 항상 파싱된 객체 또는 오류 객체를 반환합니다.
        # 별도의 파싱 로직이 필요 없습니다.
        response_obj = call_llm_blocking("You are an assistant designed to output only a single valid JSON object.", prompt)
        return jsonify(response_obj)

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
        # [BUG FIX] 요청에 'stream' 플래그가 있는지 확인하여 블로킹/스트리밍 호출을 동적으로 결정합니다.
        # cve_report_generator.py와 같이 단일 응답을 기대하는 클라이언트와의 호환성을 보장합니다.
        if cve_data.get('stream', False):
            # 스트리밍 요청 처리
            response_stream = call_llm_stream(system_message, user_message=prompt)
            full_response_str = "".join(list(response_stream))
            try:
                parsed_json = json.loads(full_response_str)
                return jsonify(parsed_json)
            except json.JSONDecodeError:
                match = re.search(r'```(json)?\s*(\{.*\}|\[.*\])\s*```', full_response_str, re.DOTALL)
                if match:
                    return Response(match.group(2), mimetype='application/json; charset=utf-8')
                return jsonify({"raw_response": full_response_str, "error": "LLM response was not in a valid JSON format."})
        else:
            # 블로킹 요청 처리
            response_obj = call_llm_blocking(system_message, user_message=prompt)
            return jsonify(response_obj)
        
    except Exception as e:
        logging.error(f"CVE analysis error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/AIBox/api/cve/export-excel', methods=['GET'])
def api_export_cve_excel():
    """[신규] cve_report_generator.py가 생성한 최종 CVE 목록을 읽어 Excel 파일을 생성하고 다운로드합니다."""
    if not IS_OPENPYXL_AVAILABLE:
        return "Excel export functionality is disabled because 'openpyxl' library is not installed.", 501

    final_list_path = os.path.join(OUTPUT_FOLDER, 'final_cve_list.json')
    if not os.path.exists(final_list_path):
        return "The analysis data file (final_cve_list.json) was not found. Please generate the report first.", 404

    try:
        # cve_report_generator.py를 임포트하여 Excel 생성 함수를 직접 호출
        # 이렇게 하면 코드 중복을 피하고 로직을 중앙에서 관리할 수 있습니다.
        import cve_report_generator

        with open(final_list_path, 'r', encoding='utf-8') as f:
            cve_list = json.load(f)
        
        workbook = cve_report_generator.create_excel_report(cve_list)
        if not workbook:
            return "Failed to create Excel workbook.", 500

        # 메모리 상의 워크북을 바이트 스트림으로 변환
        virtual_workbook_data = save_virtual_workbook(workbook)
        
        filename = f"RHEL_Vulnerability_Report_{datetime.now().strftime('%Y%m%d')}.xlsx"
        
        return Response(
            virtual_workbook_data,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={'Content-Disposition': f'attachment;filename={filename}'}
        )
    except Exception as e:
        logging.error(f"Excel export error: {e}", exc_info=True)
        return "An internal error occurred while generating the Excel file.", 500

@app.route('/AIBox/api/cve/generate-report', methods=['POST'])
def api_generate_cve_report():
    """
    [신규] cve_report.html로부터 리포트 생성 요청을 받아 create_cve_report.py를 실행하고
    그 결과를 HTML로 반환하는 엔드포인트.
    """
    cve_id = request.json.get('cve_id')
    if not cve_id:
        return jsonify({"error": "CVE ID is required."}), 400

    logging.info(f"'{cve_id}'에 대한 리포트 생성 요청을 수신했습니다.")

    try:
        # create_cve_report.py 스크립트 경로
        script_path = os.path.join(SCRIPT_DIR, 'create_cve_report.py')
        python_interpreter = "/usr/bin/python3.11" # 또는 sys.executable

        # 스크립트 실행에 필요한 인자 구성
        # 서버 자신을 가리키는 URL을 동적으로 생성하여 전달
        server_url_for_script = f"http://127.0.0.1:{CONFIG.get('port', 5000)}/AIBox/api/cve/analyze"
        command = [
            python_interpreter,
            script_path,
            cve_id,
            "--server-url", server_url_for_script
        ]

        # 스크립트를 실행하고 표준 출력을 캡처합니다.
        # [수정] check=False로 설정하여 스크립트가 0이 아닌 코드로 종료되어도 CalledProcessError를 발생시키지 않도록 합니다.
        # 대신, 반환 코드를 직접 확인하여 오류를 처리합니다.
        # [핵심 수정] 서버의 프록시 설정을 포함한 전체 환경 변수를 하위 프로세스에 전달합니다.
        # 이렇게 하면 create_cve_report.py가 외부 CISA API 등에 정상적으로 접속할 수 있습니다.
        process_env = os.environ.copy()
        
        process = subprocess.run(
            command, capture_output=True, text=True, timeout=300, encoding='utf-8', env=process_env
        )
        if process.returncode != 0:
            logging.error(f"리포트 생성 스크립트 실행 실패 (CVE: {cve_id}):\n{process.stderr}")
            return jsonify({"error": "리포트 생성 중 오류가 발생했습니다.", "details": process.stderr}), 500
        html_report = process.stdout
        return Response(html_report, mimetype='text/html')

    except subprocess.CalledProcessError as e:
        logging.error(f"리포트 생성 스크립트 실행 실패 (CVE: {cve_id}):\n{e.stderr}")
        return jsonify({"error": "리포트 생성 중 오류가 발생했습니다.", "details": e.stderr}), 500
    except Exception as e:
        logging.error(f"리포트 생성 API 처리 중 예외 발생 (CVE: {cve_id}): {e}", exc_info=True)
        return jsonify({"error": "서버 내부 오류가 발생했습니다.", "details": str(e)}), 500

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

            # [BUG FIX] sos_analyzer 스크립트가 서버 자신을 호출할 때, 외부 URL 대신
            # 항상 로컬 주소를 사용하도록 수정합니다. 이는 서버가 프록시 뒤에 있을 때
            # 외부 IP로 잘못된 요청을 보내는 문제를 해결합니다.
            # 서버가 실행 중인 포트 번호를 CONFIG에서 가져와 동적으로 URL을 생성합니다.
            local_port = CONFIG.get('port', 5000)
            server_url_for_analyzer = f"http://127.0.0.1:{local_port}/AIBox/api/sos/analyze_system"

            file.save(file_path)
            analysis_id = str(uuid.uuid4())
            
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
    # [사용자 요청] LLM 동시 요청 수를 설정하는 인자 추가
    parser.add_argument('--connection-limit', type=int, default=500, help='Maximum number of open connections for the server')
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
        logging.info("[3/8] AIBOX_PASSWORD 환경 변수가 설정되지 않았습니다.")
        logging.error("FATAL: Password is not set. Please set the AIBOX_PASSWORD environment variable.")
        sys.exit(1)
    
    # [사용자 요청] 세마포어 값 로깅
    logging.info(f"LLM 동시 요청 수가 {MAX_CONCURRENT_LLM_REQUESTS}으로 제한됩니다.")

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
    # [사용자 요청] 연결 한도를 늘려 "total open connections reached the connection limit" 오류를 방지합니다.
    serve(app, host=args.host, port=args.port, threads=16, connection_limit=args.connection_limit)
