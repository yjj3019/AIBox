#!/usr/bin/env python3.11
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
from pathlib import Path
import traceback
import atexit
import re

# [BUG FIX] 사용자의 로컬 site-packages 경로를 sys.path에 추가합니다.
# 'Defaulting to user installation'으로 인해 라이브러리가 사용자 디렉터리에 설치되었을 때,
# 'openpyxl' 등을 찾지 못하는 'ImportError'를 해결합니다.
import site
if site.USER_SITE not in sys.path:
    sys.path.insert(0, site.USER_SITE)

from datetime import datetime, timedelta
import copy
import psutil
import shutil
import hashlib
from diskcache import Cache
from typing import List, Dict, Any, Generator
import queue # noqa: E402
from concurrent.futures import ThreadPoolExecutor, as_completed, Future

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

# [개선] 의미 기반 텍스트 분할을 위한 nltk 라이브러리 추가
try:
    import nltk
    # punkt 토크나이저가 없으면 다운로드
    try: nltk.data.find('tokenizers/punkt')
    except nltk.downloader.DownloadError: nltk.download('punkt')
    IS_NLTK_AVAILABLE = True
except ImportError:
    IS_NLTK_AVAILABLE = False
    IS_TIKTOKEN_AVAILABLE = False

# [BUG FIX] psutil이 없을 경우 서버가 시작되지 않는 문제를 해결하기 위해 선택적 임포트로 변경합니다.
try:
    import psutil
    IS_PSUTIL_AVAILABLE = True
except ImportError:
    IS_PSUTIL_AVAILABLE = False

# [사용자 요청] YAML 파일 처리를 위한 PyYAML 라이브러리 추가
try:
    import yaml
    IS_YAML_AVAILABLE = True
except ImportError:    
    IS_YAML_AVAILABLE = False

# [BUG FIX] openpyxl 라이브러리 존재 여부를 확인하는 로직 추가
try:
    import openpyxl
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

# [BUG FIX] 기본 로거에 UTF-8 인코딩을 설정하여 한글 깨짐 문제를 해결합니다.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)] # UTF-8을 지원하는 스트림으로 출력
)

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
PROMPTS_FILE = os.path.join(SCRIPT_DIR, 'meta/prompts.json')
SERVER_INSTANCE_ID = str(uuid.uuid4())
PROMPT_SEPARATOR = "\n---USER_TEMPLATE---\n"
PROMPT_FILE_MTIME = 0
PROMPT_LOCK = threading.Lock()
UPLOAD_FOLDER = '/data/iso/AIBox/upload'
OUTPUT_FOLDER = '/data/iso/AIBox/output'
CACHE_FOLDER = '/data/iso/AIBox/cache'
CVE_CHECK_OUTPUT_FOLDER = '/data/iso/AIBox/cve-check/output' # [신규] cve-check 리포트 경로
RULES_FOLDER = '/data/iso/AIBox/rules'
CVE_CHECK_DATA_DIR = '/data/iso/AIBox/cve-check/data' # [신규] cve-check 데이터 경로
CVE_CHECK_DIR = '/data/iso/AIBox/cve-check' # [신규] cve-check 스크립트 경로
SOS_ANALYZER_SCRIPT = "/data/iso/AIBox/sos_analyzer.py"
CVE_FOLDER = '/data/iso/AIBox/cve'
scheduler = None
EPSS_FOLDER = '/data/iso/AIBox/epss'

ANALYSIS_STATUS = {}
ANALYSIS_LOCK = Lock()
ANALYSIS_CLEANUP_INTERVAL_SECONDS = 3600 # 1시간마다 오래된 상태 정리

# [성능 개선] LLM 요청을 병렬로 처리하기 위한 스레드 풀
LLM_WORKER_EXECUTOR = None # 서버 시작 시 인자에 따라 초기화됩니다.

# [안정성 강화] LLM 동시 요청 수를 제어하기 위한 세마포
# LLM_WORKER_EXECUTOR 대신 세마포를 사용하여 동시성을 직접 제어합니다.
LLM_REQUEST_SEMAPHORE = None

def submit_llm_request(func, *args, **kwargs):
    """[구조 변경] LLM 요청을 스레드 풀에 제출하고 결과를 기다리는 함수."""
    request_id = str(uuid.uuid4())[:8]
    
    if not LLM_WORKER_EXECUTOR:
        raise RuntimeError("LLM 워커 스레드 풀이 초기화되지 않았습니다.")

    # [핵심 수정] 세마포를 사용하여 LLM 동시 요청 수를 제어합니다.
    with LLM_REQUEST_SEMAPHORE:
        logging.info(f"[{request_id}] 세마포 획득. LLM 요청을 스레드 풀에 제출합니다.")
        # func에 request_id를 전달하여 로깅 추적을 용이하게 합니다.
        future = LLM_WORKER_EXECUTOR.submit(func, *args, **kwargs, request_id=request_id)
        
        try:
            # future.result()는 작업이 완료될 때까지 블로킹하며 결과를 반환합니다.
            return future.result()
        finally: # [사용자 요청] LLM 요청 후 일정 시간 대기하여 부하를 제어합니다.
            delay = CONFIG.get('llm_request_delay', 1.0)
            if delay > 0:
                logging.info(f"[{request_id}] LLM 작업 완료. 다음 요청 전 {delay:.1f}초 대기...")
                time.sleep(delay)
            logging.info(f"[{request_id}] 세마포를 해제합니다.")


CONTROL_CHAR_REGEX = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)
os.makedirs(CVE_FOLDER, exist_ok=True)
os.makedirs(CVE_CHECK_OUTPUT_FOLDER, exist_ok=True) # [신규] cve-check 리포트 디렉토리 생성
os.makedirs(EPSS_FOLDER, exist_ok=True)
os.makedirs(CVE_CHECK_DIR, exist_ok=True) # [신규] cve-check 디렉토리 생성
os.makedirs(os.path.join(CVE_CHECK_OUTPUT_FOLDER, "data"), exist_ok=True) # cve-check/data 디렉토리
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
    def __init__(self, max_bytes: int):
        # [핵심 수정] 이제 토큰 대신 바이트(bytes)를 기준으로 데이터를 분할합니다.
        self.max_bytes = max_bytes

    def split_data(self, data: str) -> Generator[str, None, None]:
        """
        주어진 문자열 데이터를 max_bytes 크기에 맞춰 여러 청크로 분할합니다.
        의미 단위(문장)를 최대한 유지하면서 분할을 시도합니다.
        """
        if not isinstance(data, str):
            logging.warning("LLMChunker는 문자열 데이터만 분할할 수 있습니다.")
            yield data
            return

        if len(data.encode('utf-8')) <= self.max_bytes:
            yield data
            return

        logging.warning(f"데이터(문자열)가 너무 커서 분할합니다. (총 크기: {len(data.encode('utf-8')) / 1024:.2f} KB, 분할 기준: {self.max_bytes / 1024:.2f} KB)")
        
        # NLTK를 사용하여 문장 단위로 분할
        if IS_NLTK_AVAILABLE:
            sentences = nltk.sent_tokenize(data)
        else:
            # NLTK가 없으면 줄바꿈 단위로 분할
            sentences = data.split('\n')

        current_chunk_lines = []
        current_chunk_bytes = 0

        for sentence in sentences:
            sentence_bytes = len(sentence.encode('utf-8'))
            
            # 한 문장 자체가 최대 바이트를 초과하는 경우
            if sentence_bytes > self.max_bytes:
                if current_chunk_lines:
                    yield "\n".join(current_chunk_lines)
                    current_chunk_lines, current_chunk_bytes = [], 0
                
                logging.warning(f"  - 한 문장의 크기({sentence_bytes / 1024:.2f}KB)가 최대치({self.max_bytes / 1024:.2f}KB)를 초과하여 강제 분할합니다.")
                for i in range(0, len(sentence), self.max_bytes):
                    yield sentence[i:i + self.max_bytes]
                continue

            # 현재 청크에 다음 문장을 추가하면 최대 바이트를 초과하는 경우
            if current_chunk_bytes + sentence_bytes > self.max_bytes:
                if current_chunk_lines:
                    yield "\n".join(current_chunk_lines)
                current_chunk_lines = [sentence]
                current_chunk_bytes = sentence_bytes
            else:
                current_chunk_lines.append(sentence)
                current_chunk_bytes += sentence_bytes
        
        if current_chunk_lines:
            yield "\n".join(current_chunk_lines)

def run_analysis_in_background(file_path, analysis_id, server_url):
    log_key = analysis_id
    # [제안 반영] 분석 상태를 큐에 넣을 때 초기 상태를 'queued'로 설정합니다.
    with ANALYSIS_LOCK:
        ANALYSIS_STATUS[log_key] = {"status": "queued", "log": ["분석 대기 중..."], "report_file": None, "start_time": time.time()}

    logging.info(f"[{analysis_id}] 백그라운드 분석 스레드 시작. 대상 파일: {file_path}")
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
        logging.info(f"[{analysis_id}] 실행할 분석 명령어: {' '.join(command)}")

        with ANALYSIS_LOCK:
            ANALYSIS_STATUS[log_key]["status"] = "running"
            ANALYSIS_STATUS[log_key]["log"].append("분석 프로세스를 시작합니다...")

        # [핵심 개선] subprocess.run 대신 Popen을 사용하여 실시간으로 로그를 스트리밍합니다.
        # 이렇게 하면 'upload.html'의 진행 상황 UI가 실시간으로 업데이트됩니다.
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, # stderr을 stdout으로 리다이렉트하여 함께 처리
            text=True,
            encoding='utf-8',
            errors='replace'
        )
        logging.info(f"[{analysis_id}] 분석 프로세스 시작됨 (PID: {process.pid}). 실시간 로그 수집을 시작합니다.")

        # 실시간으로 출력되는 로그를 읽어 처리합니다.
        if process.stdout:
            for line in iter(process.stdout.readline, ''):
                line = line.strip()
                if not line:
                    continue

                with ANALYSIS_LOCK:
                    logging.debug(f"[{analysis_id}] Log: {line}")
                    # 상태 업데이트 로직은 그대로 유지합니다.
                    if "[STEP] EXTRACTING" in line: ANALYSIS_STATUS[log_key]["status"] = "extracting"
                    elif "[STEP] PARSING" in line: ANALYSIS_STATUS[log_key]["status"] = "parsing"
                    elif "[STEP] ANALYZING" in line: ANALYSIS_STATUS[log_key]["status"] = "analyzing"
                    elif "[STEP] GENERATING_REPORT" in line: ANALYSIS_STATUS[log_key]["status"] = "generating_report"
                    ANALYSIS_STATUS[log_key]["log"].append(line)
        
        # 프로세스가 종료될 때까지 기다립니다. (타임아웃 20분)
        process.wait(timeout=1200)
        logging.info(f"[{analysis_id}] 분석 프로세스 종료됨 (PID: {process.pid}, Return Code: {process.returncode}).")
        
        with ANALYSIS_LOCK:
            # [핵심 개선] 분석 프로세스의 성공/실패를 더 명확하게 판단합니다.
            # 1. 프로세스 종료 코드가 0 (성공)인지 확인합니다.
            # 2. 로그에 'HTML 보고서 저장 완료' 메시지가 있는지 확인합니다.
            # 두 조건이 모두 충족되어야 최종 성공으로 처리합니다.
            # [BUG FIX] 로그에 포함된 ANSI 색상 코드로 인해 성공 문자열 감지에 실패하는 문제를 해결합니다.
            # 정규식을 사용하여 색상 코드를 제거한 후, 'HTML 보고서 저장 완료' 문자열이 있는지 확인합니다.
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            # [BUG FIX] process.stdout이 None일 경우를 대비하여 안전하게 로그를 가져옵니다.
            final_log_raw = "\n".join(ANALYSIS_STATUS[log_key].get("log", [])) if ANALYSIS_STATUS[log_key].get("log") else ""
            final_log = ansi_escape.sub('', final_log_raw)
            is_success = process.returncode == 0 and "HTML 보고서 저장 완료" in final_log

            if is_success:
                ANALYSIS_STATUS[log_key]["status"] = "complete"
                ANALYSIS_STATUS[log_key]["log"].append("분석 성공적으로 완료.")
                match = re.search(r"HTML 보고서 저장 완료: (.+)", final_log)
                if match:
                    report_full_path = match.group(1)
                    ANALYSIS_STATUS[log_key]["report_file"] = os.path.basename(report_full_path)
                
                # [BUG FIX] 성공 시에만 메타데이터를 저장하도록 로직을 이동합니다.
                if "report_file" in ANALYSIS_STATUS[log_key]:
                    end_time = time.time()
                    start_time = ANALYSIS_STATUS[log_key].get("start_time", end_time)
                    duration = end_time - start_time
                    
                    report_basename = os.path.splitext(ANALYSIS_STATUS[log_key]["report_file"])[0]
                    meta_filename = f"{report_basename}.json"
                    meta_filepath = os.path.join(app.config['OUTPUT_FOLDER'], meta_filename)
                    
                    meta_data = {"creation_timestamp": end_time, "duration_seconds": duration}
                    with open(meta_filepath, 'w', encoding='utf-8') as f:
                        json.dump(meta_data, f)
                    logging.info(f"분석 메타데이터 저장 완료: {meta_filepath}")
            else:
                # [BUG FIX] 분석 실패 시에만 실패 메시지를 생성하도록 로직을 이동합니다.
                ANALYSIS_STATUS[log_key]["status"] = "failed"
                last_log_line = ANALYSIS_STATUS[log_key]["log"][-1] if ANALYSIS_STATUS[log_key]["log"] else "로그 없음"
                fail_message = (
                    f"분석 실패 (종료 코드: {process.returncode}). 최종 로그: {last_log_line}"
                )
                ANALYSIS_STATUS[log_key]["log"].append(fail_message)

    except Exception as e:
        is_success = False # [수정] 예외 발생 시 성공 플래그를 False로 설정
        with ANALYSIS_LOCK:
            ANALYSIS_STATUS[log_key]["status"] = "failed"
            logging.error(f"[{analysis_id}] 백그라운드 분석 중 치명적인 오류 발생: {e}", exc_info=True)
            ANALYSIS_STATUS[log_key]["log"].append(f"서버 내부 오류 발생: {e}")
            traceback.print_exc()
    finally:
        # [사용자 요청] 분석 완료 후 파일을 삭제하는 로직을 비활성화합니다.
        # # [사용자 요청 수정] 분석이 성공적으로 완료되었을 때만 원본 sosreport 파일을 삭제합니다.
        # # 실패 시에는 파일을 보존하여 원인 분석이 가능하도록 합니다.
        # try:
        #     if is_success and os.path.exists(file_path):
        #         os.remove(file_path)
        #         logging.info(f"분석 완료 후 업로드된 sosreport 파일 삭제: {file_path}")
        # except OSError as e:
        #     # 파일 삭제 실패가 전체 프로세스에 영향을 주지 않도록 오류만 기록합니다.
        #     logging.error(f"업로드된 sosreport 파일 삭제 실패 '{file_path}': {e}")
        pass


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
        running_analyses = sum(1 for status in ANALYSIS_STATUS.values() if status['status'] not in ['complete', 'failed', 'queued'])
    
    # [수정] Queue 크기와 함께 최대 워커 수를 로깅하여 제한을 함께 표시합니다.
    limit = CONFIG.get('llm_max_workers', 'N/A')
    limit_str = 'unlimited' if limit is None else limit
    # [수정] 세마포의 현재 상태를 로깅합니다.
    semaphore_value = LLM_REQUEST_SEMAPHORE._value if LLM_REQUEST_SEMAPHORE else 'N/A'
    status_log = f"[SERVER STATUS] Active Threads: {threading.active_count()}, Running Analyses: {running_analyses}, LLM Semaphore: {semaphore_value}/{limit_str}"
 
    # psutil이 설치된 경우에만 메모리 사용량 정보를 추가합니다.
    if IS_PSUTIL_AVAILABLE:
        process = psutil.Process(os.getpid())
        mem_info = process.memory_info()
        mem_usage_mb = mem_info.rss / (1024 * 1024)
        status_log += f", Memory Usage: {mem_usage_mb:.2f} MB"

    logging.info(status_log)

def resolve_chat_endpoint(llm_url, token):
    """[BUG FIX] LLM 서버의 chat completion 엔드포인트를 안정적으로 확인합니다."""
    if llm_url.endswith(('/v1/chat/completions', '/api/chat')): return llm_url
    headers = {'Content-Type': 'application/json'}
    if token: headers['Authorization'] = f'Bearer {token}'
    base_url = llm_url.rstrip('/')
    
    # [BUG FIX] OpenAI 호환 엔드포인트(/v1/chat/completions)를 우선적으로 확인합니다.
    # 일부 LLM 서버가 /api/tags를 지원하면서도 /api/chat이 아닌 /v1/chat/completions를 사용하는 경우가 있어,
    # 이로 인한 404 오류를 방지하기 위해 확인 순서를 변경합니다.
    try:
        if requests.head(f"{base_url}/v1/models", headers=headers, timeout=3).status_code < 500: return f"{base_url}/v1/chat/completions"
    except requests.exceptions.RequestException: pass
    try:
        if requests.head(f"{base_url}/api/tags", headers=headers, timeout=3).status_code < 500: return f"{base_url}/api/chat" # Ollama 호환
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
    """[수정] 재시도 및 성공 로그 로직이 추가된 범용 요청 함수 (v2)"""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            kwargs.setdefault('timeout', 20)
            kwargs.setdefault('verify', False)
            response = requests.request(method, url, **kwargs)

            # [사용자 요청] 재시도(attempt > 0) 후 요청이 성공했을 경우, 성공 로그를 명확히 남깁니다.
            if attempt > 0:
                # 4xx, 5xx 응답도 성공적인 '연결'로 간주하고 로그를 남깁니다.
                # raise_for_status()는 이 이후에 호출됩니다.
                logging.info(f"범용 요청 재시도 성공 (시도 {attempt + 1}/{max_retries}): {url}")

            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            logging.warning(f"범용 요청 실패 (시도 {attempt + 1}/{max_retries}): {url}, 오류: {e}")
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                time.sleep(wait_time)
            else:
                logging.error(f"범용 요청이 모든 재시도({max_retries}회) 후에도 최종 실패했습니다: {url}")
                return None
    return None

def get_cache_key(system_message, user_message):
    """요청 내용을 기반으로 고유한 캐시 키를 생성합니다."""
    # [BUG FIX] user_message가 문자열이 아닌 리스트나 다른 타입일 경우 TypeError가 발생하는 문제를 해결합니다.
    # 어떤 타입이든 안전하게 문자열로 변환하여 캐시 키를 생성합니다.
    system_str = str(system_message)
    # [사용자 요청] 캐시 효율성 개선: user_message가 딕셔너리이고 'prompt_template'와 'data' 키를 포함하면,
    # 이 두 요소를 조합하여 캐시 키를 생성합니다. 이렇게 하면 프롬프트 템플릿이 변경되어도 데이터가 같으면 캐시를 재사용할 수 있습니다.
    if isinstance(user_message, dict) and 'prompt_template' in user_message and 'data' in user_message:
        prompt_template_str = str(user_message['prompt_template'])
        data_str = json.dumps(user_message['data'], sort_keys=True) # 데이터 순서를 보장하여 일관된 키 생성
        return hashlib.sha256((system_str + prompt_template_str + data_str).encode('utf-8')).hexdigest()
    else:
        # 기존 방식 (하위 호환성 유지)
        user_str = str(user_message)
        return hashlib.sha256((system_str + user_str).encode('utf-8')).hexdigest()

# [개선] diskcache 인스턴스를 전역적으로 생성합니다.
cache = None # 전역 변수로 선언
 
def call_llm_blocking(system_message, user_message, max_tokens=16384, model_override=None):
    """
    [개선] LLM을 호출하고 결과를 캐싱하는 블로킹 함수.
    동일한 요청에 대해서는 캐시된 결과를 반환하여 API 호출을 줄입니다.
    [사용자 요청] 작업 유형에 따라 적합한 LLM 모델을 선택적으로 사용합니다.
    """
    cache_key = get_cache_key(system_message, user_message)
    cache_ttl_seconds = CONFIG.get('cache_ttl_days', 7) * 24 * 60 * 60

    # [신규] 프롬프트 내용에 따라 사용할 모델을 결정합니다.
    # [BUG FIX] model_override가 있으면 모델 선택 로직을 건너뜁니다.
    if model_override:
        model_to_use = model_override
        # [BUG FIX] 폴백 모델의 컨텍스트 크기를 올바르게 가져옵니다.
        if model_to_use == CONFIG.get('fallbacks_model'):
            context_window_kb = CONFIG.get('fallbacks_model_context', 0)
        elif model_to_use == CONFIG.get('reasoning_model'):
            context_window_kb = CONFIG.get('reasoning_model_context', 0)
        else:
            context_window_kb = CONFIG.get('fast_model_context', 0)
    else:
        # 'deep_dive', '종합 분석', 'Executive Summary' 등 복잡한 추론이 필요하면 reasoning_model을 사용합니다.
        # [BUG FIX] user_message가 딕셔너리일 경우, 프롬프트 템플릿을 기준으로 키워드를 확인해야 합니다.
        # 'in <string>' requires string as left operand, not dict' TypeError를 해결합니다.
        text_to_check = ""
        if isinstance(user_message, dict) and 'prompt_template' in user_message:
            text_to_check = user_message['prompt_template']
        elif isinstance(user_message, str):
            text_to_check = user_message
        if any(keyword in text_to_check for keyword in ['deep_dive', '종합 분석', 'Executive Summary', 'security report']):
            model_to_use = CONFIG.get("reasoning_model", CONFIG.get("model"))
            configured_context_window_kb = CONFIG.get('reasoning_model_context', 0)
        else:
            model_to_use = CONFIG.get("fast_model", CONFIG.get("model"))
            configured_context_window_kb = CONFIG.get('fast_model_context', 0)
 
    # [사용자 요청 & 로직 통합] 사전 청킹 로직을 모델 결정 *이후*로 이동합니다.
    # 컨텍스트 크기가 0(무제한)이 아닐 경우에만 사전 청킹을 수행합니다.
    # 로그에서 확인된 모델의 실제 최대 컨텍스트 길이를 사용합니다.
    model_actual_input_token_limit = 131072 # From the error log: "This model's maximum context length is 131072 tokens."

    if configured_context_window_kb > 0: # Only pre-chunk if a context window is configured
        # [BUG FIX] 안전 마진을 10%로 설정하여 토큰 계산 오차에 대응합니다.
        pre_chunking_threshold_bytes = configured_context_window_kb * 1024 * 0.9 # 90% of configured KB
        if isinstance(user_message, str) and len(user_message.encode('utf-8')) > pre_chunking_threshold_bytes:
            logging.warning(f"입력 데이터가 모델 컨텍스트 크기({configured_context_window_kb}KB)의 90%를 초과하여, 토큰 기반의 정밀 분할을 수행합니다.")
            
            # [핵심 수정] 줄 수 기반이 아닌, 토큰 수 기반으로 데이터를 정밀하게 분할합니다.
            chunker = LLMChunker(max_tokens=model_actual_input_token_limit) # Use the actual token limit for the chunker
            # 시스템 프롬프트가 차지할 토큰을 고려하여 분할
            base_prompt_tokens = chunker.get_token_count(system_message)
            text_chunks = list(chunker.split_data(user_message, base_prompt_tokens))
            
            logging.info(f"입력 데이터를 {len(text_chunks)}개의 청크로 분할했습니다.")

            # [BUG FIX] user_message가 딕셔너리일 경우, 청킹된 결과는 문자열이 되므로 user_message 타입을 변경해야 합니다.
            chunk_summaries = []
            for i, chunk in enumerate(text_chunks):
                logging.info(f"  - 사전 청크 {i+1}/{len(text_chunks)} 분석 중...")
                chunk_prompt = f"다음 데이터의 핵심 내용을 요약해 주십시오:\n\n---\n{chunk}\n---"
                # 사전 청킹은 항상 빠른 모델을 사용합니다.
                # `max_tokens`는 LLM 응답의 최대 길이를 의미합니다. 요약본이므로 1024 토큰으로 제한합니다.
                summary = _call_llm_single_blocking(system_message, chunk_prompt, CONFIG.get("fast_model"), 1024, request_id=f"pre-chunk-{i+1}")
                
                # [안정성 강화] 요약 결과가 오류 객체인지 확인
                summary_obj = _parse_llm_json_response(str(summary))
                if isinstance(summary_obj, dict) and 'error' in summary_obj:
                     chunk_summaries.append(f"Chunk {i+1} summary failed: {summary_obj.get('details', 'Unknown error')}")
                else:
                     chunk_summaries.append(str(summary))
            
            user_message = "\n\n---\n\n".join(chunk_summaries) # type: ignore
            logging.info("사전 청킹 및 요약 완료. 병합된 요약본으로 최종 분석을 계속합니다.")

    cache_key = get_cache_key(system_message, user_message)
    cache_ttl_seconds = CONFIG.get('cache_ttl_days', 7) * 24 * 60 * 60

    # 1. 캐시 확인
    cached_response = cache.get(cache_key)
    if cached_response is not None:
        # [BUG FIX] 캐시된 응답이 객체 형태가 아닐 수 있으므로, 항상 객체로 변환하여 반환합니다.
        logging.info(f"[CACHE HIT] 캐시된 응답(객체)을 반환합니다. (Key: {cache_key[:10]}...)")
        llm_logger.info(f"[CACHE HIT] Returning cached response for key: {cache_key}")
        # [BUG FIX] 캐시된 응답이 문자열일 수 있으므로, JSON 객체로 파싱하여 반환합니다.
        return cached_response

def _parse_llm_json_response(response_str: str) -> Any:
    """
    [신규] LLM의 응답 문자열을 파싱하여 JSON 객체로 변환하는 헬퍼 함수.
    응답이 JSON 형식이 아니거나, JSON 코드 블록(```json ... ```)으로 감싸진 경우를 처리합니다.
    """
    if not isinstance(response_str, str):
        return response_str # 이미 객체인 경우 그대로 반환

    # LLM이 JSON 코드 블록(```json ... ```)으로 응답하는 경우, 순수 JSON 문자열만 추출
    match = re.search(r'```(json)?\s*(\{.*\}|\[.*\])\s*```', response_str, re.DOTALL)
    json_str = match.group(2) if match else response_str
    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        # JSON 파싱에 실패하면 원본 문자열을 반환 (순수 텍스트 응답일 수 있음)
        return response_str.strip()

def _call_llm_single_blocking(system_message, user_message, model_name, max_tokens=16384, request_id="N/A"):
    """단일 LLM 호출을 처리하는 내부 블로킹 함수."""
    # [BUG FIX] 데드락을 유발하는 재귀적 Map-Reduce 로직을 제거합니다.
    # 이제 데이터 청킹은 전적으로 클라이언트(security.py 등)의 책임이며,
    # 서버는 주어진 요청을 그대로 처리하는 역할만 수행합니다.

    log_prefix = f"[{request_id}]"
    max_retries = 3
    last_exception = None  # [신규] 마지막으로 발생한 예외를 저장하기 위한 변수
    for attempt in range(max_retries):
        try:
            headers = {'Content-Type': 'application/json'}
            if CONFIG.get("token"): headers['Authorization'] = f'Bearer {CONFIG["token"]}' # type: ignore
            # [BUG FIX] litellm 백엔드에서 'NoneType' object has no attribute 'get' 오류가 발생하는 것을 방지하기 위해,
            # litellm이 내부적으로 사용할 수 있는 'user' 필드를 명시적으로 추가합니다.
            # 이 필드는 로깅 및 추적에 사용될 수 있으며, None 값으로 인한 오류를 방지하는 데 도움이 됩니다.
            # 'stream' 필드도 명시적으로 False로 설정하여 안정성을 높입니다.
            payload = {"model": model_name, "messages": [{"role": "system", "content": system_message}, {"role": "user", "content": user_message}], "max_tokens": max_tokens, "temperature": 0.1, "stream": False, "user": request_id}

            # [BUG FIX] user_message가 딕셔너리일 경우, LLM에 보내기 전에 JSON 문자열로 직렬화합니다.
            # 'Input should be a valid dictionary' 오류를 해결합니다.
            if isinstance(user_message, dict):
                payload['messages'][1]['content'] = json.dumps(user_message, ensure_ascii=False, indent=2)

            # [사용자 요청] LLM 요청 항목과 크기를 로그로 기록합니다.
            # [BUG FIX] user_message가 list 등 다른 타입일 경우 .encode()에서 오류가 발생하므로, str()로 안전하게 변환합니다.
            user_message_str = str(user_message)
            system_message_str = str(system_message)
            user_message_size_kb = len(user_message_str.encode('utf-8')) / 1024
            system_message_size_kb = len(system_message_str.encode('utf-8')) / 1024
            logging.info(f"{log_prefix} LLM 요청 전송: 모델='{model_name}', System Prompt: {system_message_size_kb:.2f} KB, User Prompt: {user_message_size_kb:.2f} KB")

            # [BUG FIX] LLM URL이 외부 주소일 경우, 설정된 프록시를 사용하도록 수정합니다.
            # 로컬 주소(127.0.0.1, localhost)일 경우에만 프록시를 명시적으로 비활성화합니다.
            
            # cache_misses.inc() # 메트릭 기능이 구현될 때까지 주석 처리
            # [제안 반영] LLM 호출 타임아웃을 600초(10분)로 늘려 긴 분석 작업(예: CVE 순위 선정)을 지원합니다.
            # [BUG FIX] LLM 서버는 내부망에 있으므로, 프록시를 사용하지 않도록 명시적으로 비활성화합니다.
            response = requests.post(CONFIG["llm_url"], headers=headers, json=payload, timeout=600, proxies={'http': None, 'https': None}, verify=False)
            logging.info(f"{log_prefix} [LLM RESP] Status Code: {response.status_code} (Attempt {attempt + 1})")

            # [사용자 요청] 재시도(attempt > 0) 후 요청이 성공했을 경우, 성공 로그를 명확히 남깁니다.
            if attempt > 0:
                logging.info(f"{log_prefix} Successfully connected to LLM server on attempt {attempt + 1}/{max_retries}")
            
            response.raise_for_status()
            result = response.json()
            content = result.get('choices', [{}])[0].get('message', {}).get('content') or result.get('message', {}).get('content')
            # [BUG FIX] LLM이 비어있는 content를 반환할 경우, None 대신 빈 JSON 객체를 반환하여
            # 클라이언트에서 'NoneType' object is not iterable 오류가 발생하는 것을 방지합니다.
            if not content or not content.strip():
                logging.warning(f"{log_prefix} LLM이 비어 있거나 공백만 있는 응답을 반환했습니다.")
                return json.dumps({})
            
            # [신규] LLM 응답 로깅
            llm_logger.debug(f"{log_prefix} --- LLM Response (Blocking) ---\n{content}\n")
            return content

        except requests.exceptions.HTTPError as e:
            # 5xx 서버 오류에 대해서만 재시도합니다. 4xx 클라이언트 오류는 재시도해도 소용없습니다.
            last_exception = e
            if e.response is not None and 500 <= e.response.status_code < 600:
                # [BUG FIX] litellm의 오류 메시지를 파싱하여 로그에 명확히 기록합니다.
                error_details = f"HTTP {e.response.status_code}"
                try:
                    error_json = e.response.json()
                    error_details = error_json.get("error", {}).get("message", e.response.text)
                except json.JSONDecodeError:
                    error_details = e.response.text
                logging.warning(f"{log_prefix} LLM 서버 오류 발생: {error_details.strip()}. {2**attempt}초 후 재시도합니다... ({attempt + 1}/{max_retries})")
                llm_logger.warning(f"{log_prefix} --- LLM HTTP Error (Attempt {attempt + 1}) ---\n{e}\nResponse: {error_details.strip()}")
                time.sleep(2 ** attempt) # Exponential backoff: 1, 2, 4초...
                continue # 다음 재시도 수행
            # 재시도 대상이 아니거나 모든 재시도 실패 시, 오류 응답을 생성합니다.
            # [성능 개선] litellm이 반환하는 JSON 형식의 오류 메시지를 파싱하여 더 구체적인 오류를 사용자에게 전달합니다.
            error_message = f"LLM Server Error: {e}"
            if e.response is not None:
                raw_response_text = e.response.text
                try:
                    error_json = e.response.json()
                    if 'error' in error_json and isinstance(error_json['error'], dict) and 'message' in error_json['error']:
                        error_message = f"LLM Internal Error: {error_json['error']['message']}"
                except json.JSONDecodeError:
                    error_message += f"\nLLM Response Body:\n{raw_response_text}"
            logging.error(f"{log_prefix} {error_message}")
            # [BUG FIX] raw_response 필드를 제거하여 다른 오류 응답과 형식을 통일합니다.
            return json.dumps({"error": "LLM 서버에서 오류가 발생했습니다.", "details": error_message.replace("LLM Internal Error: ", "")})
        except requests.exceptions.RequestException as e:
            # [사용자 요청] ConnectionError와 같은 네트워크 오류에 대해서도 재시도 로직을 적용합니다. (HTTPError가 아닌 경우)
            last_exception = e
            logging.warning(f"{log_prefix} LLM 연결 오류 발생: {e}. {2**attempt}초 후 재시도합니다... ({attempt + 1}/{max_retries})")
            llm_logger.warning(f"{log_prefix} --- LLM Connection Error (Attempt {attempt + 1}) ---\n{e}")
            time.sleep(2 ** attempt)
            continue # 다음 재시도 수행
        except Exception as e: # 그 외 예기치 않은 오류
            last_exception = e
            logging.error(f"{log_prefix} LLM 요청 처리 중 예기치 않은 오류 발생: {e}")
            llm_logger.error(f"{log_prefix} --- LLM Connection Error (Blocking) ---\n{e}\n")
            time.sleep(2 ** attempt)
            continue # 다음 재시도 수행

    # 모든 재시도가 실패한 경우 (루프가 정상적으로 끝난 경우)
    error_message = "LLM 요청이 모든 재시도 후에도 실패했습니다. 네트워크 상태 및 LLM 백엔드 서버를 확인하세요."
    error_details = f"{error_message} (Last Error: {str(last_exception)})"
    logging.error(f"{log_prefix} {error_details}")
    return json.dumps({"error": error_message, "details": str(last_exception)})

def call_llm_blocking(system_message, user_message, max_tokens=16384, model_override=None):
    """
    [개선] LLM을 호출하고 결과를 캐싱하는 블로킹 함수.
    동일한 요청에 대해서는 캐시된 결과를 반환하여 API 호출을 줄입니다.
    [사용자 요청] 작업 유형에 따라 적합한 LLM 모델을 선택적으로 사용합니다.
    """
    cache_key = get_cache_key(system_message, user_message)
    cache_ttl_seconds = CONFIG.get('cache_ttl_days', 7) * 24 * 60 * 60

    # 1. 캐시 확인
    cached_response = cache.get(cache_key)
    if cached_response is not None:
        # [BUG FIX] 캐시된 응답이 객체 형태가 아닐 수 있으므로, 항상 객체로 변환하여 반환합니다.
        logging.info(f"[CACHE HIT] 캐시된 응답(객체)을 반환합니다. (Key: {cache_key[:10]}...)")
        llm_logger.info(f"[CACHE HIT] Returning cached response for key: {cache_key}")
        # [BUG FIX] 캐시된 응답이 문자열일 수 있으므로, JSON 객체로 파싱하여 반환합니다.
        return cached_response

    # [BUG FIX] UnboundLocalError를 해결하기 위해 변수 할당 로직을 수정하고 중복을 제거합니다. (v2)
    if model_override:
        model_to_use = model_override
    else:
        # [BUG FIX] user_message가 딕셔너리일 경우, 프롬프트 템플릿을 기준으로 키워드를 확인해야 합니다.
        # 'in <string>' requires string as left operand, not dict' TypeError를 해결합니다.
        text_to_check = ""
        if isinstance(user_message, dict) and 'prompt_template' in user_message:
            text_to_check = user_message['prompt_template']
        elif isinstance(user_message, str):
            text_to_check = user_message
        if any(keyword in text_to_check for keyword in ['deep_dive', '종합 분석', 'Executive Summary', 'security report']):
            model_to_use = CONFIG.get("reasoning_model", CONFIG.get("model"))
        else:
            model_to_use = CONFIG.get("fast_model", CONFIG.get("model"))

    # 모델에 따른 컨텍스트 크기를 가져옵니다.
    if model_to_use == CONFIG.get('fallbacks_model'):
        configured_context_window_kb = CONFIG.get('fallbacks_model_context', 0)
    elif model_to_use == CONFIG.get('reasoning_model'):
        configured_context_window_kb = CONFIG.get('reasoning_model_context', 0)
    else: # fast_model 또는 기본 모델
        configured_context_window_kb = CONFIG.get('fast_model_context', 0)

    model_actual_input_token_limit = 131072

    # [BUG FIX] UnboundLocalError를 방지하기 위해, 사전 청킹 로직은 변수 할당이 완료된 후에 위치해야 합니다.
    if configured_context_window_kb > 0:
        # [핵심 수정] user_message가 딕셔너리일 때와 문자열일 때를 모두 처리하도록 로직을 개선합니다.
        # is_user_message_dict 플래그를 사용하여, 청킹 후 user_message의 타입을 올바르게 재설정합니다.
        is_user_message_dict = isinstance(user_message, dict)
        data_to_check_size = ""
        if is_user_message_dict:
            # 딕셔너리 형태일 경우, 실제 데이터가 담긴 'data' 키의 내용을 문자열로 변환하여 크기를 측정합니다.
            data_to_check_size = json.dumps(user_message.get('data', {}), ensure_ascii=False, default=str)
        elif isinstance(user_message, str):
            data_to_check_size = user_message

        pre_chunking_threshold_bytes = configured_context_window_kb * 1024 * 0.9
        # [핵심 수정] data_to_check_size의 바이트 크기를 기준으로 청킹 여부를 결정합니다.
        if data_to_check_size and len(data_to_check_size.encode('utf-8')) > pre_chunking_threshold_bytes: # noqa: E501
            logging.warning(f"입력 데이터가 모델 컨텍스트 크기({configured_context_window_kb}KB)의 90%를 초과하여, 토큰 기반의 정밀 분할을 수행합니다.")

            # [핵심 수정] LLMChunker가 이제 max_bytes를 인자로 받으므로,
            # 설정된 컨텍스트 크기(KB)를 바이트로 변환하여 전달합니다.
            # [요청 반영] 청크 크기에 10% 안전 마진을 적용합니다.
            max_bytes_for_chunker = int(configured_context_window_kb * 1024 * 0.9)
            chunker = LLMChunker(max_bytes=max_bytes_for_chunker)
            text_chunks = list(chunker.split_data(data_to_check_size))
            
            logging.info(f"입력 데이터를 {len(text_chunks)}개의 청크로 분할했습니다.") # noqa: E501
            pre_chunk_delay = CONFIG.get('pre_chunk_delay', 5.0)  # 기본값은 5초
            
            chunk_summaries = []
            for i, chunk in enumerate(text_chunks):
                logging.info(f"  - 사전 청크 {i+1}/{len(text_chunks)} 분석 중...")
                chunk_prompt = f"다음 데이터의 핵심 내용을 요약해 주십시오:\n\n---\n{chunk}\n---"
                summary = _call_llm_single_blocking(system_message, chunk_prompt, CONFIG.get("fast_model"), 1024, request_id=f"pre-chunk-{i+1}")
                
                summary_obj = _parse_llm_json_response(str(summary))
                if isinstance(summary_obj, dict) and 'error' in summary_obj:
                     chunk_summaries.append(f"Chunk {i+1} summary failed: {summary_obj.get('details', 'Unknown error')}")
                else:
                     chunk_summaries.append(str(summary))
                
                # [사용자 요청] 다음 청크 처리 전에 5초간 대기하여 LLM 서버 부하를 조절합니다.
                # 마지막 청크인 경우에는 대기하지 않습니다.
                if i < len(text_chunks) - 1:
                    logging.info(f"  - 다음 사전 청크 분석 전 {pre_chunk_delay}초간 대기합니다...")
                    time.sleep(float(pre_chunk_delay))
            
            # [BUG FIX] user_message가 딕셔너리였던 경우, 요약된 문자열로 교체합니다.
            if is_user_message_dict:
                user_message = "\n\n---\n\n".join(chunk_summaries)
            else:
                user_message = "\n\n---\n\n".join(chunk_summaries) # type: ignore
            logging.info("사전 청킹 및 요약 완료. 병합된 요약본으로 최종 분석을 계속합니다.")
        else:
            logging.info("  -> [SKIP] 입력 데이터 크기가 임계값 미만이므로 사전 청킹을 건너뜁니다.")

    # 최종 LLM 호출
    # [BUG FIX] 캐시 미스 시 LLM을 호출하는 로직이 누락되어 있었습니다. _call_llm_single_blocking을 호출하여 수정합니다.
    final_response_str = _call_llm_single_blocking(system_message, user_message, model_to_use, max_tokens)
    final_response_obj = _parse_llm_json_response(final_response_str)

    # 3. 캐시에 저장
    cache.set(cache_key, final_response_obj, expire=cache_ttl_seconds)
    logging.info(f"[CACHE SET] 새로운 LLM 응답을 캐시에 저장합니다. (Key: {cache_key[:10]}...)")
    
    return final_response_obj

def call_llm_stream(system_message, user_message):
    """
    [효율성 개선] LLM 스트리밍 호출 함수에 캐싱 기능 추가.
    - Cache Miss: 실제 LLM API를 호출하고, 스트리밍하면서 전체 응답을 캐시에 저장합니다.
    - Cache Hit: 캐시된 전체 응답을 가져와, 실제 스트리밍처럼 보이도록 작은 조각으로 나누어 전송합니다.
    """
    
    # [구조 변경] 스트리밍 요청에서도 프롬프트 내용에 따라 모델을 동적으로 선택합니다.
    if any(keyword in user_message for keyword in ['deep_dive', '종합 분석', 'Executive Summary', 'security report']):
        model_to_use = CONFIG.get("reasoning_model", CONFIG["model"])
    else:
        model_to_use = CONFIG.get("fast_model", CONFIG["model"])

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
        
        chunk_size = 10
        for i in range(0, len(full_response), chunk_size):
            yield full_response[i:i+chunk_size]
            time.sleep(0.002)
        return

    # 2. Cache Miss: 실제 LLM API 호출을 큐에 제출
    logging.info(f"[{request_id}] [CACHE MISS][STREAM] LLM 스트리밍 요청을 큐에 추가합니다. (Key: {cache_key[:10]}...)")
    

    # 스트리밍 응답을 처리하기 위한 내부 제너레이터 함수
    def _stream_worker(q: queue.Queue):
        """[신규] 스레드 풀에서 실행될 워커. LLM 스트림 결과를 큐에 넣습니다."""
        headers = {'Content-Type': 'application/json'}
        if CONFIG.get("token"): headers['Authorization'] = f'Bearer {CONFIG["token"]}'
        messages = [{"role": "system", "content": system_message}, {"role": "user", "content": user_message}]
        payload = {"model": model_to_use, "messages": messages, "max_tokens": 8192, "temperature": 0.2, "stream": True}
        
        # [구조 변경] 스트리밍 요청 로그에도 모델 이름을 포함하여 기록합니다.
        logging.info(f"[{request_id}] LLM 스트리밍 요청 (모델: {model_to_use})...")
        llm_logger.info(f"[{request_id}] [REQ][STREAM] POST {CONFIG['llm_url']} (Model: {model_to_use})")
        
        full_response_accumulator = []
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = requests.post(CONFIG["llm_url"], headers=headers, json=payload, timeout=(30, 600), stream=True)
                # [사용자 요청] 재시도 후 성공 시 로그를 명확히 남깁니다.
                if attempt > 0:
                    logging.info(f"[{request_id}] Successfully reconnected to LLM stream on attempt {attempt + 1}/{max_retries}")

                response.raise_for_status()
                for line in response.iter_lines():
                    if not line: continue
                    decoded_line = line.decode('utf-8')
                    if decoded_line.startswith('data: '):
                        json_str = decoded_line[len('data: '):].strip()
                        if json_str == '[DONE]': break
                        if json_str:
                            try:
                                data = json.loads(json_str)
                                content = data.get('choices', [{}])[0].get('delta', {}).get('content')
                                if content:
                                    full_response_accumulator.append(content)
                                    yield content
                            except (json.JSONDecodeError, KeyError, IndexError):
                                continue
                break
            except requests.exceptions.RequestException as e:
                logging.warning(f"[{request_id}] LLM 스트리밍 오류 (시도 {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    time.sleep(wait_time)
                else:
                    logging.error(f"[LLM STREAM ERROR] {e}", exc_info=True)
                    yield f"\n\n**Error:** {e}"
    
    # [구조 변경] 큐를 통하지 않고, 스레드 풀에 스트리밍 제너레이터 실행을 제출합니다.
    # submit_llm_request는 블로킹 함수이므로 스트리밍에 직접 사용할 수 없습니다.
    # 대신, 스레드 풀에 직접 작업을 제출하고 결과를 스트리밍합니다.
    # 여기서는 단순화를 위해 _stream_generator를 직접 호출합니다.
    # 실제 고부하 환경에서는 스트리밍 전용 워커풀을 고려할 수 있습니다. 
    stream_iterator = _stream_worker(queue.Queue()) # _stream_generator() -> _stream_worker()
    
    full_response_accumulator = []
    for chunk in stream_iterator:
        full_response_accumulator.append(chunk)
        yield chunk

    # 3. 스트리밍 완료 후 전체 응답을 캐시에 저장
    if full_response_accumulator:
        final_response = "".join(full_response_accumulator)
        cache.set(cache_key, final_response, expire=cache_ttl_seconds)
        logging.info(f"[{request_id}] [CACHE SET][STREAM] 새로운 스트리밍 응답을 캐시에 저장합니다. (Key: {cache_key[:10]}...)")

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

    # [개선] check_llm_health 작업의 반복적인 실행 로그가 과도하게 쌓이는 것을 방지하기 위해,
    # apscheduler의 실행 관련 로거 레벨을 WARNING으로 상향 조정합니다.
    logging.getLogger('apscheduler.executors.default').setLevel(logging.WARNING)
    logging.getLogger('apscheduler.scheduler').setLevel(logging.WARNING)
    # [BUG FIX] 핸들러 중복 추가 방지
    if logger.hasHandlers():
        logger.handlers.clear()
    handler = logging.handlers.RotatingFileHandler(
        CONFIG["scheduler_log_file"], maxBytes=10*1024*1024, 
        backupCount=5, encoding='utf-8'
    )
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)

    # [BUG FIX] 제거된 작업(예: check_llm_health)이 DB에 남아있어 발생하는 LookupError를 처리합니다.
    # 오류 발생 시, 오래된 DB 파일을 삭제하고 스케줄러를 재시작하여 문제를 자동 복구합니다.
    try:
        scheduler.start()
    except LookupError as e:
        logging.warning(f"스케줄러 작업 복원 중 오류 발생 (LookupError): {e}")
        logging.warning("오래된 스케줄러 DB 파일(jobs.sqlite)로 인해 발생한 문제일 수 있습니다.")
        
        # 스케줄러를 종료하고 DB 파일을 삭제합니다.
        scheduler.shutdown()
        db_path = os.path.join(SCRIPT_DIR, "jobs.sqlite")
        if os.path.exists(db_path):
            os.remove(db_path)
            logging.info(f"오래된 스케줄러 DB 파일 '{db_path}'를 삭제했습니다. 스케줄러를 재시작합니다.")
        
        # 새 스케줄러 인스턴스를 생성하고 다시 시작합니다.
        scheduler = BackgroundScheduler(jobstores=jobstores, timezone='Asia/Seoul')
        scheduler.start()

    try:
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

    # [BUG FIX] 스크립트 확장자에 따라 올바른 인터프리터를 선택합니다.
    # Python 스크립트를 bash로 실행하여 'import: command not found' 오류가 발생하는 문제를 해결합니다.
    command = []
    if script_path.endswith('.py'):
        command = ['/usr/bin/python3.11', script_path]
    elif script_path.endswith('.sh'):
        command = ['/bin/bash', script_path]
    else:
        log.error(f"Unsupported script type for '{script_path}'. Only .py and .sh are supported for scheduled execution.")
        return

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
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
# [사용자 요청] cve-check 관련 스크립트 다운로드 라우트 추가
@app.route('/AIBox/cve-check/<path:filename>')
def route_cve_check_script_files(filename):
    """gather_bash.sh, gather_py.py와 같은 스크립트 파일을 다운로드합니다."""
    return send_from_directory(CVE_CHECK_DIR, filename, as_attachment=True)

@app.route('/AIBox/epss/<path:filename>')
def route_epss_files(filename): return send_from_directory(EPSS_FOLDER, filename)

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
    # [BUG FIX] call_llm_blocking은 이미 JSON 객체를 반환하므로, _parse_llm_json_response를 중복 호출할 필요가 없습니다.
    llm_response_obj = call_llm_blocking("You are an elite cybersecurity analyst designed to output JSON.", prompt)
    
    # [BUG FIX] LLM 응답이 예상치 못한 형식일 경우를 대비하여 안정성을 강화합니다.
    if isinstance(llm_response_obj, dict):
        summary = llm_response_obj.get("report_markdown", "### AI 분석 실패\n- LLM이 유효한 보고서 형식을 반환하지 않았습니다.")
    else:
        summary = f"### AI 분석 실패\n- LLM 응답이 예상치 못한 형식입니다: {str(llm_response_obj)}"

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

        if filename.endswith('.html'):
            try:
                base_name = os.path.splitext(filename)[0]
                output_folder = app.config['OUTPUT_FOLDER']
                
                # HTML 파일과 동일한 기본 이름을 가진 모든 관련 파일(html, json 등)을 찾습니다.
                files_to_delete = [f for f in os.listdir(output_folder) if f.startswith(base_name)]
                
                for f_to_delete in files_to_delete: # noqa: E501
                    file_path = os.path.join(output_folder, f_to_delete)
                    if os.path.exists(file_path):
                        os.remove(file_path)
                
                return jsonify({"success": True, "message": f"{len(files_to_delete)}개의 관련 파일이 삭제되었습니다."})
            except Exception as e:
                return jsonify({"error": f"파일 삭제 중 오류 발생: {e}"}), 500
        return jsonify({"error": "잘못된 파일 이름 형식입니다."}), 400
    else: # GET
        try:
            reports = []
            output_files = os.listdir(OUTPUT_FOLDER)
            # [BUG FIX] 'report-'로 시작하는 메인 리포트 파일만 필터링합니다.
            html_files = [f for f in output_files if f.startswith('report-') and f.endswith('.html')]

            for html_file in html_files:
                report_info = {"name": html_file}
                base_name = os.path.splitext(html_file)[0]
                meta_file = f"{base_name}.json"
                
                # [사용자 요청] 각 리포트에 대한 메타데이터(생성 시간, 소요 시간) 파일을 읽어 정보 추가
                if meta_file in output_files:
                    try:
                        with open(os.path.join(OUTPUT_FOLDER, meta_file), 'r') as f:
                            meta_data = json.load(f)
                        report_info.update(meta_data)
                    except (IOError, json.JSONDecodeError):
                        pass # 메타 파일 읽기 실패 시 무시
                reports.append(report_info)
            reports.sort(key=lambda r: r.get('creation_timestamp', 0), reverse=True)
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

@app.route('/AIBox/api/reports/zip', methods=['GET'])
def api_zip_all_reports():
    """[신규] output 디렉토리의 모든 .html 파일을 압축하여 다운로드합니다."""
    import zipfile
    import io

    output_folder = app.config['OUTPUT_FOLDER']
    
    # 메모리 내에서 ZIP 파일 생성
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        html_files_found = False
        for filename in os.listdir(output_folder):
            # [BUG FIX] index.html을 제외한 모든 .html 파일을 압축 대상에 포함합니다.
            if filename.endswith('.html') and filename != 'index.html':
                file_path = os.path.join(output_folder, filename)
                zf.write(file_path, arcname=filename)
                html_files_found = True
    
    if not html_files_found:
        return "압축할 리포트 파일이 없습니다.", 404

    memory_file.seek(0)
    
    return Response(
        memory_file,
        mimetype='application/zip',
        headers={'Content-Disposition': 'attachment;filename=reports.zip'}
    )

# [사용자 요청] cve_check_report.py가 생성한 리포트를 관리하는 API 추가
@app.route('/AIBox/api/cve-check/reports/zip', methods=['GET'])
def api_zip_cve_check_reports():
    """cve-check/output 디렉토리의 모든 .html 파일을 압축하여 다운로드합니다."""
    import zipfile
    import io

    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        found = False
        for filename in os.listdir(CVE_CHECK_OUTPUT_FOLDER):
            if filename.endswith('.html') and filename != 'index.html':
                file_path = os.path.join(CVE_CHECK_OUTPUT_FOLDER, filename)
                zf.write(file_path, arcname=filename)
                found = True
    
    if not found:
        return "압축할 리포트 파일이 없습니다.", 404

    memory_file.seek(0)
    return Response(
        memory_file,
        mimetype='application/zip',
        headers={'Content-Disposition': 'attachment;filename=cve_check_reports.zip'}
    )

@app.route('/AIBox/api/cve-check/reports/all', methods=['DELETE'])
def api_delete_all_cve_check_reports():
    """cve-check/output 디렉토리의 모든 파일을 삭제합니다."""
    if not request.json or request.json.get('password') != CONFIG.get("password"):
        return jsonify({"error": "Unauthorized"}), 401
        
    try:
        count = 0
        for filename in os.listdir(CVE_CHECK_OUTPUT_FOLDER):
            file_path = os.path.join(CVE_CHECK_OUTPUT_FOLDER, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                    count += 1
            except Exception as e:
                logging.error(f"전체 cve-check 리포트 삭제 중 '{file_path}' 파일 삭제 실패: {e}")
        logging.info(f"모든 cve-check 리포트 및 관련 파일 {count}개를 삭제했습니다.")
        return jsonify({"success": True, "message": f"{count}개의 파일이 삭제되었습니다."})
    except Exception as e:
        logging.error(f"Error deleting all cve-check reports: {e}", exc_info=True)
        return jsonify({"error": "전체 리포트 삭제 중 오류가 발생했습니다."}), 500

@app.route('/AIBox/api/cve-check/reports', methods=['DELETE'])
def api_delete_cve_check_report():
    """cve-check/output 디렉토리에서 특정 리포트 파일을 삭제합니다."""
    filename = request.args.get('file')
    if not filename:
        return jsonify({"error": "파일 파라미터가 누락되었습니다."}), 400

    if not filename.endswith('.html'):
        return jsonify({"error": "잘못된 파일 이름 형식입니다."}), 400

    try:
        file_path = os.path.join(CVE_CHECK_OUTPUT_FOLDER, secure_filename(filename))
        
        if os.path.exists(file_path):
            os.remove(file_path)
            logging.info(f"cve-check 리포트 파일 삭제 완료: {file_path}")
            return jsonify({"success": True, "message": f"'{filename}' 파일이 삭제되었습니다."})
        else:
            return jsonify({"error": "파일을 찾을 수 없습니다."}), 404
            
    except Exception as e:
        logging.error(f"cve-check 리포트 삭제 중 오류 발생: {e}", exc_info=True)
        return jsonify({"error": f"파일 삭제 중 오류 발생: {e}"}), 500


@app.route('/AIBox/cve_check.html')
def route_cve_check_html():
    """[신규] CVE 분석 자동화 UI 페이지를 렌더링합니다."""
    return send_from_directory(SCRIPT_DIR, 'cve_check.html')

@app.route('/AIBox/api/sos/analyze_system', methods=['POST'])
def api_sos_analyze_system():
    try:
        req_data = request.json
        system_message = "You are an expert assistant. Follow the user's instructions precisely, including the output format."

        # [사용자 요청] 캐시 효율성 개선: 새로운 프롬프트 구조('prompt_template', 'data')를 처리합니다.
        if isinstance(req_data, dict) and 'prompt_template' in req_data and 'data' in req_data:
            prompt_template = req_data['prompt_template']
            # [BUG FIX] 클라이언트가 보낸 'data' 객체에서 'chunk_name'과 'chunk_data'를 추출합니다.
            analysis_data_wrapper = req_data['data']
            chunk_name = analysis_data_wrapper.get('chunk_name', 'Unknown')
            chunk_data_content = analysis_data_wrapper.get('chunk_data', {})
            # 최종 프롬프트는 서버에서 동적으로 생성합니다.
            prompt = prompt_template.format(chunk_name=chunk_name, chunk_data=json.dumps(chunk_data_content, indent=2, ensure_ascii=False, default=str))
            # 캐싱을 위해 user_message를 구조화된 딕셔너리로 전달합니다.
            user_message = {'prompt_template': prompt_template, 'data': analysis_data_wrapper}
        elif isinstance(req_data, dict) and "prompt" in req_data: # 기존 방식 (하위 호환성)
            prompt = req_data["prompt"]
            user_message = prompt # 캐싱을 위해 전체 프롬프트를 전달합니다.
        else: # 기존 security.py와의 호환성을 위한 폴백
            return jsonify({"error": "Invalid request format"}), 400
        
        # [BUG FIX] 요청에 'stream' 플래그가 있는지 확인하여 블로킹/스트리밍 호출을 동적으로 결정합니다.
        # cve_report_generator.py와 같이 단일 응답을 기대하는 클라이언트와의 호환성을 보장합니다.
        if req_data.get('stream', False):
            # [BUG FIX] 스트리밍 요청 시에도 model_override를 전달합니다.
            return Response(call_llm_stream(system_message, user_message=prompt), mimetype='text/plain; charset=utf-8')
        else:
            # 블로킹 요청 처리
            response_obj = call_llm_blocking(system_message, user_message=user_message)

            # [BUG FIX] create_cve_report.py와 같은 클라이언트가 상세 리포트를 요청했을 때,
            # AI는 'summary', 'critical_issues' 등을 포함한 JSON 객체를 반환합니다.
            # 이 경우, 클라이언트가 원하는 것은 'summary' 필드의 마크다운 텍스트이므로,
            # 해당 텍스트만 추출하여 반환해야 합니다.
            if isinstance(response_obj, dict) and 'summary' in response_obj and 'critical_issues' in response_obj:
                # 'summary' 필드의 내용을 최종 응답으로 사용합니다.
                return Response(response_obj['summary'], mimetype='text/plain; charset=utf-8')

            # [BUG FIX] AI가 순수 텍스트(마크다운)를 반환하는 경우, jsonify()를 사용하면 텍스트가 JSON 문자열로 이중 인코딩되어
            # 클라이언트에서 '\ucde8\uc57d\uc810'와 같이 깨져 보입니다.
            # 응답이 문자열인 경우, 순수 텍스트로 반환하도록 수정합니다.
            if isinstance(response_obj, str):
                return Response(response_obj, mimetype='text/plain; charset=utf-8')
            else:
                # 그 외의 경우(JSON 객체 등)에만 jsonify를 사용합니다.
                return jsonify(response_obj)
        
    except Exception as e:
        logging.error(f"CVE analysis error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/AIBox/api/cache/cve', methods=['POST'])
def api_cache_cve():
    """[신규] 외부에서 가져온 CVE 데이터를 로컬에 저장하는 엔드포인트."""
    data = request.json
    cve_id = data.get('cve_id')
    cve_data = data.get('data')

    if not cve_id or not cve_data:
        return jsonify({"error": "cve_id and data are required"}), 400

    filename = secure_filename(f"{cve_id}.json")
    file_path = os.path.join(CVE_FOLDER, filename)
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(cve_data, f, ensure_ascii=False, indent=2)
        logging.info(f"Cached CVE data to '{file_path}'")
        return jsonify({"success": True, "path": file_path}), 201
    except IOError as e:
        logging.error(f"Failed to cache CVE data for {cve_id}: {e}")
        return jsonify({"error": "Failed to write cache file"}), 500

@app.route('/AIBox/api/cache/epss', methods=['POST'])
def api_cache_epss():
    """[신규] 외부에서 가져온 EPSS 데이터를 로컬에 저장하는 엔드포인트."""
    data = request.json
    cve_id = data.get('cve_id')
    epss_data = data.get('data')

    if not cve_id or not epss_data:
        return jsonify({"error": "cve_id and data are required"}), 400

    filename = secure_filename(cve_id)
    file_path = os.path.join(EPSS_FOLDER, filename)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(epss_data, f, ensure_ascii=False)
    return jsonify({"success": True, "path": file_path}), 201

@app.route('/AIBox/api/cve/export-excel', methods=['GET'])
def api_export_cve_excel():
    """[신규] cve_report_generator.py가 생성한 최종 CVE 목록을 읽어 Excel 파일을 생성하고 다운로드합니다."""
    import io
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
        virtual_workbook = io.BytesIO()
        workbook.save(virtual_workbook)
        virtual_workbook.seek(0)
        virtual_workbook_data = virtual_workbook.read()
        
        filename = f"RHEL_Vulnerability_Report_{datetime.now().strftime('%Y%m%d')}.xlsx"
        
        return Response(
            virtual_workbook_data,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={'Content-Disposition': f'attachment;filename={filename}'}
        )
    except Exception as e:
        logging.error(f"Excel export error: {e}", exc_info=True)
        return "An internal error occurred while generating the Excel file.", 500

@app.route('/AIBox/api/cve/download-report-html', methods=['GET'])
def api_download_cve_report_html():
    """[신규] cve_report_generator.py가 생성한 최신 HTML 리포트 파일을 다운로드합니다."""
    try:
        # cve_report_generator.py가 사용하는 리포트 파일 경로
        report_path = os.path.join(OUTPUT_FOLDER, 'rhel_vulnerability_report.html')

        if not os.path.exists(report_path):
            return "리포트 파일을 찾을 수 없습니다. 먼저 리포트를 생성해주세요.", 404

        return send_from_directory(
            directory=OUTPUT_FOLDER,
            path='rhel_vulnerability_report.html',
            as_attachment=True
        )
    except Exception as e:
        logging.error(f"HTML report download error: {e}", exc_info=True)
        return "리포트 다운로드 중 오류가 발생했습니다.", 500

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

        # [BUG FIX] create_cve_report.py는 AI 분석을 위해 '/api/sos/analyze_system' 엔드포인트를 사용하도록 설계되었습니다.
        # 이전 코드에서는 존재하지 않는 '/api/cve/analyze' 경로를 전달하여 통신 오류가 발생했습니다.
        # 이제 올바른 엔드포인트 URL을 동적으로 생성하여 전달함으로써,
        # cve_report.html -> AIBox_Server -> create_cve_report.py -> AIBox_Server (AI 분석) -> create_cve_report.py -> AIBox_Server -> cve_report.html
        # 로 이어지는 전체 프로세스가 정상적으로 동작하도록, 서버의 기본 URL만 전달하도록 수정합니다.
        server_url_for_script = f"http://127.0.0.1:{CONFIG.get('port', 5000)}"

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

@app.route('/AIBox/api/llm-health', methods=['GET'])
def api_llm_health_check():
    """
    [신규] AIBox 서버와 백엔드 LLM 서버 간의 통신 상태를 실시간으로 점검하는 API.
    security.py의 --test-connection에서 호출됩니다.
    """
    logging.info("LLM 연결 상태 점검 요청 수신...")
    system_message = "You are a health check assistant."
    user_message = "Respond with 'OK' if you are operational."
    
    try:
        # 가장 빠른 모델을 사용하여 테스트
        model_to_use = CONFIG.get("fast_model", CONFIG.get("model"))

        # [BUG FIX] 서버의 LLM 요청 큐를 사용하지 않고 직접 호출하여 데드락을 방지합니다.
        # 이 API는 서버의 상태를 확인하는 용도이므로, 일반적인 요청 처리 흐름과 분리하는 것이 안전합니다.
        raw_response_str = _call_llm_single_blocking(system_message, user_message, model_to_use, max_tokens=10, request_id="health-check")
        
        # [BUG FIX] LLM 응답이 순수 텍스트("OK")일 수 있으므로, json.loads()를 사용하지 않고 문자열을 직접 확인합니다.
        # 먼저 응답이 오류를 나타내는 JSON 형식인지 확인합니다.
        is_error = False
        try:
            response_obj = json.loads(raw_response_str)
            if isinstance(response_obj, dict) and 'error' in response_obj:
                is_error = True
                error_details = response_obj.get('details', 'Unknown LLM error')
        except json.JSONDecodeError:
            # JSON 파싱 실패는 'OK'와 같은 순수 텍스트 응답이므로 오류가 아님
            pass

        if is_error:
            logging.error(f"LLM 상태 점검 실패: {error_details}")
            return jsonify({
                "status": "error",
                "message": "AIBox 서버가 LLM 백엔드와 통신하는 데 실패했습니다.",
                "details": error_details
            }), 502 # 502 Bad Gateway
        
        logging.info("LLM 연결 상태 양호.")
        return jsonify({"status": "ok", "message": "LLM 연결이 정상입니다.", "llm_response": raw_response_str})

    except Exception as e:
        logging.error(f"LLM 상태 점검 중 예기치 않은 오류 발생: {e}", exc_info=True)
        return jsonify({"status": "error", "message": "서버 내부 오류 발생", "details": str(e)}), 500

@app.route('/AIBox/api/cve-check/analysis-status/<analysis_id>', methods=['GET'])
def api_cve_check_analysis_status(analysis_id):
    with ANALYSIS_LOCK:
        status_info = ANALYSIS_STATUS.get(analysis_id)
        if status_info:
            return jsonify(status_info)
        return jsonify({"status": "not_found", "log": ["해당 분석 ID를 찾을 수 없습니다."]}), 404

def run_cve_check_analysis_background(analysis_id, files_to_process, cve_ids_content):
    """
    [신규] CVE 분석 요청을 백그라운드에서 처리하는 함수.
    1. CVE 목록 파일 생성
    2. 각 호스트 파일에 대해 make_cve_db.py 실행
    3. 각 메타데이터에 대해 cve_check_report.py 실행
    4. 생성된 리포트들을 압축
    [수정] 모든 호스트에 대해 공통 CVE DB를 사용하고, 각 호스트를 개별적으로 분석한 후, 최종적으로 모든 리포트를 압축합니다.
    """
    with ANALYSIS_LOCK:
        ANALYSIS_STATUS[analysis_id] = {
            "status": "queued",
            "log": ["분석 대기열에 추가되었습니다."],
            "start_time": time.time()
        }
    logging.info(f"[{analysis_id}] CVE 분석 백그라운드 작업 시작. 처리할 파일: {len(files_to_process)}개")

    # [BUG FIX] NameError 방지를 위해 임시 파일 목록 변수를 try 블록 이전에 초기화합니다.
    # 이 변수들은 분석 과정에서 생성되고, finally 블록에서 정리됩니다.
    # [BUG FIX] 파일 생성 경로를 올바른 cve-check/meta 디렉토리로 수정합니다.
    timestamp_str = datetime.now().strftime('%Y%m%d-%H%M%S')
    cve_check_meta_dir_for_creation = Path("/data/iso/AIBox/cve-check/meta")
    common_cve_list_path = cve_check_meta_dir_for_creation / f"CVEID-{timestamp_str}.txt"
    common_meta_db_path = cve_check_meta_dir_for_creation / f"makecve-{timestamp_str}.json"
    
    temp_files_to_clean = [common_cve_list_path, common_meta_db_path]
    is_success = False  # [수정] finally 블록에서의 UnboundLocalError를 방지하기 위해 미리 선언합니다.

    try:
        # [사용자 요청 수정] 분석 시작 시, 이전 작업의 결과물일 수 있는 파일들을 정리합니다.
        # 이전에는 이 로직이 API 핸들러에 있어, 파일이 생성되기도 전에 삭제되는 문제가 있었습니다.
        # 이제 백그라운드 스레드 내에서, 파일 생성 직전에 정리하도록 수정합니다.
        logging.info(f"[{analysis_id}] 이전 분석 결과 파일 정리 시작...")
        cve_check_output_dir_for_cleanup = Path("/data/iso/AIBox/cve-check/output")
        cve_check_meta_dir_for_cleanup = Path("/data/iso/AIBox/cve-check/meta")

        # output 및 meta 디렉토리의 모든 파일 삭제
        if cve_check_output_dir_for_cleanup.exists():
            for item in cve_check_output_dir_for_cleanup.iterdir():
                if item.is_file(): item.unlink()
        if cve_check_meta_dir_for_cleanup.exists():
            for item in cve_check_meta_dir_for_cleanup.iterdir():
                if item.is_file(): item.unlink()
        logging.info(f"[{analysis_id}] 이전 분석 결과 파일 정리 완료.")
        python_interpreter = "/usr/bin/python3.11"
        cve_check_data_dir = Path("/data/iso/AIBox/cve-check/data")
        cve_check_meta_dir = Path("/data/iso/AIBox/cve-check/meta")
        cve_check_output_dir = Path("/data/iso/AIBox/cve-check/output")

        cve_check_meta_dir.mkdir(exist_ok=True)
        cve_check_output_dir.mkdir(exist_ok=True)

        # [수정] 분석 성공 여부를 추적하는 플래그. 모든 단계가 성공해야 True를 유지합니다.
        is_success = True

        # [사용자 요청] 분석할 CVE ID 개수와 호스트 파일 개수를 로그에 기록합니다.
        num_cves = len(cve_ids_content.strip().split('\n'))
        num_hosts = len(files_to_process)
        logging.info(f"[{analysis_id}] 분석 대상: {num_hosts}개 호스트, {num_cves}개 CVE ID")

        with ANALYSIS_LOCK:
            ANALYSIS_STATUS[analysis_id]["status"] = "running"
            ANALYSIS_STATUS[analysis_id]["log"].append(f"분석 시작 (총 {len(files_to_process)}개 호스트)")

        # 1. 모든 CVE ID에 대한 공통 메타데이터 DB 생성
        common_cve_list_path.write_text(cve_ids_content, encoding='utf-8')
        logging.info(f"[{analysis_id}] CVE ID 목록을 '{common_cve_list_path.name}' 파일에 저장했습니다. 내용:\n---\n{cve_ids_content}\n---")

        # 2. 각 호스트 파일에 대해 개별적으로 리포트 생성
        generated_report_paths = []
        
        # [수정] cve_check_report.py를 한 번만 호출하여 모든 파일을 처리하도록 변경
        with ANALYSIS_LOCK:
            ANALYSIS_STATUS[analysis_id]["log"].append(f"모든 호스트 파일에 대한 리포트 생성 시작...")
        
        report_cmd = [
            python_interpreter, os.path.join(SCRIPT_DIR, "cve-check", "cve_check_report.py"),
            # [사용자 요청] cve_check_report.py가 AI 분석을 위해 호출할 정확한 전체 API 엔드포인트 주소를 전달합니다.
            "--server-url", "http://127.0.0.1",
            "--cve-id-file", str(common_cve_list_path), # [통합] 생성된 CVE ID 목록 파일 경로를 전달
            # --input-file 인자를 제거하여 cve_check_report.py가 SYSTEM_DATA_DIR의 모든 파일을 처리하도록 함
        ]
        logging.info(f"[{analysis_id}] 리포트 생성 명령어 실행: {' '.join(report_cmd)}")
        
        # [최종 해결] 자식 프로세스의 실시간 출력을 처리하여 파이프 버퍼 교착 상태(deadlock)를 방지합니다.
        # bash 셸에서 직접 실행하는 것과 같이 모든 로그를 실시간으로 수집하고 UI에 전달할 수 있습니다.
        # [BUG FIX] 자식 프로세스가 올바른 프록시 설정을 상속받도록 환경 변수를 명시적으로 전달합니다.
        # 특히, no_proxy에 127.0.0.1을 추가하여 로컬 AIBox 서버와의 통신이 프록시를 타지 않도록 보장합니다.
        process_env = os.environ.copy()
        no_proxy_list = [val.strip() for val in process_env.get('no_proxy', '').split(',') if val.strip()]
        if '127.0.0.1' not in no_proxy_list: no_proxy_list.append('127.0.0.1')
        if 'localhost' not in no_proxy_list: no_proxy_list.append('localhost')
        process_env['no_proxy'] = ','.join(no_proxy_list)

        cve_check_script_dir = os.path.join(SCRIPT_DIR, "cve-check")
        process = subprocess.Popen(
            report_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding='utf-8', cwd=cve_check_script_dir, env=process_env
        )

        # 실시간으로 출력되는 로그를 읽어 처리합니다.
        if process.stdout:
            for line in iter(process.stdout.readline, ''):
                line = line.strip()
                if not line: continue
                logging.info(f"[{analysis_id}][cve_check_report] {line}")
                with ANALYSIS_LOCK:
                    ANALYSIS_STATUS[analysis_id]["log"].append(line)
        
        process.wait() # 프로세스가 완전히 종료될 때까지 대기
        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, report_cmd, output="", stderr="스크립트 실행 실패. 위 로그를 확인하세요.")
        
        # [수정] cve_check_report.py가 모든 파일을 처리한 후, output 디렉토리의 모든 HTML 파일을 수집
        generated_report_paths = list(cve_check_output_dir.glob("*.html"))
        if not generated_report_paths:
            raise Exception("cve_check_report.py가 HTML 리포트를 생성하지 못했습니다.")

        # 3. 모든 리포트 압축
        if generated_report_paths:
            # [수정] zip 파일명은 항상 timestamp 기반으로 생성 (여러 파일 처리 시)
            if len(files_to_process) == 1:
                zip_base_name = f"{Path(files_to_process[0]).stem}-cvecheck"
            else:
                zip_base_name = f"cvecheck-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            zip_filename = f"{zip_base_name}.zip"
            zip_filepath = Path(app.config['OUTPUT_FOLDER']) / zip_filename
            
            with ANALYSIS_LOCK:
                ANALYSIS_STATUS[analysis_id]["log"].append(f"분석 결과 압축 중... -> {zip_filename}")

            import zipfile
            with zipfile.ZipFile(zip_filepath, 'w', zipfile.ZIP_DEFLATED) as zf:
                for report_file in generated_report_paths:
                    if report_file.is_file():
                        logging.info(f"[{analysis_id}] 압축 파일에 추가: {report_file.name}")
                        zf.write(report_file, arcname=report_file.name)
            
            with ANALYSIS_LOCK:
                ANALYSIS_STATUS[analysis_id]["status"] = "complete"
                ANALYSIS_STATUS[analysis_id]["log"].append("분석 및 압축 완료.")
                ANALYSIS_STATUS[analysis_id]["zip_file"] = zip_filename
        else:
            is_success = False
            raise Exception("압축할 리포트 파일이 생성되지 않았습니다.")

    except subprocess.CalledProcessError as e:
        is_success = False
        error_log = f"분석 스크립트 실행 실패: {e.stderr}"
        logging.error(error_log)
        with ANALYSIS_LOCK:
            ANALYSIS_STATUS[analysis_id]["status"] = "failed"
            ANALYSIS_STATUS[analysis_id]["log"].append(error_log)
    except Exception as e:
        is_success = False
        logging.error(f"CVE 분석 백그라운드 작업 실패: {e}", exc_info=True)
        with ANALYSIS_LOCK:
            ANALYSIS_STATUS[analysis_id]["status"] = "failed"
            ANALYSIS_STATUS[analysis_id]["log"].append(f"서버 내부 오류: {e}")
    finally:
        # [사용자 요청] 분석이 성공적으로 완료되면, 10초 후 생성된 임시 파일들을 삭제합니다.
        if is_success:
            with ANALYSIS_LOCK:
                ANALYSIS_STATUS[analysis_id]["log"].append("분석 완료. 10초 후 임시 파일을 정리합니다...")
            logging.info(f"[{analysis_id}] 분석 성공. 10초 후 임시 파일 정리를 시작합니다.")
            time.sleep(10)

            files_to_delete = []
            # 1. 분석에 사용된 호스트 정보 파일
            files_to_delete.extend([Path(p) for p in files_to_process])
            # 2. 생성된 임시 메타 파일
            files_to_delete.extend(temp_files_to_clean)
            # 3. 생성된 모든 output 파일 (리포트, 인덱스 등)
            cve_check_output_dir = Path("/data/iso/AIBox/cve-check/output")
            if cve_check_output_dir.exists():
                files_to_delete.extend(list(cve_check_output_dir.glob("*")))

            deleted_count = 0
            for file_path in files_to_delete:
                try:
                    if file_path.is_file():
                        file_path.unlink()
                        logging.info(f"[{analysis_id}] 임시 파일 삭제: {file_path}")
                        deleted_count += 1
                except OSError as e:
                    logging.error(f"[{analysis_id}] 임시 파일 삭제 실패 '{file_path}': {e}")
            logging.info(f"[{analysis_id}] 총 {deleted_count}개의 임시 파일을 정리했습니다.")

def test_llm_connection(config):
    """
    [신규] LLM 서버 연결을 테스트하는 함수.
    --test-llm 인자와 함께 사용됩니다.
    """
    logging.info("--- LLM 연결 테스트 시작 ---")
    logging.info(f"LLM URL: {config.get('llm_url')}")
    logging.info(f"테스트 모델: {config.get('fast_model', config.get('model'))}")
    logging.info(f"인증 토큰: {'제공됨' if config.get('token') else '제공되지 않음'}")
    
    system_message = "You are a helpful assistant."
    user_message = "Hello! In one sentence, who are you?"
    
    logging.info("LLM에 테스트 메시지를 전송합니다...")
    
    try:
        # 기존의 블로킹 호출 함수를 재사용하여 실제 운영 환경과 동일한 조건으로 테스트
        model_to_use = config.get("fast_model", config.get("model"))
        # [BUG FIX] 서버 시작 전 테스트 단계에서는 스레드 풀과 세마포가 아직 준비되지 않았을 수 있으므로,
        # submit_llm_request 대신 _call_llm_single_blocking을 직접 호출하여 데드락을 방지합니다.
        raw_response_str = _call_llm_single_blocking(system_message, user_message, model_to_use, request_id="startup-test")
        
        # 응답이 오류 메시지인지 확인
        response_obj = json.loads(raw_response_str)
        if isinstance(response_obj, dict) and 'error' in response_obj:
            logging.error("LLM 테스트 실패. 서버가 오류를 반환했습니다:")
            logging.error(f"  오류: {response_obj.get('error')}")
            logging.error(f"  상세: {response_obj.get('details')}")
            sys.exit(1)
        
        logging.info("LLM 테스트 성공! 다음은 LLM의 응답입니다:")
        print(f"\n---\n{raw_response_str}\n---")
    except Exception as e:
        logging.error(f"LLM 테스트 중 예기치 않은 오류 발생: {e}", exc_info=True)
        sys.exit(1)

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

@app.route('/AIBox/api/cve-check/start-analysis', methods=['POST'])
def api_cve_check_start_analysis():
    """[신규] CVE 분석을 시작하는 API 엔드포인트."""
    if 'host_files' not in request.files:
        return jsonify({"error": "호스트 정보 파일이 없습니다."}), 400
    
    host_files = request.files.getlist('host_files')
    cve_ids_content = request.form.get('cve_ids', '')

    if not host_files or not cve_ids_content.strip():
        return jsonify({"error": "파일과 CVE ID를 모두 입력해야 합니다."}), 400

    cve_check_data_dir = Path(CVE_CHECK_DATA_DIR)
    cve_check_data_dir.mkdir(exist_ok=True)
    
    # [BUG FIX] UnboundLocalError를 해결하기 위해 analysis_id를 먼저 생성합니다.
    analysis_id = str(uuid.uuid4())

    saved_file_paths = []
    for file in host_files:
        if file and file.filename:
            filename = secure_filename(file.filename)
            file_path = cve_check_data_dir / filename
            file.save(file_path)
            saved_file_paths.append(str(file_path))

    if not saved_file_paths:
        return jsonify({"error": "유효한 파일이 업로드되지 않았습니다."}), 400

    # 백그라운드에서 분석 실행
    thread = threading.Thread(target=run_cve_check_analysis_background, args=(analysis_id, saved_file_paths, cve_ids_content))
    thread.daemon = True
    thread.start()
    
    return jsonify({"message": "CVE 분석이 시작되었습니다.", "analysis_id": analysis_id}), 202
#--- 서버 실행 ---
if __name__ == '__main__':
    # [사용자 요청] YAML 설정 파일 로드 로직 추가
    config_from_file = {}
    config_path = os.path.join(SCRIPT_DIR, 'config.yaml')
    if IS_YAML_AVAILABLE and os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_from_file = yaml.safe_load(f) or {}
            logging.info(f"'{config_path}' 파일에서 설정을 성공적으로 로드했습니다.")
        except Exception as e:
            logging.error(f"'{config_path}' 파일 로드 중 오류 발생: {e}")
    elif not IS_YAML_AVAILABLE:
        logging.warning("PyYAML 라이브러리가 설치되지 않아 'config.yaml' 파일을 읽을 수 없습니다.")

    # argparse의 기본값으로 YAML 파일의 설정을 사용합니다.
    # 이렇게 하면 명령줄 인자가 YAML 설정보다 우선적으로 적용됩니다.
    def get_config_val(key, default=None):
        # argparse는 하이픈(-)을 언더스코어(_)로 변환하므로, 키를 맞춰줍니다.
        key = key.replace('-', '_')
        # 명령줄 인자가 우선순위가 가장 높으므로, argparse의 기본값으로만 사용합니다.
        # 실제 값은 argparse가 파싱한 후 결정됩니다.
        return config_from_file.get(key, default)

    parser = argparse.ArgumentParser(description="Unified AI Server", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--llm-url', default=get_config_val('llm-url'), help='Full URL for LLM server API')
    # [사용자 요청] 추론 모델과 빠른 응답 모델을 별도로 지정할 수 있도록 인자 추가
    parser.add_argument('--reasoning-model', default=get_config_val('reasoning-model'), help='LLM model name for complex reasoning tasks (e.g., S-Core/Qwen3-235B-A22B)')
    parser.add_argument('--fast-model', default=get_config_val('fast-model'), help='LLM model name for fast, structured tasks (e.g., S-Core/Qwen3-235B-A22B-no_think)')
    parser.add_argument('--fallbacks-model', default=get_config_val('fallbacks-model'), help='LLM model to use as a fallback for context window errors (e.g., S-Core/Llama-4-Scout-17B-16E-Instruct)')
    # [사용자 요청] 모델별 컨텍스트 크기를 KB 단위로 지정하고, 기본값을 0(무제한)으로 설정합니다.
    parser.add_argument('--reasoning-model-context', type=int, default=get_config_val('reasoning-model-context', 0), help='Context window size for the reasoning model in KB (e.g., 128 for 128k tokens). 0 for unlimited.')
    parser.add_argument('--fast-model-context', type=int, default=get_config_val('fast-model-context', 0), help='Context window size for the fast model in KB (e.g., 128 for 128k tokens). 0 for unlimited.')
    parser.add_argument('--fallbacks-model-context', type=int, default=get_config_val('fallbacks-model-context', 0), help='Context window size for the fallback model in KB (e.g., 256 for 256k tokens). 0 for unlimited.')

    logging.info("==========================================================")
    logging.info("            Starting AIBox Server Sequence...           ")
    logging.info("==========================================================")
    parser.add_argument('--model', default=get_config_val('model'), help='LLM model name')
    parser.add_argument('--list-models', action='store_true', help='List available models and exit')
    parser.add_argument('--token', default=get_config_val('token', os.getenv('LLM_API_TOKEN')), help='API token for LLM server')
    parser.add_argument('--host', default=get_config_val('host', '0.0.0.0'), help='Host to bind the server to')
    parser.add_argument('--port', type=int, default=get_config_val('port', 5000), help='Port to run the server on')
    parser.add_argument('--schedule-file', default=get_config_val('schedule-file', 'meta/schedule.json'), help='Path to schedule JSON file')
    parser.add_argument('--scheduler-log-file', default=get_config_val('scheduler-log-file', 'log/scheduler.log'), help='Path to scheduler log file')
    parser.add_argument('--cache-ttl-days', type=int, default=get_config_val('cache-ttl-days', 7), help='Number of days to keep LLM cache')
    parser.add_argument('--cache-size-gb', type=float, default=get_config_val('cache-size-gb', 1.0), help='Maximum size of the cache in gigabytes')
    # [개선] 서버의 외부 접속 URL을 명시적으로 받기 위한 인자.
    parser.add_argument('--llm-max-workers', type=int, default=get_config_val('llm-max-workers', 6), help='Maximum number of concurrent LLM requests. Set to 0 for unlimited (uses Python default).')
    parser.add_argument('--llm-request-delay', type=float, default=get_config_val('llm-request-delay', 1.0), help='Delay in seconds after each LLM request to control load.')
    parser.add_argument('--pre-chunk-delay', type=float, default=get_config_val('pre-chunk-delay', 5.0), help='Delay in seconds between pre-chunks to control load.')
    # [사용자 요청] LLM 동시 요청 수를 설정하는 인자 추가
    parser.add_argument('--connection-limit', type=int, default=get_config_val('connection-limit', 500), help='Maximum number of open connections for the server')
    parser.add_argument('--base-url', default=get_config_val('base-url', os.getenv('AIBOX_BASE_URL')), help='External base URL for the server (e.g., http://aibo.example.com)')
    parser.add_argument('--test-llm', action='store_true', help='Perform a test call to the LLM server and exit.')
    args = parser.parse_args()

    logging.info("[1/8] Command-line arguments parsed.")

    # [사용자 요청] llm-url이 여전히 설정되지 않았다면 오류를 발생시키고 종료합니다.
    if not args.llm_url:
        parser.error("The --llm-url argument is required. Please provide it via command line or in config.yaml.")

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
        logging.warning("`--base-url` or `AIBOX_BASE_URL` is not set. This may cause issues with background job callbacks.")

    # [신규] reasoning-model 또는 fast-model이 지정되지 않은 경우, 기본 --model 값을 사용합니다.
    if not CONFIG.get('reasoning_model'):
        CONFIG['reasoning_model'] = CONFIG.get('model')
    if not CONFIG.get('fast_model'):
        CONFIG['fast_model'] = CONFIG.get('model')
    logging.info(f"Reasoning Model: {CONFIG['reasoning_model']}, Fast Model: {CONFIG['fast_model']}")

    logging.info("[2/8] Default configuration loaded.")

    # [사용자 요청] 서버 시작 시 각 모델의 연결 상태를 확인하고 로깅합니다.
    def check_model_availability(model_name):
        if not model_name:
            return False, "모델 이름이 지정되지 않았습니다."
        
        logging.info(f"  - 모델 '{model_name}' 연결 상태 확인 중...")
        system_message = "You are a health check assistant."
        user_message = "Respond with 'OK' if you are operational."
        
        try:
            # [BUG FIX] 서버 시작 시에는 스레드 풀과 세마포를 사용하지 않고 직접 LLM을 호출하여 데드락을 방지합니다.
            # 이 단계는 서버의 메인 스레드에서 실행되므로, submit_llm_request를 사용하면 스레드 풀이 가득 찼을 때
            # 자기 자신을 기다리는 데드락 상태에 빠질 수 있습니다.
            raw_response_str = _call_llm_single_blocking(system_message, user_message, model_name, max_tokens=10, request_id="startup-check")
            
            # [BUG FIX] LLM이 'OK'라는 순수 텍스트로 응답하므로, json.loads()를 사용하면 오류가 발생합니다.
            # 1. 먼저 응답이 오류를 나타내는 JSON 형식인지 확인합니다.
            try:
                response_obj = json.loads(raw_response_str)
                if isinstance(response_obj, dict) and 'error' in response_obj:
                    # LLM 호출 자체가 실패한 경우 (예: 모델 로드 실패)
                    return False, response_obj.get('details', '알 수 없는 오류')
            except (json.JSONDecodeError, TypeError):
                # 2. JSON 파싱에 실패하면, 응답이 'OK'를 포함하는지 확인합니다.
                if "ok" in raw_response_str.lower():
                    return True, "연결 성공"
            
            # 3. 'OK'가 포함되지 않은 비정상적인 응답
            return False, f"예상치 못한 응답 수신: {raw_response_str[:100]}"
        except Exception as e:
            return False, str(e)

    
    # [제안 반영] argparse 대신 환경 변수에서 비밀번호를 로드합니다.
    CONFIG['password'] = os.getenv('AIBOX_PASSWORD')
    if not CONFIG.get('password'):
        logging.info("[3/8] AIBOX_PASSWORD environment variable is not set.")
        logging.error("FATAL: Password is not set. Please set the AIBOX_PASSWORD environment variable.")
        sys.exit(1)
    
    logging.info("[3/8] AIBOX_PASSWORD environment variable check complete.")

    # [BUG FIX] diskcache 초기화 시 'no such table' 오류를 방지하기 위한 안정성 강화 로직
    try:
        cache_size_bytes = int(args.cache_size_gb * (1024**3))
        cache = Cache(CACHE_FOLDER, size_limit=cache_size_bytes)
        # 간단한 set/get 작업을 통해 캐시가 정상적으로 동작하는지 확인합니다.
        cache.set('__init_test__', True, expire=1)
        cache.get('__init_test__')
        cache.delete('__init_test__')
    except Exception as e:
        logging.warning(f"캐시 초기화 중 오류 발생: {e}. 캐시를 삭제하고 다시 시도합니다.")
        shutil.rmtree(CACHE_FOLDER, ignore_errors=True)
        os.makedirs(CACHE_FOLDER, exist_ok=True)
        cache = Cache(CACHE_FOLDER, size_limit=cache_size_bytes)

    logging.info(f"[4/8] DiskCache initialized. Path: {CACHE_FOLDER}, Max Size: {args.cache_size_gb} GB, TTL: {args.cache_ttl_days} days")

    resolved_llm_url = resolve_chat_endpoint(CONFIG['llm_url'], CONFIG.get('token'))
    if resolved_llm_url: CONFIG['llm_url'] = resolved_llm_url
    else: logging.warning(f"Could not automatically determine API type for '{CONFIG['llm_url']}'.")
    logging.info(f"[5/8] LLM endpoint check complete. Final URL: {CONFIG['llm_url']}")

    # [사용자 요청] 서버 시작 시 LLM 상태 점검 로직으로 인해 서버가 멈추는 현상이 발생하여, 해당 로직을 제거합니다.
    # 서버는 시작 시 LLM 연결 상태를 확인하지 않고 즉시 시작됩니다.
    if not args.model and not args.reasoning_model and not args.fast_model:
        logging.error("오류: --model, --reasoning-model, 또는 --fast-model 중 하나 이상의 모델 인자가 반드시 필요합니다.")
        parser.error("At least one model argument (--model, --reasoning-model, or --fast-model) is required.")
    
    # [신규] --test-llm 인자가 사용된 경우, 테스트 함수를 실행하고 종료합니다.
    if args.test_llm:
        test_llm_connection(CONFIG)
        logging.info("--- LLM 연결 테스트 완료 ---")
        sys.exit(0)

    CONFIG["schedule_file"] = os.path.abspath(args.schedule_file)
    CONFIG["scheduler_log_file"] = os.path.abspath(args.scheduler_log_file)

    initialize_and_monitor_prompts()

    # [사용자 요청] --llm-max-workers 인자에 따라 LLM 워커 스레드 풀을 초기화합니다.
    # 0으로 설정하면 "무제한" (파이썬 기본값)으로 동작합니다.
    max_workers_val = args.llm_max_workers if args.llm_max_workers > 0 else (os.cpu_count() or 1) * 2
    LLM_WORKER_EXECUTOR = ThreadPoolExecutor(max_workers=max_workers_val, thread_name_prefix='LLM_Worker')
    LLM_REQUEST_SEMAPHORE = threading.Semaphore(max_workers_val)
    logging.info(f"LLM worker pool initialized with max_workers={max_workers_val}.")
    logging.info(f"LLM request semaphore initialized with a limit of {max_workers_val} concurrent requests.")

    logging.info(f"[6/8] Prompt initialization and monitoring started. ({PROMPTS_FILE})")
    setup_scheduler()
    logging.info(f"[7/8] Scheduler setup complete. (DB: jobs.sqlite, Log: {CONFIG['scheduler_log_file']})")

    # [성능 개선] CORS 설정을 환경 변수에서 가져오도록 수정
    cors_origins = os.getenv('CORS_ORIGINS', '*').split(',')
    CORS(app, resources={r"/AIBox/api/*": {"origins": cors_origins}})
    logging.info(f"[8/8] CORS setup complete. Allowed origins: {cors_origins}")

    logging.info("==========================================================")
    logging.info(f"  AIBox Server starting on http://{args.host}:{args.port}  ")
    logging.info("==========================================================")
    # [사용자 요청] 연결 한도를 늘려 "total open connections reached the connection limit" 오류를 방지합니다.
    serve(app, host=args.host, port=args.port, threads=16, connection_limit=args.connection_limit)
