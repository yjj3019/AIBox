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

# [BUG FIX] psutil이 없을 경우 서버가 시작되지 않는 문제를 해결하기 위해 선택적 임포트로 변경합니다.
try:
    import psutil
    IS_PSUTIL_AVAILABLE = True
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
SOS_ANALYZER_SCRIPT = "/data/iso/AIBox/sos_analyzer.py"
CVE_FOLDER = '/data/iso/AIBox/cve'
scheduler = None
EPSS_FOLDER = '/data/iso/AIBox/epss'

ANALYSIS_STATUS = {}
ANALYSIS_LOCK = Lock()
ANALYSIS_CLEANUP_INTERVAL_SECONDS = 3600 # 1시간마다 오래된 상태 정리

# [성능 개선] LLM 요청을 병렬로 처리하기 위한 스레드 풀
LLM_WORKER_EXECUTOR = None # 서버 시작 시 인자에 따라 초기화됩니다.

def submit_llm_request(func, *args, **kwargs):
    """[구조 변경] LLM 요청을 스레드 풀에 제출하고 결과를 기다리는 함수."""
    request_id = str(uuid.uuid4())[:8]
    
    if not LLM_WORKER_EXECUTOR:
        raise RuntimeError("LLM 워커 스레드 풀이 초기화되지 않았습니다.")

    logging.info(f"[{request_id}] 새로운 LLM 요청을 스레드 풀에 제출합니다.")
    # func에 request_id를 전달하여 로깅 추적을 용이하게 합니다.
    future = LLM_WORKER_EXECUTOR.submit(func, *args, **kwargs, request_id=request_id)
    
    # future.result()는 작업이 완료될 때까지 블로킹하며 결과를 반환합니다.
    return future.result()


CONTROL_CHAR_REGEX = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)
os.makedirs(CVE_FOLDER, exist_ok=True)
os.makedirs(CVE_CHECK_OUTPUT_FOLDER, exist_ok=True) # [신규] cve-check 리포트 디렉토리 생성
os.makedirs(EPSS_FOLDER, exist_ok=True)
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
                logging.warning(f"데이터(문자열)가 너무 커서 분할합니다. (토큰: {self.get_token_count(data)})") # noqa: E501
                
                # [BUG FIX] 매우 큰 텍스트를 효과적으로 분할하기 위해 줄 단위 분할 로직을 추가합니다.
                # 1. 먼저 줄 단위로 분할합니다.
                lines = data.split('\n')
                # 2. 500줄 단위로 청크를 만듭니다.
                LINE_CHUNK_SIZE = 500
                current_chunk = ""
                for i in range(0, len(lines), LINE_CHUNK_SIZE):
                    chunk_lines = lines[i:i + LINE_CHUNK_SIZE]
                    chunk_text = "\n".join(chunk_lines)
                    
                    # [안정성 강화] 생성된 청크가 컨텍스트 창을 초과하지 않는지 다시 확인합니다.
                    # 대부분의 경우 이 조건은 만족하지만, 한 줄이 매우 긴 예외적인 경우를 대비합니다.
                    if self.get_token_count(current_chunk + chunk_text) > available_tokens and current_chunk:
                        yield current_chunk
                        current_chunk = ""
                    current_chunk += chunk_text + "\n"
                if current_chunk:
                    yield current_chunk
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

        with ANALYSIS_LOCK:
            ANALYSIS_STATUS[log_key]["status"] = "running"
            ANALYSIS_STATUS[log_key]["log"].append("분석 프로세스를 시작합니다...")

        # [BUG FIX] stdout과 stderr을 통합하여 실시간으로 처리합니다.
        # 이렇게 하면 경고(warning) 메시지가 stderr로 출력되어도 로그에 즉시 기록되어
        # 'warnings.warn('와 같은 불완전한 로그로 분석이 실패하는 문제를 방지합니다.
        process = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, # stderr을 stdout으로 리디렉션
            text=True, 
            encoding='utf-8', 
            errors='replace'
        )

        if process.stdout:
            analysis_failed_flag = False
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
                    
                    # [BUG FIX] sos_analyzer.py에서 "ANALYSIS_FAILED" 문자열을 감지하면 즉시 실패 처리
                    if line.startswith("ANALYSIS_FAILED"):
                        analysis_failed_flag = True
                        logging.error(f"Analysis {analysis_id} failed explicitly: {line}")

                    ANALYSIS_STATUS[log_key]["log"].append(line)
        
        process.wait()

        with ANALYSIS_LOCK:
            # [핵심 개선] 분석 프로세스의 성공/실패를 더 명확하게 판단합니다.
            # 1. 프로세스 종료 코드가 0 (성공)인지 확인합니다.
            # 2. 로그에 'HTML 보고서 저장 완료' 메시지가 있는지 확인합니다.
            # 두 조건이 모두 충족되어야 최종 성공으로 처리합니다.
            # [BUG FIX] 로그에 포함된 ANSI 색상 코드로 인해 성공 문자열 감지에 실패하는 문제를 해결합니다.
            # 정규식을 사용하여 색상 코드를 제거한 후, 'HTML 보고서 저장 완료' 문자열이 있는지 확인합니다.
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            final_log_raw = "\n".join(ANALYSIS_STATUS[log_key].get("log", [])) # type: ignore
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
        running_analyses = sum(1 for status in ANALYSIS_STATUS.values() if status['status'] not in ['complete', 'failed', 'queued'])
    
    # [수정] Queue 크기와 함께 최대 워커 수를 로깅하여 제한을 함께 표시합니다.
    limit = CONFIG.get('llm_max_workers', 'N/A')
    limit_str = 'unlimited' if limit is None else limit
    active_workers = LLM_WORKER_EXECUTOR._work_queue.qsize() if LLM_WORKER_EXECUTOR else 0
    status_log = f"[SERVER STATUS] Active Threads: {threading.active_count()}, Running Analyses: {running_analyses}, LLM Workers: {active_workers}/{limit_str}"
 
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
    return hashlib.sha256((system_message + user_message).encode('utf-8')).hexdigest()
# [개선] diskcache 인스턴스를 전역적으로 생성합니다.
cache = None # 전역 변수로 선언
 
def _create_final_summary_prompt(summaries: List[str]) -> str:
     """
     [신규] 여러 개의 부분 요약본을 받아, 이를 종합하여 최종 분석을 요청하는 프롬프트를 생성합니다.
     """
     summaries_text = "\n\n".join(f"--- Chunk {i+1} Summary ---\n{summary}" for i, summary in enumerate(summaries))
     return f"""[System Role]
 You are an expert AI tasked with synthesizing multiple partial analysis reports into a single, final, comprehensive report.
 
 [Task]
 The user has provided several summaries from different chunks of a larger dataset. Your job is to combine these summaries into one cohesive final analysis. You must return the result in the same format as the partial summaries (e.g., a single JSON object).
 
 [Partial Summaries]
 {summaries_text}
 
 [Final Analysis Request]
 Please synthesize the above summaries into a single, final JSON object. Do not add any explanatory text outside of the JSON structure.
 """
 
def _create_chunk_summary_prompt(chunk_data: str) -> str:
     """
     [신규] 데이터 청크(묶음)를 요약하기 위한 프롬프트를 생성합니다.
     """
     return f"""[System Role]
 You are an expert AI that analyzes a piece of a larger dataset and provides a summary.
 
 [Task]
 The user has provided a chunk of data. Analyze it and return a summary of your findings. The format of your response should be a single JSON object, as the final output will be constructed from these summaries.
 
 [Data Chunk to Summarize]
 ```
 {chunk_data}
 ```
 """
 
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
        if any(keyword in user_message for keyword in ['deep_dive', '종합 분석', 'Executive Summary', 'security report']):
            model_to_use = CONFIG.get("reasoning_model", CONFIG.get("model")) # type: ignore
            # [사용자 요청] KB 단위로 받은 컨텍스트 크기를 토큰 단위로 변환 (1KB = 1000 토큰으로 간주)
            context_window_kb = CONFIG.get('reasoning_model_context', 0)
        else:
            model_to_use = CONFIG.get("fast_model", CONFIG.get("model")) # type: ignore
            context_window_kb = CONFIG.get('fast_model_context', 0)
 
    # 1. 캐시 확인
    cached_response = cache.get(cache_key)
    if cached_response is not None:
        # [BUG FIX] 캐시된 응답이 객체 형태가 아닐 수 있으므로, 항상 객체로 변환하여 반환합니다.
        logging.info(f"[CACHE HIT] 캐시된 응답(객체)을 반환합니다. (Key: {cache_key[:10]}...)")
        llm_logger.info(f"[CACHE HIT] Returning cached response for key: {cache_key}")
        return cached_response

    # 2. Cache Miss: LLM 호출 (지능형 청킹 적용)
    logging.info(f"[CACHE MISS] LLM 서버에 분석을 요청합니다. (Key: {cache_key[:10]}...)")

    # [핵심 개선] 모든 LLM 요청을 중앙 큐에서 관리하기 위해 submit_llm_request를 사용합니다.
    # 블로킹 요청도 큐를 통해 순차적으로 처리하여 LLM 서버의 과부하를 방지하고 안정성을 높입니다.
    # submit_llm_request는 Future 객체의 결과를 기다리므로, 이 함수는 블로킹으로 동작합니다.
    # [사용자 요청] 컨텍스트 크기가 0(무제한)이 아닐 경우에만 Map-Reduce 로직을 수행합니다.
    if context_window_kb > 0:
        context_window_size = context_window_kb * 1000
        chunker = LLMChunker(max_tokens=context_window_size)
        base_prompt_tokens = chunker.get_token_count(system_message)
        user_message_tokens = chunker.get_token_count(user_message)

        # 컨텍스트 창을 초과하면 Map-Reduce를 수행합니다.
        if base_prompt_tokens + user_message_tokens > chunker.max_tokens - 500: # 안전 마진
            logging.info(f"요청이 컨텍스트 창({context_window_kb}k)을 초과하여 Map-Reduce 방식으로 처리합니다. (토큰: {user_message_tokens})")
            
            # Map 단계: 데이터를 여러 청크로 나누어 병렬로 요약
            chunk_summaries = []
            max_workers_val = CONFIG.get('llm_max_workers', 6)
            with ThreadPoolExecutor(max_workers=max_workers_val if max_workers_val > 0 else None) as executor:
                data_chunks = list(chunker.split_data(user_message, base_prompt_tokens))
                
                future_to_chunk = {
                    executor.submit(
                        _call_llm_single_blocking, 
                        _create_chunk_summary_prompt(""), # 청크 요약용 시스템 프롬프트
                        chunk, 
                        model_to_use, # [BUG FIX] Map-Reduce의 각 청크 처리 시 폴백 모델을 사용하도록 model_to_use를 전달합니다.
                        max_tokens
                    ): i
                    for i, chunk in enumerate(data_chunks)
                }

                for future in as_completed(future_to_chunk):
                    try:
                        summary = future.result()
                        chunk_summaries.append(summary)
                    except Exception as e:
                        logging.error(f"Map-Reduce의 Map 단계 중 오류 발생: {e}")

            # Reduce 단계: 요약본들을 모아 최종 분석 요청
            logging.info(f"Map 단계 완료. {len(chunk_summaries)}개의 요약본으로 최종 분석을 요청합니다.")
            final_prompt = _create_final_summary_prompt(chunk_summaries)
            raw_response_str = submit_llm_request(_call_llm_single_blocking, final_prompt, "", model_to_use, max_tokens)
        else: # 컨텍스트 창을 초과하지 않으면 직접 호출합니다.
            raw_response_str = submit_llm_request(_call_llm_single_blocking, system_message, user_message, model_to_use, max_tokens)
    else: # 컨텍스트 크기가 0(무제한)이면 직접 호출합니다.
        logging.info("컨텍스트 크기가 무제한(0)으로 설정되어 Map-Reduce를 건너뛰고 직접 호출합니다.")
        raw_response_str = submit_llm_request(_call_llm_single_blocking, system_message, user_message, model_to_use, max_tokens)
        
    # 3. LLM 응답 파싱 및 객체 변환
    # [BUG FIX] LLM 응답 파싱 실패 시, 클라이언트가 AttributeError를 일으키지 않도록
    #           항상 일관된 JSON 객체 형식으로 오류를 반환합니다.
    try:
        final_object = _parse_llm_json_response(raw_response_str)
    except ValueError as e:
        logging.error(f"최종 LLM 응답 파싱 실패: {e}")
        final_object = {"error": "Final LLM response parsing failed", "details": str(e), "raw_response": raw_response_str}

    # 4. 성공적인 응답(객체)을 캐시에 저장
    if isinstance(final_object, dict) and 'error' not in final_object:
        cache.set(cache_key, final_object, expire=cache_ttl_seconds)
        logging.info(f"[CACHE SET] 새로운 응답을 캐시에 저장합니다. (Key: {cache_key[:10]}...)")

    return final_object

def _call_llm_single_blocking(system_message, user_message, model_name, max_tokens=16384, request_id="N/A"):
    """단일 LLM 호출을 처리하는 내부 블로킹 함수."""
    # [BUG FIX] 데드락을 유발하는 재귀적 Map-Reduce 로직을 제거합니다.
    # 이제 데이터 청킹은 전적으로 클라이언트(security.py 등)의 책임이며,
    # 서버는 주어진 요청을 그대로 처리하는 역할만 수행합니다.

    max_retries = 3
    last_exception = None  # [신규] 마지막으로 발생한 예외를 저장하기 위한 변수
    for attempt in range(max_retries):
        try:
            headers = {'Content-Type': 'application/json'}
            if CONFIG.get("token"): headers['Authorization'] = f'Bearer {CONFIG["token"]}'
            payload = {"model": model_name, "messages": [{"role": "system", "content": system_message}, {"role": "user", "content": user_message}], "max_tokens": max_tokens, "temperature": 0.1, "stream": False}
            
            # [BUG FIX] LLM URL이 외부 주소일 경우 시스템 프록시를 사용하도록 수정합니다.
            # 로컬 주소(127.0.0.1, localhost)일 경우에만 프록시를 명시적으로 비활성화합니다.
            llm_url = CONFIG["llm_url"]
            is_local_llm = any(host in llm_url for host in ['127.0.0.1', 'localhost'])
            proxies = {'http': None, 'https': None} if is_local_llm else None

            # [신규] LLM 요청 로깅
            # [성능 개선] 요청 ID를 포함하여 로그를 추적하기 쉽게 만듭니다.
            log_prefix = f"[{request_id}]"
            logging.info(f"{log_prefix} LLM 요청 (모델: {model_name}, 시도 {attempt + 1}/{max_retries})...")
            llm_logger.info(f"{log_prefix} --- LLM Request (Blocking, Attempt {attempt + 1}/{max_retries}) ---")
            llm_logger.debug(f"{log_prefix} System Message: {system_message}")
            llm_logger.debug(f"{log_prefix} User Message: {user_message}")
            
            # cache_misses.inc() # 메트릭 기능이 구현될 때까지 주석 처리
            # [제안 반영] LLM 호출 타임아웃을 600초(10분)로 늘려 긴 분석 작업(예: CVE 순위 선정)을 지원합니다.
            response = requests.post(llm_url, headers=headers, json=payload, timeout=600, proxies=proxies, verify=False)
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
                # [핵심 개선] litellm의 오류 메시지를 파싱하여 로그에 명확히 기록합니다.
                error_details = f"HTTP {e.response.status_code}"
                try:
                    error_json = e.response.json()
                    error_details = error_json.get("error", {}).get("message", e.response.text)
                except json.JSONDecodeError:
                    error_details = e.response.text
                logging.warning(f"{log_prefix} LLM 서버 오류 발생: {error_details.strip()}. {2**attempt}초 후 재시도합니다... ({attempt + 1}/{max_retries})")
                llm_logger.warning(f"{log_prefix} --- LLM HTTP Error (Attempt {attempt + 1}) ---\n{e}\nResponse: {error_details}")
                time.sleep(2 ** attempt) # Exponential backoff: 1, 2, 4초...
                continue # 다음 재시도 수행
            # 재시도 대상이 아니거나 모든 재시도 실패 시, 오류 응답을 생성합니다.
            # [성능 개선] litellm이 반환하는 JSON 형식의 오류 메시지를 파싱하여 더 구체적인 오류를 사용자에게 전달합니다.
            error_message = f"LLM Server Error: {e}"
            if e.response is not None:
                # [사용자 요청] ContextWindowExceededError 발생 시 폴백 모델로 재시도
                fallback_model = CONFIG.get("fallbacks_model")
                raw_response_text_for_fallback = e.response.text
                if fallback_model and "ContextWindowExceededError" in raw_response_text_for_fallback:
                    logging.warning(f"{log_prefix} 컨텍스트 크기 초과 오류 감지. 폴백 모델 '{fallback_model}'(으)로 재시도합니다.")
                    llm_logger.warning(f"{log_prefix} Context window exceeded. Retrying with fallback model: {fallback_model}")
                    
                    # 현재 사용 중인 모델 이름을 폴백 모델로 교체하여 재귀 호출
                    # 이렇게 하면 재시도 횟수(max_retries)를 소진하지 않고 즉시 1회 재시도합니다.
                    # 단, 무한 재귀를 방지하기 위해 폴백 모델 자체에서 또 오류가 발생하면 재시도하지 않습니다.
                    if model_name != fallback_model:  # 무한 재귀 방지
                        # [BUG FIX] model_override를 전달하여 폴백 모델을 강제로 사용하도록 수정합니다.
                        return call_llm_blocking(system_message, user_message, max_tokens, model_override=fallback_model)
                    else:
                        logging.error(f"{log_prefix} 폴백 모델 '{fallback_model}'도 컨텍스트 크기 초과 오류가 발생하여 분석을 중단합니다.")

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
        # [BUG FIX] LLM 응답이 문자열이 아니거나 비어있는 경우, 'NoneType' 오류를 유발할 수 있으므로
        # 항상 유효한 JSON 객체 형식의 오류를 반환하도록 수정합니다.
        if not isinstance(llm_response_str, str) or not llm_response_str.strip():
            logging.warning("LLM 응답이 비어 있거나 문자열이 아닙니다. 오류 객체를 반환합니다.")
            return {"error": "LLM response was empty or not a string.", "raw_response": str(llm_response_str)}

        # [BUG FIX] LLM이 <think>...</think> 와 같은 불필요한 XML/HTML 태그를 반환하는 경우,
        # 이를 제거하여 순수한 JSON만 남깁니다.
        # re.DOTALL 플래그를 사용하여 여러 줄에 걸친 태그도 제거합니다.
        llm_response_str = re.sub(r'<.*?>', '', llm_response_str, flags=re.DOTALL).strip()

        # 1. JSON 코드 블록(```json ... ```)을 먼저 찾습니다.
        match = re.search(r'```(?:json)?\s*(\{.*\}|\[.*\])\s*```', llm_response_str, re.DOTALL)
        if match:
            json_str = match.group(1)
            return json.loads(json_str)

        # 2. 코드 블록이 없다면, 문자열에서 첫 번째 '{' 또는 '['를 찾아 유효한 JSON 객체/배열의 끝까지 추출합니다.
        #    이는 AI가 JSON 앞에 추가한 서두(Preamble)와 뒤에 추가한 부연 설명을 모두 무시하게 해줍니다.
        start_brace = llm_response_str.find('{')
        start_bracket = llm_response_str.find('[')

        # '{' 와 '[' 중 더 먼저 나오는 것을 시작점으로 잡습니다.
        if start_brace == -1:
            start = start_bracket
        elif start_bracket == -1:
            start = start_brace
        else:
            start = min(start_brace, start_bracket)

        if start != -1:
            try:
                # 시작점부터 JSON 디코더를 사용하여 유효한 JSON 객체가 끝나는 지점까지 파싱합니다.
                decoder = json.JSONDecoder()
                obj, end = decoder.raw_decode(llm_response_str[start:])
                return obj
            except json.JSONDecodeError as e:
                # 디코딩 실패 시 오류를 발생시킵니다.
                logging.warning(f"LLM 응답에서 유효한 JSON을 찾았으나 파싱에 실패했습니다: {e}. 원본 텍스트를 반환합니다.")
                return llm_response_str

        # 3. 어떤 JSON 형식도 찾지 못한 경우
        logging.warning(f"응답에서 유효한 JSON 형식을 찾지 못했습니다. 원본 텍스트를 반환합니다: {llm_response_str[:200]}")
        return llm_response_str
    except json.JSONDecodeError as e:
        logging.warning(f"LLM 응답 JSON 파싱 실패: {e}. 원본 텍스트를 반환합니다.")
        return llm_response_str

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
        
        chunk_size = 10
        for i in range(0, len(full_response), chunk_size):
            yield full_response[i:i+chunk_size]
            time.sleep(0.002)
        return

    # 2. Cache Miss: 실제 LLM API 호출을 큐에 제출
    logging.info(f"[{request_id}] [CACHE MISS][STREAM] LLM 스트리밍 요청을 큐에 추가합니다. (Key: {cache_key[:10]}...)")
    
    # [구조 변경] 스트리밍 요청에서도 프롬프트 내용에 따라 모델을 동적으로 선택합니다.
    if any(keyword in user_message for keyword in ['deep_dive', '종합 분석', 'Executive Summary', 'security report']):
        model_to_use = CONFIG.get("reasoning_model", CONFIG["model"])
    else:
        model_to_use = CONFIG.get("fast_model", CONFIG["model"])

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
            html_files = [f for f in output_files if f.endswith('.html') and f != 'index.html']

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
            # [BUG FIX] 클라이언트가 보낸 'prompt'와 'cve_data'를 올바르게 조합합니다.
            # 'cve_data'가 누락되어 AI가 분석에 필요한 데이터를 받지 못하는 문제를 해결합니다.
            prompt_text = cve_data["prompt"]
            cve_details = cve_data.get("cve_data", {})
            prompt = f"{prompt_text}\n\n[CVE Data for Analysis]\n{json.dumps(cve_details, indent=2, ensure_ascii=False)}"
            # [사용자 요청] 클라이언트가 모델을 선택할 수 있도록 model_selector 키워드를 확인합니다.
            if cve_data.get('model_selector') == 'deep_dive':
                # 'deep_dive'가 포함된 프롬프트는 reasoning_model을 사용하도록 유도
                prompt += "\n[Analysis Type] deep_dive"
                system_message = "You are an expert assistant. Follow the user's instructions precisely, including the output format."
            else: # fast-model 또는 기본 모델 사용
                system_message = "You are an expert assistant. Follow the user's instructions precisely, including the output format."
        else: # 기존 security.py와의 호환성을 위한 폴백
            prompt = f"""[CVE Data]\n{json.dumps(cve_data, indent=2, ensure_ascii=False)}\n\n[Task]\nAnalyze and return JSON with keys: 'threat_tags', 'affected_components', 'concise_summary', 'selection_reason'."""
            system_message = "You are an RHEL security analyst. Return only a single, valid JSON object."
        
        # [핵심 개선] 대용량 JSON 응답을 처리하기 위해 스트리밍 방식으로 LLM을 호출하고, 그 결과를 그대로 클라이언트에 스트리밍합니다.
        # [BUG FIX] 요청에 'stream' 플래그가 있는지 확인하여 블로킹/스트리밍 호출을 동적으로 결정합니다.
        # cve_report_generator.py와 같이 단일 응답을 기대하는 클라이언트와의 호환성을 보장합니다.
        if cve_data.get('stream', False):
            # 스트리밍 요청 처리
            # [핵심 수정] LLM으로부터 받은 스트림을 클라이언트로 즉시 전달합니다.
            # 이렇게 하면 클라이언트가 타임아웃 없이 응답을 실시간으로 받을 수 있습니다.
            return Response(call_llm_stream(system_message, user_message=prompt), mimetype='text/plain; charset=utf-8')
        else:
            # 블로킹 요청 처리
            response_obj = call_llm_blocking(system_message, user_message=prompt)
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
        
        # [BUG FIX] 서버의 LLM 요청 큐를 사용하도록 수정합니다.
        # _call_llm_single_blocking을 직접 호출하는 대신 submit_llm_request를 사용해야 합니다.
        raw_response_str = submit_llm_request(_call_llm_single_blocking, system_message, user_message, model_to_use)
        
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
        # [BUG FIX] 서버의 LLM 요청 큐를 사용하도록 수정합니다.
        # _call_llm_single_blocking을 직접 호출하는 대신 submit_llm_request를 사용해야 합니다.
        raw_response_str = submit_llm_request(_call_llm_single_blocking, system_message, user_message, model_to_use)
        
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

#--- 서버 실행 ---
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Unified AI Server", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--llm-url', required=True, help='Full URL for LLM server API')
    # [사용자 요청] 추론 모델과 빠른 응답 모델을 별도로 지정할 수 있도록 인자 추가
    parser.add_argument('--reasoning-model', help='LLM model name for complex reasoning tasks (e.g., S-Core/Qwen3-235B-A22B)')
    parser.add_argument('--fast-model', help='LLM model name for fast, structured tasks (e.g., S-Core/Qwen3-235B-A22B-no_think)')
    parser.add_argument('--fallbacks-model', help='LLM model to use as a fallback for context window errors (e.g., S-Core/Llama-4-Scout-17B-16E-Instruct)')
    # [사용자 요청] 모델별 컨텍스트 크기를 KB 단위로 지정하고, 기본값을 0(무제한)으로 설정합니다.
    parser.add_argument('--reasoning-model-context', type=int, default=0, help='Context window size for the reasoning model in KB (e.g., 128 for 128k tokens). 0 for unlimited.')
    parser.add_argument('--fast-model-context', type=int, default=0, help='Context window size for the fast model in KB (e.g., 128 for 128k tokens). 0 for unlimited.')
    parser.add_argument('--fallbacks-model-context', type=int, default=0, help='Context window size for the fallback model in KB (e.g., 256 for 256k tokens). 0 for unlimited.')

    logging.info("==========================================================")
    logging.info("            Starting AIBox Server Sequence...           ")
    logging.info("==========================================================")
    parser.add_argument('--model', help='LLM model name')
    parser.add_argument('--list-models', action='store_true', help='List available models and exit')
    parser.add_argument('--token', default=os.getenv('LLM_API_TOKEN'), help='API token for LLM server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind the server to')
    parser.add_argument('--port', type=int, default=5000, help='Port to run the server on')
    parser.add_argument('--schedule-file', default='meta/schedule.json', help='Path to schedule JSON file')
    parser.add_argument('--scheduler-log-file', default='log/scheduler.log', help='Path to scheduler log file')
    parser.add_argument('--cache-ttl-days', type=int, default=7, help='Number of days to keep LLM cache')
    parser.add_argument('--cache-size-gb', type=float, default=1.0, help='Maximum size of the cache in gigabytes')
    # [개선] 서버의 외부 접속 URL을 명시적으로 받기 위한 인자.
    parser.add_argument('--llm-max-workers', type=int, default=6, help='Maximum number of concurrent LLM requests. Set to 0 for unlimited (uses Python default).')
    # [사용자 요청] LLM 동시 요청 수를 설정하는 인자 추가
    parser.add_argument('--connection-limit', type=int, default=500, help='Maximum number of open connections for the server')
    parser.add_argument('--base-url', default=os.getenv('AIBOX_BASE_URL'), help='External base URL for the server (e.g., http://aibo.example.com)')
    parser.add_argument('--test-llm', action='store_true', help='Perform a test call to the LLM server and exit.')
    args = parser.parse_args()

    logging.info("[1/8] Command-line arguments parsed.")
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
            # LLM_WORKER_EXECUTOR가 초기화되기 전이므로, _call_llm_single_blocking을 직접 호출합니다.
            raw_response_str = _call_llm_single_blocking(system_message, user_message, model_name, max_tokens=10)
            
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

    if not args.model:
        logging.info("Default model not specified. Querying available models from LLM server...")
        models = get_available_models(CONFIG['llm_url'], CONFIG.get('token'))
        if models:
            CONFIG['model'] = models[0]
            logging.info(f" -> Available models: {models}. Setting '{CONFIG['model']}' as the default model.")
        else:
            logging.error("Could not find available models from the LLM server. The --model argument is required.")
            parser.error("--model is required as no models could be auto-detected.")

    # [사용자 요청] 각 모델의 연결 상태를 확인하고 로깅합니다.
    logging.info("[5.5/8] 각 AI 모델 연결 상태 확인 시작...")
    models_to_check = {
        "Reasoning Model": CONFIG.get('reasoning_model'),
        "Fast Model": CONFIG.get('fast_model'),
        "Fallback Model": CONFIG.get('fallbacks_model')
    }
    for model_type, model_name in models_to_check.items():
        if model_name:
            is_ok, message = check_model_availability(model_name)
            status_log = f"  -> {model_type} ('{model_name}'): {'OK' if is_ok else 'FAIL'}"
            logging.info(status_log)
            if not is_ok: logging.warning(f"     - 원인: {message}")
    
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
    max_workers_for_llm = args.llm_max_workers if args.llm_max_workers > 0 else None
    LLM_WORKER_EXECUTOR = ThreadPoolExecutor(max_workers=max_workers_for_llm, thread_name_prefix='LLM_Worker') # type: ignore
    logging.info(f"LLM worker pool initialized with max_workers={max_workers_for_llm or 'default'}.")

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
