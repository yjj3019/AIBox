#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-
import urllib3
import requests
# [개선] 표준 json 라이브러리보다 빠른 orjson을 사용하고, 없을 경우 표준 라이브러리로 대체합니다.
# [BUG FIX] orjson이 있더라도, 예외 처리 등을 위해 표준 json 라이브러리를 항상 임포트합니다.
import json as _json_lib_std
try:
    import orjson
    _JSON_LIB = "orjson"
except ImportError:
    _JSON_LIB = "json"

from datetime import datetime, timedelta
import re
import os
import argparse
import sys
import time
import logging
import html

from concurrent.futures import ThreadPoolExecutor, as_completed

# [개선 & 안정성 강화] Markdown 라이브러리가 없을 경우 자동으로 설치하는 로직 추가
try:
    from markdown import markdown
except ImportError:
    logging.warning("The 'markdown' library is not installed. Attempting to install it now...")
    try:
        import subprocess
        # [BUG FIX] pip가 시스템에 여러 버전 설치된 경우를 대비하여, 현재 스크립트를 실행하는
        # 파이썬의 실행 파일(sys.executable)을 사용하여 정확한 pip를 호출합니다.
        # 이렇게 하면 가상 환경 등에서도 올바르게 라이브러리를 설치할 수 있습니다.
        # [BUG FIX] PermissionError: [Errno 13]를 방지하기 위해 --user 플래그를 추가하여
        # 시스템 디렉토리가 아닌 사용자 디렉토리에 라이브러리를 설치하도록 합니다.
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", "markdown"])
        from markdown import markdown

        # [BUG FIX] 'No module named markdown' 오류 해결
        # pip install --user로 설치한 후, 현재 실행 중인 프로세스가 새 라이브-러리를 즉시 찾지 못하는 문제를 해결합니다.
        # 1. 사용자 site-packages 경로를 sys.path에 추가합니다.
        # 2. importlib를 사용하여 import 캐시를 무효화합니다.
        import site
        import importlib
        # site.USER_SITE는 --user로 설치된 패키지의 경로입니다.
        if site.USER_SITE not in sys.path:
            sys.path.append(site.USER_SITE)
        importlib.invalidate_caches()
        logging.info("Successfully installed and imported the 'markdown' library.")
    except Exception as e:
        logging.error(f"Failed to auto-install 'markdown' library: {e}")
        logging.error("Executive Summary will be rendered as plain text. Please install it manually using: pip install markdown")
        markdown = None

# --- Settings ---
# 분석 기간 (일)
ANALYSIS_PERIOD_DAYS = 180
# 최종 리포트에 포함할 상위 CVE 개수
TOP_CVE_COUNT = 20
# [제안 반영] 캐시 설정
CACHE_DIR = "/data/iso/AIBox/cache"
CACHE_TTL_SECONDS = 86400  # 24시간
os.makedirs(CACHE_DIR, exist_ok=True)

# 랭킹 기록을 저장할 파일
INSTALLED_PACKAGES = set() # [개선] sos_analyzer로부터 전달받을 설치된 패키지 목록
# 분석 대상으로 고려할 최소 CVSSv3 점수
MIN_CVSS_SCORE = 7.0
# [수정] 사용자가 요청한 분석 대상 RHEL 제품 목록
TARGET_PRODUCT_PATTERNS = [
    re.compile(r"^Red Hat Enterprise Linux 7$"),
    re.compile(r"^Red Hat Enterprise Linux 7 Extended Lifecycle Support$"),
    re.compile(r"^Red Hat Enterprise Linux 8$"),
    re.compile(r"^Red Hat Enterprise Linux 8\.\d+ Extended Update Support$"),
    re.compile(r"^Red Hat Enterprise Linux 8\.\d+ Extended Update Support Long-Life Add-On$"),
    re.compile(r"^Red Hat Enterprise Linux 8\.\d+ Update Services for SAP Solutions$"),
    re.compile(r"^Red Hat Enterprise Linux 9$"),
    re.compile(r"^Red Hat Enterprise Linux 9\.\d+ Extended Update Support$"),
    re.compile(r"^Red Hat Enterprise Linux 9\.\d+ Extended Update Support Long-Life Add-On$"),
    re.compile(r"^Red Hat Enterprise Linux 9\.\d+ Update Services for SAP Solutions$"),
    re.compile(r"^Red Hat Enterprise Linux 10$"),
    re.compile(r"^Red Hat Enterprise Linux 10\.\d+ Extended Update Support$"),
    re.compile(r"^Red Hat Enterprise Linux 10\.\d+ Extended Update Support Long-Life Add-On$"),
    re.compile(r"^Red Hat Enterprise Linux 10\.\d+ Update Services for SAP Solutions$"),
    re.compile(r"^Red Hat Enterprise Linux \d+\.\d+ for SAP Solutions$")
]

# --- Global Configuration ---
CONFIG = {
    'AIBOX_SERVER_URL': "",
    'PROXIES': None,
    'HISTORY_FILE': '/data/iso/AIBox/ranking_history.json',
    'MAX_WORKERS': min(20, (os.cpu_count() or 1) * 2)
}

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# [사용자 요청 반영] 콘솔 출력에 색상을 추가하기 위한 Color 클래스
class Color:
    """콘솔 출력에 사용할 ANSI 색상 코드입니다."""
    PURPLE, CYAN, BLUE, GREEN, YELLOW, RED, BOLD, END = '\033[95m', '\033[96m', '\033[94m', '\033[92m', '\033[93m', '\033[91m', '\033[1m', '\033[0m'
    @staticmethod
    def header(text: str) -> str: return f"{Color.PURPLE}{Color.BOLD}{text}{Color.END}"
    @staticmethod
    def success(text: str) -> str: return f"{Color.GREEN}{text}{Color.END}"
    @staticmethod
    def error(text: str) -> str: return f"{Color.RED}{text}{Color.END}"
    @staticmethod
    def info(text: str) -> str: return f"{Color.CYAN}{text}{Color.END}"

def dumps_json(data, indent=False, ensure_ascii=False):
    """orjson과 표준 json 라이브러리를 모두 지원하는 JSON 직렬화 함수."""
    if _JSON_LIB == "orjson":
        # orjson은 ensure_ascii 인자를 지원하지 않지만, 기본적으로 UTF-8을 처리합니다.
        # 다른 코드와의 호환성을 위해 인자는 받지만 orjson 호출 시에는 사용하지 않습니다.
        options = orjson.OPT_INDENT_2 if indent else 0
        # orjson은 bytes를 반환하므로 decode()가 필요합니다.
        return orjson.dumps(data, option=options).decode('utf-8')
    else:
        # 표준 json 라이브러리는 ensure_ascii를 지원합니다.
        return _json_lib_std.dumps(data, indent=2 if indent else None, ensure_ascii=ensure_ascii)

def make_request(method, url, use_proxy=True, max_retries=3, **kwargs):
    """
    requests 라이브러리를 위한 중앙 집중식 래퍼 함수.
    use_proxy 플래그와 CONFIG에 따라 프록시 설정을 제어합니다.
    [개선] 제안에 따라 재시도 및 지수 백오프 로직을 추가합니다.
    """
    for attempt in range(max_retries):
        try:
            # [개선] use_proxy=False일 때, requests 호출 시 프록시를 명시적으로 비활성화합니다.
            if use_proxy and CONFIG.get('PROXIES'):
                kwargs['proxies'] = CONFIG['PROXIES']
            elif not use_proxy:
                kwargs['proxies'] = {'http': None, 'https': None}

            # [BUG FIX] 프록시 환경에서 발생할 수 있는 SSL 인증서 검증 오류를 방지하기 위해
            # verify=False 옵션을 추가합니다. 이는 시스템이 프록시의 자체 서명 인증서를
            # 신뢰하지 못할 때 발생합니다.
            kwargs.setdefault('verify', False)

            # 기본 타임아웃을 30초로 설정합니다.
            kwargs.setdefault('timeout', 30)

            response = requests.request(method, url, **kwargs)
            response.raise_for_status()
            return response # 성공 시 즉시 반환

        except requests.exceptions.ProxyError as e:
            logging.warning(f"Proxy Error during {method.upper()} request to {url}: {e}")
        except requests.exceptions.RequestException as e:
            logging.warning(f"Network Error during {method.upper()} request to {url}: {e}")

        # 재시도 전 대기 (지수 백오프)
        if attempt < max_retries - 1:
            wait_time = 2 ** attempt
            logging.info(f"Retrying in {wait_time} seconds...")
            time.sleep(wait_time)

    logging.error(f"All {max_retries} retries failed for {method.upper()} request to {url}.")
    return None

# [사용자 요청] verify=False 사용 시 발생하는 InsecureRequestWarning을 비활성화합니다.
# 이는 내부 프록시 환경에서 흔히 발생하는 경고로, 로그를 깔끔하게 유지하기 위함입니다.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def fetch_external_threat_intel(cve_id: str) -> dict:
    """[신규] CISA KEV 및 EPSS와 같은 외부 위협 인텔리전스 정보를 수집합니다."""
    intel = {
        "cisa_kev": {"in_kev": False, "date_added": None},
        "epss": {"score": None, "percentile": None},
        "has_poc": False # PoC 정보는 다른 소스에서 가져와야 할 수 있음
    }

    # 1. CISA KEV 정보 조회 (로컬 파일)
    # [사용자 요청] cisa_kev.json 파일에서 CVE ID 등재 여부 확인
    kev_file_path = "/data/iso/AIBox/data/cisa_kev.json" # AIBox_Server.py와 경로 통일
    try:
        with open(kev_file_path, 'rb') as f:
            kev_data = orjson.loads(f.read()) if _JSON_LIB == "orjson" else _json_lib_std.load(f)
        for vuln in kev_data.get("vulnerabilities", []):
            if vuln.get("cveID") == cve_id:
                intel["cisa_kev"]["in_kev"] = True
                intel["cisa_kev"]["date_added"] = vuln.get("dateAdded")
                logging.info(f"-> 로컬 KEV 파일에서 '{cve_id}'를 찾았습니다.")
                break
    except (FileNotFoundError, _json_lib_std.JSONDecodeError, IOError) as e:
        logging.warning(f"로컬 CISA KEV 데이터({kev_file_path}) 조회 중 오류 발생: {e}")

    # 2. EPSS 점수 조회 (외부 API)
    # [사용자 요청] EPSS 점수 조회 시 로컬 캐시 우선 확인
    local_epss_url = f"http://127.0.0.1:5000/AIBox/epss/{cve_id}"
    logging.info(f"로컬 서버에서 '{cve_id}' EPSS 데이터 조회를 시도합니다...")
    try:
        # 로컬 통신이므로 프록시 비활성화
        response = make_request('get', local_epss_url, use_proxy=False, timeout=10)
        if response and response.status_code == 200:
            logging.info(f"-> 로컬 서버에서 '{cve_id}' EPSS 데이터를 성공적으로 찾았습니다.")
            epss_data = response.json()
            intel["epss"]["score"] = epss_data.get("epss")
            intel["epss"]["percentile"] = epss_data.get("percentile")
            return intel # 로컬에서 찾았으므로 함수 종료
        logging.warning(f"로컬 서버에 '{cve_id}' EPSS 정보가 없습니다. 외부 API 조회를 시도합니다.")
    except Exception as e:
        logging.warning(f"로컬 EPSS 서버 연결 실패: {e}. 외부 API 조회를 시도합니다.")

    # 로컬 조회 실패 시 외부 EPSS API에서 조회
    external_epss_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    logging.info(f"EPSS API에서 '{cve_id}' 데이터 조회를 시도합니다...")
    response = make_request('get', external_epss_url, use_proxy=True, timeout=20)
    if response and response.status_code == 200:
        epss_response_data = response.json()
        if epss_response_data.get("status") == "OK" and epss_response_data.get("data"):
            epss_item = next((item for item in epss_response_data["data"] if item.get("cve") == cve_id), None)
            if epss_item:
                intel["epss"]["score"] = epss_item.get("epss")
                intel["epss"]["percentile"] = epss_item.get("percentile")
                logging.info(f"-> EPSS API에서 '{cve_id}' 점수를 찾았습니다 (EPSS: {epss_item.get('epss')}).")

                # 서버에 파일 저장을 요청하는 API 호출
                save_epss_url = f"http://127.0.0.1:5000/AIBox/api/cache/epss"
                save_payload = {
                    "cve_id": cve_id,
                    "data": {"epss": intel["epss"]["score"], "percentile": intel["epss"]["percentile"]}
                }
                try:
                    # 서버에 저장을 요청하고 응답을 기다리지 않음 (fire and forget)
                    make_request('post', save_epss_url, use_proxy=False, json=save_payload, timeout=5)
                    logging.info(f"-> '{cve_id}' EPSS 데이터를 로컬 서버에 저장하도록 요청했습니다.")
                except Exception as save_e:
                    logging.warning(f"-> 로컬 서버에 EPSS 데이터 저장 요청 실패: {save_e}")
            else:
                logging.info(f"-> EPSS API에서 '{cve_id}' 정보를 찾을 수 없습니다.")
    elif response:
        logging.warning(f"EPSS API 조회 실패 (HTTP {response.status_code}).")

    return intel

def fetch_redhat_cves(start_date):
    """Step 1: 로컬 파일에서 모든 CVE 목록을 가져옵니다. (JSON 파싱 강화)"""
    cve_file_path = '/data/iso/AIBox/cve_data.json'
    logging.info(f"\n{Color.header('Step 1: 로컬 파일에서 모든 CVE 목록 가져오기')}...\n")

    if not os.path.exists(cve_file_path):
        logging.error(f"CVE data file not found at '{cve_file_path}'.")
        return []

    cves = []
    try:
        if os.path.getsize(cve_file_path) == 0:
            logging.warning(f"The CVE data file '{cve_file_path}' is empty.")
            return []

        # [개선] orjson을 사용하여 대용량 JSON 파일을 더 빠르게 파싱합니다.
        # orjson은 바이너리 모드('rb')로 파일을 읽어야 합니다.
        with open(cve_file_path, 'rb') as f:
            cves = orjson.loads(f.read()) if _JSON_LIB == "orjson" else _json_lib_std.load(f)
            
    except Exception as e:
        # orjson 파싱 실패 시, 기존의 텍스트 기반 줄 단위 파싱으로 폴백합니다.
        logging.warning(f"Could not parse '{cve_file_path}' as a single JSON array. Error: {e}")
        logging.info(" -> Attempting to read file line-by-line as a stream of JSON objects...")

        cves_from_lines = []
        try:
            with open(cve_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line: # Skip empty lines
                        cves_from_lines.append(orjson.loads(line) if _JSON_LIB == "orjson" else _json_lib_std.loads(line))
            cves = cves_from_lines # If successful, replace cves with the line-by-line result
            logging.info(f" -> Successfully parsed {len(cves)} CVEs from line-by-line reading.")
        except Exception as e_line:
            logging.error(f"Failed to decode JSON from the file '{cve_file_path}' even when reading line-by-line.")
            logging.error(f" -> JSON Error Details: {e_line}")
            logging.error(" -> Please ensure the file contains valid JSON (either a single array or one JSON object per line).")
            return [] # Exit if both methods fail
            
    except IOError as e:
        logging.error(f"Could not read the file '{cve_file_path}': {e}")
        return []

    # --- Common processing logic ---
    if not isinstance(cves, list):
        logging.error("Expected a list of CVEs from the JSON file, but got a different type.")
        return []

    valid_cves = [cve for cve in cves if isinstance(cve, dict) and 'resource_url' in cve and 'CVE' in cve]
    print(f"-> Found {len(valid_cves)} initial CVEs from the local file.")
    
    # [BUG FIX & 개선] start_date를 사용하여 CVE 목록을 필터링합니다.
    if not isinstance(cves, list):
        logging.error("Expected a list of CVEs from the JSON file, but got a different type.")
        return []

    filtered_cves = []
    start_datetime = datetime.strptime(start_date, '%Y-%m-%d')
    for cve in cves:
        if isinstance(cve, dict) and 'public_date' in cve:
            try:
                public_datetime = datetime.strptime(cve['public_date'].split('T')[0], '%Y-%m-%d')
                if public_datetime >= start_datetime:
                    filtered_cves.append(cve)
            except (ValueError, TypeError):
                continue
    logging.info(f"-> Found {len(filtered_cves)} CVEs published after {start_date}.")
    return filtered_cves

def fetch_cve_details(cve_url: str):
    """
    [수정] CVE 상세 정보 URL을 사용하여 데이터를 가져옵니다.
    URL이 로컬 서버(127.0.0.1)를 가리키는 경우 프록시를 사용하지 않습니다.
    """
    # URL이 로컬 서버를 가리키는지 확인
    is_local = '127.0.0.1' in cve_url or 'localhost' in cve_url

    # [추가] 데이터 수집 출처 로그
    source = "local server" if is_local else "external Red Hat server"
    logging.info(f"   -> Fetching details from {source}: {cve_url}")
    
    # 로컬 통신일 경우 프록시를 비활성화(use_proxy=False)하고, 외부 통신일 경우 기본값(use_proxy=True)을 사용합니다.
    response = make_request('get', cve_url, use_proxy=not is_local, timeout=15)
    
    return response.json() if response else None

def filter_cves_by_strict_criteria(all_cves):
    """
    [핵심 수정] 사용자의 명확한 요구사항에 따른 엄격한 필터링 함수
    1. RHEL 제품 관련성 확인
    2. Severity가 'important' 또는 'critical'인지 확인
    3. CVSSv3 점수가 7.0 이상인지 확인
    """
    logging.info(f"\n{Color.header(f'Step 3: {len(all_cves)}개 CVE에 대한 엄격한 기준 필터링 적용')}...\n")
    passed_cves = []
    
    for cve in all_cves:
        if not isinstance(cve, dict):
            continue
        
        cve_id = cve.get('CVE', 'N/A')
        
        # 조건 1: 제품 관련성 확인
        package_states = cve.get('package_state', [])
        affected_rhel_products = set()
        affected_package_names = set()

        if isinstance(package_states, list):
            for state in package_states:
                product_name = state.get('product_name')
                if state.get('fix_state') == 'Affected' and any(pattern.match(product_name) for pattern in TARGET_PRODUCT_PATTERNS):
                    affected_rhel_products.add(product_name)
                    pkg_name_match = re.match(r'([^-\s]+)', state.get('package_name', ''))
                    if pkg_name_match:
                        affected_package_names.add(pkg_name_match.group(1))

        if not affected_rhel_products:
            continue

        # 조건 2: Severity 확인
        severity = cve.get('severity')
        if severity not in ['critical', 'important']:
            continue
        
        # 조건 3: CVSSv3 점수 확인
        # [BUG FIX] CVSS 점수 파싱 로직을 강화하여, cve.get('cvss3_score')가 None일 경우 발생하는 TypeError를 방지합니다.
        # 또한, 점수가 문자열이 아닌 경우를 대비하여 str()로 감싸줍니다.
        cvss3_score = 0.0
        cvss3_data = cve.get('cvss3', {})
        if isinstance(cvss3_data, dict):
            try:
                score_str = cvss3_data.get('cvss3_base_score') or cve.get('cvss3_score')
                if score_str:
                    cvss3_score = float(score_str)
            except (ValueError, TypeError):
                pass
        
        if cvss3_score < MIN_CVSS_SCORE:
            continue
        
        # 모든 조건을 통과한 CVE만 추가
        # [개선] 필터링 과정에서 추출한 제품 및 패키지 정보를 CVE 객체에 추가합니다.
        cve['affected_rhel_products'] = sorted(list(affected_rhel_products))
        cve['affected_package_names'] = sorted(list(affected_package_names))

        passed_cves.append(cve)

    logging.info(f"\n-> Initial filtering complete. {len(passed_cves)} CVEs passed basic criteria.")

    # [요청 반영] 패키지별 중복 제거 로직을 제거합니다.
    # 이제 기본 필터링을 통과한 모든 CVE가 LLM 분석 대상으로 전달됩니다.
    logging.info(f"-> {len(passed_cves)} CVEs will be sent to LLM for analysis.")
    return passed_cves

def get_from_cache(cache_name):
    """지정된 이름의 캐시 파일에서 데이터를 로드합니다."""
    cache_file = os.path.join(CACHE_DIR, f"{cache_name}.json")
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                cache_data = _json_lib_std.load(f) if _JSON_LIB != "orjson" else orjson.loads(f.read())
            if time.time() - cache_data.get('timestamp', 0) < CACHE_TTL_SECONDS:
                logging.info(f"Using cached data for '{cache_name}'.")
                return cache_data.get('data')
        except (json.JSONDecodeError, IOError):
            logging.warning(f"Could not read or parse cache file: {cache_file}")
    return None

def _create_final_analysis_prompt(cves_chunk: list) -> str:
    """[신규] 최종 후보 CVE 묶음을 분석하고 우선순위를 선정하기 위한 통합 전문가 프롬프트를 생성합니다."""
    
    cves_for_prompt = []
    for cve in cves_chunk:
        # [개선] 외부 위협 인텔리전스 정보를 프롬프트에 포함
        cvss3_score = cve.get('cvss3', {}).get('cvss3_base_score', 'N/A') if isinstance(cve.get('cvss3'), dict) else 'N/A'
        summary = extract_summary_from_cve(cve)
        cves_for_prompt.append({
            "cve_id": cve.get('CVE'),
            "severity": cve.get('severity', 'N/A'),
            "cvss_score": cvss3_score,
            "summary": summary,
            "is_in_kev": cve.get('is_in_kev', False),
            "has_poc": cve.get('has_poc', False),
            "epss_details": {
                "score": cve.get('epss_score'),
                "percentile": cve.get('epss_percentile')
            }
        })

    return f"""[시스템 역할]
당신은 Red Hat Enterprise Linux(RHEL)의 보안 취약점을 분석하는 최고 수준의 사이버 보안 전문가입니다. 당신의 임무는 주어진 여러 개의 CVE 데이터 목록을 분석하여, 실제 위협이 되는 CVE의 우선순위를 선정하고 상세 분석을 수행하는 것입니다. **모든 분석 결과는 반드시 자연스러운 한국어로 작성해야 합니다.**

[분석 대상 시스템 정보]
이 분석은 특정 시스템에 종속되지 않은, RHEL 생태계 전반에 대한 일반적인 위협 평가입니다.

[분석 가이드라인 및 웹 검색 활용]
1.  **외부 정보 수집 (Web Search)**: 각 CVE에 대해 웹 검색을 수행하여 다음 정보를 수집합니다.
    *   **한국 KISA/KrCERT 경보 발령 또는 등재 여부를 최우선으로 고려합니다.**
    *   **CISA KEV (Known Exploited Vulnerabilities) 등재 여부**
    *   **PoC (Proof-of-Concept) 코드 공개 여부** (예: Exploit-DB, GitHub)
    *   **EPSS (Exploit Prediction Scoring System) 점수 및 백분위**
2.  **우선순위 선정**: 위에서 수집한 정보를 바탕으로 우선순위를 선정합니다. 한국 KISA/KrCERT 등재 CVE 를 최우선으로 고려하고, CISA KEV 등재 CVE를 차선으로 고려합니다. 그 다음으로 **패키지 중요도('kernel', 'glibc', 'openssl', 'systemd', 'grub2', 'gcc', 'bash', 'pacemaker', 'corosync', 'openssh' 등)**, PoC 공개 여부, EPSS 백분위, CVSS 점수, 공격 심각도(RCE, 권한 상승) 순으로 종합 평가하여 가장 시급한 CVE부터 정렬합니다.
3.  **상세 분석**: 각 CVE에 대해 다음 항목을 분석하고 식별하십시오.
    *   **위협 태그(threat_tags)**: "RCE", "Privilege Escalation", "DoS" 등 위협 유형을 식별합니다. CISA KEV에 등재되었다면 **반드시 "Exploited in wild" 태그를 포함**해야 합니다. EPSS 점수가 0.2 이상이면 "High Exploit Probability" 태그를 추가하세요.
    *   PoC가 공개되었다면 **"PoC Available"** 태그를 추가하세요. EPSS 백분위가 0.9 (90%) 이상이면 **"Top 10% Exploit Risk"** 태그를 추가하세요.
    *   **영향받는 핵심 컴포넌트(affected_components)**: 'kernel', 'glibc', 'openssl', 'systemd', 'grub2', 'gcc', 'bash', 'pacemaker', 'corosync', 'openssh' 등 RHEL 시스템의 핵심 컴포넌트를 식별합니다.
    *   **간결한 요약(concise_summary)**: 비전문가도 이해할 수 있도록 **한국어 2~3줄로** 요약합니다.
    *   **선정 이유(selection_reason)**: **웹 검색으로 찾은 CISA KEV, PoC, EPSS 정보를 핵심 근거로** 사용하여, RHEL 환경에서의 실질적인 위협 시나리오, 공격 난이도, 영향받는 서비스의 중요도를 종합하여 **한국어로 구체적으로 설명**합니다.

[입력 데이터: CVE 목록]
```json
{dumps_json(cves_for_prompt, indent=True)}
```

[출력 형식]
분석 결과를 다음의 키를 가진 단일 JSON 객체로만 반환하십시오. **객체의 최상위 키는 반드시 "cve_analysis_results" 이어야 하며, 값은 우선순위에 따라 정렬된 각 CVE 분석 결과의 배열이어야 합니다.** 다른 설명은 절대 추가하지 마세요.
```json
{{
  "cve_analysis_results": [
    {{ "cve_id": "<가장 중요한 CVE ID>", "threat_tags": [], "affected_components": [], "concise_summary": "", "selection_reason": "" }},
    {{ "cve_id": "<두 번째로 중요한 CVE ID>", "threat_tags": [], "affected_components": [], "concise_summary": "", "selection_reason": "" }}
  ]
}}
```"""

def _create_preliminary_analysis_prompt(cves_chunk: list) -> str:
    """[신규] 예선 분석을 위한 프롬프트를 생성합니다. 각 묶음에서 상위 CVE를 선정합니다."""
    cves_for_prompt = []
    for cve in cves_chunk:
        threat_intel = cve.get('threat_intel', {})
        cves_for_prompt.append({
            "cve_id": cve.get('CVE'),
            "severity": cve.get('severity', 'N/A'),
            "cvss_score": cve.get('cvss3', {}).get('cvss3_base_score', 'N/A'),
            "affected_packages": cve.get('affected_package_names', []),
            "is_in_kev": threat_intel.get('cisa_kev', {}).get('in_kev', False),
            "epss_score": threat_intel.get('epss', {}).get('score')
        })

    return f"""[시스템 역할]
당신은 주어진 지침을 정확히 따르는, 출력을 제어하는 AI 어시스턴트입니다.

[임무]
아래에 제공된 CVE 목록 중에서, 가장 중요하고 시급하다고 판단되는 CVE의 ID 목록을 **JSON 배열 형식으로만 반환**하십시오.

[평가 기준]
**CISA KEV 등재 여부**와 **EPSS 점수**를 최우선으로 고려하고, 그 다음으로 CVSS 점수, 심각도, 패키지 중요도('kernel', 'glibc', 'openssh' 등)를 종합적으로 고려하여 실제 위협이 되는 CVE를 선정해야 합니다.

[제한 조건]
- **패키지별 대표 선정:** 동일한 패키지(예: 'kernel')에 여러 취약점이 있다면, 그중 가장 위험한 **단 하나의 CVE만** 대표로 선정해야 합니다.
- **출력 형식 엄수:** **반드시 JSON 배열 형식으로만 응답해야 합니다.** 다른 설명, 노트, 분석 과정 등은 절대 포함하지 마십시오.

[입력 데이터: CVE 목록]
```json
{dumps_json(cves_for_prompt, indent=True)}
```

[출력 형식]
**가장 중요한 순서대로 CVE ID 문자열을 포함하는 JSON 배열 하나만 출력하십시오.** 다른 설명은 절대 추가하지 마세요.
```json
["CVE-XXXX-YYYY", "CVE-AAAA-BBBB", "CVE-CCCC-DDDD", "CVE-EEEE-FFFF", "CVE-GGGG-HHHH"]
```"""

def _create_final_analysis_prompt(cves_chunk: list) -> str:
    """[수정] 최종 후보 CVE 묶음을 분석하고 우선순위를 선정하기 위한 통합 전문가 프롬프트를 생성합니다.""" # noqa: E501
    
    cves_for_prompt = []
    for cve in cves_chunk:
        threat_intel = cve.get('threat_intel', {})
        cvss3_score = cve.get('cvss3', {}).get('cvss3_base_score', 'N/A') if isinstance(cve.get('cvss3'), dict) else 'N/A'
        summary = extract_summary_from_cve(cve)
        cves_for_prompt.append({
            "cve_id": cve.get('CVE'),
            "severity": cve.get('severity', 'N/A'),
            "cvss_score": cvss3_score,
            "summary": summary,
            "affected_packages": cve.get('affected_package_names', []),
            # [사용자 요청] 최종 분석 프롬프트에도 KEV 및 EPSS 정보를 포함하여 AI가 활용하도록 합니다.
            "is_in_kev": threat_intel.get('cisa_kev', {}).get('in_kev', False),
            "epss_score": threat_intel.get('epss', {}).get('score')
        })

    return f"""[시스템 역할] deep_dive 종합 분석
당신은 Red Hat Enterprise Linux(RHEL)의 보안 취약점을 분석하는 최고 수준의 사이버 보안 전문가입니다. 당신의 임무는 주어진 여러 개의 CVE 데이터 목록을 분석하여, 실제 위협이 되는 CVE의 우선순위를 선정하고 상세 분석을 수행하는 것입니다. **모든 분석 결과는 반드시 자연스러운 한국어로 작성해야 합니다.**

[분석 가이드라인 및 웹 검색 활용]
1.  **외부 정보 수집 (Web Search)**: 각 CVE에 대해 웹 검색을 수행하여 다음 정보를 수집합니다.
    *   **한국 KISA/KrCERT 경보**: 한국 관련 기관의 경보 발령 여부 (최우선 고려)
    *   **CISA KEV**: 실제 공격에 악용되었는지 여부
    *   **PoC (Proof-of-Concept)**: 공개된 공격 코드가 있는지 여부
    *   **EPSS (Exploit Prediction Scoring System)**: 향후 30일 내 공격 발생 가능성
2.  **우선순위 선정 및 최종 {TOP_CVE_COUNT}개 선택**: **입력 데이터에 명시된 `is_in_kev`와 `epss_score` 정보를 최우선으로 고려**하고, 웹 검색 결과를 종합하여 우선순위를 선정합니다. (KISA/KrCERT 등재 > CISA KEV 등재 > PoC 공개 > 높은 EPSS 점수 > 높은 CVSS 점수 순으로 중요)
3.  **패키지별 대표 선정 (매우 중요)**: 최종 리포트에 포함할 CVE를 선정할 때, 동일한 패키지(예: 'kernel')에 여러 취약점이 있다면, 그중 가장 위험한 **단 하나의 CVE만** 대표로 선정하여 최종 목록에 포함시켜야 합니다.
4.  **상세 분석**: 각 CVE에 대해 다음 항목을 분석하고 식별하십시오.
    *   **위협 태그(threat_tags)**: "RCE", "Privilege Escalation", "DoS" 등 위협 유형을 식별합니다. CISA KEV에 등재되었다면 **반드시 "Exploited in wild" 태그를 포함**해야 합니다. EPSS 점수가 0.2 이상이면 "High Exploit Probability" 태그를 추가하세요.
    *   PoC가 공개되었다면 **"PoC Available"** 태그를 추가하세요. EPSS 백분위가 0.9 (90%) 이상이면 **"Top 10% Exploit Risk"** 태그를 추가하세요.
    *   **영향받는 핵심 컴포넌트(affected_components)**: 'kernel', 'glibc', 'openssl', 'systemd', 'grub2', 'gcc', 'bash', 'pacemaker', 'corosync', 'openssh' 등 RHEL 시스템의 핵심 컴포넌트를 식별합니다.
    *   **간결한 요약(concise_summary)**: 비전문가도 이해할 수 있도록 **한국어 2~3줄로** 요약합니다.
    *   **선정 이유(selection_reason)**: **웹 검색으로 찾은 CISA KEV, PoC, EPSS 정보를 핵심 근거로** 사용하여, RHEL 환경에서의 실질적인 위협 시나리오, 공격 난이도, 영향받는 서비스의 중요도를 종합하여 **한국어로 구체적으로 설명**합니다.
[입력 데이터: CVE 목록]
```json
{dumps_json(cves_for_prompt, indent=True)}
```

[출력 형식]
분석 결과를 다음의 키를 가진 단일 JSON 객체로만 반환하십시오. **객체의 최상위 키는 반드시 "cve_analysis_results" 이어야 하며, 값은 우선순위에 따라 정렬된 각 CVE 분석 결과의 배열이어야 합니다.** 다른 설명은 절대 추가하지 마세요.
```json
{{
  "cve_analysis_results": [
    {{ "cve_id": "<가장 중요한 CVE ID>", "threat_tags": [], "affected_components": [], "concise_summary": "", "selection_reason": "" }},
    {{ "cve_id": "<두 번째로 중요한 CVE ID>", "threat_tags": [], "affected_components": [], "concise_summary": "", "selection_reason": "" }}
  ]
}}
```"""

def _create_batch_translation_prompt(cves_to_translate: list) -> str:
    """[신규] 여러 CVE 요약을 한번에 번역하기 위한 프롬프트를 생성합니다."""
    return f"""[시스템 역할]
당신은 영문으로 된 여러 개의 CVE 요약 정보를 각각 2~3줄의 간결하고 명확한 한국어 요약으로 변환하는 보안 전문가입니다.

[입력 데이터]
```json
{dumps_json(cves_to_translate, indent=True)}
```

[출력 형식]
반드시 다음의 키를 가진 단일 JSON 객체로만 응답하십시오. 다른 설명은 절대 추가하지 마세요.
```json
{{
  "translations": [
    {{ "cve_id": "<CVE-ID-1>", "korean_summary": "<CVE-1의 한국어 요약>" }},
    {{ "cve_id": "<CVE-ID-2>", "korean_summary": "<CVE-2의 한국어 요약>" }}
  ]
}}
```"""

def extract_summary_from_cve(cve_data):
    """CVE 데이터 객체에서 요약 정보를 추출합니다."""
    if not isinstance(cve_data, dict): return ""
    
    details = cve_data.get('details', [])
    if details and isinstance(details, list):
        summary = " ".join(details)
        if summary.strip(): return summary.strip()
            
    statement = cve_data.get('statement', "")
    if statement and isinstance(statement, str):
        if statement.strip(): return statement.strip()

    return ""

def translate_text_with_llm(text_to_translate: str) -> str:
    """주어진 텍스트를 한국어로 번역하기 위해 LLM을 호출합니다."""
    if not text_to_translate:
        return "번역할 내용이 없습니다."

    # 번역을 위한 간단한 프롬프트
    translation_prompt = f"""Please translate the following English text into natural-sounding Korean.

**English Text:**
"{html.escape(text_to_translate)}"

**Korean Translation:**
"""
    payload = {"prompt": translation_prompt}
    api_url = f'{CONFIG["AIBOX_SERVER_URL"].rstrip("/")}/AIBox/api/cve/analyze' # 범용 분석 엔드포인트 사용

    try:
        # 내부 통신이므로 프록시 비활성화
        response = make_request('post', api_url, use_proxy=False, json=payload, timeout=60)
        if response and response.ok:
            # [BUG FIX] 서버가 JSON 객체 대신 순수 텍스트로 응답하는 경우를 처리합니다.
            # 'str' object has no attribute 'get' 오류를 방지하기 위해 .text를 직접 사용합니다.
            return html.escape(response.text.strip())
        elif response:
            # 응답은 있지만 ok가 아닌 경우
            logging.warning(f"Text translation failed with status {response.status_code}")
    except Exception as e:
        logging.warning(f"Text translation failed: {e}")

    return "요약 정보를 한국어로 번역하는 데 실패했습니다." # 번역 실패 시 대체 텍스트

def get_rhsa_ids_from_cve(cve_data):
    """CVE 상세 데이터 객체에서 직접 공식 RHSA ID 목록을 추출합니다."""
    if not isinstance(cve_data, dict): return []
    rhsa_ids = cve_data.get('advisories', [])
    return sorted([rhsa for rhsa in rhsa_ids if isinstance(rhsa, str) and rhsa.startswith("RHSA-")])

def generate_fallback_analysis(cve, affected_packages):
    """서버 오류 시 기본 분석 결과를 생성하고, 요약을 한국어로 번역합니다."""
    severity = cve.get('severity', 'N/A')
    english_summary = extract_summary_from_cve(cve)
    korean_summary = translate_text_with_llm(english_summary)
    
    # 기본 태그 생성
    threat_tags = []
    if severity == 'critical':
        threat_tags.append("Critical Vulnerability")
    if re.search(r'remote code execution|rce', english_summary, re.IGNORECASE):
        threat_tags.append("RCE")
    if re.search(r'privilege escalation', english_summary, re.IGNORECASE):
        threat_tags.append("Privilege Escalation")
    
    return {
        "threat_tags": threat_tags,
        "affected_components": affected_packages[:5],
        "concise_summary": korean_summary,
        "selection_reason": f"심각도 {severity}의 RHEL 관련 취약점으로, 자동 분석 시스템에 의해 선정되었습니다."
    }

def _create_batch_cve_analysis_prompt(cves_chunk: list) -> str:
    """[신규] CVE 묶음(chunk)을 한번에 분석하기 위한 전문가 프롬프트를 생성합니다."""
    
    cves_for_prompt = []
    for cve in cves_chunk:
        cvss3_score = cve.get('cvss3', {}).get('cvss3_base_score', 'N/A') if isinstance(cve.get('cvss3'), dict) else 'N/A'
        cvss3_vector = cve.get('cvss3', {}).get('cvss3_vector', 'N/A') if isinstance(cve.get('cvss3'), dict) else 'N/A'
        summary = extract_summary_from_cve(cve)
        affected_packages = cve.get('affected_package_names', []) # [개선] 미리 추출된 정보 사용
        
        cves_for_prompt.append({
            "cve_id": cve.get('CVE'),
            "severity": cve.get('severity', 'N/A'),
            "public_date": cve.get('public_date', 'N/A'),
            "cvss_score": cvss3_score,
            "cvss_vector": cvss3_vector,
            "affected_packages": affected_packages,
            "summary": summary
        })

    return f"""[시스템 역할]
당신은 Red Hat Enterprise Linux(RHEL)의 보안 취약점을 분석하는 Red Hat 최고 수준의 사이버 보안 전문가입니다. 당신의 임무는 주어진 여러 개의 CVE 데이터 목록을 분석하여 각각의 실제 위협 수준과 RHEL 환경에 미치는 영향을 평가하는 것입니다.

[분석 가이드라인]
각 CVE에 대해 다음 항목을 분석하고 식별하십시오.
1. **위협 태그(threat_tags)**: CVE 설명과 CVSS 벡터를 종합하여 "RCE", "Privilege Escalation", "DoS", "Exploited in the wild" 등의 위협 태그를 식별합니다.
2. **영향받는 핵심 컴포넌트(affected_components)**: RHEL 시스템의 중요도에 따라 'kernel', 'glibc', 'openssl', 'systemd', 'grub2', 'gcc', 'bash', 'pacemaker', 'corosync', 'openssh' 등 핵심 컴포넌트를 식별합니다.
3. **간결한 요약(concise_summary)**: 비전문가도 이해할 수 있도록 1~2 문장으로 요약합니다.
4. **선정 이유(selection_reason)**: RHEL 운영 환경에서의 실질적인 위협 시나리오, 공격 난이도, 영향받는 서비스의 중요도를 종합하여 구체적으로 설명합니다.

[입력 데이터: CVE 목록]
```json
{json.dumps(cves_for_prompt, indent=2, ensure_ascii=False)}
```

[출력 형식]
분석 결과를 다음의 키를 가진 단일 JSON 객체로만 반환하십시오. **객체의 최상위 키는 반드시 "cve_analysis_results" 이어야 하며, 값은 각 CVE 분석 결과의 배열이어야 합니다.** 다른 설명은 절대 추가하지 마세요.
```json
{{
  "cve_analysis_results": [
    {{
      "cve_id": "<분석한 CVE ID>",
      "threat_tags": ["<분석된 위협 태그 목록>"],
      "affected_components": ["<핵심 컴포넌트 목록>"],
      "concise_summary": "<1~2 문장의 간결한 요약>",
      "selection_reason": "<상세한 선정 이유>"
    }}
  ]
}}
```"""

def _call_llm_for_batch_analysis(prompt: str) -> dict:
    """[신규] 배치 분석 프롬프트를 AIBox 서버로 보내고 결과를 받습니다."""
    api_url = f'{CONFIG["AIBOX_SERVER_URL"].rstrip("/")}/AIBox/api/cve/analyze'
    payload = {"prompt": prompt}
    
    # [핵심 개선] 서버가 스트리밍으로 응답하므로, stream=True로 요청하고 응답을 조립합니다.
    # 타임아웃을 600초(10분)로 늘려 대규모 분석을 지원합니다.
    try:
        response = make_request('post', api_url, use_proxy=False, json=payload, timeout=600, stream=True)

        if not response or not response.ok:
            status_code = response.status_code if response else 'N/A'
            error_text = response.text if response else "No response from server."
            logging.error(f"AIBox 서버로부터 유효한 응답을 받지 못했습니다. 상태 코드: {status_code}")
            return {"error": f"AIBox server returned status {status_code}", "details": error_text[:500]}
        
        # [핵심 수정] 스트리밍 응답을 처리합니다.
        # 서버가 보내주는 데이터 조각(chunk)들을 순서대로 합쳐서 전체 응답을 만듭니다.
        # 이 방식은 타임아웃 문제를 해결하고, 대용량 응답을 메모리 효율적으로 처리합니다.
        # [BUG FIX] iter_content가 decode_unicode=True 임에도 bytes를 반환하는 경우에 대비하여
        # 명시적으로 디코딩하여 TypeError를 방지합니다.
        # 'must be str, not bytes' 오류를 해결합니다.
        full_response_str = "".join(
            chunk.decode('utf-8', errors='ignore') if isinstance(chunk, bytes) else chunk
            for chunk in response.iter_content(chunk_size=8192, decode_unicode=True)
            if chunk
        )
                
        if not full_response_str:
            logging.error("AIBox server returned an empty response body.")
            return {}
        
        # LLM이 JSON 코드 블록(```json ... ```)으로 응답하는 경우를 처리
        match = re.search(r'```(json)?\s*(\{.*\}|\[.*\])\s*```', full_response_str, re.DOTALL)
        if match:
            json_str = match.group(2)
        else:
            json_str = full_response_str
            
        return orjson.loads(json_str) if _JSON_LIB == "orjson" else _json_lib_std.loads(json_str)
        
    except _json_lib_std.JSONDecodeError:
        # [BUG FIX] 이미 소진된 response.text 대신, 미리 받아둔 full_response_str을 로깅합니다.
        logging.error("Failed to parse JSON response from AIBox server.")
        logging.error(f"Raw response text: {full_response_str[:500]}")

    return {}

def analyze_and_prioritize_with_llm(cves: list) -> list:
    """[프로세스 통합] Step 4: 최종 후보 CVE를 LLM을 통해 분석하고 우선순위를 선정합니다."""
    # [핵심 수정] 분할 정복(Divide and Conquer) 방식의 AI 분석 로직
    finalists = []
    # 1. 후보 CVE가 20개를 초과하면, 예선 분석을 통해 후보군을 줄입니다. (청크 크기: 20)
    if len(cves) > 20:
        logging.info(f"\n{Color.header(f'Step 4.1: 예선 분석 (후보 {len(cves)}개 > 최종 후보 선정)')}...")
        preliminary_finalists_ids = set()
        
        CHUNK_SIZE = 5
        cve_chunks = [cves[i:i + CHUNK_SIZE] for i in range(0, len(cves), CHUNK_SIZE)]

        with ThreadPoolExecutor(max_workers=6) as executor:
            future_to_chunk = {
                executor.submit(_call_llm_for_batch_analysis, _create_preliminary_analysis_prompt(chunk)): chunk
                for chunk in cve_chunks
            }
            for i, future in enumerate(as_completed(future_to_chunk), 1):
                chunk = future_to_chunk[future]
                chunk_cve_ids = [cve.get('CVE') for cve in chunk if cve.get('CVE')]
                # [BUG FIX] 병렬 처리 시 로그 순서가 섞이는 문제를 해결하기 위해, 작업 완료 시점에 로그를 기록합니다.
                logging.info(f"  - 예선 {i}/{len(cve_chunks)}번째 묶음 처리 완료. (대상: {len(chunk_cve_ids)}개)")
                try:
                    # AI 응답은 CVE ID의 리스트 형태일 것으로 기대
                    result = future.result()
                    # [안정성 강화] AI 분석 요청이 실패했는지(error 키 존재) 확인합니다.
                    if isinstance(result, dict) and 'error' in result:
                        logging.error(f"    -> AI 분석 요청 실패: {result.get('details', result['error'])}")
                        continue # 실패한 경우, 이 청크는 건너뛰고 다음으로 진행
                    
                    # [안정성 강화] AI 응답이 예상과 다른 형식일 경우를 대비한 처리
                    if isinstance(result, list):
                        logging.info(f"    -> AI가 {len(result)}개 선정: {', '.join(result[:5])}...")
                        preliminary_finalists_ids.update(result)

                    # [BUG FIX] AI가 예선 분석에서 실수로 결선 분석 형식(객체)의 응답을 보낸 경우 처리
                    elif isinstance(result, dict) and 'cve_analysis_results' in result:
                        cve_ids_from_dict = [item.get('cve_id') for item in result['cve_analysis_results'] if item.get('cve_id')]
                        logging.warning(f"    -> AI 응답이 객체 형식이었으나, 'cve_analysis_results' 키에서 {len(cve_ids_from_dict)}개의 CVE를 추출했습니다.")
                        preliminary_finalists_ids.update(cve_ids_from_dict)
                    else:
                        # [오류 로깅 개선] AI 서버가 반환한 오류 객체에서 'details' 키의 내용을 로그에 명시적으로 기록합니다.
                        error_details = result.get('details', str(result))
                        raw_text = str(result)
                        extracted_cves = re.findall(r'CVE-\d{4}-\d{4,}', raw_text)
                        if extracted_cves:
                            logging.warning(f"    -> AI 응답이 리스트가 아니었지만, 텍스트에서 {len(extracted_cves)}개의 CVE 목록을 추출했습니다.")
                            preliminary_finalists_ids.update(extracted_cves)
                        else:
                            logging.warning(f"    -> AI 응답이 예상과 다름 (리스트가 아님): {error_details[:250]}...")
                except Exception as e:
                    logging.error(f"CVE 예선 분석 묶음 처리 중 오류 발생: {e}")

        finalists = [cve for cve in cves if cve.get('CVE') in preliminary_finalists_ids]
        # [사용자 요청] 예선 통과 CVE 목록을 최종적으로 한 번만 출력합니다.
        logging.info(f"-> 예선 분석 완료. 최종 선정된 예선 통과 CVE: {len(finalists)}개 - {', '.join(sorted(list(preliminary_finalists_ids)))}")

    # 2. 최종 후보군에 대해 결선 분석을 수행합니다.
    else: # CVE가 20개 이하이면 예선 없이 바로 결선으로 진행
        finalists = cves

    # 2. 최종 후보군에 대해 결선 분석을 수행합니다.
    logging.info(f"\n{Color.header(f'Step 4.2: 결선 분석 ({len(finalists)}개 CVE 최종 순위 및 상세 분석)')}...")

    analyzed_cves = []
    cve_map = {cve.get('CVE'): cve for cve in finalists if cve.get('CVE')}

    # [핵심 개선] LLM의 컨텍스트 크기를 초과하지 않도록 최종 후보군을 안전하게 분할합니다.
    # 프롬프트의 기본 구조가 차지하는 토큰을 약 2000으로 가정합니다.
    # LLMChunker 유틸리티가 서버에 있으므로, 여기서는 보수적인 청크 크기를 사용합니다.
    # 일반적으로 CVE 객체 하나가 500~1000 토큰을 차지하므로, 5개씩 묶는 것이 안전합니다.
    FINAL_CHUNK_SIZE = 5
    finalist_chunks = [finalists[i:i + FINAL_CHUNK_SIZE] for i in range(0, len(finalists), FINAL_CHUNK_SIZE)] if finalists else []

    logging.info(f"  - 최종 후보 {len(finalists)}개를 {len(finalist_chunks)}개의 묶음으로 나누어 분석합니다.")
    with ThreadPoolExecutor(max_workers=6) as executor:
        future_to_chunk = {executor.submit(_call_llm_for_batch_analysis, _create_final_analysis_prompt(chunk)): chunk for chunk in finalist_chunks}
        for i, future in enumerate(as_completed(future_to_chunk), 1):
            chunk = future_to_chunk[future]
            chunk_cve_ids = [cve.get('CVE') for cve in chunk if cve.get('CVE')]
            # [BUG FIX] 병렬 처리 시 로그 순서가 섞이는 문제를 해결하기 위해, 작업 완료 시점에 로그를 기록합니다.
            logging.info(f"  - 결선 {i}/{len(finalist_chunks)}번째 묶음 처리 완료. (대상: {len(chunk_cve_ids)}개)")
            try:
                result = future.result()
                cve_results = result.get("cve_analysis_results", [])
                logging.info(f"    -> AI가 {len(cve_results)}개 분석 및 순위 선정 완료.")
                # [사용자 요청] AI가 선정한 CVE ID 목록을 로그에 출력합니다.
                if cve_results and isinstance(cve_results, list):
                    selected_cve_ids = [item.get('cve_id', 'N/A') for item in cve_results]
                    logging.info(f"    -> 선정된 CVE: {', '.join(selected_cve_ids)}")
                
                # [안정성 강화] cve_results가 리스트가 아닐 경우를 대비
                if not isinstance(cve_results, list):
                    logging.warning(f"    -> 결선 분석 결과가 리스트가 아닙니다: {cve_results}")
                    continue

                for analysis in cve_results: # cve_results가 리스트임을 보장
                    cve_id = analysis.get("cve_id")
                    if cve_id in cve_map:
                        cve_map[cve_id].update(analysis)
                        analyzed_cves.append(cve_map[cve_id])
            except Exception as e:
                logging.error(f"CVE 결선 분석 묶음 처리 중 오류 발생: {e}")

    # [사용자 요청 수정] AI 분석이 하나라도 성공했다면, AI의 결과를 최종 결과로 사용합니다.
    # AI 분석이 완전히 실패했을 경우에만 점수 기반 폴백 분석을 수행합니다.
    if not analyzed_cves and finalists:
        logging.warning("AI 분석이 완전히 실패했습니다. 점수 기반 폴백 분석을 수행합니다.")
        analyzed_cves = analyze_and_prioritize_manual(finalists)
    else:
        # AI가 일부만 분석한 경우, 분석되지 않은 나머지는 버리고 AI의 결과만 사용합니다.
        analyzed_cve_ids_from_llm = {cve.get('cve_id') for cve in analyzed_cves if cve.get('cve_id')}
        unalyzed_cves = [cve for cve in finalists if cve.get('CVE') not in analyzed_cve_ids_from_llm]
        if unalyzed_cves:
            logging.warning(f"AI가 분석하지 않은 {len(unalyzed_cves)}개의 CVE에 대해 점수 기반 폴백 분석 및 번역을 수행합니다.")
            # [사용자 요청] AI가 분석하지 않은 CVE에 대해 수동 분석(번역 포함)을 수행하고 결과를 병합합니다.
            fallback_analyzed_cves = analyze_and_prioritize_manual(unalyzed_cves)
            analyzed_cves.extend(fallback_analyzed_cves)
        

    # [핵심 개선] "패키지당 1개" 규칙을 적용하되, 최종 CVE 개수가 TOP_CVE_COUNT에 근접하도록 보장하는 로직.
    # 1. AI가 분석한 CVE 목록 외에, 예선은 통과했으나 결선에서 밀린 CVE도 후보군으로 사용합니다.
    analyzed_cve_ids = {cve.get("cve_id") for cve in analyzed_cves if cve.get("cve_id")}
    fallback_cves = [cve for cve in finalists if cve.get("CVE") not in analyzed_cve_ids]
    
    final_cves = []
    seen_packages = set()

    # 2. AI가 우선순위로 정렬한 목록과 폴백 목록을 합쳐 전체 후보군을 만듭니다.
    # [수정] AI 분석 결과와 폴백 분석 결과를 합치고, AI가 정한 순서를 최대한 유지하면서 점수 기반으로 재정렬합니다.
    full_candidate_list = analyzed_cves + fallback_cves
    full_candidate_list.sort(key=lambda x: x.get('priority_score', 0), reverse=True)

    for cve in full_candidate_list:
        # 최종 목록이 꽉 차면 중단합니다.
        if len(final_cves) >= TOP_CVE_COUNT:
            break

        # CVE 데이터에서 패키지 이름을 가져옵니다. AI 분석 결과가 있으면 'affected_components'를, 없으면 'affected_package_names'를 사용합니다.
        pkg_names_from_ai = cve.get('affected_components', [])
        pkg_names_from_filter = cve.get('affected_package_names', [])
        # [BUG FIX] 패키지 이름이 문자열로 잘못 들어오는 경우를 대비하여 항상 set으로 처리합니다.
        affected_pkg_names = set(pkg_names_from_ai if isinstance(pkg_names_from_ai, list) else ([pkg_names_from_ai] if pkg_names_from_ai else []))
        affected_pkg_names.update(pkg_names_from_filter if isinstance(pkg_names_from_filter, list) else ([pkg_names_from_filter] if pkg_names_from_filter else []))

        # 이 CVE의 패키지 중 하나라도 아직 선정되지 않았다면, 이 CVE를 최종 목록에 추가하고 패키지를 '선정됨'으로 기록합니다.
        if affected_pkg_names and not affected_pkg_names.intersection(seen_packages):
            final_cves.append(cve) # 최종 목록에 추가
            seen_packages.update(affected_pkg_names) # 사용된 패키지로 등록

    # LLM의 응답은 이미 우선순위대로 정렬되어 있으므로, 별도의 점수 기반 정렬이 필요 없습니다.
    logging.info(f"\n--- LLM analysis and prioritization complete. Finalized top {len(final_cves)} unique package CVEs. ---")
    # TOP_CVE_COUNT 만큼 잘라서 반환합니다.
    return final_cves[:TOP_CVE_COUNT]
    
    
def analyze_and_prioritize_manual(cves):
    """Step 5: 수집된 데이터와 점수 모델을 기반으로 CVE 우선순위를 정합니다."""
    logging.info(f"\nStep 5: Starting priority ranking based on scoring model...")

    for cve in cves:
        if not isinstance(cve, dict): continue
        score = 0
        summary = extract_summary_from_cve(cve)
        threat_tags = cve.get('threat_tags', [])
        
        if isinstance(threat_tags, list):
            if "Exploited in the wild" in threat_tags or re.search(r'in the wild|actively exploited', summary, re.IGNORECASE): score += 1000
            if "RCE" in threat_tags or re.search(r'remote code execution|rce', summary, re.IGNORECASE): score += 200
            if "Privilege Escalation" in threat_tags or re.search(r'privilege escalation', summary, re.IGNORECASE): score += 150

        # [제안 반영] KEV 및 EPSS 점수 모델 확장
        if cve.get('is_in_kev'):
            score += 500
        if cve.get('has_poc'):
            score += 250 # PoC 존재 시 추가 점수
        if 'epss_percentile' in cve:
            score += cve['epss_percentile'] * 500 # 백분위 점수 반영
        if 'epss_score' in cve:
            score += cve['epss_score'] * 1000
        
        if cve.get('severity') == 'critical': score += 100
        elif cve.get('severity') == 'important': score += 50

        cvss3_score = 0.0
        cvss3_data = cve.get('cvss3', {})
        if isinstance(cvss3_data, dict):
             try:
                score_str = cvss3_data.get('cvss3_base_score') or cve.get('cvss3_score')
                if score_str: cvss3_score = float(score_str)
             except (ValueError, TypeError): pass
        score += cvss3_score * 10
        
        components = cve.get('affected_components', [])
        critical_components = {'kernel', 'glibc', 'openssl', 'systemd', 'grub2', 'gcc', 'bash', 'pacemaker', 'corosync', 'openssh'}
        if isinstance(components, list) and any(comp.lower() in critical_components for comp in components):
            score += 100

        cve['priority_score'] = score
    
    # 점수 기반으로 상위 CVE를 먼저 선정합니다.
    cves.sort(key=lambda x: x.get('priority_score', 0), reverse=True)
    top_cves = cves[:TOP_CVE_COUNT]

    # [사용자 요청 수정] AI 분석 실패 시, 선정된 CVE의 요약을 LLM으로 번역합니다.
    logging.info(f"-> Fallback: Translating summaries for top {len(top_cves)} CVEs using LLM...")
    
    # 번역할 CVE 목록 준비
    # [개선] 외부 위협 인텔리전스(CISA KEV, EPSS)를 병렬로 조회합니다.
    with ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
        future_to_cve = {executor.submit(fetch_external_threat_intel, cve.get('CVE')): cve for cve in top_cves}
        for future in as_completed(future_to_cve):
            cve = future_to_cve[future]
            try:
                intel = future.result()
                cve['is_in_kev'] = intel.get('cisa_kev', {}).get('in_kev', False)
                cve['has_poc'] = intel.get('has_poc', False) # fetch_external_threat_intel에 PoC 조회 로직 추가 필요
                cve['epss_score'] = intel.get('epss', {}).get('score', 0.0)
                cve['epss_percentile'] = intel.get('epss', {}).get('percentile', 0.0)
            except Exception as e:
                logging.error(f"Error fetching threat intel for {cve.get('CVE')}: {e}")

    # [개선] 번역할 CVE 목록을 위협 인텔리전스 조회 후에 생성합니다.
    cves_to_translate = [
        {"cve_id": cve.get('CVE'), "summary": extract_summary_from_cve(cve)} for cve in top_cves if extract_summary_from_cve(cve)
    ]
    if cves_to_translate:
        # LLM을 호출하여 일괄 번역
        translation_prompt = _create_batch_translation_prompt(cves_to_translate)
        llm_response = _call_llm_for_batch_analysis(translation_prompt)
        translations_map = {item['cve_id']: item['korean_summary'] for item in llm_response.get('translations', []) if 'cve_id' in item}
        
        # 번역된 요약을 원본 CVE 데이터에 병합
        for cve in top_cves:
            cve['concise_summary'] = translations_map.get(cve.get('CVE'), "한국어 요약 생성에 실패했습니다.")

    logging.info(f"-> Analysis complete. Finalized top {len(top_cves)} CVEs.")
    return top_cves

def load_history():
    """랭킹 기록을 파일에서 불러옵니다."""
    if not os.path.exists(CONFIG['HISTORY_FILE']): return {}
    try:
        # [BUG FIX] orjson은 .load()를 지원하지 않으므로, 파일을 읽은 후 .loads()를 사용합니다.
        # orjson은 바이너리 읽기를 선호하므로 'rb'로 열고, 표준 json을 위해 디코딩합니다.
        with open(CONFIG['HISTORY_FILE'], 'rb') as f:
            content = f.read()
            if not content: return {} # 빈 파일 처리
            # orjson은 bytes를, 표준 json은 str을 처리하므로 isinstance로 분기
            return orjson.loads(content) if _JSON_LIB == "orjson" else _json_lib_std.loads(content)
    except (_json_lib_std.JSONDecodeError, IOError): return {}

def save_history(cve_ranks):
    """오늘의 랭킹 데이터를 파일에 저장합니다."""
    try:
        with open(CONFIG['HISTORY_FILE'], 'w', encoding='utf-8') as f: f.write(dumps_json(cve_ranks, indent=True, ensure_ascii=False))
        logging.info(f"\nToday's ranking information has been saved to '{CONFIG['HISTORY_FILE']}'.")
    except IOError as e: logging.error(f"Failed to save ranking history file. {e}")

def process_ranking_changes(todays_cves, previous_ranks):
    """최초 발견일을 기준으로 순위 변경 및 유지일을 계산합니다."""
    logging.info(f"\n{Color.header('Step 6: 순위 변동 및 유지 기간 계산')}...\n")
    processed_cves, todays_ranks_for_saving = [], {}
    today_str = datetime.now().strftime('%Y-%m-%d')
    today_date = datetime.strptime(today_str, '%Y-%m-%d')

    for i, cve in enumerate(todays_cves):
        if not isinstance(cve, dict): continue
        rank, cve_id = i + 1, cve.get('CVE')
        if not cve_id: continue
        
        cve_data = cve.copy()
        if cve_id in previous_ranks:
            previous_rank_data = previous_ranks[cve_id]
            previous_rank = previous_rank_data.get('rank')
            if rank < previous_rank: cve_data['rank_change'] = 'up'
            elif rank > previous_rank: cve_data['rank_change'] = 'down'
            else: cve_data['rank_change'] = 'same'
            # [BUG FIX] 과거 데이터가 있으면, 그 날짜를 그대로 사용
            cve_data['first_seen_date'] = previous_rank_data.get('first_seen_date', today_str)
        else:
            cve_data['rank_change'] = 'new'
            cve_data['first_seen_date'] = today_str

        # 날짜 계산
        first_seen_date = datetime.strptime(cve_data['first_seen_date'], '%Y-%m-%d')
        days_in_rank = (today_date - first_seen_date).days + 1
        cve_data['days_in_rank'] = days_in_rank
        
        processed_cves.append(cve_data)
        todays_ranks_for_saving[cve_id] = {'rank': rank, 'first_seen_date': cve_data['first_seen_date']}
        
    return processed_cves, todays_ranks_for_saving

def generate_executive_summary(top_cves):
    """[개선] 최종 선정된 CVE 목록을 바탕으로 CISO 관점의 Executive Summary를 생성하도록 AI에 요청합니다."""
    # [BUG FIX] 분석된 CVE가 없을 경우, LLM 호출을 건너뛰고 기본 메시지를 반환합니다.
    # 이는 LLM이 빈 데이터로 인해 500 오류를 반환하는 것을 방지합니다.
    if not top_cves:
        logging.info("\nNo CVEs to analyze for Executive Summary. Skipping LLM call.")
        return "분석 기간 내에 보고된 주요 보안 위협이 발견되지 않았습니다. 시스템은 현재 알려진 주요 취약점으로부터 안전한 것으로 보입니다."

    logging.info(f"\n{Color.header('Step 7: CISO 요약 보고서(Executive Summary) 생성 요청')}...\n")
    
    summary_data = [
        {
            "cve_id": cve.get('CVE'),
            "concise_summary": cve.get('concise_summary', ''),
            "severity": cve.get('severity', 'N/A'),
            "threat_tags": cve.get('threat_tags', []),
            "selection_reason": cve.get('selection_reason', ''),
            "cvss_score": cve.get('cvss3', {}).get('cvss3_base_score', 'N/A'),
            # [개선] Executive Summary 프롬프트에 외부 위협 인텔리전스 정보를 추가하여 AI가 활용하도록 합니다.
            "is_in_kev": cve.get('threat_intel', {}).get('cisa_kev', {}).get('in_kev', False),
            "epss_score": cve.get('threat_intel', {}).get('epss', {}).get('score')
        }
        for cve in top_cves
    ]

    current_date = datetime.now().strftime('%Y-%m-%d')

    # [사용자 요청 반영] Executive Summary의 분석 품질을 높이기 위해 프롬프트를 전면 개편합니다.
    summary_prompt = f"""[시스템 역할]
당신은 C-Level 경영진에게 RHEL 시스템의 보안 상태를 보고하는 **수석 보안 아키텍트(Principal Security Architect)**입니다. 당신의 분석은 기술적 사실 나열을 넘어, 비즈니스에 미치는 영향을 중심으로 명확한 실행 계획과 전략적 권고를 제시해야 합니다. **모든 내용은 반드시 유려하고 자연스러운 한국어로 작성해야 합니다.**

[컨텍스트]
분석 대상은 RHEL 환경에서 발견된 주요 보안 위협 {len(summary_data)}개이며, 보고일은 {current_date}입니다.

[임무]
제공된 보안 위협 목록과 **입력 데이터에 포함된 `is_in_kev`, `epss_score`와 같은 외부 위협 인텔리전스**를 종합적으로 분석하여, 아래 가이드라인에 따라 체계적인 **Executive Summary**를 **Markdown 형식의 텍스트**로 작성하십시오.
[분석 유형] Executive Summary
## 분석 가이드라인
1.  **종합 평가 (Overall Assessment)**: 현재 보안 상태에 대한 전반적인 평가(예: '심각', '주의 필요', '양호')와 그 핵심 근거(예: '실제 공격에 악용되는 `Exploited in wild` 태그가 포함된 CVE가 다수 발견됨')를 제시하며 보고서를 시작하십시오.
2.  **핵심 위협 상세 분석 (Key Threats Analysis)**:
    *   가장 시급하고 비즈니스 영향이 큰 위협 **2~3개**를 선정합니다.
    *   각 위협에 대해 **구체적인 공격 시나리오**와 **비즈니스 영향**(서비스 중단, 데이터 유출, 평판 하락 등)을 명확하게 설명합니다.
    *   **[매우 중요]** 위협 간의 연관성(예: A 취약점으로 초기 침투 후 B 취약점으로 권한 상승)을 분석하여 **공격 체인(Attack Chain) 관점의 위험도**를 제시합니다.
3.  **대응 전략 (Action Plan)**: 식별된 위협에 대한 대응 방안을 **표(테이블) 형식**으로 명확하게 제시합니다.
    *   **단기 조치 (Immediate Actions)**: 즉시 수행해야 할 패치, 임시 완화책, 긴급 차단 정책 등을 구체적으로 명시합니다.
    *   **중장기 전략 (Long-term Strategy)**: 근본적인 문제 해결을 위한 아키텍처 개선, 보안 강화 설정, 정기적인 취약점 관리 프로세스 도입 등을 제안합니다.
4.  **결론 및 권고 (Conclusion & Recommendation)**: 전체 내용을 요약하고, **가장 시급하게 실행해야 할 조치 1~2가지**를 다시 한번 강조하여 경영진의 의사결정을 돕습니다.

[입력 데이터: 상위 20개 보안 위협 목록]
```json
{dumps_json(summary_data, indent=True)}
```

[출력]
Executive Summary 텍스트를 여기에 작성하십시오. (HTML 태그 없이 순수 텍스트로)
"""

    payload = {"prompt": summary_prompt}
    api_url = f'{CONFIG["AIBOX_SERVER_URL"].rstrip("/")}/AIBox/api/cve/analyze' # 범용 분석 엔드포인트 사용
    
    # 내부 통신이므로 프록시 비활성화
    response = make_request('post', api_url, use_proxy=False, json=payload, timeout=300)

    if response:
        # [사용자 요청] AI 서버 응답이 JSON이거나 순수 텍스트(raw)인 모든 경우를 처리합니다.
        try:
            summary_json = response.json()
            # 1. JSON 응답 처리: 여러 가능한 키를 확인하여 요약 텍스트를 추출합니다.
            possible_keys = ['raw_response', 'executive_summary', 'analysis_text', 'analysis_report']
            summary_text = next((summary_json.get(key) for key in possible_keys if summary_json.get(key)), None)
            if summary_text:
                logging.info("Successfully extracted summary text from AI server's JSON response.")
            else:
                # 1-1. JSON 응답에 요약 키는 없지만 'error' 키가 있는 경우
                if 'error' in summary_json:
                    error_details = summary_json.get('details', summary_json['error'])
                    logging.error(f"AI 요약 생성 실패: {summary_json['error']} - Details: {error_details}")
                    return f"### AI 요약 생성 실패\n\nAI 서버로부터 다음 오류를 수신했습니다:\n- {error_details}"
                logging.warning(f"AI 서버가 예상치 못한 JSON 응답을 반환했습니다: {summary_json}")
                # 1-2. 요약 키도, 오류 키도 없는 비정상적인 JSON 응답
                return f"### AI 요약 처리 실패\n\nAI 서버로부터 예상치 못한 형식의 JSON 응답을 수신했습니다:\n```json\n{dumps_json(summary_json, indent=True)}\n```"
        except (_json_lib_std.JSONDecodeError, orjson.JSONDecodeError):
            # 2. 순수 텍스트(Raw) 응답 처리: JSON 파싱에 실패하면 응답을 일반 텍스트로 간주합니다.
            logging.warning("AI server response was not JSON. Processing as plain text.")
            summary_text = response.text.strip()
    else:
        return "### AI 요약 생성 실패\n\nAI 서버로부터 응답을 받지 못했습니다. 서버 상태 및 네트워크 연결을 확인해 주세요."

    # 모든 경우에 대해 불필요한 접두사를 제거하고 반환합니다.
    return re.sub(r'^\s*Executive Summary:\s*', '', summary_text, flags=re.IGNORECASE).strip()

def print_selection_reasons_to_console(cves):
    """상위 CVE의 선정 이유를 콘솔에 출력합니다."""
    logging.info("\n--- RHEL 컨텍스트 기반 상위 20개 CVE 선정 이유 ---")
    logging.info("=" * 70)
    for i, cve in enumerate(cves):
        if not isinstance(cve, dict): continue
        rank = i + 1
        cve_id = cve.get('CVE', 'N/A')
        reason = cve.get('selection_reason', 'LLM 분석 정보가 없습니다. RHEL 관련성, 심각도(Severity) 및 점수 모델 기반으로 선정되었습니다.')

        affected_products = cve.get('affected_rhel_products', []) # [개선] 미리 추출된 정보 사용
        logging.info(f" [{rank}위] {cve_id}")
        logging.info(f"  - 영향받는 제품: {', '.join(affected_products)}")
        logging.info(f"  - 선정 이유: {reason}\n")
    logging.info("=" * 70)

def markdown_to_html(md_text):
    """
    [개선] LLM이 생성한 Markdown 형식의 텍스트를 HTML로 변환하는 함수.
    'markdown' 라이브러리를 사용하여 테이블, 목록, 강조 등 다양한 서식을 지원합니다.
    """
    if not md_text:
        return "<p>요약 정보를 생성하지 못했습니다.</p>"
    
    if markdown:
        # 'markdown' 라이브러리를 사용하여 HTML로 변환합니다.
        # 'tables' 확장 기능을 활성화하여 Markdown 테이블을 올바르게 렌더링합니다.
        # 'nl2br' 확장 기능은 개행 문자를 <br> 태그로 변환하여 줄바꿈을 유지하고, 'tables' 확장 기능으로 표를 올바르게 렌더링합니다.
        return markdown(md_text, extensions=['tables', 'nl2br', 'fenced_code'])
    else:
        # 라이브러리가 없는 경우, 기존의 단순 변환 로직을 유지합니다.
        # 이 경우, 테이블은 제대로 표시되지 않을 수 있습니다.
        logging.warning("The 'markdown' library is not installed. Falling back to basic text formatting. Tables may not render correctly.")
        # 기존의 단순 변환 로직 (pre 태그로 감싸서 원본 유지)
        return f'<pre style="white-space: pre-wrap; font-family: inherit;">{html.escape(md_text)}</pre>'

def generate_report(processed_cves, executive_summary):
    """최종 분석 리포트를 HTML 파일로 생성합니다."""
    logging.info(f"\n{Color.header('Step 8: 최종 HTML 분석 리포트 생성')}...\n")

    # [사용자 요청] 로컬 폰트 파일을 읽어 Base64로 인코딩
    font_base64 = ""
    font_path = os.path.join(os.path.dirname(__file__), 'fonts', 'NanumGothicBold.ttf')
    if os.path.exists(font_path):
        try:
            import base64
            with open(font_path, 'rb') as f:
                font_base64 = base64.b64encode(f.read()).decode('utf-8')
            logging.info(f"로컬 폰트 '{font_path}'를 성공적으로 로드하여 보고서에 포함합니다.")
        except Exception as e:
            logging.warning(f"로컬 폰트 파일을 읽는 중 오류 발생: {e}")
    else:
        logging.warning(f"지정된 폰트 파일 '{font_path}'를 찾을 수 없습니다. 기본 웹 폰트를 사용합니다.")

    
    table_rows_html = ""
    for i, cve in enumerate(processed_cves):
        if not isinstance(cve, dict): continue
        rank, cve_id, severity = i + 1, cve.get('CVE', 'N/A'), cve.get('severity', 'N/A')

        # [BUG FIX] RHSA 필터링 로직을 for 루프 안으로 이동하여 각 CVE에 대해 개별적으로 적용합니다.
        rhsa_product_map = {}
        if isinstance(cve.get('affected_release'), list):
            for release in cve['affected_release']:
                advisory = release.get('advisory')
                product_name = release.get('product_name', '')
                # [핵심 수정] TARGET_PRODUCT_PATTERNS에 해당하는 제품의 RHSA만 추가합니다.
                if advisory and advisory.startswith("RHSA") and any(pattern.match(product_name) for pattern in TARGET_PRODUCT_PATTERNS):
                    # [BUG FIX] re.sub에서 백레퍼런스를 사용하려면 백슬래시를 이스케이프해야 합니다.
                    # r'RHEL \1' -> r'RHEL \\1'로 수정하여 'RHEL 9'와 같이 올바르게 출력되도록 합니다.
                    short_product_name = re.sub(r'Red Hat Enterprise Linux (\d+).*', r'RHEL \\1', product_name)
                    rhsa_product_map.setdefault(advisory, set()).add(short_product_name)

        remediation_html = ""
        if rhsa_product_map:
            sorted_rhsa = sorted(rhsa_product_map.keys())
            for rhsa_id in sorted_rhsa:
                products = ", ".join(sorted(list(rhsa_product_map[rhsa_id])))
                # [사용자 요청] RHSA와 제품 버전을 별도의 태그로 표시하여 시인성 향상
                product_tags_html = "".join(
                    f'<span class="rhsa-product-tag">{html.escape(p.strip())}</span>'
                    for p in products.split(',')
                )
                remediation_html += f'<div class="rhsa-item"><span class="rhsa-id-tag"><a href="https://access.redhat.com/errata/{html.escape(rhsa_id)}" target="_blank">{html.escape(rhsa_id)}</a></span>{product_tags_html}</div>'
        else:
            remediation_html = "발행 예정"

        # [BUG FIX] CISA/EPSS 정보 표시 로직을 for 루프 안으로 이동하여 각 CVE에 대해 개별적으로 적용합니다.
        threat_intel = cve.get('threat_intel', {})
        cisa_kev_data = threat_intel.get('cisa_kev', {})

        public_date = cve.get('public_date', 'N/A').split('T')[0]
        default_summary = " ".join(cve.get('details', [])) or '요약 정보 없음'
        summary = html.escape(cve.get('concise_summary') or default_summary)
        
        # [요구사항 반영] 'Affected' 상태인 제품 목록을 추출하여 요약 정보에 추가
        # [사용자 요청] affected_release와 package_state의 모든 제품명을 수집하여 중복 제거
        # [사용자 요청] '영향 받는 제품' 선정 기준 강화
        # 1. affected_release와 package_state(fix_state='Affected')에서 제품명 수집
        # 2. TARGET_PRODUCT_PATTERNS와 일치하는 제품만 필터링
        # 3. 중복 제거 후 정렬하여 출력
        affected_products_html = ""
        all_affected_products = set()

        if isinstance(cve.get('affected_release'), list):
            for release in cve['affected_release']:
                product_name = release.get('product_name')
                if product_name and any(pattern.match(product_name) for pattern in TARGET_PRODUCT_PATTERNS):
                    all_affected_products.add(product_name)

        if isinstance(cve.get('package_state'), list):
            for state in cve['package_state']:
                product_name = state.get('product_name')
                if state.get('fix_state') == 'Affected' and product_name and any(pattern.match(product_name) for pattern in TARGET_PRODUCT_PATTERNS):
                    all_affected_products.add(product_name)

        if all_affected_products:
            # 제품명을 정렬하여 일관된 순서로 표시
            products_str = '<br>'.join(sorted(list(all_affected_products)))
            affected_products_html = f'<br><br><strong>영향 받는 제품:</strong><br>{products_str}'

        # [개선] 통합된 선정 이유와 리스크 평가를 가져옴
        selection_reason = html.escape(cve.get('selection_reason', 'RHEL 관련성, 심각도 및 CVSS 점수 기반으로 선정되었습니다.'))
        tags_html, packages_html = "", ""
        
        threat_tags = cve.get('threat_tags', [])
        if isinstance(threat_tags, list) and threat_tags:
            for tag in threat_tags:
                tag_class = "tag-exploited" if "Exploited" in str(tag) else "tag-threat" # [수정] Exploit 태그 강조
                tags_html += f'<span class="threat-tag {tag_class}">{tag}</span>'
        
        affected_components = cve.get('affected_components', [])
        if isinstance(affected_components, list) and affected_components:
            for pkg in [html.escape(p) for p in affected_components[:3]]:
                packages_html += f'<span class="threat-tag tag-pkg">{pkg}</span>'
            if len(affected_components) > 3: packages_html += f'<span class="threat-tag tag-pkg">...</span>'
        
        severity_icon, severity_class = ('🔥', 'severity-critical') if severity == 'critical' else ('⚠️', 'severity-important')
        rank_change_icon = {'up': '▲', 'down': '▼', 'same': '—', 'new': 'N'}.get(cve.get('rank_change'), '—')
        rank_change_class = f"rank-{cve.get('rank_change', 'same')}"
        days_in_rank = cve.get('days_in_rank', 1)
        
        cvss3_score = 0.0
        cvss3_data = cve.get('cvss3', {})
        if isinstance(cvss3_data, dict):
             try:
                score_str = cvss3_data.get('cvss3_base_score') or cve.get('cvss3_score')
                if score_str: cvss3_score = float(score_str)
             except (ValueError, TypeError): pass

        # [사용자 요청] CISA, EPSS 정보 추가
        # [BUG FIX] CISA/EPSS 정보가 리포트에 누락되는 문제를 해결합니다.
        # threat_intel 데이터를 사용하여 cisa_info와 epss_info를 생성합니다.
        threat_intel = cve.get('threat_intel', {})
        cisa_kev_info = threat_intel.get('cisa_kev', {})
        if cisa_kev_info.get('in_kev'):
            cisa_info = cisa_kev_info.get('date_added', '등재됨')
        else:
            cisa_info = "해당 없음"
        
        epss_info = "N/A"
        epss_score = threat_intel.get('epss', {}).get('score')
        # [BUG FIX] epss_score가 숫자인 경우에만 포맷팅을 적용하여 ValueError를 방지합니다.
        epss_info = "N/A"
        if epss_score is not None and isinstance(epss_score, (int, float)):
            try:
                epss_info = f"{float(epss_score):.5f}"
            except (ValueError, TypeError):
                pass # 숫자로 변환할 수 없으면 "N/A" 유지
        
        score_details_html = f"""
            <div class="score-details">
                <span>CVSS: {cvss3_score if cvss3_score > 0 else 'N/A'}</span>
                <span>CISA: {cisa_info}</span>
                <span>EPSS: {epss_info}</span>
            </div>
        """

        table_rows_html += f"""<tr>
            <td class="center-align"><div class="rank-cell"><span class="rank-number">{rank}</span><span class="rank-change {rank_change_class}">{html.escape(rank_change_icon)}</span></div></td>
            <td><a href="https://access.redhat.com/security/cve/{cve_id}" target="_blank">{cve_id}</a><br><small>{public_date if public_date != 'N/A' else ''}</small></td>
            <td class="center-align"><span class="{severity_class} severity-badge">{severity_icon} {str(severity).capitalize()}</span>{score_details_html}</td>
            <td class="center-align">{days_in_rank}일</td>
            <td><div class="summary-tags">{tags_html}{packages_html}</div>{summary}{affected_products_html}</td>
            <td>{selection_reason}</td>
            <td>{remediation_html}</td></tr>"""
    
    analysis_date, report_month = datetime.now().strftime('%Y-%m-%d'), datetime.now().strftime('%Y-%m')

    html_content = f"""<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RHEL 보안 위협 분석 리포트 ({report_month})</title>
    <style>
    {'@font-face {{ font-family: "NanumGothic"; src: url(data:font/truetype;base64,{font_base64}) format("truetype"); font-weight: normal; font-style: normal; }}' if font_base64 else ''}
    :root{{
        --primary-color: #007bff; --secondary-color: #6c757d; --success-color: #28a745;
        --danger-color: #dc3545; --warning-color: #ffc107; --background-color: #f0f4f8;
        --surface-color: #ffffff; --text-color: #212529; --header-bg: #0d1b2a;
        --header-text: #ffffff; --border-color: #dee2e6; --shadow: 0 4px 12px rgba(0,0,0,0.08);
    }}
    body{{
        font-family:{'"NanumGothic", "Noto Sans KR", sans-serif' if font_base64 else '"Noto Sans KR", sans-serif'}; margin:0; padding: 2rem;
        background-color:var(--background-color); color:var(--text-color); 
        font-size:16px; line-height:1.6;
    }}
    .container{{ max-width:1600px; margin:0 auto; }}
    .header{{
        background-color: var(--header-bg); color: var(--header-text);
        padding: 3rem 2rem; text-align: center; border-radius: 12px;
        margin-bottom: 2rem; box-shadow: var(--shadow);
    }}
    h1{{ font-size:2.5rem; font-weight:700; margin:0; }}
    .header p{{ font-size:1.1rem; opacity: 0.8; max-width:800px; margin:1rem auto 0; }}
    .summary-card, .report-card{{
        background-color:var(--surface-color); border:1px solid var(--border-color);
        border-radius:12px; box-shadow:var(--shadow);
        overflow:hidden; margin-bottom:2rem;
    }}
    .summary-card .card-header {{
        font-size:1.5rem; color: var(--text-color); border-bottom: 1px solid var(--border-color);
        padding:1.25rem 1.5rem; margin:0;
    }}
    .summary-card .card-body {{ padding:1.5rem; margin:0; font-size:1.05rem; line-height:1.8; }}
    .summary-card .card-body h3 {{ font-size: 1.25rem; font-weight: 700; margin-top: 1.5rem; margin-bottom: 0.5rem; padding-bottom: 0.25rem; border-bottom: 2px solid #e2e8f0; }}
    .summary-card .card-body ul {{ list-style-type: disc; padding-left: 1.5rem; margin-top: 0.5rem; }}
    .summary-card .card-body li {{ margin-bottom: 0.5rem; }}
    .summary-card .card-body p {{ margin-bottom: 1rem; }}
    .summary-card h2 {{
        font-size:1.5rem; color: var(--text-color); border-bottom: 1px solid var(--border-color);
        padding:1.25rem 1.5rem; margin:0;
    }}
    .summary-card p{{ padding:1.5rem; margin:0; font-size:1.05rem; line-height:1.8; }}
    table{{ width:100%; border-collapse:collapse; }}
    th,td{{
        padding:1rem 1.25rem; text-align:left;
        vertical-align:top; border-bottom:1px solid var(--border-color);
    }}
    thead th{{
        background-color:#f8f9fa; color: var(--text-color); font-weight:700;
        font-size:.9rem; position:sticky; top:0; z-index:1;
    }}
    tbody tr{{ transition:background-color .2s ease-in-out; }}
    tbody tr:hover{{ background-color:#f8f9fa; }}
    tbody tr:last-child td{{ border-bottom:none; }}
    a{{ color:var(--primary-color); text-decoration:none; font-weight:500; }}
    a:hover{{ text-decoration:underline; }}
    .center-align{{ text-align:center; }}
    .rank-cell{{ display:flex; align-items:center; justify-content:center; gap:8px; }}
    .rank-number{{ font-size:1.5rem; font-weight:700; color:var(--text-color); }}
    .rank-change{{ font-size:1rem; font-weight:700; }}
    .rank-up{{ color:var(--danger-color); }}
    .rank-down{{ color:var(--primary-color); }}
    .rank-same{{ color:var(--secondary-color); }}
    .rank-new{{ color:var(--success-color); }}
    .severity-badge{{
        display:inline-block; padding:.3em .6em; font-size:.85rem;
        font-weight:700; border-radius:.375rem; border: 1px solid transparent;
    }}
    .severity-critical{{
        background-color: #ffebee; color: var(--danger-color); border-color: var(--danger-color);
    }}
    .severity-important{{
        background-color: #fff8e1; color: #f57c00; border-color: #f57c00;
    }}
    .summary-tags{{ margin-bottom:.5rem; }}
    .threat-tag{{
        display:inline-block; padding:.2em .6em; margin-right:.5rem;
        margin-bottom:.3rem; font-size:.8rem; font-weight:500;
        color:#fff; border-radius:4px;
    }}
    .tag-exploited{{ background-color: var(--danger-color); }}
    .tag-threat{{ background-color: #f57c00; }}
    .tag-pkg{{ background-color: var(--secondary-color); }}
    /* [사용자 요청] RHSA 조치 방안 스타일 개선 */
    .rhsa-item {{ display: flex; align-items: center; flex-wrap: wrap; gap: 0.4rem; margin-bottom: 0.4rem; }}
    .rhsa-id-tag {{ display: inline-block; background-color: var(--success-color); color: white; padding: .2em .6em; border-radius: 4px; font-size: .85rem; font-weight: 500; }}
    .rhsa-id-tag a {{ color: white; text-decoration: none; }}
    .rhsa-id-tag a:hover {{ text-decoration: underline; }}
    .rhsa-product-tag {{ display: inline-block; background-color: #e9ecef; color: #495057; padding: .2em .6em; border-radius: 4px; font-size: .8rem; font-weight: 500; }}
    /* --- END RHSA 스타일 --- */
    .score-details {{
        font-size: 0.8em; color: #6c757d; margin-top: 0.4rem;
        display: flex; flex-direction: column; align-items: center; gap: 2px;
    }}
    .button-container {{
        text-align: right;
        margin-top: 2rem;
    }}
    .button {{
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        background-image: linear-gradient(to right, #007bff, #0056b3);
        color: white;
        border: none;
        padding: 0.8rem 1.5rem;
        border-radius: 8px;
        cursor: pointer;
        font-size: 1rem;
        font-weight: 500;
        text-decoration: none;
        transition: all 0.3s ease;
    }}
    .button:hover {{
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0, 123, 255, 0.2);
    }}
    </style></head><body><div class="container">
    <div class="header"><h1>RHEL 보안 위협 분석 리포트</h1><p><strong>분석 기준일: {analysis_date}</strong> | <strong>분석 대상 기간:</strong> 최근 {ANALYSIS_PERIOD_DAYS}일 및 과거 주요 취약점</p></div>
    <div class="summary-card"><div class="card-header">Executive Summary</div><div class="card-body">{markdown_to_html(executive_summary)}</div></div>
    <div class="report-card"><table><thead><tr>
    <th style="width:5%">순위</th><th style="width:12%">CVE-ID & 공개일</th><th style="width:10%">심각도 & 점수</th><th style="width:8%">순위 유지일</th>
    <th style="width:25%">취약점 요약</th><th style="width:25%">선정 이유</th><th style="width:15%">조치 방안 (RHSA)</th>
    </tr></thead><tbody>{table_rows_html}</tbody></table></div>
    <div class="button-container">
        <button id="save-html-btn" class="button">HTML로 저장</button>
    </div>
    </div>
    <script>
        document.getElementById('save-html-btn').addEventListener('click', function() {{
            const docClone = document.documentElement.cloneNode(true);
            const buttonContainerClone = docClone.querySelector('.button-container');
            if (buttonContainerClone) buttonContainerClone.remove();
            const scriptTagClone = docClone.querySelector('script');
            if (scriptTagClone) scriptTagClone.remove();
            const htmlContent = '<!DOCTYPE html>\\n' + docClone.outerHTML;
            const blob = new Blob([htmlContent], {{ type: 'text/html;charset=utf-8' }});
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'rhel_top20_report_{report_month}.html';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(a.href);
        }});
    </script>
    </body></html>"""
    
    report_filename = "/data/iso/AIBox/rhel_top20_report.html"
    try:
        with open(report_filename, "w", encoding="utf-8") as f: f.write(html_content)
        logging.info(f"-> Success: Report '{report_filename}' has been generated.")
    except IOError as e: logging.error(f"-> Error: Failed to generate HTML report. {e}")

def load_config(args):
    """Load configuration from arguments and environment variables."""
    CONFIG['AIBOX_SERVER_URL'] = args.server_url or os.getenv('AIBOX_SERVER_URL')
    if args.proxy:
        CONFIG['PROXIES'] = {'http': args.proxy, 'https': args.proxy}
        logging.info(f"Using proxy server: {args.proxy}")

    if args.no_proxy:
        os.environ['no_proxy'] = args.no_proxy
        logging.info(f"Excluding from proxy: {args.no_proxy}")


def main():
    """메인 실행 함수"""
    logging.info("===== RHEL Security Threat Analysis Script Started =====")
    global INSTALLED_PACKAGES
    parser = argparse.ArgumentParser(
        description="RHEL Top Security Threat Analysis Script",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--server-url', required=True, help='Full URL of the AIBox API server (e.g., http://localhost:5000)')
    # [개선] sos_analyzer로부터 설치된 패키지 목록을 파일 형태로 전달받기 위한 인자 추가
    parser.add_argument('--packages-file', help='A file containing a list of installed packages, one per line.')
    parser.add_argument('--proxy', help='HTTP/HTTPS proxy server URL (e.g., http://user:pass@host:port)')
    parser.add_argument('--no-proxy', help='Comma-separated list of hosts to exclude from proxy')
    
    args = parser.parse_args()

    load_config(args)

    # [개선] 패키지 파일이 제공되면, 내용을 읽어 INSTALLED_PACKAGES 세트에 저장
    if args.packages_file and os.path.exists(args.packages_file):
        logging.info(f"Loading installed packages from '{args.packages_file}'...")
        with open(args.packages_file, 'r', encoding='utf-8') as f:
            INSTALLED_PACKAGES = {line.strip() for line in f if line.strip()}
        logging.info(f"-> Loaded {len(INSTALLED_PACKAGES)} installed packages for filtering.")
    else:
        logging.warning("No package file provided. CVE filtering will be less accurate.")

    start_date = (datetime.now() - timedelta(days=ANALYSIS_PERIOD_DAYS)).strftime('%Y-%m-%d')
    
    previous_ranks = load_history()
    logging.info(f"-> Loaded {len(previous_ranks)} previous ranking records.")

    recent_cves_summary = fetch_redhat_cves(start_date)

    if not recent_cves_summary:
        logging.error("Could not load any CVEs from the local file. Exiting program.")
        return

    
    # [리팩토링] 후보 CVE 목록 생성 로직 통합
    # 1. 최신 CVE 목록을 기반으로 후보군 생성
    candidate_cves_map = {cve['CVE']: cve for cve in recent_cves_summary}
    # 2. 과거 순위에만 있던 CVE를 후보군에 추가
    for cve_id in previous_ranks.keys():
        if cve_id not in candidate_cves_map:
            # [개선] 과거 순위에만 있던 CVE가 후보군에 추가되었음을 로그로 명시합니다.
            logging.info(f"  -> 과거 순위의 CVE '{cve_id}'를 분석 후보에 추가합니다.")
            candidate_cves_map[cve_id] = {'CVE': cve_id}

    logging.info(f"\n{Color.header(f'Step 2: {len(candidate_cves_map)}개 후보 CVE 상세 정보 조회')}...\n")
    all_cve_data = []

    # [안정성 강화] 1단계: 상세 정보와 외부 위협 인텔리전스를 병렬로 조회
    failed_cve_ids = []
    with ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
        # 각 CVE에 대해 상세 정보 조회와 외부 정보 조회를 동시에 제출
        future_to_cve = {
            executor.submit(fetch_cve_details, f"http://127.0.0.1:5000/AIBox/cve/{cve_id}.json"): (cve_id, 'details')
            for cve_id in candidate_cves_map.keys()
        }
        future_to_cve.update({
            executor.submit(fetch_external_threat_intel, cve_id): (cve_id, 'intel')
            for cve_id in candidate_cves_map.keys()
        })

        processed_count = 0
        for future in as_completed(future_to_cve):
            cve_id, data_type = future_to_cve[future]
            result_data = future.result()

            if result_data:
                # 조회된 데이터를 기존 CVE 맵에 병합
                candidate_cves_map[cve_id].update(result_data if data_type == 'details' else {'threat_intel': result_data})
            elif data_type == 'details':
                failed_cve_ids.append(cve_id) # 상세 정보 조회 실패 시에만 폴백
            
            # [개선] 진행률 로깅 (전체 작업의 절반이므로 2로 나눔)
            processed_count += 1
            logging.info(f"  -> 상세 정보 조회 진행률: {processed_count}/{len(future_to_cve)} ({cve_id}, {data_type})")

    all_cve_data = list(candidate_cves_map.values())
    logging.info(f"-> [완료] 총 {len(all_cve_data)}개 CVE에 대한 상세 정보 조회를 완료했습니다 (로컬 실패: {len(failed_cve_ids)}건).")

    # [BUG FIX] 외부 위협 인텔리전스(CISA, EPSS) 조회 로직 추가
    logging.info(f"\n{Color.header(f'Step 2.2: {len(all_cve_data)}개 CVE에 대한 외부 위협 인텔리전스 조회')}...\n")
    with ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
        processed_count = 0
        future_to_cve = {executor.submit(fetch_external_threat_intel, cve.get('CVE')): cve for cve in all_cve_data if cve.get('CVE')}
        for future in as_completed(future_to_cve):
            cve = future_to_cve[future]
            try:
                intel = future.result()
                cve['threat_intel'] = intel
            except Exception as e:
                logging.error(f"Error fetching threat intel for {cve.get('CVE')}: {e}")
                cve['threat_intel'] = {} # 실패 시 빈 객체 할당
            processed_count += 1
            logging.info(f"  -> 외부 위협 정보 조회 진행률: {processed_count}/{len(future_to_cve)} ({cve.get('CVE')})")
    logging.info("-> [완료] 외부 위협 인텔리전스 조회가 완료되었습니다.")

    # [안정성 강화] 2단계: 로컬 조회에 실패한 CVE들을 Red Hat 공식 사이트에서 다시 조회 (폴백)
    if failed_cve_ids:
        logging.info(f"\n{Color.info(f'Step 2.3: 로컬 조회 실패 CVE ({len(failed_cve_ids)}개) 외부 API로 재시도')}...\n")
        with ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
            future_to_cve_id = {}
            for cve_id in failed_cve_ids:
                fallback_url = f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"
                future = executor.submit(fetch_cve_details, fallback_url)
                future_to_cve_id[future] = cve_id
            
            for future in as_completed(future_to_cve_id):
                cve_id = future_to_cve_id[future]
                detailed_data = future.result()
                if detailed_data:
                    all_cve_data.append({**candidate_cves_map[cve_id], **detailed_data})
                else:
                    logging.critical(f"Failed to fetch details for {cve_id} from all sources. It will be excluded from analysis.")
        logging.info(f"-> [완료] 외부 Red Hat API를 통해 추가로 {len(failed_cve_ids)}개 CVE 정보를 수집했습니다.")

    cves_meeting_criteria = filter_cves_by_strict_criteria(all_cve_data)

    if not cves_meeting_criteria:
        logging.info("No CVEs meeting the specified criteria were found. Generating an empty report.")
        # [개선] CVE가 없더라도 빈 리포트를 생성하여 프로세스를 완료합니다.
        generate_report([], "분석 기간 내에 보고된 주요 보안 위협이 발견되지 않았습니다.")
        return
    
    if not CONFIG['AIBOX_SERVER_URL']:
         logging.error("AIBox Server URL must be provided to get recommendations. Exiting program.")
         sys.exit(1)

    llm_recommended_cves = analyze_and_prioritize_with_llm(cves_meeting_criteria)
    logging.info(f"-> AI가 최종적으로 리포트에 포함할 {Color.success(f'Top {len(llm_recommended_cves)}개')} CVE를 선정했습니다.")
        
    processed_cves, todays_ranks_to_save = process_ranking_changes(llm_recommended_cves, previous_ranks)
    
    executive_summary = generate_executive_summary(processed_cves)

    generate_report(processed_cves, executive_summary)
    save_history(todays_ranks_to_save)
    logging.info("===== RHEL Security Threat Analysis Script Finished =====")

if __name__ == "__main__":
    main()
