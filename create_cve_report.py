#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-

# 특정 조건의 cve 를 리스트 형태로 출력하는 소스

import os
import sys
import json
import re
import requests
import argparse
import time
import logging
import html
from jinja2 import Environment, FileSystemLoader
from datetime import datetime

# [개선] orjson 라이브러리가 있으면 사용하여 JSON 처리 속도를 높입니다.
try:
    import orjson
    def dumps(data, indent=False):
        options = orjson.OPT_INDENT_2 if indent else 0
        return orjson.dumps(data, option=options).decode('utf-8')
    def loads(data):
        return orjson.loads(data)
except ImportError:
    def dumps(data, indent=False):
        return json.dumps(data, indent=2 if indent else None, ensure_ascii=False)
    def loads(data):
        return json.loads(data)
    logging.warning("'orjson' 라이브러리를 찾을 수 없습니다. 표준 'json' 라이브러리를 사용합니다.")

# [개선] markdown 라이브러리가 있으면 사용하여 AI 응답을 미려한 HTML로 변환합니다.
try:
    from markdown import markdown
except ImportError:
    markdown = None
    logging.warning("'markdown' 라이브러리가 설치되지 않았습니다. AI 분석 결과가 기본 텍스트로 표시됩니다.")

# --- 로깅 설정 ---
# 표준 에러(stderr)로 로그를 출력하여, 표준 출력(stdout)으로는 순수 HTML 결과만 나가도록 합니다.
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s', stream=sys.stderr)

# [BUG FIX] requests의 InsecureRequestWarning 비활성화 (security.py 로직 참고)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- [신규] 필터링할 RHEL 제품 목록 (정규표현식 사용) ---
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
# --- AI(LLM) 분석 함수 ---
def make_request_with_retry(method, url, max_retries=3, **kwargs):
    """[수정] 재시도 및 성공 로그 로직이 추가된 범용 요청 함수 (security.py 로직 참고)"""
    for attempt in range(max_retries):
        try:
            response = requests.request(method, url, **kwargs)
            response.raise_for_status()
            if attempt > 0:
                logging.info(f"요청 재시도 성공 (시도 {attempt + 1}/{max_retries}): {url}")
            return response
        except requests.RequestException as e:
            logging.warning(f"요청 실패 (시도 {attempt + 1}/{max_retries}): {url}, 오류: {e}")
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                time.sleep(wait_time)
            else:
                logging.error(f"요청이 모든 재시도({max_retries}회) 후에도 최종 실패했습니다: {url}")
                return None
    return None

def analyze_data_with_llm(cve_id: str, cve_data: dict, external_data: dict, server_url: str) -> str:
    """제공된 CVE 데이터를 기반으로 지정된 AIBox 서버를 호출하여 분석을 수행합니다."""
    # [사용자 요청] LLM 응답 파싱 실패 시 3회 재시도 로직 추가
    max_retries = 3 # noqa: F841

    # [BUG FIX] CVE 데이터가 비어있으면 AI 분석을 시도하지 않고 즉시 반환합니다.
    if not cve_data:
        return "### AI 분석 불가\n\n제공된 CVE에 대한 정보가 없습니다. 해당 CVE의 세부 정보나 영향을 분석하기 위해 구체적인 식별자(CVE 번호)가 필요합니다."

    for attempt in range(max_retries):
        logging.info(f"'{cve_id}'에 대한 AI 분석을 시작합니다 (시도 {attempt + 1}/{max_retries}, 서버: {server_url})...")
        
        # [요청사항 반영] 프롬프트에 포함할 제품 목록 문자열 생성
        target_products_str = "\n".join([f"- `{p.pattern}`" for p in TARGET_PRODUCT_PATTERNS])

        # [BUG FIX] 외부 위협 인텔리전스 정보를 프롬프트에 포함하여 AI가 활용하도록 합니다.
        external_intel_str = f"""
[입력 데이터: 외부 위협 인텔리전스]
```json
{dumps(external_data, indent=True)}
```"""
        # [사용자 요청 반영] Red Hat 보안 전문가의 관점에서 체계적인 보고서를 생성하도록 프롬프트를 전면 개편합니다.
        # AI가 웹 검색을 통해 최신 정보를 수집하고, 지정된 형식에 맞춰 상세 분석을 수행하도록 지시합니다.
        prompt = f"""[시스템 역할]
당신은 Red Hat의 최고 수준 보안 전문가이자, 복잡한 기술 내용을 명확하고 간결한 한국어로 전달하는 데 능숙한 IT 전문 번역가입니다. 주어진 CVE 데이터와 **웹 검색을 통해 수집한 최신 정보를 바탕으로**, 아래의 상세한 가이드라인과 출력 형식에 맞춰 전문적인 보안 분석 보고서를 한국어로 작성하십시오. {external_intel_str}

[분석 대상 제품 목록]
아래 목록에 해당하는 Red Hat Enterprise Linux 제품에 대해서만 분석을 집중하십시오.
{target_products_str}

[분석 가이드라인]
1.  **정확성**: 제공된 JSON 데이터와 웹 검색 결과를 교차 검증하여 기술적으로 정확한 내용만 전달합니다.
2.  **명확성**: 기술 용어는 한국 IT 환경에서 보편적으로 사용되는 용어를 채택하되, 비전문가도 이해할 수 있도록 쉽게 설명합니다.
3.  **용어 선택**: 한국어로 번역 시 의미가 모호해질 수 있는 기술 용어는 원문(영어)을 그대로 사용하거나 병기하여 명확성을 유지합니다. (예: 'Orchestration'은 '오케스트레이션'으로 음차 표기)
4.  **간결성**: 각 항목은 핵심 내용 위주로 간결하게 요약하여 작성합니다.

[분석 유형] security report
[입력 데이터: CVE 정보] 
```json
{dumps(cve_data, indent=True)}
```

[출력 형식: 상세 분석 보고서 (Markdown)]
### 취약점 개요 (Vulnerability Summary)
- **[분석 대상 제품 목록]에 명시된 제품 중에서** 이 취약점의 영향을 받는 소프트웨어, 문제 발생 원인, 그리고 그로 인해 유발되는 핵심적인 취약점(예: 정수 오버플로우, 힙 버퍼 오버플로우)을 **마크다운(굵은 글씨, 목록 등)을 적극적으로 사용하여** 명확하고 간결하게 설명합니다. 다른 제품은 절대 언급하지 마십시오.

### 근본 원인 분석 (Root Cause Analysis)
- 제공된 'cwe'와 상세 설명을 바탕으로 취약점이 발생하는 기술적 원인을 **마크다운을 활용하여 구조적으로** 심층 분석합니다.

### 잠재적 영향 (Impact Assessment)
- 'cvss3' 점수와 'EPSS' 점수를 기반으로, 이 취약점이 악용될 경우 발생할 수 있는 비즈니스 및 보안 위험을 **마크다운 목록을 사용하여 구체적으로** 기술합니다. (예: 데이터 유출, 서비스 거부, 원격 코드 실행 등)

"""
    # [BUG FIX] AIBox 서버로부터 받은 기본 URL을 사용하여 올바른 API 엔드포인트 주소를 구성합니다.
    api_url = f"{server_url.rstrip('/')}/AIBox/api/sos/analyze_system"
    payload = {
        "prompt": prompt,
        "model_selector": "deep_dive" # 복잡한 리포트 생성이므로 reasoning_model 사용
    }

    try:
        # [개선] 타임아웃을 180초(3분)로 늘려 복잡한 분석에도 대응할 수 있도록 합니다.
        # [BUG FIX] 서버 내부 통신이므로 프록시를 사용하지 않도록 명시합니다.
        response = make_request_with_retry('post', api_url, json=payload, timeout=180, proxies={'http': None, 'https': None})
        if not response:
            raise requests.RequestException("AI 서버 요청 최종 실패")
        
        # [BUG FIX] AI 서버가 순수 텍스트(text/plain)로 응답하므로, JSON으로 파싱하지 않고 .text 속성을 직접 사용합니다.
        # 이전 코드에서 loads()를 호출하여 순수 텍스트가 다시 JSON 문자열로 변환되면서 이스케이프 문자(\n)가 포함되는 문제가 있었습니다.
        # 이제 응답 본문을 그대로 반환하여 이 문제를 해결합니다.
        summary = response.text.strip()
        if not summary:
            logging.warning("AI 서버가 빈 응답을 반환했습니다.")
            return "### AI 분석 실패\n- AI 서버가 빈 응답을 반환했습니다."
        return summary

    except requests.RequestException as e:
        logging.error(f"AIBox 서버 통신 오류: {e}")
        return "### AI 분석 실패\n- AIBox 서버와의 통신 중 오류가 발생했습니다. 서버 주소와 네트워크 상태를 확인해주세요."

# --- 외부 데이터 소스 조회 함수 ---
def fetch_cve_data(cve_id: str) -> dict:
    """
    [사용자 요청 반영] CVE 데이터를 조회합니다.
    1. 로컬 서버(http://127.0.0.1:5000)에서 먼저 조회 (프록시 미사용)
    2. 실패 시, 외부 Red Hat 서버에서 조회 (프록시 사용)
    """
    max_retries = 3 # noqa: F841
    urls_to_try = [
        {"url": f"http://127.0.0.1/AIBox/cve/{cve_id}.json", "source": "로컬 서버", "proxies": {'http': None, 'https': None}},
        {"url": f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json", "source": "Red Hat API", "proxies": None}
    ]

    for source_info in urls_to_try: # noqa: E501
        url, source, proxies = source_info["url"], source_info["source"], source_info["proxies"]
        logging.info(f"{source}에서 '{cve_id}' 데이터 조회를 시도합니다...")
        for attempt in range(max_retries):
            try:
                response = requests.get(url, timeout=30, proxies=proxies, verify=False) # proxies가 None이면 시스템 프록시 사용
                if response.status_code == 200:
                    if attempt > 0:
                        logging.info(f" -> {source}에서 재시도 성공 (시도 {attempt + 1}/{max_retries}).")
                    logging.info(f" -> '{cve_id}' 데이터를 {source}에서 성공적으로 찾았습니다.")
                    return loads(response.content)
                # 404(Not Found)는 재시도할 필요 없는 오류이므로 즉시 다음 소스로 넘어갑니다.
                if response.status_code == 404:
                    logging.warning(f" -> {source}에 '{cve_id}' 정보가 없습니다 (HTTP 404).")
                    break # 현재 소스에 대한 재시도를 중단하고 다음 소스로 넘어감
                
                # 그 외의 HTTP 오류
                response.raise_for_status()

            except requests.RequestException as e:
                logging.warning(f" -> {source} 연결 오류 (시도 {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(1) # 재시도 전 잠시 대기
                else:
                    logging.error(f" -> {source}에서 {max_retries}번의 시도 후에도 최종 연결 실패.")
        # 현재 소스에서 실패하면 다음 소스로 넘어감

    logging.error(f"모든 소스에서 '{cve_id}' 데이터 조회에 실패했습니다.")
    return None

def fetch_external_threat_intel(cve_id: str) -> dict:
    """[사용자 요청 반영] 로컬 cisa_kev.json 파일에서 외부 위협 인텔리전스 정보를 수집합니다."""
    logging.info(f"'{cve_id}'에 대한 외부 위협 인텔리전스(CISA KEV, EPSS) 조회를 시작합니다...")
    intel = {
        "cisa_kev": {"in_kev": False, "date_added": None},
        "epss": {"score": None, "percentile": None}
    }

    # 1. CISA KEV 정보 조회 (로컬 파일)
    kev_file_path = "/data/iso/AIBox/meta/cisa_kev.json"
    try:
        with open(kev_file_path, 'rb') as f:
            kev_data = loads(f.read())
        for vuln in kev_data.get("vulnerabilities", []):
            if vuln.get("cveID") == cve_id:
                intel["cisa_kev"]["in_kev"] = True
                intel["cisa_kev"]["date_added"] = vuln.get("dateAdded")
                logging.info(f"-> 로컬 KEV 파일에서 '{cve_id}'를 찾았습니다 (추가된 날짜: {vuln.get('dateAdded')}).")
                break
    except (FileNotFoundError, json.JSONDecodeError, orjson.JSONDecodeError) as e:
        logging.warning(f"로컬 CISA KEV 데이터({kev_file_path}) 조회 중 오류 발생: {e}")

    # 2. EPSS 점수 조회 (로컬 캐시 우선)
    local_epss_url = f"http://127.0.0.1/AIBox/epss/{cve_id}"
    logging.info(f"로컬 서버에서 '{cve_id}' EPSS 데이터 조회를 시도합니다...")
    try: # noqa: E501
        response = make_request_with_retry('get', local_epss_url, timeout=10, proxies={'http': None, 'https': None})
        if response and response.status_code == 200:
            logging.info(f"-> 로컬 서버에서 '{cve_id}' EPSS 데이터를 성공적으로 찾았습니다.")
            epss_data = loads(response.content)
            intel["epss"]["score"] = epss_data.get("epss")
            intel["epss"]["percentile"] = epss_data.get("percentile")
            return intel # 로컬에서 찾았으므로 함수 종료
        logging.warning(f"로컬 서버에 '{cve_id}' EPSS 정보가 없습니다. 외부 API 조회를 시도합니다.")
    except requests.RequestException as e:
        logging.warning(f"로컬 EPSS 서버 연결 실패: {e}. 외부 API 조회를 시도합니다.")

    # 로컬 조회 실패 시 외부 EPSS API에서 조회
    external_epss_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    logging.info(f"EPSS API에서 '{cve_id}' 데이터 조회를 시도합니다...")
    try:
        response = make_request_with_retry('get', external_epss_url, timeout=20, verify=False, proxies=None)
        if response and response.status_code == 200:
            epss_response_data = response.json()
            if epss_response_data.get("status") == "OK" and epss_response_data.get("data"):
                epss_item = next((item for item in epss_response_data["data"] if item.get("cve") == cve_id), None)
                if epss_item:
                    intel["epss"]["score"] = epss_item.get("epss")
                    intel["epss"]["percentile"] = epss_item.get("percentile")
                    logging.info(f"-> EPSS API에서 '{cve_id}' 점수를 찾았습니다 (EPSS: {epss_item.get('epss')}, Percentile: {epss_item.get('percentile')}).")

                    # 서버에 파일 저장을 요청하는 API 호출
                    save_epss_url = f"http://127.0.0.1:5000/AIBox/api/cache/epss"
                    save_payload = {
                        "cve_id": cve_id,
                        "data": {"epss": intel["epss"]["score"], "percentile": intel["epss"]["percentile"]}
                    }
                    try:
                        # 서버에 저장을 요청하고 응답을 기다리지 않음 (fire and forget)
                        make_request_with_retry('post', save_epss_url, json=save_payload, timeout=5, proxies={'http': None, 'https': None})
                        logging.info(f"-> '{cve_id}' EPSS 데이터를 로컬 서버에 저장하도록 요청했습니다.")
                    except requests.RequestException as save_e:
                        logging.warning(f"-> 로컬 서버에 EPSS 데이터 저장 요청 실패: {save_e}")
                else:
                    logging.info(f"-> EPSS API에서 '{cve_id}' 정보를 찾을 수 없습니다.")
        else:
            logging.warning(f"EPSS API 조회 실패.")
    except requests.RequestException as e:
        logging.warning(f"EPSS API 네트워크 오류: {e}")

    return intel

def _get_base_package_name(full_package_name: str) -> str:
    """
    [로직 교체] cve_check_report.py의 안정적인 로직을 참고하여 패키지 기본 이름을 추출합니다.
    - 'go-toolset:rhel8/golang' -> 'golang'
    - 'kernel-0:4.18.0-...' -> 'kernel'
    - 'firefox-0:140.4.0-3.el10_0' -> 'firefox'
    """
    if not full_package_name:
        return ""

    # 1. 모듈 스트림 정보(예: 'go-toolset:rhel8/')가 있으면 제거
    if '/' in full_package_name:
        full_package_name = full_package_name.split('/')[-1]

    # 2. epoch 및 버전 정보 제거 (cve_check_report.py의 parse_cve_package_field 로직 참고)
    # 패턴 1: 이름-에포크:버전-릴리즈 (예: kernel-0:4.18.0-...)
    match1 = re.match(r'^(.+?)-(\d+):(.+-.+)$', full_package_name)
    if match1:
        return match1.group(1)

    # 패턴 2: 마지막 하이픈을 기준으로 이름과 버전 분리 (일반적인 경우)
    parts = full_package_name.rsplit('-', 1)
    if len(parts) == 2 and re.search(r'[\d.]', parts[1]):
        return parts[0]

    return full_package_name # 모든 방법으로 분리 실패 시 원본 반환

def get_rhsa_product_label(product_name: str) -> str:
    """
    [신규] security.py의 로직을 참고하여, 제품명에 따라 RHSA ID 옆에 표시할 라벨을 생성합니다.
    """
    if not product_name: return ""

    if "Extended Lifecycle Support" in product_name:
        return "ELS"
    if "Extended Update Support Long-Life Add-On" in product_name:
        return "EUS-LongLife"
    if "Extended Update Support" in product_name:
        return "EUS"
    if "Update Services for SAP Solutions" in product_name:
        return "Update-SAP"
    if "for SAP Solutions" in product_name:
        return "SAP"
    return ""

def process_affected_packages(cve_data: dict) -> dict:
    """
    [로직 교체] security.py 로직을 기반으로 'package_state'와 'affected_release' 정보를 통합하여,
    대상 제품에 영향을 미치는 패키지와 패치 정보를 그룹화합니다.
    """
    # [사용자 요청 반영] 'affected_release'와 'package_state' 정보를 명확히 구분하여 처리합니다. (v4)
    processed_packages = {}

    # 1. 'affected_release' 처리: 패치가 존재하는 경우 "해결됨 (Patched)"으로 먼저 수집
    for release in cve_data.get('affected_release', []):
        product_name = release.get('product_name', 'Unknown Product')
        if any(p.match(product_name) for p in TARGET_PRODUCT_PATTERNS):
            package_name = release.get('package', 'N/A')
            advisory = release.get('advisory')

            if product_name not in processed_packages:
                processed_packages[product_name] = []
            
            # 중복 추가 방지
            if not any(p['package'] == package_name and p.get('advisory') == advisory for p in processed_packages[product_name]):
                processed_packages[product_name].append({
                    'package': package_name,
                    'advisory': advisory,
                    'status': '해결됨 (Patched)',
                    'rhsa_label': get_rhsa_product_label(product_name)
                })

    # 2. 'package_state' 처리: 'fix_state'가 "Affected"이고 아직 패치되지 않은 경우 "영향 있음 (Affected)"으로 추가
    for state in cve_data.get('package_state', []):
        product_name = state.get('product_name', 'Unknown Product')
        if state.get('fix_state') == 'Affected' and any(p.match(product_name) for p in TARGET_PRODUCT_PATTERNS):
            state_package_name = state.get('package_name', 'N/A')
            state_base_pkg_name = _get_base_package_name(state_package_name)

            # 'affected_release'에서 이미 패치된 패키지인지 기본 이름을 비교하여 확인
            is_already_patched = any(
                _get_base_package_name(p['package']) == state_base_pkg_name and p.get('advisory')
                for p in processed_packages.get(product_name, [])
            )

            if not is_already_patched:
                if product_name not in processed_packages:
                    processed_packages[product_name] = []
                processed_packages[product_name].append({
                    'package': state_package_name,
                    'advisory': None,
                    'status': '영향 있음 (Affected)',
                    'rhsa_label': get_rhsa_product_label(product_name)
                })

    return processed_packages

# --- HTML 렌더링 함수 ---
def render_html_report(template_path: str, cve_id: str, context: dict) -> str:
    """[수정] Jinja2 템플릿과 컨텍스트 데이터를 사용하여 최종 HTML 문자열을 생성합니다."""
    env = Environment(loader=FileSystemLoader(os.path.dirname(template_path)), autoescape=True)
    template = env.get_template(os.path.basename(template_path))
    
    summary_text = context.get('comprehensive_summary', '')
    
    # Markdown 라이브러리가 설치된 경우, AI가 생성한 마크다운을 HTML로 변환합니다.
    if markdown:
        # [BUG FIX] 마크다운 변환 및 Markup 객체 생성을 if 블록 안으로 이동하여 SyntaxError를 해결합니다.
        # [BUG FIX] Jinja2 3.0+ 버전에서는 Markup 클래스가 markupsafe 라이브러리로 이동했습니다.
        # 'cannot import name 'Markup' from 'jinja2'' 오류를 해결하기 위해 import 경로를 수정합니다.
        html_content = markdown(summary_text, extensions=['tables', 'fenced_code', 'nl2br'])
        from markupsafe import Markup
        context['comprehensive_summary_html'] = Markup(html_content)
    else:
        # 설치되지 않은 경우, 기본적인 텍스트로 표시합니다.
        escaped_text = html.escape(summary_text).replace('\n', '<br>')
        context['comprehensive_summary_html'] = f'<pre style="white-space: pre-wrap; font-family: inherit;">{escaped_text}</pre>'

    # HTML 파일로 저장하는 대신, 렌더링된 HTML 문자열을 반환합니다.
    return template.render(context)

# --- 메인 실행 로직 ---
def main():
    parser = argparse.ArgumentParser(
        description="지능형 CVE 보안 리포트 생성 스크립트. CVE 데이터를 수집하고 AI로 분석하여 결과를 HTML 형식으로 표준 출력합니다.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("cve_id", help="분석할 CVE ID (예: CVE-2023-12345)")
    parser.add_argument("--server-url", required=True, help="분석을 요청할 AIBox API 서버의 전체 URL (예: http://127.0.0.1:5000)")
    
    args = parser.parse_args()
    cve_id = args.cve_id.strip().upper()
    server_url = args.server_url

    logging.info(f"'{cve_id}'에 대한 리포트 생성을 시작합니다.")

    cve_data = fetch_cve_data(cve_id)
    
    if not cve_data:
        logging.warning(f"'{cve_id}'에 대한 정보를 로컬 서버와 Red Hat API에서 모두 찾을 수 없습니다. 기본 리포트를 생성합니다.")
        # [수정] CVE 정보가 없을 경우, 템플릿에 필요한 모든 키를 포함한 기본 컨텍스트를 생성합니다.
        context = {
            'cve_id': cve_id,
            'report_title': f"{cve_id} 분석 리포트",
            'public_date_str': 'N/A',
            'severity': '정보 없음',
            'cvss3_score': 'N/A',
            'bugzilla': {},
            'cwe': '',
            'grouped_packages': {},
            'all_rhsa_ids': [],
            'comprehensive_summary': "### CVE 정보 없음\n\n요청하신 CVE ID에 대한 상세 정보를 Red Hat Product Security 데이터베이스에서 찾을 수 없습니다. CVE ID가 정확한지 확인하거나, 아직 Red Hat에서 분석/발표하지 않은 취약점일 수 있습니다.",
            'external_intel': {"cisa_kev": {"in_kev": False, "date_added": None}, "epss": {"score": None, "percentile": None}},
        }
        template_path = os.path.join(os.path.dirname(__file__), 'cve_report_template.html')
        html_output = render_html_report(template_path, cve_id, context)
        print(html_output)
        return

    external_intel = fetch_external_threat_intel(cve_id)

    llm_summary = analyze_data_with_llm(cve_id, cve_data, external_intel, server_url)

    # [로직 수정] 'affected_release'와 'package_state'를 통합하여 처리하는 함수 호출
    grouped_packages = process_affected_packages(cve_data)

    # 최종적으로 제품 이름과 패키지 이름으로 정렬합니다.
    for product in grouped_packages:
        grouped_packages[product].sort(key=lambda p: p.get('package', ''))
    grouped_packages = dict(sorted(grouped_packages.items()))

    context = {
        'cve_id': cve_id,
        'report_title': cve_data.get('bugzilla', {}).get('description', cve_id).replace(f"{cve_id} ", ""),
        'public_date_str': cve_data.get('public_date', 'N/A').split('T')[0],
        'severity': cve_data.get('threat_severity', '정보 없음'),
        'cvss3_score': cve_data.get('cvss3', {}).get('cvss3_base_score', '정보 없음'),
        'bugzilla': cve_data.get('bugzilla'),
        'cwe': cve_data.get('CWE'),
        'package_state': cve_data.get('package_state'),
        'grouped_packages': grouped_packages, # 그룹화된 데이터를 컨텍스트에 추가
        'all_rhsa_ids': sorted([rhsa for rhsa in cve_data.get('advisories', []) if isinstance(rhsa, str) and rhsa.startswith("RHSA-")]), # 전체 RHSA 목록을 컨텍스트에 추가
        'comprehensive_summary': llm_summary, # AI 분석 결과 추가
        'external_intel': external_intel # 외부 위협 정보 추가
    }
    # [사용자 요청] 템플릿에서 현재 시간을 사용할 수 있도록 컨텍스트에 추가
    context['now'] = datetime.now

    # 템플릿 파일 경로를 이 스크립트가 위치한 디렉토리 기준으로 설정합니다.
    template_path = os.path.join(os.path.dirname(__file__), 'cve_report_template.html')
    
    if not os.path.exists(template_path):
        error_msg = f"Error: Template file not found at {template_path}\n"
        logging.error(error_msg.strip())
        sys.stderr.write(error_msg)
        sys.exit(1)
        
    html_output = render_html_report(template_path, cve_id, context)
    
    # 최종 결과물인 HTML을 표준 출력으로 내보냅니다.
    print(html_output)

if __name__ == '__main__':
    main()
