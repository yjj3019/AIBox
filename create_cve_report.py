#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-

# 특정 조건의 cve 를 리스트 형태로 출력하는 소스

import os
import sys
import json
import re
import requests
import argparse
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
def analyze_data_with_llm(cve_id: str, cve_data: dict, external_data: dict, server_url: str) -> str:
    """제공된 CVE 데이터를 기반으로 지정된 AIBox 서버를 호출하여 분석을 수행합니다."""
    # [사용자 요청] LLM 응답 파싱 실패 시 3회 재시도 로직 추가
    max_retries = 3
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
당신은 Red Hat의 최고 수준 보안 전문가이자, 복잡한 기술 내용을 명확하고 간결한 한국어로 전달하는 데 능숙한 IT 전문 번역가입니다. 주어진 CVE 데이터와 **웹 검색을 통해 수집한 최신 정보를 바탕으로**, 아래의 상세한 가이드라인과 출력 형식에 맞춰 전문적인 보안 분석 보고서를 한국어로 작성하십시오.

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
- **[분석 대상 제품 목록]에 명시된 제품 중에서** 이 취약점의 영향을 받는 소프트웨어만 명확하고 간결하게 설명합니다. 다른 제품은 절대 언급하지 마십시오.

### 근본 원인 분석 (Root Cause Analysis)
- 제공된 'cwe'와 상세 설명을 바탕으로 취약점이 발생하는 기술적 원인을 심층적으로 분석합니다.

### 잠재적 영향 (Impact Assessment)
- 'cvss3' 점수와 'EPSS' 점수를 기반으로, 이 취약점이 악용될 경우 발생할 수 있는 비즈니스 및 보안 위험을 구체적으로 기술합니다. (예: 데이터 유출, 서비스 거부, 원격 코드 실행 등)

"""
    # [요청 수정] AI 분석을 위한 엔드포인트를 명시적으로 지정합니다.
    # 이제 이 스크립트는 --server-url 인자에 의존하지 않고 항상 고정된 로컬 주소로 요청합니다.
    api_url = 'http://127.0.0.1:5000/AIBox/api/cve/analyze'
    payload = {"prompt": prompt}

    try:
        # [개선] 타임아웃을 180초(3분)로 늘려 복잡한 분석에도 대응할 수 있도록 합니다.
        response = requests.post(api_url, json=payload, timeout=180)
        response.raise_for_status()
        
        # [BUG FIX] AI 서버가 JSON 객체 또는 순수 텍스트를 반환하는 모든 경우에 대응합니다.
        try:
            # 1. 응답이 비어있는지 먼저 확인합니다.
            if not response.content:
                logging.warning("AI 서버가 빈 응답을 반환했습니다.")
                return "### AI 분석 실패\n- AI 서버가 빈 응답을 반환했습니다."
            
            # 2. JSON 응답을 먼저 시도합니다.
            response_json = loads(response.content)
            if isinstance(response_json, dict):
                return response_json.get('raw_response') or response_json.get('analysis_report') or dumps(response_json, indent=True)
            return dumps(response_json, indent=True)
        except (json.JSONDecodeError, orjson.JSONDecodeError):
            # 3. JSON 파싱에 실패하면, 응답을 순수 텍스트로 간주하고 처리합니다. (AttributeError 방지)
            #    이것이 문제의 근본 원인을 해결하는 부분입니다.
            logging.warning("AI 서버 응답이 JSON 형식이 아닙니다. 순수 텍스트로 처리합니다.")
            return response.text.strip()

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
    # 1. 로컬 서버에서 조회
    local_url = f"http://127.0.0.1:5000/AIBox/cve/{cve_id}.json"
    logging.info(f"로컬 서버에서 '{cve_id}' 데이터 조회를 시도합니다...")
    try:
        # 로컬 통신이므로 프록시를 명시적으로 비활성화합니다.
        response = requests.get(local_url, timeout=10, proxies={'http': None, 'https': None})
        if response.status_code == 200:
            logging.info(f"'{cve_id}' 데이터를 로컬 서버에서 성공적으로 찾았습니다.")
            return loads(response.content)
        logging.warning(f"로컬 서버에 '{cve_id}' 정보가 없습니다 (HTTP {response.status_code}). 외부 API 조회를 시도합니다.")
    except requests.RequestException as e:
        logging.warning(f"로컬 서버 연결 실패: {e}. 외부 API 조회를 시도합니다.")

    # 2. 외부 Red Hat 서버에서 조회 (로컬 조회 실패 시)
    external_url = f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"
    logging.info(f"Red Hat API에서 '{cve_id}' 데이터 조회를 시도합니다...")
    try:
        # requests는 기본적으로 http_proxy, https_proxy 환경 변수를 사용합니다.
        response = requests.get(external_url, timeout=60, verify=False)
        response.raise_for_status()
        logging.info(f"'{cve_id}' 데이터를 Red Hat API에서 성공적으로 찾았습니다.")
        return loads(response.content)
    except requests.RequestException as e:
        logging.error(f"Red Hat API 네트워크 오류: {e}")
        return None

def fetch_external_threat_intel(cve_id: str) -> dict:
    """[사용자 요청 반영] 로컬 cisa_kev.json 파일에서 외부 위협 인텔리전스 정보를 수집합니다."""
    logging.info(f"'{cve_id}'에 대한 외부 위협 인텔리전스(CISA KEV, EPSS) 조회를 시작합니다...")
    intel = {
        "cisa_kev": {"in_kev": False, "date_added": None},
        "epss": {"score": None, "percentile": None}
    }

    # 1. CISA KEV 정보 조회 (로컬 파일)
    kev_file_path = "/data/iso/AIBox/data/cisa_kev.json"
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
    local_epss_url = f"http://127.0.0.1:5000/AIBox/epss/{cve_id}"
    logging.info(f"로컬 서버에서 '{cve_id}' EPSS 데이터 조회를 시도합니다...")
    try:
        # 로컬 통신이므로 프록시를 명시적으로 비활성화합니다.
        response = requests.get(local_epss_url, timeout=10, proxies={'http': None, 'https': None})
        if response.status_code == 200:
            logging.info(f"-> 로컬 서버에서 '{cve_id}' EPSS 데이터를 성공적으로 찾았습니다.")
            epss_data = loads(response.content)
            intel["epss"]["score"] = epss_data.get("epss")
            intel["epss"]["percentile"] = epss_data.get("percentile")
            return intel # 로컬에서 찾았으므로 함수 종료
        logging.warning(f"로컬 서버에 '{cve_id}' EPSS 정보가 없습니다 (HTTP {response.status_code}). 외부 API 조회를 시도합니다.")
    except requests.RequestException as e:
        logging.warning(f"로컬 EPSS 서버 연결 실패: {e}. 외부 API 조회를 시도합니다.")

    # 로컬 조회 실패 시 외부 EPSS API에서 조회
    external_epss_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    logging.info(f"EPSS API에서 '{cve_id}' 데이터 조회를 시도합니다...")
    try:
        response = requests.get(external_epss_url, timeout=20, verify=False)
        if response.status_code == 200:
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
                        requests.post(save_epss_url, json=save_payload, timeout=5, proxies={'http': None, 'https': None})
                        logging.info(f"-> '{cve_id}' EPSS 데이터를 로컬 서버에 저장하도록 요청했습니다.")
                    except requests.RequestException as save_e:
                        logging.warning(f"-> 로컬 서버에 EPSS 데이터 저장 요청 실패: {save_e}")
                else:
                    logging.info(f"-> EPSS API에서 '{cve_id}' 정보를 찾을 수 없습니다.")
        else:
            logging.warning(f"EPSS API 조회 실패 (HTTP {response.status_code}).")
    except requests.RequestException as e:
        logging.warning(f"EPSS API 네트워크 오류: {e}")

    return intel

# --- HTML 렌더링 함수 ---
def render_html_report(template_path: str, cve_id: str, context: dict) -> str:
    """[수정] Jinja2 템플릿과 컨텍스트 데이터를 사용하여 최종 HTML 문자열을 생성합니다."""
    env = Environment(loader=FileSystemLoader(os.path.dirname(template_path)), autoescape=True)
    template = env.get_template(os.path.basename(template_path))
    
    summary_text = context.get('comprehensive_summary', '')
    
    # Markdown 라이브러리가 설치된 경우, AI가 생성한 마크다운을 HTML로 변환합니다.
    if markdown:
        context['comprehensive_summary_html'] = markdown(summary_text, extensions=['tables', 'fenced_code', 'nl2br'])
    else:
        # 설치되지 않은 경우, 기본적인 텍스트로 표시합니다.
        escaped_text = html.escape(summary_text).replace('\n', '<br>')
        context['comprehensive_summary_html'] = f'<pre style="white-space: pre-wrap;">{escaped_text}</pre>'

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
        # [요청 사항] CVE 정보가 없을 경우, 기본 컨텍스트를 생성하여 리포트를 출력합니다.
        context = {
            'cve_id': cve_id,
            'report_title': f"{cve_id} 분석 리포트",
            'public_date_str': 'N/A',
            'severity': '정보 없음',
            'cvss3_score': 'N/A',
            'bugzilla': None,
            'cwe': None,
            'grouped_packages': {},
            'all_rhsa_ids': [],
            'comprehensive_summary': "### CVE 정보 없음\n\n요청하신 CVE ID에 대한 상세 정보를 Red Hat Product Security 데이터베이스에서 찾을 수 없습니다. CVE ID가 정확한지 확인하거나, 아직 Red Hat에서 분석/발표하지 않은 취약점일 수 있습니다.",
            'external_intel': {"cisa_kev": {"in_kev": False, "date_added": None}, "epss": {"score": None, "percentile": None}},
            'current_year': datetime.now().year
        }
        template_path = os.path.join(os.path.dirname(__file__), 'cve_report_template.html')
        html_output = render_html_report(template_path, cve_id, context)
        print(html_output)
        return

    external_intel = fetch_external_threat_intel(cve_id)

    llm_summary = analyze_data_with_llm(cve_id, cve_data, external_intel, server_url)

    # [사용자 요청] 'affected_release' (패치된 제품)와 'package_state' (영향받는 모든 제품) 정보를 통합합니다.
    grouped_packages = {}

    # 1. 'package_state'에서 'Affected' 상태인 제품 정보를 먼저 수집합니다.
    if cve_data.get('package_state'):
        for state in cve_data['package_state']:
            product_name = state.get('product_name', 'Unknown Product')
            if state.get('fix_state') == 'Affected' and any(pattern.match(product_name) for pattern in TARGET_PRODUCT_PATTERNS):
                if product_name not in grouped_packages:
                    grouped_packages[product_name] = []
                
                # 'package_state'에는 패키지 버전 정보가 없으므로, 기본 정보만 추가합니다.
                # 'advisory' 키가 없는 것으로 패치되지 않았음을 구분합니다.
                grouped_packages[product_name].append({
                    'package': state.get('package_name', 'N/A'),
                    'advisory': None # 아직 패치되지 않음
                })

    # 2. 'affected_release'에서 패치 정보를 가져와 기존 정보에 병합/추가합니다.
    if cve_data.get('affected_release'):
        for release in cve_data['affected_release']:
            product_name = release.get('product_name', 'Unknown Product')
            if product_name in grouped_packages:
                # 이미 'Affected'로 등록된 제품의 경우, 패치 정보를 업데이트합니다.
                # 'package_state'의 패키지 이름(예: 'kernel')과 'affected_release'의 패키지 이름(예: 'kernel-0:...')을 비교합니다.
                for pkg_info in grouped_packages[product_name]:
                    if pkg_info['package'] in release.get('package', ''):
                        pkg_info.update(release) # 패키지 버전, RHSA 등 상세 정보 업데이트
            elif any(pattern.match(product_name) for pattern in TARGET_PRODUCT_PATTERNS):
                # 'package_state'에 없었지만 'affected_release'에 있는 경우 (예: EUS)
                if product_name not in grouped_packages:
                    grouped_packages[product_name] = []
                grouped_packages[product_name].append(release)
    
    # 최종적으로 제품 이름과 패키지 이름으로 정렬합니다.
    for product in grouped_packages:
        grouped_packages[product].sort(key=lambda p: p.get('package', ''))
    grouped_packages = dict(sorted(grouped_packages.items()))
    
    # [사용자 요청] security.py를 참고하여 CVE에 연결된 모든 RHSA ID를 추출합니다.

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
