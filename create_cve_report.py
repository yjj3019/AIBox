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

# --- AI(LLM) 분석 함수 ---
def analyze_data_with_llm(cve_id: str, cve_data: dict, external_data: dict, server_url: str) -> str:
    """제공된 CVE 데이터를 기반으로 지정된 AIBox 서버를 호출하여 분석을 수행합니다."""
    logging.info(f"'{cve_id}'에 대한 AI 분석을 시작합니다 (서버: {server_url})...")
    
    # [사용자 요청 반영] Red Hat 보안 전문가의 관점에서 체계적인 보고서를 생성하도록 프롬프트를 전면 개편합니다.
    # AI가 웹 검색을 통해 최신 정보를 수집하고, 지정된 형식에 맞춰 상세 분석을 수행하도록 지시합니다.
    prompt = f"""[시스템 역할]
당신은 Red Hat의 최고 수준 보안 전문가입니다. 주어진 CVE 데이터와 **웹 검색을 통해 수집한 최신 정보를 바탕으로**, 아래의 상세한 가이드라인과 출력 형식에 맞춰 전문적인 보안 분석 보고서를 한국어로 작성하십시오.
**모든 분석 내용은 핵심만 간결하게 요약해야 합니다.**

[입력 데이터: CVE 정보]
```json
{dumps(cve_data, indent=True)}
```

[출력 형식: 상세 분석 보고서 (Markdown)]
### 취약점 개요 (Vulnerability Summary)
- CVE의 기술적 내용과 영향을 받는 소프트웨어를 명확하고 간결하게 설명합니다.

### 근본 원인 분석 (Root Cause Analysis)
- 제공된 'cwe'와 상세 설명을 바탕으로 취약점이 발생하는 기술적 원인을 심층적으로 분석합니다.

### 잠재적 영향 (Impact Assessment)
- 'cvss3' 데이터를 기반으로, 이 취약점이 악용될 경우 발생할 수 있는 비즈니스 및 보안 위험을 구체적으로 기술합니다. (예: 데이터 유출, 서비스 거부, 원격 코드 실행 등)

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
        response = requests.get(external_url, timeout=60)
        response.raise_for_status()
        logging.info(f"'{cve_id}' 데이터를 Red Hat API에서 성공적으로 찾았습니다.")
        return loads(response.content)
    except requests.RequestException as e:
        logging.error(f"Red Hat API 네트워크 오류: {e}")
        return None

def fetch_external_threat_intel(cve_id: str) -> dict:
    """[사용자 요청 반영] 로컬 cisa_kev.json 파일에서 외부 위협 인텔리전스 정보를 수집합니다."""
    logging.info(f"'{cve_id}'에 대한 외부 위협 인텔리전스 조회를 시작합니다...")
    intel = {"cisa_kev": {"in_kev": False, "date_added": None}}
    kev_file_path = "/data/iso/AIBox/cisa_kev.json"
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
    return intel

# --- HTML 렌더링 함수 ---
def render_html_report(template_path: str, cve_id: str, context: dict) -> str:
    """Jinja2 템플릿과 컨텍스트 데이터를 사용하여 최종 HTML 문자열을 생성합니다."""
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
        logging.error(f"Red Hat Product Security에서 '{cve_id}' 정보를 찾지 못했습니다. 스크립트를 종료합니다.")
        # [수정] 에러 발생 시 표준 에러로 메시지를 출력하고 0이 아닌 코드로 종료하여 호출 측에서 오류를 인지할 수 있도록 합니다.
        sys.stderr.write(f"Error: Could not find CVE data for {cve_id} from Red Hat.\n")
        sys.exit(1)

    # [사용자 요청 복원] 로컬 파일에서 외부 위협 인텔리전스 수집 및 AI 분석을 다시 활성화합니다.
    external_intel = fetch_external_threat_intel(cve_id)
    llm_summary = analyze_data_with_llm(cve_id, cve_data, external_intel, server_url)

    # [사용자 요청] 지정된 제품 목록 및 패턴에 대해서만 'affected_release' 정보를 그룹화하고 정렬합니다.
    TARGET_PRODUCTS_EXACT = {
        "Red Hat Enterprise Linux 7",
        "Red Hat Enterprise Linux 7 Extended Lifecycle Support",
        "Red Hat Enterprise Linux 8",
        "Red Hat Enterprise Linux 9",
        "Red Hat Enterprise Linux 10"
    }
    # 'Red Hat Enterprise Linux {major}.{minor} for SAP Solutions' 와 같은 패턴을 처리하기 위한 정규식
    target_product_pattern = re.compile(r'^Red Hat Enterprise Linux \d+\.\d+ for SAP Solutions$')

    # [사용자 요청] 'affected_release' (패치된 제품)와 'package_state' (영향받는 모든 제품) 정보를 통합합니다.
    grouped_packages = {}

    # 1. 'package_state'에서 'Affected' 상태인 제품 정보를 먼저 수집합니다.
    if cve_data.get('package_state'):
        for state in cve_data['package_state']:
            product_name = state.get('product_name', 'Unknown Product')
            # 지정된 제품이거나, 패턴에 맞는 경우에만 데이터를 포함합니다.
            if state.get('fix_state') == 'Affected' and (product_name in TARGET_PRODUCTS_EXACT or target_product_pattern.match(product_name)):
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
            elif product_name in TARGET_PRODUCTS_EXACT or target_product_pattern.match(product_name):
                # 'package_state'에 없었지만 'affected_release'에 있는 경우 (예: EUS)
                if product_name not in grouped_packages:
                    grouped_packages[product_name] = []
                grouped_packages[product_name].append(release)
    
    # 최종적으로 제품 이름과 패키지 이름으로 정렬합니다.
    for product in grouped_packages:
        grouped_packages[product].sort(key=lambda p: p.get('package', ''))
    grouped_packages = dict(sorted(grouped_packages.items()))
    
    # [사용자 요청] security.py를 참고하여 CVE에 연결된 모든 RHSA ID를 추출합니다.
    all_rhsa_ids = sorted([rhsa for rhsa in cve_data.get('advisories', []) if isinstance(rhsa, str) and rhsa.startswith("RHSA-")])

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
        'all_rhsa_ids': all_rhsa_ids, # 전체 RHSA 목록을 컨텍스트에 추가
        'comprehensive_summary': llm_summary, # AI 분석 결과 추가
        'external_intel': external_intel # 외부 위협 정보 추가
    }
    context['current_year'] = datetime.now().year

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
