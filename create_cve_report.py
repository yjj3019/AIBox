import os
import sys
import json
import re
import requests
import argparse
import logging
import html
from jinja2 import Environment, FileSystemLoader

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
def analyze_data_with_llm(cve_id: str, cve_data: dict, server_url: str) -> str:
    """제공된 CVE 데이터를 기반으로 지정된 AIBox 서버를 호출하여 분석을 수행합니다."""
    logging.info(f"'{cve_id}'에 대한 AI 분석을 시작합니다 (서버: {server_url})...")
    
    # [개선] LLM이 Markdown 형식으로 구조화된 답변을 생성하도록 프롬프트를 강화했습니다.
    prompt = f"""[시스템 역할]
당신은 Red Hat Enterprise Linux(RHEL)의 보안 취약점을 분석하는 최고 수준의 사이버 보안 전문가입니다. 주어진 CVE 데이터를 분석하여 상세 보고서를 한국어 Markdown 형식으로 작성하십시오.

[분석 가이드라인]
1.  **외부 정보 통합**: 웹 검색을 통해 KISA/KrCERT, CISA KEV, 알려진 PoC(Proof of Concept), EPSS(Exploit Prediction Scoring System) 점수 등의 추가 정보를 수집하여 분석에 포함시키십시오.
2.  **상세 분석**: 수집된 모든 정보를 종합하여 아래 각 항목에 대해 깊이 있는 분석을 수행합니다.
3.  **출력 형식 준수**: 반드시 아래의 Markdown 구조에 맞춰 응답을 생성해야 합니다.

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

### 완화 및 해결 방안 (Mitigation & Remediation)
- 'package_state' 정보를 분석하여 공식 패치 적용 방법을 안내하고, 패치가 불가능할 경우 적용할 수 있는 임시 완화책(workaround)을 제안합니다.

### 최신 위협 동향 (Recent Threat Intelligence)
- 웹 검색 결과를 바탕으로 실제 공격(in-the-wild) 여부, 관련 공격 그룹 정보, PoC 공개 여부 등 최신 동향을 종합하여 위협 수준을 평가합니다.
"""

    api_url = f'{server_url.rstrip("/")}/AIBox/api/cve/analyze'
    payload = {"prompt": prompt}

    try:
        # [개선] 타임아웃을 180초(3분)로 늘려 복잡한 분석에도 대응할 수 있도록 합니다.
        response = requests.post(api_url, json=payload, timeout=180)
        response.raise_for_status()
        
        # AI 서버는 분석 결과를 순수 텍스트(Markdown)로 반환합니다.
        return response.text.strip()

    except requests.RequestException as e:
        logging.error(f"AIBox 서버 통신 오류: {e}")
        return "### AI 분석 실패\n- AIBox 서버와의 통신 중 오류가 발생했습니다. 서버 주소와 네트워크 상태를 확인해주세요."

# --- 외부 데이터 소스 조회 함수 ---
def fetch_cve_data_from_redhat(cve_id: str) -> dict:
    """Red Hat Product Security API에서 CVE 데이터를 조회합니다."""
    url = f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"
    logging.info(f"Red Hat API에서 '{cve_id}' 데이터 조회를 시도합니다...")
    try:
        # [개선] 프록시 설정이 필요한 환경을 위해 환경 변수(HTTP_PROXY, HTTPS_PROXY)를 자동으로 사용합니다.
        # 실행 환경에서 `export HTTPS_PROXY=http://your-proxy-server:port` 와 같이 설정해야 합니다.
        proxies = {
            "http": os.environ.get("HTTP_PROXY"),
            "https": os.environ.get("HTTPS_PROXY"),
        }
        response = requests.get(url, timeout=15, proxies=proxies)
        if response.status_code == 200:
            logging.info(f"'{cve_id}' 데이터를 Red Hat API에서 성공적으로 찾았습니다.")
            return loads(response.content)
        logging.warning(f"Red Hat API에 '{cve_id}' 정보가 없습니다 (HTTP {response.status_code}).")
    except requests.RequestException as e:
        logging.error(f"Red Hat API 네트워크 오류: {e}")
    return None

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

    cve_data = fetch_cve_data_from_redhat(cve_id)
    
    if not cve_data:
        logging.error(f"Red Hat Product Security에서 '{cve_id}' 정보를 찾지 못했습니다. 스크립트를 종료합니다.")
        # [수정] 에러 발생 시 표준 에러로 메시지를 출력하고 0이 아닌 코드로 종료합니다.
        sys.stderr.write(f"Error: Could not find CVE data for {cve_id} from Red Hat.\n")
        sys.exit(1)

    llm_summary = analyze_data_with_llm(cve_id, cve_data, server_url)
    cve_data['comprehensive_summary'] = llm_summary
    
    # Jinja2 템플릿에 전달할 데이터(context)를 구성합니다.
    context = {
        'cve_id': cve_id,
        'report_title': cve_data.get('bugzilla', {}).get('description', cve_id).replace(f"{cve_id} ", ""),
        'public_date_str': cve_data.get('public_date', 'N/A').split('T')[0],
        'severity': cve_data.get('threat_severity', '정보 없음'),
        'cvss3_score': cve_data.get('cvss3', {}).get('cvss3_base_score', '정보 없음'),
        'bugzilla': cve_data.get('bugzilla'),
        'cwe': cve_data.get('CWE'),
        'package_state': cve_data.get('package_state'),
        'comprehensive_summary': llm_summary
    }

    # 템플릿 파일 경로를 이 스크립트가 위치한 디렉토리 기준으로 설정합니다.
    template_path = os.path.join(os.path.dirname(__file__), 'cve_report_template.html')
    
    if not os.path.exists(template_path):
        error_msg = f"Error: Template file not found at {template_path}\n"
        sys.stderr.write(error_msg)
        sys.exit(1)
        
    html_output = render_html_report(template_path, cve_id, context)
    
    # 최종 결과물인 HTML을 표준 출력으로 내보냅니다.
    print(html_output)

if __name__ == '__main__':
    main()
