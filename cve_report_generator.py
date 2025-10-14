#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-

import os
import json
import requests
import sys
import re
import time
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

# --- 기본 설정 ---
ANALYSIS_PERIOD_DAYS = 180
CVE_DATA_FILE = '/data/iso/AIBox/cve_data.json'
OUTPUT_DIR = '/data/iso/AIBox/output'
REPORT_FILE_PATH = os.path.join(OUTPUT_DIR, 'rhel_vulnerability_report.html')
MAX_WORKERS = 10


# --- API 엔드포인트 ---
LOCAL_CVE_URL = 'http://127.0.0.1:5000/AIBox/cve/{cve_id}.json'
REDHAT_CVE_URL = 'https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json'
LLM_ANALYZE_URL = 'http://127.0.0.1:5000/AIBox/api/cve/analyze'

# --- 필터링할 RHEL 제품 목록 (정규표현식 사용) ---
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

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', stream=sys.stdout)

def collect_cve_ids_from_file():
    logging.info(f"데이터 파일에서 CVE 목록 수집을 시작합니다: {CVE_DATA_FILE}")
    try:
        with open(CVE_DATA_FILE, 'r', encoding='utf-8') as f:
            all_cves = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"오류: CVE 데이터 파일을 읽을 수 없습니다. {e}")
        return []

    cve_ids = set()
    start_date = datetime.now() - timedelta(days=ANALYSIS_PERIOD_DAYS)
    for cve in all_cves:
        try:
            if 'public_date' in cve:
                public_date = datetime.strptime(cve['public_date'].split('T')[0], '%Y-%m-%d')
                if public_date >= start_date:
                    cve_id = cve.get('name') or cve.get('CVE')
                    if cve_id: cve_ids.add(cve_id)
        except (ValueError, TypeError):
            continue
    logging.info(f"분석 기간 내 {len(cve_ids)}개의 고유 CVE를 발견했습니다.")
    return sorted(list(cve_ids), reverse=True)

def fetch_cve_details(cve_id):
    try:
        response = requests.get(LOCAL_CVE_URL.format(cve_id=cve_id), timeout=10)
        if response.status_code == 200:
            data = response.json()
            if 'name' not in data: data['name'] = cve_id
            return data
    except requests.RequestException:
        pass # Red Hat 서버에서 재시도

    try:
        response = requests.get(REDHAT_CVE_URL.format(cve_id=cve_id), timeout=20)
        if response.status_code == 200:
            data = response.json()
            if 'name' not in data: data['name'] = cve_id
            return data
    except requests.RequestException as e:
        logging.error(f"[{cve_id}] 모든 소스에서 정보 조회 실패: {e}")
    return None

def process_cve_data(cve_data):
    if not cve_data: return None
    cve_id = cve_data.get('name', 'N/A')
    
    filtered_releases = {}
    
    all_releases = cve_data.get('affected_release', [])
    for release in all_releases:
        product_name = release.get('product_name', 'Unknown Product')

        is_target_product = any(pattern.match(product_name) for pattern in TARGET_PRODUCT_PATTERNS)
        if not is_target_product:
            continue

        package = release.get('package', '')
        if 'kpatch-patch' in package or 'kernel-rt' in package: continue
        
        is_not_affected = any(
            s.get('product_name') == product_name and s.get('fix_state') == 'Not affected'
            for s in cve_data.get('package_state', [])
        )
        if is_not_affected: continue
        
        advisory = release.get('advisory', 'N/A')
        if product_name not in filtered_releases: filtered_releases[product_name] = {}
        if advisory not in filtered_releases[product_name]: filtered_releases[product_name][advisory] = []
        filtered_releases[product_name][advisory].append(package)

    if not filtered_releases: 
        return None
    
    bugzilla_info = cve_data.get('bugzilla', {})
    
    return {
        'cve_id': cve_id,
        'public_date': cve_data.get('public_date', 'N/A').split('T')[0],
        'severity': cve_data.get('threat_severity', 'N/A'),
        'cvss3_score': cve_data.get('cvss3', {}).get('cvss3_base_score', 'N/A'),
        'summary_en': cve_data.get('statement') or " ".join(cve_data.get('details', [])),
        'affected_releases': filtered_releases,
        'bugzilla_id': bugzilla_info.get('id'),
        'bugzilla_url': bugzilla_info.get('url'),
        'cwe_id': cve_data.get('cwe')
    }

def get_korean_summaries_with_llm(cve_list):
    """
    [NEW] security.py 로직 적용: 모든 CVE를 한번에 LLM에 요청하여 번역 안정성 극대화
    """
    if not cve_list:
        return []
        
    logging.info(f"LLM 국문 요약 생성을 시작합니다: 총 {len(cve_list)}개 CVE (단일 배치 요청)")
    
    prompt_data = [{
        'cve_id': cve['cve_id'],
        'english_summary': cve['summary_en']
    } for cve in cve_list]

    # AI에게 전달할 명확한 지시사항 정의
    prompt = {
        "task": "translate_cve_summaries_to_korean_batch",
        "instructions": (
            "You are a security expert. For each CVE in the provided list, "
            "create a concise 2-3 sentence summary and translate it into PERFECT, NATURAL KOREAN. "
            "The output must be a single JSON object with a key 'analysis_results'. "
            "The value of 'analysis_results' must be a JSON array where each object contains "
            "'cve_id' and 'korean_summary'."
        ),
        "cves": prompt_data
    }
    
    analyzed_data = {}
    logging.info("LLM API에 모든 CVE 요약 및 번역 요청...")
    try:
        # 타임아웃을 넉넉하게 설정 (최대 10분)
        response = requests.post(LLM_ANALYZE_URL, json=prompt, timeout=600, headers={'Content-Type': 'application/json'})
        
        if response.status_code == 200:
            try:
                api_results = response.json()
                # AI가 반환한 결과가 올바른 형식인지 꼼꼼히 확인
                if 'analysis_results' in api_results and isinstance(api_results['analysis_results'], list):
                    for res in api_results['analysis_results']:
                        if isinstance(res, dict) and 'cve_id' in res and 'korean_summary' in res:
                            analyzed_data[res['cve_id']] = res.get('korean_summary', '[번역 데이터 없음]')
                    logging.info("-> LLM 분석 및 번역 성공.")
                else:
                    logging.error(f"-> LLM 응답 형식이 올바르지 않습니다. 'analysis_results' 키를 찾을 수 없거나 배열이 아닙니다. 응답: {api_results}")
            except json.JSONDecodeError:
                logging.error(f"-> LLM 응답이 유효한 JSON이 아닙니다. 응답 내용: {response.text}")
        else:
            logging.error(f"-> LLM 분석 실패. 상태 코드: {response.status_code}, 응답: {response.text}")
    except requests.RequestException as e:
        logging.error(f"-> LLM API 요청 중 오류 발생: {e}")

    # 원본 cve_list에 번역 결과를 매칭하여 추가
    for cve in cve_list:
        cve['analysis'] = {
            "korean_summary": analyzed_data.get(cve['cve_id'], f"[번역 실패] {cve['summary_en']}")
        }
    
    logging.info("LLM 국문 요약 생성 완료.")
    return cve_list


def generate_interactive_html_report(cve_list):
    logging.info("HTML 리포트 생성을 시작합니다.")

    table_rows_html = ""
    cve_list.sort(key=lambda x: x['public_date'], reverse=True)

    for cve in cve_list:
        flat_releases = []
        if cve.get('affected_releases'):
            for product, advisories in cve.get('affected_releases', {}).items():
                for advisory, packages in advisories.items():
                    package_list_html = "<br>".join(packages)
                    flat_releases.append({
                        'product': product, 'advisory': advisory, 'packages': package_list_html
                    })
        
        if not flat_releases:
            flat_releases.append({'product': '-', 'advisory': '-', 'packages': '-'})

        num_rows_for_cve = len(flat_releases)
        
        analysis = cve.get("analysis", {})
        summary = analysis.get("korean_summary", "요약 없음").replace('\n', '<br>')
        
        summary_details_html = f"<p>{summary}</p>"

        reference_links_html = ""
        if cve.get("bugzilla_id") and cve.get("bugzilla_url"):
            reference_links_html += f'<span>Bugzilla: <a href="{cve["bugzilla_url"]}" target="_blank">{cve["bugzilla_id"]}</a></span>'
        
        if cve.get("cwe_id"):
            try:
                cwe_num = re.search(r'\d+', cve["cve_id"]).group()
                cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
                if reference_links_html: reference_links_html += ' | '
                reference_links_html += f'<span>CWE: <a href="{cwe_url}" target="_blank">{cve["cwe_id"]}</a></span>'
            except (AttributeError, TypeError):
                pass

        summary_html_block = f'<div>{summary_details_html}<div class="reference-links">{reference_links_html}</div></div>'
        
        for i, release_info in enumerate(flat_releases):
            table_rows_html += '<tr>'
            if i == 0:
                severity = cve.get("severity", "N/A")
                cve_id = cve["cve_id"]
                cve_url = f"https://access.redhat.com/security/cve/{cve_id}"
                cve_link_html = f'<a href="{cve_url}" target="_blank">{cve_id}</a>'
                
                table_rows_html += f'<td rowspan="{num_rows_for_cve}">{cve_link_html}</td>'
                table_rows_html += f'<td rowspan="{num_rows_for_cve}">{cve["public_date"]}</td>'
                table_rows_html += f'<td rowspan="{num_rows_for_cve}">{severity}</td>'
                table_rows_html += f'<td rowspan="{num_rows_for_cve}">{cve["cvss3_score"]}</td>'
                table_rows_html += f'<td rowspan="{num_rows_for_cve}" class="summary-cell">{summary_html_block}</td>'
            
            advisory = release_info["advisory"]
            if advisory != 'N/A' and advisory.startswith('RHSA'):
                advisory_url = f"https://access.redhat.com/errata/{advisory}"
                advisory_html = f'<a href="{advisory_url}" target="_blank">{advisory}</a>'
            else:
                advisory_html = advisory

            table_rows_html += f'<td>{release_info["product"]}</td>'
            table_rows_html += f'<td>{advisory_html}</td>'
            table_rows_html += f'<td class="package-cell">{release_info["packages"]}</td>'
            table_rows_html += '</tr>'
    
    html_template = f"""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Red Hat 취약점 분석 리포트</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+KR:wght@400;700&display=swap" rel="stylesheet">
        <style>
            body {{
                font-family: 'Noto Sans KR', sans-serif;
                margin: 0;
                padding: 20px;
                background-color: #f4f7f9;
                color: #333;
            }}
            .container {{
                max-width: 98%;
                margin: 0 auto;
                background-color: #ffffff;
                border-radius: 12px;
                box-shadow: 0 8px 24px rgba(149, 157, 165, 0.2);
                padding: 30px;
            }}
            .report-header {{
                text-align: center;
                margin-bottom: 30px;
                border-bottom: 2px solid #e0e0e0;
                padding-bottom: 20px;
            }}
            .report-header h1 {{
                color: #c92127; /* Red Hat Red */
                font-size: 2.2em;
                font-weight: 700;
                margin: 0;
            }}
            .report-header p {{
                color: #666;
                font-size: 1.1em;
                margin-top: 5px;
            }}
            .controls {{
                margin-bottom: 20px;
                text-align: right;
            }}
            #export-btn {{
                background-color: #0088ce;
                color: white;
                border: none;
                padding: 12px 24px;
                font-size: 16px;
                font-weight: 700;
                cursor: pointer;
                border-radius: 8px;
                transition: background-color 0.3s, box-shadow 0.3s;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            #export-btn:hover {{
                background-color: #006da7;
                box-shadow: 0 4px 8px rgba(0,0,0,0.15);
            }}
            #report-table {{
                width: 100%;
                border-collapse: separate;
                border-spacing: 0;
                border: 1px solid #e0e0e0;
                border-radius: 10px;
                overflow: hidden; /* For border-radius on table */
            }}
            #report-table th, #report-table td {{
                padding: 15px;
                text-align: center;
                vertical-align: middle;
                border-bottom: 1px solid #e0e0e0;
            }}
            #report-table th {{
                background-color: #333a40;
                color: white;
                font-weight: 700;
                font-size: 1.05em;
            }}
            #report-table tbody tr:last-child td {{
                border-bottom: none;
            }}
            #report-table tbody tr:nth-child(even) {{
                background-color: #f9f9f9;
            }}
            #report-table tbody tr:hover {{
                background-color: #eef7ff;
            }}
            #report-table td a {{
                color: #0066cc;
                text-decoration: none;
                font-weight: 700;
            }}
            #report-table td a:hover {{
                text-decoration: underline;
            }}
            .summary-cell, .package-cell {{
                text-align: left;
                white-space: pre-wrap;
                word-break: break-word;
            }}
            .reference-links {{
                margin-top: 12px;
                padding-top: 10px;
                border-top: 1px dashed #ccc;
                font-size: 0.9em;
                color: #555;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="report-header">
                <h1>Red Hat Enterprise Linux 취약점 분석 리포트</h1>
                <p>AI 기반 자동 요약 및 번역 | 최종 업데이트: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            <div class="controls"><button id="export-btn">Excel로 저장</button></div>
            <table id="report-table">
                <thead><tr>
                    <th style="width: 12%;">CVE ID</th><th style="width: 8%;">발행 일자</th><th style="width: 8%;">심각도</th><th style="width: 8%;">CVSSv3</th>
                    <th style="width: 24%;">취약점 요약 (AI 번역)</th><th style="width: 15%;">영향받는 제품</th><th style="width: 10%;">RHSA ID</th><th style="width: 15%;">패치된 패키지</th>
                </tr></thead>
                <tbody>{table_rows_html}</tbody>
            </table>
        </div>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>
        <script>
            document.getElementById('export-btn').addEventListener('click', function() {{
                const table = document.getElementById('report-table');
                const wb = XLSX.utils.table_to_book(table, {{ sheet: "RHEL 취약점 리포트" }});
                XLSX.writeFile(wb, "RHEL_Vulnerability_Report_{datetime.now().strftime('%Y%m%d')}.xlsx");
            }});
        </script>
    </body>
    </html>
    """

    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        with open(REPORT_FILE_PATH, 'w', encoding='utf-8') as f:
            f.write(html_template)
        logging.info(f"성공: HTML 리포트가 '{REPORT_FILE_PATH}'에 저장되었습니다.")
    except IOError as e:
        logging.error(f"오류: HTML 리포트 파일 저장 실패: {e}")

def main():
    logging.info("===== Red Hat 취약점 분석 스크립트(v29, security.py 로직 적용)를 시작합니다. =====")
    
    cve_ids_to_fetch = collect_cve_ids_from_file()
    if not cve_ids_to_fetch:
        logging.warning("분석할 CVE가 없습니다. 종료합니다.")
        return

    all_cve_details = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        f_to_cve = {executor.submit(fetch_cve_details, cid): cid for cid in cve_ids_to_fetch}
        for f in as_completed(f_to_cve):
            data = f.result()
            if data: all_cve_details.append(data)
    
    processed_cves = [p for p in [process_cve_data(d) for d in all_cve_details] if p]
    if not processed_cves:
        logging.warning("필터링 후 리포트에 포함할 CVE가 없습니다.")
        generate_interactive_html_report([])
        return
        
    logging.info(f"데이터 정제 완료. 분석 대상 CVE는 총 {len(processed_cves)}개 입니다.")

    # [NEW] AI 분석 및 국문 요약 생성 (security.py의 안정적인 단일 요청 방식 적용)
    final_cve_list = get_korean_summaries_with_llm(processed_cves)
    
    generate_interactive_html_report(final_cve_list)

    logging.info("===== 모든 작업이 완료되었습니다. =====")

if __name__ == '__main__':
    main()

