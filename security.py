#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import requests
import json
from datetime import datetime, timedelta
import re
import os
import argparse
import sys
import time

# --- Settings ---
# 분석 기간 (일)
ANALYSIS_PERIOD_DAYS = 180
# 최종 리포트에 포함할 상위 CVE 개수
TOP_CVE_COUNT = 20
# 랭킹 기록을 저장할 파일
HISTORY_FILE = '/data/iso/AIBox/ranking_history.json'
# 분석 대상으로 고려할 최소 CVSSv3 점수
MIN_CVSS_SCORE = 7.0
# [수정] 사용자가 요청한 분석 대상 RHEL 제품 목록
TARGET_RHEL_PRODUCTS = [
    "Red Hat Enterprise Linux 7",
    "Red Hat Enterprise Linux 8",
    "Red Hat Enterprise Linux 9",
    "Red Hat Enterprise Linux 10",
    "Red Hat Enterprise Linux for SAP Application",
    "Red Hat Enterprise Linux for SAP Solutions"
]

# --- AIBox Server Settings ---
AIBOX_SERVER_URL = ""

# --- Network Settings ---
PROXIES = None

def make_request(method, url, use_proxy=True, **kwargs):
    """
    requests 라이브러리를 위한 중앙 집중식 래퍼 함수.
    use_proxy 플래그에 따라 환경 변수를 포함한 프록시 설정을 제어합니다.
    """
    global PROXIES
    
    # 원래 프록시 환경 변수 상태를 저장합니다.
    original_proxies = {
        'http': os.environ.get('http_proxy'),
        'https': os.environ.get('https_proxy')
    }

    try:
        if not use_proxy:
            # 프록시를 사용하지 않으려면, 환경 변수를 일시적으로 제거합니다.
            if 'http_proxy' in os.environ:
                del os.environ['http_proxy']
            if 'https_proxy' in os.environ:
                del os.environ['https_proxy']
            # kwargs에서도 프록시 설정을 제거합니다.
            kwargs.pop('proxies', None)
        elif use_proxy and PROXIES:
            # 프록시를 사용해야 할 경우, 명시적으로 설정합니다.
            kwargs['proxies'] = PROXIES

        # 기본 타임아웃을 30초로 설정합니다.
        kwargs.setdefault('timeout', 30)

        response = requests.request(method, url, **kwargs)
        response.raise_for_status()
        return response
        
    except requests.exceptions.ProxyError as e:
        print(f"  -> Proxy Error during {method.upper()} request to {url}: {e}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"  -> Network Error during {method.upper()} request to {url}: {e}")
        return None
    finally:
        # 요청이 성공하든 실패하든, 원래 프록시 환경 변수 상태로 복원합니다.
        if original_proxies['http']:
            os.environ['http_proxy'] = original_proxies['http']
        if original_proxies['https']:
            os.environ['https_proxy'] = original_proxies['https']


def fetch_redhat_cves(start_date):
    """Step 1: 로컬 파일에서 모든 CVE 목록을 가져옵니다. (JSON 파싱 강화)"""
    cve_file_path = '/data/iso/AIBox/cve_data.json'
    print(f"Step 1: Fetching all CVEs from local file: {cve_file_path}...")
    
    if not os.path.exists(cve_file_path):
        print(f"Error: CVE data file not found at '{cve_file_path}'.")
        return []

    cves = []
    try:
        # First, check if the file is empty to provide a clearer error message.
        if os.path.getsize(cve_file_path) == 0:
            print(f"Warning: The CVE data file '{cve_file_path}' is empty.")
            return []

        with open(cve_file_path, 'r', encoding='utf-8') as f:
            cves = json.load(f)
            
    except json.JSONDecodeError as e:
        print(f"Warning: Could not parse '{cve_file_path}' as a single JSON array. Error: {e}")
        print(" -> Attempting to read file line-by-line as a stream of JSON objects...")
        
        cves_from_lines = []
        try:
            with open(cve_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line: # Skip empty lines
                        cves_from_lines.append(json.loads(line))
            cves = cves_from_lines # If successful, replace cves with the line-by-line result
            print(f" -> Successfully parsed {len(cves)} CVEs from line-by-line reading.")
        except json.JSONDecodeError as e_line:
            print(f"Error: Failed to decode JSON from the file '{cve_file_path}' even when reading line-by-line.")
            print(f" -> JSON Error Details: {e_line}")
            print(" -> Please ensure the file contains valid JSON (either a single array or one JSON object per line).")
            return [] # Exit if both methods fail
            
    except IOError as e:
        print(f"Error: Could not read the file '{cve_file_path}': {e}")
        return []

    # --- Common processing logic ---
    if not isinstance(cves, list):
        print("Error: Expected a list of CVEs from the JSON file, but got a different type.")
        return []

    valid_cves = [cve for cve in cves if isinstance(cve, dict) and 'resource_url' in cve and 'CVE' in cve]
    print(f"-> Found {len(valid_cves)} initial CVEs from the local file.")
    return valid_cves

def fetch_cve_details(cve_url):
    """resource_url을 사용하여 단일 CVE에 대한 전체 JSON 데이터를 가져옵니다. 이 함수는 프록시를 사용합니다."""
    # make_request의 기본값인 use_proxy=True가 적용되어 프록시를 사용합니다.
    response = make_request('get', cve_url, timeout=15)
    return response.json() if response else None

def filter_cves_by_strict_criteria(all_cves):
    """
    [핵심 수정] 사용자의 명확한 요구사항에 따른 엄격한 필터링 함수
    1. RHEL 제품 관련성 확인
    2. Severity가 'important' 또는 'critical'인지 확인
    3. CVSSv3 점수가 7.0 이상인지 확인
    """
    print(f"\nStep 3: Applying strict filtering to {len(all_cves)} CVEs...")
    passed_cves = []
    
    for cve in all_cves:
        if not isinstance(cve, dict):
            continue
        
        cve_id = cve.get('CVE', 'N/A')
        
        # 조건 1: 제품 관련성 확인
        package_states = cve.get('package_state', [])
        is_relevant_product = False
        if isinstance(package_states, list):
            for state in package_states:
                if state.get('fix_state') == 'Affected' and state.get('product_name') in TARGET_RHEL_PRODUCTS:
                    is_relevant_product = True
                    break
        
        if not is_relevant_product:
            continue

        # 조건 2: Severity 확인
        severity = cve.get('severity')
        if severity not in ['critical', 'important']:
            continue

        # 조건 3: CVSSv3 점수 확인
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
        print(f"  -> Including {cve_id}: Meets all criteria (Severity: {severity}, CVSS: {cvss3_score}, Relevant).")
        passed_cves.append(cve)

    print(f"\n-> Filtering complete. {len(passed_cves)} CVEs met all strict criteria and will be analyzed by LLM.")
    return passed_cves

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

def get_rhsa_ids_from_cve(cve_data):
    """CVE 상세 데이터 객체에서 직접 공식 RHSA ID 목록을 추출합니다."""
    if not isinstance(cve_data, dict): return []
    rhsa_ids = cve_data.get('advisories', [])
    return sorted([rhsa for rhsa in rhsa_ids if isinstance(rhsa, str) and rhsa.startswith("RHSA-")])

def generate_fallback_analysis(cve, affected_packages):
    """서버 오류 시 기본 분석 결과를 생성합니다."""
    severity = cve.get('severity', 'N/A')
    summary = extract_summary_from_cve(cve)
    
    # 기본 태그 생성
    threat_tags = []
    if severity == 'critical':
        threat_tags.append("Critical Vulnerability")
    if re.search(r'remote code execution|rce', summary, re.IGNORECASE):
        threat_tags.append("RCE")
    if re.search(r'privilege escalation', summary, re.IGNORECASE):
        threat_tags.append("Privilege Escalation")
    
    return {
        "threat_tags": threat_tags,
        "affected_components": affected_packages[:5],
        "concise_summary": summary[:200] + "..." if len(summary) > 200 else summary,
        "selection_reason": f"심각도 {severity}의 RHEL 관련 취약점으로, 자동 분석 시스템에 의해 선정되었습니다."
    }

def analyze_cve_with_llm_single(cve, total_count, current_index):
    """Sends a single CVE to the AIBox Server for analysis via API."""
    cve_id = cve.get('CVE', 'N/A')
    summary = extract_summary_from_cve(cve)

    if not summary:
        print(f"({current_index}/{total_count}) Skipping {cve_id}: No summary available for analysis.")
        return {}

    print(f"({current_index}/{total_count}) Analyzing {cve_id} via AIBox Server API...")

    cvss3_score = cve.get('cvss3', {}).get('cvss3_base_score', 'N/A') if isinstance(cve.get('cvss3'), dict) else 'N/A'
    
    package_states = cve.get('package_state', [])
    affected_products = sorted(list({
        state.get('product_name') for state in package_states
        if isinstance(state, dict) and state.get('fix_state') == 'Affected' and state.get('product_name') in TARGET_RHEL_PRODUCTS
    }))
    affected_packages = sorted(list({
        re.match(r'([^-\s]+)', state.get('package_name', '')).group(1)
        for state in package_states
        if isinstance(state, dict) and state.get('fix_state') == 'Affected' and state.get('product_name') in TARGET_RHEL_PRODUCTS
        and re.match(r'([^-\s]+)', state.get('package_name', ''))
    }))

    payload = {
        "cve_id": cve_id,
        "severity": cve.get('severity', 'N/A'),
        "public_date": cve.get('public_date', 'N/A'),
        "rh_cvss_score": cvss3_score,
        "affected_rhel_products": affected_products,
        "affected_packages": affected_packages,
        "summary": summary
    }

    # Use the existing make_request function to call our own API server
    # It's an internal call, so we disable proxy usage for this specific request.
    api_url = f'{AIBOX_SERVER_URL.rstrip("/")}/api/cve/analyze'
    
    try:
        response = make_request('post', api_url, use_proxy=False, json=payload, timeout=120)
        
        if not response:
            print(f"  -> Failed to get analysis for {cve_id} from AIBox server. Using fallback analysis.")
            # 서버 응답 실패 시 기본 분석 결과 생성
            return generate_fallback_analysis(cve, affected_packages)
            
        try:
            return response.json()
        except json.JSONDecodeError as e:
            print(f"  -> Failed to parse analysis for {cve_id} from AIBox server. Reason: {e}. Using fallback analysis.")
            return generate_fallback_analysis(cve, affected_packages)
            
    except Exception as e:
        print(f"  -> Exception during analysis for {cve_id}: {e}. Using fallback analysis.")
        return generate_fallback_analysis(cve, affected_packages)

def analyze_and_prioritize_with_llm(cves):
    """Step 4: 각 필터링된 CVE를 개별적으로 분석합니다."""
    print(f"\nStep 4: Starting LLM analysis for {len(cves)} CVEs that met the criteria...")
    
    analyzed_cves = []
    for i, cve in enumerate(cves):
        if not isinstance(cve, dict): continue
        analysis_result = analyze_cve_with_llm_single(cve, len(cves), i + 1)
        # Check if the analysis result is not empty, even with fallback it might be under some conditions
        if analysis_result:
            cve.update(analysis_result)
            analyzed_cves.append(cve)
        else:
            # This path should be less likely with the fallback, but kept for safety
            print(f"  -> Warning: Analysis failed for {cve.get('CVE')} and no fallback was generated. It will be excluded from the final report.")
        time.sleep(1)
    
    print("\n--- LLM analysis for all CVEs is complete ---")
    return analyze_and_prioritize_manual(analyzed_cves)

def analyze_and_prioritize_manual(cves):
    """Step 5: 수집된 데이터와 점수 모델을 기반으로 CVE 우선순위를 정합니다."""
    print(f"\nStep 5: Starting priority ranking based on scoring model...")
    
    for cve in cves:
        if not isinstance(cve, dict): continue
        score = 0
        summary = extract_summary_from_cve(cve)
        threat_tags = cve.get('threat_tags', [])
        
        if isinstance(threat_tags, list):
            if "Exploited in the wild" in threat_tags or re.search(r'in the wild|actively exploited', summary, re.IGNORECASE): score += 1000
            if "RCE" in threat_tags or re.search(r'remote code execution|rce', summary, re.IGNORECASE): score += 200
            if "Privilege Escalation" in threat_tags or re.search(r'privilege escalation', summary, re.IGNORECASE): score += 150
        
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
        critical_components = {'kernel', 'glibc', 'openssl', 'systemd', 'qemu-kvm', 'grub2', 'httpd', 'nginx'}
        if isinstance(components, list) and any(comp.lower() in critical_components for comp in components):
            score += 100

        cve['priority_score'] = score
    
    cves.sort(key=lambda x: x.get('priority_score', 0), reverse=True)
    top_cves = cves[:TOP_CVE_COUNT]
    print(f"-> Analysis complete. Finalized top {len(top_cves)} CVEs.")
    return top_cves

def load_history():
    """랭킹 기록을 파일에서 불러옵니다."""
    if not os.path.exists(HISTORY_FILE): return {}
    try:
        with open(HISTORY_FILE, 'r', encoding='utf-8') as f: return json.load(f)
    except (json.JSONDecodeError, IOError): return {}

def save_history(cve_ranks):
    """오늘의 랭킹 데이터를 파일에 저장합니다."""
    try:
        with open(HISTORY_FILE, 'w', encoding='utf-8') as f: json.dump(cve_ranks, f, indent=4, ensure_ascii=False)
        print(f"\nToday's ranking information has been saved to '{HISTORY_FILE}'.")
    except IOError as e: print(f"Error: Failed to save ranking history file. {e}")

def process_ranking_changes(todays_cves, previous_ranks):
    """최초 발견일을 기준으로 순위 변경 및 유지일을 계산합니다."""
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
            first_seen_str = previous_rank_data.get('first_seen_date', today_str)
            cve_data['first_seen_date'] = first_seen_str
        else:
            cve_data['rank_change'] = 'new'
            cve_data['first_seen_date'] = today_str

        first_seen_date = datetime.strptime(cve_data['first_seen_date'], '%Y-%m-%d')
        days_in_rank = (today_date - first_seen_date).days + 1
        cve_data['days_in_rank'] = days_in_rank
        
        processed_cves.append(cve_data)
        todays_ranks_for_saving[cve_id] = {'rank': rank, 'first_seen_date': cve_data['first_seen_date']}
        
    return processed_cves, todays_ranks_for_saving

def generate_executive_summary(top_cves):
    """Requests an Executive Summary from the AIBox Server via API."""
    print("\nRequesting Executive Summary from AIBox Server...")
    
    # Prepare data for the API payload
    summary_data = [
        {
            "cve_id": cve.get('CVE'),
            "summary": cve.get('concise_summary', ''),
            "severity": cve.get('severity', 'N/A'),
            "tags": cve.get('threat_tags', [])
        }
        for cve in top_cves
    ]

    payload = {"top_cves": summary_data}
    api_url = f'{AIBOX_SERVER_URL.rstrip("/")}/api/cve/executive_summary'
    
    # Disable proxy for internal call
    response = make_request('post', api_url, use_proxy=False, json=payload, timeout=120)

    if response:
        return response.text # The server returns HTML-formatted text
    else:
        return "상위 취약점에 대한 요약 정보를 생성하지 못했습니다."

def print_selection_reasons_to_console(cves):
    """상위 CVE의 선정 이유를 콘솔에 출력합니다."""
    print("\n--- RHEL 컨텍스트 기반 상위 20개 CVE 선정 이유 ---")
    print("=" * 70)
    for i, cve in enumerate(cves):
        if not isinstance(cve, dict): continue
        rank = i + 1
        cve_id = cve.get('CVE', 'N/A')
        reason = cve.get('selection_reason', 'LLM 분석 정보가 없습니다. RHEL 관련성, 심각도(Severity) 및 점수 모델 기반으로 선정되었습니다.')

        package_states = cve.get('package_state', [])
        affected_products = sorted(list({
            state.get('product_name') for state in package_states
            if isinstance(state, dict) and state.get('fix_state') == 'Affected' and state.get('product_name') in TARGET_RHEL_PRODUCTS
        }))

        print(f" [{rank}위] {cve_id}")
        print(f"  - 영향받는 제품: {', '.join(affected_products)}")
        print(f"  - 선정 이유: {reason}\n")
    print("=" * 70)

def generate_report(processed_cves, executive_summary):
    """최종 분석 리포트를 HTML 파일로 생성합니다."""
    print("\nGenerating final HTML analysis report...")
    
    table_rows_html = ""
    for i, cve in enumerate(processed_cves):
        if not isinstance(cve, dict): continue
        rank, cve_id, severity = i + 1, cve.get('CVE', 'N/A'), cve.get('severity', 'N/A')
        public_date = cve.get('public_date', 'N/A').split('T')[0]
        default_summary = " ".join(cve.get('details', [])) or '요약 정보 없음'
        summary = cve.get('concise_summary', default_summary) if cve.get('concise_summary') else default_summary
        selection_reason = cve.get('selection_reason', 'RHEL 관련성 및 심각도 등급 기반으로 선정되었습니다.')
        
        tags_html, packages_html = "", ""
        threat_tags = cve.get('threat_tags', [])
        if isinstance(threat_tags, list) and threat_tags:
            for tag in threat_tags:
                tag_class = "tag-exploited" if "Exploited" in str(tag) else "tag-threat"
                tags_html += f'<span class="threat-tag {tag_class}">{tag}</span>'
        
        affected_components = cve.get('affected_components', [])
        if isinstance(affected_components, list) and affected_components:
            for pkg in affected_components[:3]:
                packages_html += f'<span class="threat-tag tag-pkg">{pkg}</span>'
            if len(affected_components) > 3: packages_html += f'<span class="threat-tag tag-pkg">...</span>'
        
        final_tags_html = f'<div class="summary-tags">{tags_html}{packages_html}</div>'
        rhsa_ids = get_rhsa_ids_from_cve(cve)
        remediation_html = " ".join([f'<a href="https://access.redhat.com/errata/{rhsa_id}" target="_blank">{rhsa_id}</a>' for rhsa_id in rhsa_ids]) if rhsa_ids else "발행 예정"
        if rhsa_ids: remediation_html += "<br><small>해당 RHSA 최신 패키지로 업데이트하십시오.</small>"
        
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

        table_rows_html += f"""<tr>
            <td class="center-align"><div class="rank-cell"><span class="rank-number">{rank}</span><span class="rank-change {rank_change_class}">{rank_change_icon}</span></div></td>
            <td><a href="https://access.redhat.com/security/cve/{cve_id}" target="_blank">{cve_id}</a><br><small>{public_date}</small></td>
            <td class="center-align"><span class="{severity_class} severity-badge">{severity_icon} {str(severity).capitalize()}</span><br><small>CVSS: {cvss3_score}</small></td>
            <td class="center-align">{days_in_rank}일</td>
            <td>{final_tags_html}{summary}</td><td>{selection_reason}</td><td>{remediation_html}</td></tr>"""
    
    analysis_date, report_month = datetime.now().strftime('%Y-%m-%d'), datetime.now().strftime('%Y-%m')

    html_content = f"""<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RHEL 보안 위협 분석 리포트 ({report_month})</title>
    <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+KR:wght@300;400;500;700&display=swap" rel="stylesheet">
    <style>
    :root{{
        --primary-color: #007bff; --secondary-color: #6c757d; --success-color: #28a745;
        --danger-color: #dc3545; --warning-color: #ffc107; --background-color: #f0f4f8;
        --surface-color: #ffffff; --text-color: #212529; --header-bg: #0d1b2a;
        --header-text: #ffffff; --border-color: #dee2e6; --shadow: 0 4px 12px rgba(0,0,0,0.08);
    }}
    body{{
        font-family:'Noto Sans KR',sans-serif; margin:0; padding: 2rem;
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
    .summary-card h2{{
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
    <div class="summary-card"><h2>Executive Summary</h2><p>{executive_summary}</p></div>
    <div class="report-card"><table><thead><tr>
    <th style="width:5%">순위</th><th style="width:12%">CVE-ID & 공개일</th><th style="width:10%">심각도 & 점수</th>
    <th style="width:8%">순위 유지일</th><th style="width:25%">취약점 요약</th><th style="width:28%">취약점 선정 이유</th>
    <th style="width:12%">조치 방안 (RHSA)</th>
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
        print(f"-> Success: Report '{report_filename}' has been generated.")
    except IOError as e: print(f"-> Error: Failed to generate HTML report. {e}")

def main():
    """메인 실행 함수"""
    global AIBOX_SERVER_URL, PROXIES
    parser = argparse.ArgumentParser(
        description="RHEL Top Security Threat Analysis Script",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--server-url', required=True, help='Full URL of the AIBox API server (e.g., http://localhost:5000)')
    parser.add_argument('--proxy', help='HTTP/HTTPS proxy server URL (e.g., http://user:pass@host:port)')
    parser.add_argument('--no-proxy', help='Comma-separated list of hosts to exclude from proxy')
    
    args = parser.parse_args()

    AIBOX_SERVER_URL = args.server_url or os.getenv('AIBOX_SERVER_URL')
    
    # Setup proxy and no_proxy environment variables
    if args.proxy:
        PROXIES = {'http': args.proxy, 'https': args.proxy}
        print(f"Using proxy server: {args.proxy}")
        os.environ['https_proxy'] = args.proxy
        os.environ['http_proxy'] = args.proxy
        
    if args.no_proxy:
        # os.environ['no_proxy'] is the standard way requests library checks for exceptions.
        os.environ['no_proxy'] = args.no_proxy
        print(f"Excluding from proxy: {args.no_proxy}")
        # Remove the no_proxy hosts from our custom PROXIES dict if they were added
        if PROXIES:
            for host in args.no_proxy.split(','):
                if host in PROXIES.get('http', '') or host in PROXIES.get('https', ''):
                     print(f"Note: {host} will be accessed directly, bypassing the proxy.")

    start_date = (datetime.now() - timedelta(days=ANALYSIS_PERIOD_DAYS)).strftime('%Y-%m-%d')
    
    previous_ranks = load_history()
    recent_cves_summary = fetch_redhat_cves(start_date)

    if not recent_cves_summary:
        print("\nCould not load any CVEs from the local file. Exiting program.")
        return

    candidate_cves = {cve['CVE']: cve for cve in recent_cves_summary}
    for cve_id in previous_ranks.keys():
        if cve_id not in candidate_cves:
            candidate_cves[cve_id] = {
                'CVE': cve_id,
                'resource_url': f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"
            }

    print(f"\nStep 2: Fetching and merging full details for {len(candidate_cves)} candidate CVEs...")
    all_cve_data = []
    
    for i, (cve_id, summary_data) in enumerate(candidate_cves.items()):
        print(f"  ({i+1}/{len(candidate_cves)}) Fetching {cve_id}...")
        resource_url = summary_data.get('resource_url')
        if not resource_url:
            print(f"   -> Skipping {cve_id}: resource_url not found.")
            continue

        detailed_data = fetch_cve_details(resource_url)
        
        if detailed_data:
            merged_data = {**summary_data, **detailed_data}
            all_cve_data.append(merged_data)
        else:
            print(f"  -> Warning: Failed to fetch details for {cve_id}. Using summary data as a fallback.")
            all_cve_data.append(summary_data)
        time.sleep(0.2)

    cves_meeting_criteria = filter_cves_by_strict_criteria(all_cve_data)

    if not cves_meeting_criteria:
        print("\nNo CVEs meeting the specified criteria were found. Exiting program.")
        return
    
    if not AIBOX_SERVER_URL:
         print("\nError: AIBox Server URL must be provided to get recommendations. Exiting program.")
         sys.exit(1)

    llm_recommended_cves = analyze_and_prioritize_with_llm(cves_meeting_criteria)
        
    processed_cves, todays_ranks_to_save = process_ranking_changes(llm_recommended_cves, previous_ranks)
    
    executive_summary = generate_executive_summary(processed_cves)

    print_selection_reasons_to_console(processed_cves)
    
    generate_report(processed_cves, executive_summary)
    save_history(todays_ranks_to_save)

if __name__ == "__main__":
    main()
