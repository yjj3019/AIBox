#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-

import os
import re
import json
import html
from pathlib import Path
from datetime import datetime
import requests
import logging
import sys
import shutil

# --- [신규] 콘솔 출력 색상 및 로깅 설정 ---
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
    def warn(text: str) -> str: return f"{Color.YELLOW}{text}{Color.END}"
    @staticmethod
    def info(text: str) -> str: return f"{Color.CYAN}{text}{Color.END}"

# [수정] print 대신 logging을 사용하도록 설정
logging.basicConfig(level=logging.INFO, format='%(message)s', stream=sys.stdout)

# --- 설정값 ---
SYSTEM_DATA_DIR = Path("/data/iso/AIBox/cve-check/data")
REPORT_OUTPUT_DIR = Path("/data/iso/AIBox/cve-check/output")
CVE_DB_PATH = Path("/data/iso/AIBox/cve-check/cve-check_db.json")

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
    re.compile(r"^Red Hat Enterprise Linux 10$"), # 요청에 포함된 RHEL 10 패턴 추가
    re.compile(r"^Red Hat Enterprise Linux 10\.\d+ Extended Update Support$"),
    re.compile(r"^Red Hat Enterprise Linux 10\.\d+ Extended Update Support Long-Life Add-On$"),
    re.compile(r"^Red Hat Enterprise Linux 10\.\d+ Update Services for SAP Solutions$"),
    re.compile(r"^Red Hat Enterprise Linux \d+\.\d+ for SAP Solutions$")
]

# --- RPM 버전 비교를 위한 라이브러리 ---
# pip install rpm-vercomp
try:
    # [사용자 요청] rpm-vercomp 라이브러리 설치 오류 해결
    # 해당 라이브러리를 찾을 수 없는 환경을 위해, 순수 Python으로 RPM 버전 비교 로직을 구현합니다.
    # 이제 'pip install rpm-vercomp'는 더 이상 필요하지 않습니다.
    from rpm_vercomp import compare_versions
    logging.info(Color.info("Info: Using installed 'rpm-vercomp' library for version comparison."))
except ImportError:
    logging.info(Color.info("Info: 'rpm-vercomp' library not found. Using the built-in pure Python version comparison logic."))

    def compare_versions(v1, v2):
        """
        순수 Python으로 구현된 RPM 버전 비교 함수.
        Epoch, Version, Release를 처리하며, rpm-vercomp 라이브러리를 대체합니다.
        v1이 v2보다 오래되었으면 -1, 같으면 0, 최신이면 1을 반환합니다.
        """
        def split_version(version_str):
            epoch_match = re.match(r"(\d+):", version_str)
            epoch = 0
            if epoch_match:
                epoch = int(epoch_match.group(1))
                version_str = version_str[len(epoch_match.group(0)):]
            return epoch, version_str

        def compare_strings(s1, s2):
            # 문자열을 알파벳과 숫자 덩어리로 분리
            parts1 = re.findall(r"([a-zA-Z]+)|(\d+)|(~)", s1)
            parts2 = re.findall(r"([a-zA-Z]+)|(\d+)|(~)", s2)

            for p1, p2 in zip(parts1, parts2):
                # p1, p2는 ('alpha', '', '') 또는 ('', '123', '') 또는 ('', '', '~') 형태의 튜플
                if p1[2] or p2[2]: # 틸드(~) 처리
                    if p1[2] and not p2[2]: return -1
                    if not p1[2] and p2[2]: return 1
                
                p1_alpha, p1_num, _ = p1
                p2_alpha, p2_num, _ = p2

                if p1_num and p2_num: # 둘 다 숫자
                    diff = int(p1_num) - int(p2_num)
                    if diff != 0: return 1 if diff > 0 else -1
                elif p1_alpha and p2_alpha: # 둘 다 알파벳
                    if p1_alpha != p2_alpha: return 1 if p1_alpha > p2_alpha else -1
                elif p1_num: return 1 # 숫자 > 알파벳
                elif p2_num: return -1 # 알파벳 < 숫자
            
            return (len(parts1) > len(parts2)) - (len(parts1) < len(parts2))

        e1, ver_rel1 = split_version(v1)
        e2, ver_rel2 = split_version(v2)

        if e1 != e2: return 1 if e1 > e2 else -1
        return compare_strings(ver_rel1, ver_rel2)

# --- 유틸리티 함수 ---

def parse_rpm_full_name(rpm_full_name):
    """RPM 전체 이름에서 이름, 버전, 아키텍처를 분리합니다."""
    # 예: "NetworkManager-1.40.16-20.el8_10.x86_64"
    # 예: "1:NetworkManager-1.40.16-20.el8_10.x86_64" (표준 epoch)
    # 예: "dbus-1:1.12.8-24.el8_8.1" (비표준 epoch 포함, arch 없음)
    
    # 1. 아키텍처(.arch)를 먼저 분리합니다.
    arch_match = re.search(r'\.([^\.]+)$', rpm_full_name)
    if not arch_match or arch_match.group(1) in ['src', 'rpm']: # 소스 RPM은 제외
        # 아키텍처가 없는 경우 (예: dbus-1:1.12.8-24.el8_8.1)
        name_ver_part = rpm_full_name
        arch = 'N/A'
    else:
        arch = arch_match.group(1)
        name_ver_part = rpm_full_name[:arch_match.start()]

    # 2. 이름과 버전-릴리즈를 분리합니다.
    # 마지막 두 개의 하이픈을 기준으로 분리하여 이름에 하이픈이 포함된 경우를 처리합니다.
    parts = name_ver_part.rsplit('-', 2)
    if len(parts) == 3 and parts[1].replace('.', '').isdigit(): # name-version-release 형식
        name, version, release = parts
        full_version = f"{version}-{release}"
    else: # name-version-release 형식이 아닌 경우 (예: epoch 포함)
        # 마지막 하이픈을 기준으로 버전과 이름을 분리합니다.
        try:
            name, full_version = name_ver_part.rsplit('-', 1)
        except ValueError:
            return None, None, None # 분리 실패
    
    # 3. 이름에 포함된 epoch를 버전 앞으로 이동시킵니다. (예: 'name-epoch:' -> 'epoch:version')
    epoch_match = re.match(r'(.+)-(\d+):$', name)
    if epoch_match:
        name, epoch = epoch_match.groups()
        full_version = f"{epoch}:{full_version}"
    # 표준 epoch 처리 (예: '1:name')
    elif ':' in name:
        epoch, name = name.split(':', 1)
        full_version = f"{epoch}:{full_version}"
    
    return name, full_version, arch

def parse_cve_package_field(package_field: str):
    """
    [사용자 요청] CVE의 affected_release.package 필드에서 이름과 버전을 분리하는 로직을 개선합니다.
    - 예1: "webkitgtk4-0:2.48.3-2.el7_9" -> name: "webkitgtk4", version: "0:2.48.3-2.el7_9"
    - 예2: "kernel-3.10.0-1160.el7" -> name: "kernel", version: "3.10.0-1160.el7"
    - 예3: "openssl-1:1.1.1k-9.el8_7" -> name: "openssl", version: "1:1.1.1k-9.el8_7"
    - 예4: "gmp-1:6.1.2-11.el8" -> name: "gmp", version: "1:6.1.2-11.el8"
    - 예5: "kernel-0:4.18.0-553.74.1.el8_10" -> name: "kernel", version: "0:4.18.0-553.74.1.el8_10"
    """
    # [핵심 수정] RPM 이름 파싱 로직을 전면 재구성하여 안정성과 정확성을 높입니다.
    # 정규식: (이름)-(epoch):(버전)-(릴리즈) 또는 (이름)-(버전)-(릴리즈)
    # 그룹 1: 패키지 이름 (욕심내지 않고 최소한으로 일치)
    # 그룹 2: (선택) Epoch 값 (예: '0:')
    # 그룹 3: 버전 및 릴리즈
    match = re.match(r'^(.*?)-(\d+:)?([\w.~+-]+-[\w.~+-]+)$', package_field)
    if match:
        name, epoch, version_release = match.groups()
        if epoch:
            # epoch가 이름과 버전 사이에 있는 경우 (예: kernel-0:4.18.0-...)
            return name, f"{epoch.rstrip(':')}:{version_release}"
        return name, version_release

    # 위의 정규식으로 처리되지 않는 경우 (이름에 하이픈이 많은 경우 등)를 위한 폴백
    # 마지막 하이픈을 기준으로 이름과 버전을 분리합니다.
    parts = package_field.rsplit('-', 1)
    if len(parts) == 2 and re.search(r'^\d', parts[1]):
        return parts[0], parts[1]

    return package_field, "" # 분리 실패

def summarize_vulnerability(details, statement):
    """취약점 요약 생성 (LLM 대신 규칙 기반으로 핵심 내용 요약)"""
    # [사용자 요청] AI 서버를 호출하여 한글 요약 및 번역을 수행하도록 수정합니다.
    # 1. 영문 요약본을 먼저 생성합니다.
    english_summary = "No summary available."
    if details and isinstance(details, list) and details[0]:
        english_summary = details[0]
    elif statement:
        english_summary = statement.split('.')[0] + '.'
    
    english_summary = english_summary.strip().replace('\n', ' ')
    if len(english_summary) > 250: # AI에 전달할 요약의 최대 길이
        english_summary = english_summary[:247] + "..."

    # 2. AIBox 서버에 번역 및 요약 요청
    try:
        # AIBox 서버의 범용 분석 엔드포인트를 사용합니다.
        api_url = 'http://127.0.0.1:5000/AIBox/api/cve/analyze'
        # [BUG FIX] LLM이 항상 JSON 형식으로 응답하도록 프롬프트를 수정합니다.
        prompt = f"""[SYSTEM ROLE]
You are an expert IT translator specializing in cybersecurity. Your task is to read the following English vulnerability summary, fully understand its technical content, and then summarize its core meaning into a single, clear Korean sentence.

[ENGLISH SUMMARY]
{english_summary}

[OUTPUT FORMAT]
You MUST return ONLY a single, valid JSON object with the key "analysis_report".
Example: {{"analysis_report": "리눅스 커널의 특정 기능에서 발견된 취약점으로, 권한 상승으로 이어질 수 있습니다."}}
"""
        # [사용자 요청] AIBox 서버가 fast-model을 사용하도록 model_selector 추가
        payload = {
            "prompt": prompt,
            "model_selector": "fast" # 'fast' 또는 다른 키워드를 서버 로직에 맞게 추가
        }
        
        # 로컬 서버 통신이므로 프록시를 사용하지 않습니다.
        response = requests.post(api_url, json=payload, timeout=30, proxies={'http': '', 'https': ''})
        
        if response.ok:
            # [사용자 요청] 한글 깨짐 문제 해결: JSON 응답을 올바르게 파싱합니다.
            try:
                # AIBox 서버는 JSON 형식으로 응답합니다.
                result = response.json()
                # [BUG FIX] AI 서버가 리스트를 반환하는 경우에 대한 처리
                if isinstance(result, list) and result:
                    # 리스트의 첫 번째 항목이 딕셔너리인지 확인
                    first_item = result[0]
                    if isinstance(first_item, dict):
                        return first_item.get('analysis_report', str(first_item))
                    return str(first_item) # 딕셔너리가 아니면 문자열로 변환
                elif isinstance(result, dict):
                    return result.get('analysis_report', str(result))
            except json.JSONDecodeError:
                # JSON 파싱 실패 시, 순수 텍스트로 처리합니다.
                return response.text.strip().strip('"')
    except requests.RequestException as e:
        logging.warning(Color.warn(f"Warning: AI summary generation failed - {e}. Falling back to English summary."))
    
    # 3. AI 서버 호출 실패 시, 영문 요약을 반환합니다.
    return english_summary

def is_target_product(product_name):
    """주어진 제품 이름이 대상 RHEL 제품 목록에 포함되는지 확인합니다."""
    for pattern in TARGET_PRODUCT_PATTERNS:
        if pattern.match(product_name):
            return True
    return False

# --- HTML 리포트 생성 함수 ---

def generate_html_report(system_info, vulnerabilities):
    hostname = system_info.get('hostname', 'N/A')
    os_version = system_info.get('os_version', 'N/A')
    kernel_version = system_info.get('kernel_version', 'N/A')
    uptime = system_info.get('uptime', 'N/A')
    boot_time = system_info.get('boot_time', 'N/A')    

    vuln_rows = ""
    # CVE ID와 발행일 기준으로 정렬
    for i, vuln in enumerate(sorted(vulnerabilities, key=lambda x: (x['cve_id'], x['public_date']), reverse=True), 1):
        # [사용자 요청] CVE 당 하나의 행만 생성하도록 로직 변경
        # [사용자 요청 수정] 여러 패키지 중 대표 패키지 하나만 표시하고, RHSA는 모두 표시합니다.
        representative_finding = None
        rhsa_ids_html = []
        
        # [사용자 요청] 버전 비교 결과를 종합하여 최종 상태를 결정합니다.
        # -1: 조치 필요 (하나라도 낮음), 0: 조치 완료 (모두 동일), 1: 조치 완료 (하나라도 높음)
        overall_status = 0 # 기본값: 모두 동일
        
        findings = vuln.get('findings', [])
        if findings:
            # 기본 대표 finding을 첫 번째 항목으로 설정
            representative_finding = findings[0]
        
        for finding in findings: # noqa: E501
            rhsa_link = f'<a href="https://access.redhat.com/errata/{html.escape(finding["rhsa_id"])}" target="_blank">{html.escape(finding["rhsa_id"])}</a>' if finding.get("rhsa_id") and finding["rhsa_id"] != "N/A" else "N/A"
            rhsa_ids_html.append(rhsa_link)
            
            comparison = finding.get('version_comparison', -1)
            if comparison < 0:
                overall_status = -1 # 하나라도 낮으면 최종 상태는 '낮음'
                # 조치가 필요한 finding을 대표로 설정
                representative_finding = finding
            elif comparison > 0 and overall_status != -1:
                overall_status = 1 # '낮음'이 없는 상태에서 '높음'이 발견되면 최종 상태는 '높음'

        cve_link = f'<a href="https://access.redhat.com/security/cve/{html.escape(vuln["cve_id"])}" target="_blank">{html.escape(vuln["cve_id"])}</a>'
        
        # [사용자 요청] 종합된 상태(overall_status)에 따라 아이콘과 툴팁을 다르게 표시합니다.
        if not representative_finding: # finding 정보가 없으면
            status_html = '<span class="status-icon status-nok" title="정보 없음">N/A</span>'
        elif overall_status < 0:
            status_html = '<span class="status-icon status-nok" title="조치 필요 (설치된 버전이 권고 버전보다 낮음)">NOK &darr;</span>'
        elif overall_status == 0:
            status_html = '<span class="status-icon status-ok" title="조치 완료 (버전 동일)">OK =</span>'
        else:
            status_html = '<span class="status-icon status-higher" title="조치 완료 (버전 높음)">OK &uarr;</span>'
        
        # [사용자 요청] 대표 finding의 정보만 추출하여 표시
        current_pkg_html = html.escape(representative_finding['current_package']) if representative_finding else '정보 없음'
        fix_pkg_html = html.escape(representative_finding['fix_package']) if representative_finding else '정보 없음'
        # RHSA ID는 중복을 제거하고 모두 표시
        unique_rhsa_html = '<br>'.join(sorted(list(set(rhsa_ids_html)))) if rhsa_ids_html else '정보 없음'


        vuln_rows += f"""
        <tr>
            <td>{i}</td>
            <td>{cve_link} ({html.escape(vuln['public_date'])})</td>
            <td>{html.escape(vuln['severity'])}<br>(CVSS: {html.escape(vuln['score'])})</td>
            <td>{html.escape(vuln['summary'])}</td>
            <td>{current_pkg_html}</td>
            <td>{fix_pkg_html}</td>
            <td>{unique_rhsa_html}</td>
            <td class="status-cell">{status_html}</td>
        </tr>
        """

    html_template = f"""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <title>취약점 분석 리포트 - {html.escape(hostname)}</title>
        <style>
            body {{ font-family: sans-serif; margin: 2em; line-height: 1.6; color: #333; }}
            /* [사용자 요청] 요약 정보 스타일 추가 */
            .summary-box {{ background-color: #eef7ff; border: 1px solid #cce5ff; padding: 15px; margin-bottom: 20px; border-radius: 5px; }}
            .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }}
            .summary-item {{ background-color: white; padding: 1rem; border-radius: 8px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
            .summary-item .count {{ font-size: 2rem; font-weight: bold; }}
            h1, h2 {{ color: #0056b3; border-bottom: 2px solid #eee; padding-bottom: 0.5em; margin-top: 1.5em; }}
            .info-box {{ background-color: #eef7ff; border: 1px solid #cce5ff; padding: 15px; margin-bottom: 20px; border-radius: 5px; }}
            .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }}
            .info-box p {{ margin: 0.5em 0; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; box-shadow: 0 2px 3px rgba(0,0,0,0.1); }}
            th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; vertical-align: top; }}
            th {{ background-color: #f2f2f2; font-weight: bold; color: #555; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
            a {{ color: #007bff; text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
            /* [사용자 요청] 아이콘 스타일 추가 */
            .status-cell {{ text-align: center; vertical-align: middle; }}
            .status-icon {{
                display: inline-block;
                width: 40px;
                height: 40px;
                line-height: 40px;
                border-radius: 50%;
                color: white;
                font-weight: bold;
            }}
            .status-ok {{ background-color: #28a745; }}
            .status-nok {{ background-color: #dc3545; }}
            .status-higher {{ background-color: #007bff; }} /* 높은 버전에 대한 색상 추가 */
        </style>
    </head>
    <body>
        <h1>취약점 분석 리포트</h1>
        <div class="info-box">
            <h2>시스템 정보</h2>
            <p><strong>Hostname:</strong> {html.escape(hostname)}</p>
            <p><strong>OS Version:</strong> {html.escape(os_version)}</p>
            <p><strong>Kernel Version:</strong> {html.escape(kernel_version)}</p>
            <p><strong>Uptime:</strong> {html.escape(uptime)}</p>
            <p><strong>Boot Time:</strong> {html.escape(boot_time)}</p>
        </div>

        <!-- [사용자 요청] 취약점 요약 정보 추가 -->
        <h2>분석 요약</h2>
        <p>총 <strong>{len(vulnerabilities)}</strong>개의 고유 CVE에 대해 분석했으며, 그 중 <strong>{sum(1 for v in vulnerabilities if any(f.get('version_comparison', -1) < 0 for f in v.get('findings', [])))}</strong>개의 CVE에 대한 조치가 필요합니다.</p>
        
        <h2>취약점 정보</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 5%;">No.</th>
                    <th>CVE ID (발행일)</th>
                    <th>심각도 & 점수</th>
                    <th>취약점 요약</th>
                    <th style="width: 15%;">현재 패키지 버전</th>
                    <th style="width: 15%;">권고 버전</th>
                    <th style="width: 10%;">RHSA ID</th>
                    <th style="width: 8%;">조치 상태</th>
                </tr>
            </thead>
            <tbody>
                {vuln_rows if vuln_rows else "<tr><td colspan='8' style='text-align:center; color: #666;'>발견된 취약점이 없습니다.</td></tr>"}
            </tbody>
        </table>
    </body>
    </html>
    """
    return html_template

# --- [신규] 인덱스 HTML 생성 함수 ---
def generate_index_html(report_list, total_input_files):
    """
    분석된 모든 리포트의 목록을 보여주는 index.html 파일을 생성합니다.
    """
    # [사용자 요청] 각 리포트 앞에 번호를 붙이기 위해 enumerate 사용
    report_rows = ""
    for i, report in enumerate(sorted(report_list, key=lambda x: x['creation_time'], reverse=True), 1):
        report_rows += f""" # noqa: E501
        <tr id="report-row-{html.escape(report['hostname'])}">
            <td>{i}</td>  <!-- No. 열 추가 -->
            <td>{html.escape(report['hostname'])}</td> 
            <td><a href="{html.escape(report['report_filename'])}" target="_blank">{html.escape(report['report_filename'])}</a></td>
            <td>{html.escape(report['creation_time'])}</td>
            <td>{report['total_vulnerabilities']}</td>
            <td style="color: #dc3545; font-weight: bold;">{report['nok_vulnerabilities']}</td>
        </tr>
        """

    index_html_template = f"""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <title>취약점 분석 리포트 목록</title>
        <!-- [신규] 아이콘 라이브러리 추가 -->
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
        <style>
            body {{ font-family: sans-serif; margin: 2em; line-height: 1.6; color: #333; }}
            h1, h2 {{ color: #0056b3; border-bottom: 2px solid #eee; padding-bottom: 0.5em; margin-top: 1.5em; }}
            .summary-box {{ background-color: #eef7ff; border: 1px solid #cce5ff; padding: 15px; margin-bottom: 20px; border-radius: 5px; }}
            /* [신규] 전역 제어 버튼 스타일 */
            .global-controls {{ display: flex; justify-content: flex-end; gap: 1rem; margin-bottom: 1.5rem; }}
            .button {{ display: inline-flex; align-items: center; gap: 0.5rem; padding: 8px 15px; border-radius: 5px; border: 1px solid transparent; font-weight: 500; cursor: pointer; text-decoration: none; transition: all 0.2s; }}
            .button-zip {{ background-color: #198754; color: white; border-color: #198754; }}
            .button-zip:hover {{ background-color: #157347; }}
            .button-delete-all {{ background-color: #dc3545; color: white; border-color: #dc3545; }}
            .button-delete-all:hover {{ background-color: #bb2d3b; }}
            .button-download {{ background-color: #0d6efd; color: white; border-color: #0d6efd; font-size: 0.85rem; padding: 6px 12px;}}
            .button-download:hover {{ background-color: #0b5ed7; }}
            .button-delete {{ background-color: #6c757d; color: white; border-color: #6c757d; font-size: 0.85rem; padding: 6px 12px;}}
            .button-delete:hover {{ background-color: #5c636a; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; box-shadow: 0 2px 3px rgba(0,0,0,0.1); }}
            th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; vertical-align: top; }}
            th {{ background-color: #f2f2f2; font-weight: bold; color: #555; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
            a {{ color: #007bff; text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
        </style>
    </head>
    <body>
        <h1>취약점 분석 리포트 목록</h1>
        <div class="summary-box">
            <h2>분석 요약</h2>
            <p>총 <strong>{total_input_files}</strong>개의 시스템 정보 파일이 입력되어 <strong>{len(report_list)}</strong>개의 리포트가 생성되었습니다.</p>
        </div>
        <!-- [신규] 전역 제어판 -->
        <div class="global-controls">
            <button class="button button-zip" onclick="downloadAllAsZip()"><i class="fas fa-file-archive"></i> 전체 압축 다운로드</button>
            <button class="button button-delete-all" onclick="deleteAllReports()"><i class="fas fa-trash-alt"></i> 전체 리포트 삭제</button>
        </div>
        <table>
            <thead>
                <tr>
                    <th style="width: 5%;">No.</th><th>Hostname</th><th>Report File</th><th>생성 시간</th><th>총 취약점</th><th>조치 필요</th> <!-- No. 헤더 추가 -->
                </tr>
            </thead>
            <tbody>
                {report_rows if report_rows else "<tr><td colspan='6' style='text-align:center; color: #666;'>생성된 리포트가 없습니다.</td></tr>"} <!-- colspan 5 -> 6 -->
            </tbody>
        </table>

        <!-- [신규] 비밀번호 입력 모달 -->
        <div id="password-modal" style="display:none; position:fixed; z-index:1000; left:0; top:0; width:100%; height:100%; background-color:rgba(0,0,0,0.5); justify-content:center; align-items:center;">
            <div style="background:white; padding:2rem; border-radius:8px; box-shadow:0 5px 15px rgba(0,0,0,0.3); width:350px;">
                <h3 style="margin-top:0;">관리자 비밀번호 확인</h3>
                <p style="color:#666; font-size:0.9rem;">모든 리포트를 삭제하려면 비밀번호를 입력하세요.</p>
                <input type="password" id="password-input" style="width:100%; padding:10px; margin:1rem 0; border:1px solid #ccc; border-radius:4px;">
                <div style="display:flex; justify-content:flex-end; gap:1rem;">
                    <button id="cancel-delete-btn" class="button" style="background-color:#6c757d;">취소</button>
                    <button id="confirm-delete-btn" class="button button-delete-all">삭제 확인</button>
                </div>
            </div>
        </div>

        <!-- [신규] JavaScript 로직 -->
        <script>
            const passwordModal = document.getElementById('password-modal');
            const passwordInput = document.getElementById('password-input');
            const confirmDeleteBtn = document.getElementById('confirm-delete-btn');
            const cancelDeleteBtn = document.getElementById('cancel-delete-btn');

            // 개별 리포트 삭제 함수
            async function deleteReport(filename, hostname) {{
                if (!confirm(`'${{filename}}' 리포트와 관련 데이터를 정말 삭제하시겠습니까?`)) return;

                try {{
                    // 서버의 삭제 API 호출
                    const response = await fetch(`/AIBox/api/reports?file=${{encodeURIComponent(filename)}}`, {{ method: 'DELETE' }});
                    if (!response.ok) {{
                        const result = await response.json();
                        throw new Error(result.error || '삭제에 실패했습니다.');
                    }}
                    // 성공 시 테이블에서 해당 행 제거
                    const row = document.getElementById(`report-row-${{hostname}}`);
                    if (row) row.remove();

                    // 테이블이 비었는지 확인하고 메시지 표시
                    const tbody = document.querySelector('tbody');
                    if (tbody.children.length === 0) {{
                        tbody.innerHTML = "<tr><td colspan='5' style='text-align:center; color: #666;'>생성된 리포트가 없습니다.</td></tr>";
                    }}
                }} catch (error) {{
                    alert(`리포트 삭제 오류: ${{error.message}}`);
                }}
            }}

            // 전체 리포트 삭제 함수
            async function deleteAllReports() {{
                if (confirm('생성된 모든 리포트와 분석 데이터를 정말 삭제하시겠습니까?\\n이 작업은 되돌릴 수 없습니다.')) {{
                    passwordModal.style.display = 'flex';
                    passwordInput.focus();
                }}
            }}

            // [BUG FIX] 모달 제어 로직 추가
            if (passwordModal) {{
                // 모달 취소 버튼
                cancelDeleteBtn.addEventListener('click', () => {{
                    passwordModal.style.display = 'none';
                    passwordInput.value = '';
                }});

                // 모달 삭제 확인 버튼
                confirmDeleteBtn.addEventListener('click', async () => {{
                    const password = passwordInput.value;
                    if (!password) {{
                        alert('비밀번호를 입력해주세요.');
                        return;
                    }}

                    passwordModal.style.display = 'none';
                    passwordInput.value = '';

                    try {{
                        const response = await fetch('/AIBox/api/reports/all', {{ method: 'DELETE', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ password: password }}) }});
                        const result = await response.json();
                        if (!response.ok) throw new Error(result.error || '전체 삭제에 실패했습니다.');
                        alert('모든 리포트가 성공적으로 삭제되었습니다.');
                    document.querySelector('tbody').innerHTML = "<tr><td colspan='6' style='text-align:center; color: #666;'>생성된 리포트가 없습니다.</td></tr>";
                    }} catch (error) {{ alert(`전체 삭제 오류: ${{error.message}}`); }}
                }});
            }}

            // 전체 압축 다운로드 함수
            function downloadAllAsZip() {{
                // 서버의 ZIP 다운로드 API 엔드포인트로 리디렉션
                window.location.href = '/AIBox/api/reports/zip';
            }}
        </script>
    </body>
    </html>
    """
    return index_html_template

# --- 메인 로직 ---

def main():
    # 디렉토리 준비
    # [사용자 요청] 스크립트 실행 시 output 디렉토리 초기화
    if REPORT_OUTPUT_DIR.exists():
        logging.info(f"기존 output 디렉토리 '{REPORT_OUTPUT_DIR}'의 내용을 삭제합니다.")
        shutil.rmtree(REPORT_OUTPUT_DIR)
    
    REPORT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True) # 삭제 후 다시 생성
    SYSTEM_DATA_DIR.mkdir(parents=True, exist_ok=True) # data 디렉토리는 유지
    CVE_DB_PATH.parent.mkdir(parents=True, exist_ok=True) # CVE DB 디렉토리도 확인

    # 시스템 정보 파일 목록 가져오기
    system_files = list(SYSTEM_DATA_DIR.glob("*.json"))
    if not system_files:
        logging.error(Color.error(f"오류: 분석할 시스템 정보 파일이 '{SYSTEM_DATA_DIR}'에 없습니다."))
        return

    # CVE DB 로드
    if not CVE_DB_PATH.is_file():
        logging.error(Color.error(f"오류: CVE 데이터베이스 파일 '{CVE_DB_PATH}'를 찾을 수 없습니다."))
        logging.error(Color.error("'make_cve_db.py'를 먼저 실행하여 데이터베이스를 생성해주세요."))
        return
    try:
        with open(CVE_DB_PATH, 'r', encoding='utf-8') as f:
            cve_database = json.load(f)
    except json.JSONDecodeError:
        logging.error(Color.error(f"오류: CVE DB 파일 '{CVE_DB_PATH}'이 손상되었거나 비어있습니다. 'make_cve_db.py'를 다시 실행해주세요."))
        return

    logging.info(Color.header(f"\n총 {len(system_files)}개의 시스템에 대한 분석을 시작합니다..."))

    # [신규] 생성된 리포트 정보를 저장할 리스트
    report_metadata_list = []

    for i, system_file in enumerate(system_files, 1):
        logging.info(f"\n--- [{i}/{len(system_files)}] '{system_file.name}' 파일 분석 시작 ---")
        
        try:
            with open(system_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            logging.error(Color.error(f"오류: '{system_file.name}' 파일 파싱 실패 - {e}. 이 파일을 건너뜁니다."))
            continue

        # 1. 시스템 정보 파싱
        logging.info("  - [1/4] 시스템 정보 파싱 중...")
        host_data = data.get('data', {})
        uptime_full = host_data.get("uptime", "")
        # "15:37:53 up 198 days" 부분만 추출
        uptime_match = re.match(r'(\d{2}:\d{2}:\d{2} up \d+ days(?:, \s*\d+:\d+)?).*', uptime_full)
        
        system_info = {
            "hostname": data.get("host", "N/A"),
            "os_version": host_data.get("OS Version", "N/A"),
            "kernel_version": host_data.get("Kernel version", "N/A"),
            "uptime": uptime_match.group(1) if uptime_match else uptime_full.split(',')[0].strip(), # 매치 안되면 첫 콤마까지
            "boot_time": host_data.get("Boot time", "N/A"),
            "installed_packages": {}
        }

        # 설치된 패키지 정보 파싱
        for pkg_full_name in host_data.get("Install Packages", []):
            name, ver, arch = parse_rpm_full_name(pkg_full_name)
            if name and ver and arch:
                system_info["installed_packages"][name] = (ver, arch)
        
        logging.info(f"    - 호스트: {system_info['hostname']}, OS: {system_info['os_version']}")
        logging.info(f"    - 설치된 패키지 {len(system_info['installed_packages'])}개 파싱 완료.")

        # 2. 취약점 분석
        logging.info("  - [2/4] 취약점 분석 중...")
        # [사용자 요청] CVE별로 결과를 그룹화하기 위해 딕셔너리로 변경
        found_vulnerabilities_map = {}
        for cve_id, cve_data in cve_database.items():
            cve_findings = []
            # 'affected_release' 확인
            for release in cve_data.get("affected_release", []):
                product_name = release.get("product_name")
                package_field = release.get("package")

                if not product_name or not package_field:
                    continue
                
                # 대상 RHEL 제품인지 확인
                if not is_target_product(product_name):
                    continue # noqa: E701
                
                # [사용자 요청] OS 버전 기반 제품 필터링 강화 (v2)
                # 예: 시스템 OS가 "Red Hat Enterprise Linux 8.10"일 경우,
                # product_name이 "Red Hat Enterprise Linux 8" 또는 "Red Hat Enterprise Linux 8.10"으로 시작하는 것만 매칭
                system_os_version = system_info.get('os_version', '') # noqa: E501
                os_ver_match = re.search(r'Red Hat Enterprise Linux\s+(\d+)(?:\.(\d+))?', system_os_version)
                if not os_ver_match:
                    continue
                
                major_ver, minor_ver = os_ver_match.groups()
                
                # 주 버전 또는 주.부 버전과 일치하는지 확인
                is_major_match = f"Red Hat Enterprise Linux {major_ver}" == product_name.split(' for ')[0].strip()
                is_minor_match = minor_ver and f"Red Hat Enterprise Linux {major_ver}.{minor_ver}" in product_name # noqa: E501
                if not (is_major_match or is_minor_match):
                    continue

                vuln_pkg_name, fix_version = parse_cve_package_field(package_field)
                if not vuln_pkg_name or not fix_version:
                    continue

                if vuln_pkg_name in system_info["installed_packages"]: # noqa: E501
                    installed_ver, installed_arch = system_info["installed_packages"][vuln_pkg_name]
                    
                    # [BUG FIX] 버전 비교 결과와 상관없이, 영향을 받는 패키지라면 모든 RHSA 정보를 수집합니다.
                    # 버전 비교는 보고서의 '조치 상태' 표시에만 사용됩니다.
                    version_comparison_result = compare_versions(installed_ver, fix_version)
                    finding_details = {
                        "current_package": f"{vuln_pkg_name}-{installed_ver}.{installed_arch}",
                        "fix_package": f"{vuln_pkg_name}-{fix_version}",
                        "rhsa_id": release.get("advisory", "N/A"),
                        "version_comparison": version_comparison_result
                    }
                    cve_findings.append(finding_details) # noqa: E501
            
            if cve_findings:
                if cve_id not in found_vulnerabilities_map:
                    found_vulnerabilities_map[cve_id] = {
                        "cve_id": cve_id,
                        "public_date": cve_data.get("public_date", "N/A").split('T')[0],
                        "severity": cve_data.get("threat_severity", "N/A"),
                        "score": cve_data.get("cvss3", {}).get("cvss3_base_score", "N/A"),
                        "summary": summarize_vulnerability(cve_data.get("details"), cve_data.get("statement")),
                        "findings": []
                    }
                found_vulnerabilities_map[cve_id]['findings'].extend(cve_findings)

        # 최종 리포트용 리스트로 변환
        final_vulnerabilities = list(found_vulnerabilities_map.values())
        logging.info(f"    - 총 {len(final_vulnerabilities)}개의 유효한 취약점을 발견했습니다.")

        # 3. 리포트 생성
        logging.info("  - [3/4] HTML 리포트 생성 중...")
        report_html = generate_html_report(system_info, final_vulnerabilities)
        
        # 파일명 패턴: {hostname}_{date YYYYMMDD}_report.html
        date_str = datetime.now().strftime("%Y%m%d")
        report_filename = f"{system_info['hostname']}_{date_str}_report.html"
        report_path = REPORT_OUTPUT_DIR / report_filename
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_html)
        
        logging.info(Color.success(f"    - 리포트 생성 완료: {report_path}"))

        # 4. 분석 완료된 시스템 파일 삭제
        try:
            os.remove(system_file)
            logging.info(f"  - [4/4] 분석 완료된 파일 삭제: '{system_file.name}'")
        except OSError as e:
            logging.error(Color.error(f"오류: 파일 '{system_file.name}' 삭제 실패 - {e}"))

        # [사용자 요청] 인덱스 생성을 위해 리포트 메타데이터 저장 (취약점 개수 정보 추가)
        nok_count = sum(1 for cve in final_vulnerabilities for finding in cve.get('findings', []) if finding.get('version_comparison', -1) < 0)
        report_metadata_list.append({
            'hostname': system_info['hostname'],
            'report_filename': report_filename,
            'creation_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_vulnerabilities': len(final_vulnerabilities),
            'nok_vulnerabilities': nok_count
        })

    # [신규] 모든 리포트 생성이 끝난 후, 인덱스 파일 생성
    if report_metadata_list:
        logging.info(Color.header("\n--- 모든 분석 완료. 인덱스 파일 생성 중 ---"))
        index_html_content = generate_index_html(report_metadata_list, len(system_files))
        index_path = REPORT_OUTPUT_DIR / "index.html"
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write(index_html_content)
        logging.info(Color.success(f"인덱스 파일 생성 완료: {index_path}"))

    logging.info(Color.header("\n모든 작업이 완료되었습니다."))

if __name__ == "__main__":
    main()