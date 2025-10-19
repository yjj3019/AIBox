#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-

import os
import json
import requests
import time
import argparse
from pathlib import Path
import logging
import sys
from tqdm import tqdm

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

logging.basicConfig(level=logging.INFO, format='%(message)s', stream=sys.stdout)

# CVE 정보를 가져올 URL
LOCAL_CVE_URL = "http://127.0.0.1:5000/AIBox/cve/{cve_id}.json"
REDHAT_CVE_URL = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"

# CVE DB 저장 경로
CVE_DB_PATH = Path("/data/iso/AIBox/cve-check/meta/cve-check_db.json")

def fetch_cve_data(cve_id):
    """[수정] 재시도 로직이 추가된 CVE 데이터 조회 함수"""
    urls_to_try = [
        {"url": LOCAL_CVE_URL.format(cve_id=cve_id), "source": "로컬 서버"},
        {"url": REDHAT_CVE_URL.format(cve_id=cve_id), "source": "Red Hat API"}
    ]
    max_retries = 3

    for source_info in urls_to_try:
        url, source = source_info["url"], source_info["source"]
        for attempt in range(max_retries):
            try:
                response = requests.get(url, timeout=20)
                if response.status_code == 200:
                    if attempt > 0: logging.info(f" -> [{cve_id}] {source}에서 재시도 성공 (시도 {attempt + 1}).")
                    return response.json()
                if response.status_code == 404: break # 404는 재시도 불필요
                response.raise_for_status()
            except requests.RequestException as e:
                if attempt < max_retries - 1: time.sleep(1)
    return None

def extract_cve_info(cve_data):
    """CVE JSON 데이터에서 필요한 정보를 추출합니다."""
    if not cve_data:
        return None
    
    # CVSS3 정보 추출 (없을 경우 대비)
    cvss3_data = cve_data.get("cvss3", {})
    
    # Bugzilla 정보 추출 (없을 경우 대비)
    bugzilla_data = cve_data.get("bugzilla", {})

    return {
        "threat_severity": cve_data.get("threat_severity", "N/A"),
        "public_date": cve_data.get("public_date", "N/A"),
        "bugzilla": {
            "description": bugzilla_data.get("description", ""),
            "id": bugzilla_data.get("id", ""),
            "url": bugzilla_data.get("url", "")
        },
        "cvss3": {
            "cvss3_base_score": cvss3_data.get("cvss3_base_score", "N/A"),
            "cvss3_scoring_vector": cvss3_data.get("cvss3_scoring_vector", ""),
            "status": cvss3_data.get("status", "")
        },
        "cwe": cve_data.get("cwe", "N/A"),
        "details": cve_data.get("details", []),
        "statement": cve_data.get("statement", ""),
        "affected_release": cve_data.get("affected_release", []),
        "package_state": cve_data.get("package_state", [])
    }

def main():
    parser = argparse.ArgumentParser(description="CVE ID 목록을 읽어 CVE 데이터베이스를 생성합니다.")
    parser.add_argument("cve_list_file", type=str, help="CVE ID 목록이 포함된 텍스트 파일 경로")
    args = parser.parse_args()

    cve_list_path = Path(args.cve_list_file)
    if not cve_list_path.is_file():
        logging.error(Color.error(f"오류: CVE 목록 파일 '{cve_list_path}'를 찾을 수 없습니다."))
        return

    # 기존 DB가 있으면 로드, 없으면 새로 생성
    cve_database = {}
    if CVE_DB_PATH.exists():
        try:
            with open(CVE_DB_PATH, 'r', encoding='utf-8') as f:
                cve_database = json.load(f)
        except json.JSONDecodeError:
            logging.warning(Color.warn(f"경고: 기존 CVE DB 파일 '{CVE_DB_PATH}'이 손상되었거나 비어있습니다. 새 파일을 생성합니다."))
            cve_database = {}
    
    with open(cve_list_path, 'r') as f:
        cve_ids = [line.strip() for line in f if line.strip()]

    # DB 파일 디렉토리 생성
    CVE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    # --- [요청사항] 수집 결과 카운터 추가 ---
    success_count = 0
    failure_count = 0
    skipped_count = 0
    # [사용자 요청] 수집에 실패한 CVE ID를 저장할 리스트
    failed_cves = []

    logging.info(Color.header(f"\n===== CVE 데이터베이스 생성을 시작합니다 (총 {len(cve_ids)}개) ====="))
    with tqdm(total=len(cve_ids), desc="CVE 수집 진행률", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]") as pbar:
        for cve_id in cve_ids:
            pbar.set_description(f"Processing {cve_id}")
            if cve_id in cve_database:
                skipped_count += 1
                pbar.update(1)
                continue
            
            cve_data = fetch_cve_data(cve_id)
            if cve_data:
                extracted_info = extract_cve_info(cve_data)
                if extracted_info:
                    cve_database[cve_id] = extracted_info
                    success_count += 1
            else:
                failure_count += 1
                failed_cves.append(cve_id)
            
            pbar.set_postfix_str(f"성공: {Color.success(str(success_count))}, 실패: {Color.error(str(failure_count))}, 건너뜀: {Color.warn(str(skipped_count))}")
            pbar.update(1)

    # 업데이트된 DB 저장
    with open(CVE_DB_PATH, 'w', encoding='utf-8') as f:
        json.dump(cve_database, f, indent=2, ensure_ascii=False)

    logging.info(Color.success("\nCVE 데이터베이스 생성이 완료되었습니다."))
    logging.info(f"  - 총 저장된 CVE: {len(cve_database)}개")
    logging.info(f"  - DB 위치: {CVE_DB_PATH}")

    # --- [요청사항] 최종 수집 결과 요약 출력 ---
    logging.info(Color.header("\n--- 수집 결과 요약 ---"))
    logging.info(f"  - 총 요청: {len(cve_ids)}개")
    logging.info(f"  - {Color.success('신규 수집 성공')}: {success_count}개")
    logging.info(f"  - {Color.error('수집 실패')}: {failure_count}개")
    logging.info(f"  - {Color.warn('건너뜀 (중복)')}: {skipped_count}개")
    # [사용자 요청] 최종적으로 수집에 실패한 CVE 목록을 출력합니다.
    if failed_cves:
        logging.info(Color.error("\n--- 최종 수집 실패 CVE 목록 ---"))
        for cve in failed_cves:
            logging.info(Color.error(f"  - {cve}"))
    logging.info(Color.header("----------------------"))

if __name__ == "__main__":
    main()