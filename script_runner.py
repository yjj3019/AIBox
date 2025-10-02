#!/usr/bin/env python3
import os
import sys
import subprocess
import logging
from pathlib import Path
import time

# 로그 디렉토리 설정
LOG_DIR = "/data/iso/AIBox/log"
os.makedirs(LOG_DIR, exist_ok=True)

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"{LOG_DIR}/script_runner.log"),
        logging.StreamHandler()
    ]
)

def daemonize():
    """데몬 프로세스 생성"""
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as err:
        logging.error(f'First fork failed: {err}')
        sys.exit(1)

    os.chdir('/')
    os.setsid()
    os.umask(0)

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as err:
        logging.error(f'Second fork failed: {err}')
        sys.exit(1)

def run_script(script_path):
    """스크립트 실행"""
    log_file = f"{LOG_DIR}/collect_data.log"
    
    try:
        with open('/dev/null', 'r') as devnull:
            with open(log_file, 'a') as log:
                process = subprocess.Popen(
                    ['/bin/bash', script_path],
                    stdin=devnull,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True
                )
                return process.pid
    except Exception as e:
        logging.error(f'Failed to run script: {e}')
        sys.exit(1)

def main():
    if len(sys.argv) != 2:
        print("Usage: script_runner.py <target_script>")
        sys.exit(1)

    script_path = sys.argv[1]

    # 스크립트 파일 존재 확인
    if not Path(script_path).is_file():
        logging.error(f"Script not found: {script_path}")
        sys.exit(1)

    logging.info(f"Starting script runner for: {script_path}")
    
    # 데몬화
    daemonize()

    # 스크립트 실행
    pid = run_script(script_path)
    logging.info(f"Script started with PID: {pid}")

if __name__ == "__main__":
    main()
