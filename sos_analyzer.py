#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-
# ==============================================================================
# Smart sosreport Analyzer - The Truly Final & Stabilized Edition
# ------------------------------------------------------------------------------
# [혁신] old.py의 전문가 프롬프트를 계승하고 발전시켜, LLM이 최고 수준의
# RHEL 전문가 및 보안 분석가 역할을 수행하도록 AI 분석 로직을 전면 개편했습니다.
# 이제 sos_analyzer는 단순 데이터 전송을 넘어, 동적으로 생성한 전문가 프롬프트를
# 서버에 전달하여 비교할 수 없는 수준의 고품질 분석을 수행합니다.
# ==============================================================================

import argparse
import json
import os
import tarfile
import re
import logging
import datetime
import threading
import sys
import requests
import base64
from pathlib import Path
import html
import io
import shutil
import tempfile
import time
import traceback
from typing import Dict, Any, List, Optional
from collections import Counter
import xml.etree.ElementTree as ET
from datetime import timedelta, date
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from html_template import get_html_template
from security_analyzer import SecurityAnalyzer
from knowledge_base import KnowledgeBase

# --- 그래프 라이브러리 설정 ---
try:
    # [대체 구현] Plotly는 동적 그래프, Matplotlib은 정적 이미지 생성에 사용합니다.
    try:
        import plotly.graph_objects as go
        import plotly.io as pio
        pio.templates.default = "plotly_white"
        IS_PLOTLY_AVAILABLE = True
    except ImportError:
        IS_PLOTLY_AVAILABLE = False

    import matplotlib
    matplotlib.use('Agg') # GUI 백엔드 없이 실행
    import matplotlib.pyplot as plt
    import matplotlib.font_manager as fm
    IS_MATPLOTLIB_AVAILABLE = True
except ImportError:
    IS_PLOTLY_AVAILABLE, IS_MATPLOTLIB_AVAILABLE = False, False

# [BUG FIX] 그래프 라이브러리 사용 가능 여부를 나타내는 플래그를 정의합니다.
IS_GRAPHING_ENABLED = IS_PLOTLY_AVAILABLE and IS_MATPLOTLIB_AVAILABLE

# [효율성 제안] Pandas 라이브러리 추가
try:
    import pandas as pd
    IS_PANDAS_AVAILABLE = True
except ImportError:
    IS_PANDAS_AVAILABLE = False

# [정확성 제안] pytz 라이브러리 추가
try:
    import pytz
    IS_PYTZ_AVAILABLE = True
except ImportError:
    IS_PYTZ_AVAILABLE = False

# [개선] 토큰 기반 청크 분할을 위한 tiktoken 라이브러리 추가
try:
    import tiktoken
    IS_TIKTOKEN_AVAILABLE = True
except ImportError:
    IS_TIKTOKEN_AVAILABLE = False

# --- 로깅 및 콘솔 출력 설정 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', stream=sys.stdout)

class Color:
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

def log_step(message: str) -> None:
    print(f"\n{Color.header(f'===== {message} =====')}")

def json_serializer(obj):
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    raise TypeError(f"Object of type '{type(obj).__name__}' is not JSON serializable")

class SosreportParser:
    def __init__(self, extract_path: Path):
        log_step("1. sosreport 데이터 파서 초기화")
        subdirs = [d for d in extract_path.iterdir() if d.is_dir()]
        if not subdirs: raise FileNotFoundError(f"sosreport 베이스 디렉토리를 찾을 수 없습니다: {extract_path}")
        self.base_path = subdirs[0]
        # [BUG FIX & 사용자 요청] report_date를 None으로 초기화하고, _initialize_report_date를 먼저 호출하여 올바른 날짜를 설정합니다.
        self.report_date: Optional[datetime.datetime] = None
        self._initialize_report_date()
        self.cpu_cores_count = 0
        self._sar_cache = {}  # [개선] SAR 출력 캐싱
        self._initialize_cpu_cores() # [BUG FIX] 생성자에서 CPU 코어 수를 먼저 초기화합니다.
        self.device_map = self._create_device_map() # [개선] 장치명 매핑 정보 생성
        self.metadata = {'device_map': self.device_map} # [추가] 메타데이터에 장치 맵 추가
        self.dmesg_content = self._read_file(['dmesg', 'sos_commands/kernel/dmesg'])
        # [사용자 요청] HA 클러스터 및 DRBD 정보 파싱 로직 추가
        self.ha_cluster_info = self._parse_ha_cluster_info()
        self.drbd_info = self._parse_drbd_info()
        if self.ha_cluster_info:
            self.metadata['ha_cluster_info'] = self.ha_cluster_info
        if self.drbd_info:
            self.metadata['drbd_info'] = self.drbd_info

        # [사용자 요청] 메타데이터에 호스트 이름 추가
        hostname = self._read_file(['hostname'])
        if hostname != 'N/A':
            self.metadata['hostname'] = hostname

        # [사용자 요청] 메타데이터에 OS 릴리스 정보 추가
        os_release = self._read_file(['etc/redhat-release'])
        if os_release != 'N/A':
            self.metadata['os_release'] = os_release
        logging.info(f"  - 파서 초기화 완료. 분석 대상 경로: '{self.base_path}'")

    def _read_file(self, possible_paths: List[str], default: str = 'N/A') -> str:
        for path_suffix in possible_paths:
            full_path = self.base_path / path_suffix
            if full_path.exists():
                try: return full_path.read_text(encoding='utf-8', errors='ignore').strip()
                except Exception: continue
        return default

    def _initialize_report_date(self):
        date_content = self._read_file(['sos_commands/date/date', 'date'])
        # [사용자 요청] sar 데이터 추출 기준 날짜를 sosreport 내의 date 파일로 설정합니다.
        try:
            # [BUG FIX] 정규식을 수정하여 요일(Weekday) 대신 월(Month)을 올바르게 캡처합니다.
            match = re.search(r'[A-Za-z]{3}\s+([A-Za-z]{3})\s+(\d{1,2})\s+([\d:]+)\s+([A-Z]+)\s+(\d{4})', date_content)
            if match:
                month_abbr, day, time_str, tz_str, year = match.groups()
                month_map = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
                if month_abbr in month_map:
                    hour, minute, second = map(int, time_str.split(':'))
                    # [정확성 제안] pytz를 사용하여 타임존을 명시적으로 처리
                    if IS_PYTZ_AVAILABLE:
                        try:
                            tz = pytz.timezone(tz_str)
                            self.report_date = tz.localize(datetime.datetime(int(year), month_map[month_abbr], int(day), hour, minute, second))
                        except pytz.UnknownTimeZoneError:
                            self.report_date = datetime.datetime(int(year), month_map[month_abbr], int(day), hour, minute, second)
                    else:
                        self.report_date = datetime.datetime(int(year), month_map[month_abbr], int(day), hour, minute, second)

                    logging.info(f"  - 분석 기준 날짜를 'date' 파일 기준으로 설정: {self.report_date.strftime('%Y-%m-%d %Z')}")
                    return
        except Exception as e: logging.warning(f"sosreport 생성 날짜 파싱 중 오류 발생: {e}")

        # [사용자 제안] date 파일 파싱 실패 시, sosreport 디렉터리 이름에서 날짜를 추출하는 폴백 로직을 추가합니다.
        if self.report_date is None:
            logging.warning(Color.warn("'date' 파일에서 날짜를 파싱하지 못했습니다. sosreport 디렉터리 이름에서 날짜 추출을 시도합니다."))
            try:
                # [BUG FIX] Python 3.8 미만 버전과의 호환성을 위해 할당 표현식(:=)을 사용하지 않도록 수정합니다.
                match = re.search(r'(\d{4})-(\d{2})-(\d{2})', self.base_path.name)
                if match:
                    year, month, day = map(int, match.groups())
                    self.report_date = datetime.datetime(year, month, day)
                    logging.info(f"  - 분석 기준 날짜를 'sosreport 디렉터리명' 기준으로 설정: {self.report_date.strftime('%Y-%m-%d')}")
                    return
            except Exception as e:
                logging.warning(f"sosreport 디렉터리명에서 날짜 파싱 중 오류 발생: {e}")

        # 모든 날짜 추출 로직이 실패하면, 현재 시간을 기본값으로 사용합니다.
        if self.report_date is None:
            self.report_date = datetime.datetime.now()
            logging.error("  - 분석 기준 날짜를 설정하지 못했습니다. 현재 시간을 기준으로 분석을 시도합니다.")

    def _initialize_cpu_cores(self):
        lscpu_output = self._read_file(['lscpu', 'sos_commands/processor/lscpu'])
        match = re.search(r'^CPU\(s\):\s+(\d+)', lscpu_output, re.MULTILINE)
        if match: self.cpu_cores_count = int(match.group(1))

    def _create_device_map(self) -> Dict[str, str]:
        """
        [신규] proc/partitions와 dmsetup 정보를 결합하여 (major, minor) -> device_name 매핑을 생성합니다.
        """
        device_map: Dict[str, str] = {}

        # 1. dmsetup 정보 파싱 (LVM 장치명 매핑)
        dmsetup_content = self._read_file(['sos_commands/devicemapper/dmsetup_info_-c'])
        for line in dmsetup_content.split('\n')[1:]:
            # Name, Maj, Min, ... (공백으로 분리)
            parts = line.split()
            if len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit():
                name, major, minor = parts[0], parts[1], parts[2]
                device_map[f"{major}:{minor}"] = name.strip()

        # 2. lsblk 정보 파싱 (일반 파티션 및 LVM 장치명 보강)
        lsblk_content = self._read_file(['sos_commands/block/lsblk'])
        if lsblk_content != 'N/A':
            for line in lsblk_content.split('\n')[1:]:
                # [BUG FIX] 장치 이름에 하이픈(-)이 포함된 경우(예: rhel-root)를 처리하도록 정규식 수정
                # NAME, MAJ:MIN, ... (장치 이름에 하이픈, 백틱, 파이프, 작은따옴표 포함 가능)
                # [BUG FIX] Python 3.8 미만 버전과의 호환성을 위해 할당 표현식(:=)을 사용하지 않도록 수정합니다.
                match = re.search(r'^([\w\-\`|\'\s]+)\s+(\d+:\d+)', line) # noqa: W605
                if match:
                    name, maj_min = match.groups()
                    # dmsetup에서 이미 매핑된 정보가 아니라면 추가
                    if maj_min not in device_map:
                        # lsblk 출력의 '|-`' 같은 트리 문자를 제거합니다.
                        device_map[maj_min] = name.strip('|-`')

        return device_map

    def _parse_ha_cluster_info(self) -> Dict[str, Any]:
        """[신규] Pacemaker, Corosync 등 HA 클러스터 관련 정보를 파싱합니다."""
        logging.info("  - HA 클러스터 정보 파싱 중...")
        ha_info: Dict[str, Any] = {}

        # 1. crm_report 또는 crm status 파싱
        crm_report_content = self._read_file(['sos_commands/pacemaker/crm_report', 'sos_commands/pacemaker/crm_status'])
        if crm_report_content != 'N/A':
            ha_info['crm_report'] = crm_report_content
            # 간단한 상태 정보 추출
            if "OFFLINE" in crm_report_content:
                ha_info['nodes_offline'] = re.findall(r'OFFLINE:\s*\[\s*([^\]]+)\s*\]', crm_report_content)
            if "Failed Actions" in crm_report_content:
                ha_info['failed_actions'] = True

        # 2. cib.xml 파싱 (리소스 및 제약 조건)
        cib_content = self._read_file(['cib.xml', 'var/lib/pacemaker/cib/cib.xml'])
        if cib_content != 'N/A':
            try:
                root = ET.fromstring(cib_content)
                ha_info['resources'] = [res.get('id') for res in root.findall(".//primitive")]
                ha_info['constraints'] = {
                    'location': [loc.get('id') for loc in root.findall(".//rsc_location")],
                    'colocation': [co.get('id') for co in root.findall(".//rsc_colocation")],
                    'order': [ord.get('id') for ord in root.findall(".//rsc_order")]
                }
            except ET.ParseError:
                logging.warning("cib.xml 파싱에 실패했습니다.")

        # 3. corosync.conf 파싱
        corosync_conf_content = self._read_file(['etc/corosync/corosync.conf'])
        if corosync_conf_content != 'N/A':
            ha_info['corosync_config'] = corosync_conf_content

        if ha_info:
            logging.info(f"  - HA 클러스터 정보 파싱 완료: {list(ha_info.keys())}")
        return ha_info

    def _parse_drbd_info(self) -> Dict[str, Any]:
        """[신규] DRBD 관련 정보를 파싱합니다."""
        logging.info("  - DRBD 정보 파싱 중...")
        drbd_info: Dict[str, Any] = {}

        # 1. /proc/drbd 상태 파싱
        proc_drbd_content = self._read_file(['proc/drbd'])
        if proc_drbd_content != 'N/A':
            drbd_info['proc_drbd_status'] = proc_drbd_content
            resources = []
            for line in proc_drbd_content.splitlines():
                # " 0: cs:Connected ro:Primary/Secondary ds:UpToDate/UpToDate C r-----"
                match = re.match(r'^\s*(\d+):\s*(cs:\S+)\s*(ro:\S+)\s*(ds:\S+)', line)
                if match:
                    res_id, cs, ro, ds = match.groups()
                    resource_status = {'id': res_id, 'connection': cs, 'roles': ro, 'disk_states': ds}
                    resources.append(resource_status)
                    # Split-brain 감지
                    if 'Primary/Primary' in ro or 'Secondary/Secondary' in ro:
                        resource_status['warning'] = 'Potential Split-Brain detected in roles.'
                    if 'Inconsistent' in ds:
                        resource_status['warning'] = 'Inconsistent disk state detected.'
            if resources:
                drbd_info['resources'] = resources

        # 2. drbd.conf 파싱
        drbd_conf_content = self._read_file(['etc/drbd.conf'])
        if drbd_conf_content != 'N/A':
            drbd_info['drbd_config'] = drbd_conf_content

        if drbd_info:
            logging.info(f"  - DRBD 정보 파싱 완료: {list(drbd_info.keys())}")
        return drbd_info

    def _safe_float(self, value: Any) -> float:
        """[개선] 입력값을 float으로 안전하게 변환합니다."""
        if isinstance(value, (int, float)):
            return float(value)
        try:
            # [안정성 강화] locale에 따라 소수점이 쉼표(,)로 표현되는 경우를 처리합니다.
            return float(str(value).replace(',', '.'))
        except (ValueError, TypeError): return 0.0

    def _parse_system_details(self) -> Dict[str, Any]:
        logging.info("  - [1/8] 시스템 기본 정보 파싱 중...")
        lscpu_output = self._read_file(['lscpu', 'sos_commands/processor/lscpu']); meminfo = self._read_file(['proc/meminfo']); dmidecode = self._read_file(['dmidecode', 'sos_commands/hardware/dmidecode'])
        mem_total_match = re.search(r'MemTotal:\s+(\d+)\s+kB', meminfo)
        cpu_model_match = re.search(r'Model name:\s+(.+)', lscpu_output)
        model_match = re.search(r'Product Name:\s*(.*)', dmidecode)
        cpu_str = f"{self.cpu_cores_count} x {cpu_model_match.group(1).strip()}" if self.cpu_cores_count > 0 and cpu_model_match else 'N/A'
        uptime_content = self._read_file(['uptime', 'sos_commands/general/uptime'])
        uptime_str = "N/A"
        uptime_match = re.search(r'up\s+(.*?),\s*\d+\s+user', uptime_content)
        if uptime_match: uptime_str = uptime_match.group(1).strip()
        uname_content = self._read_file(['uname', 'sos_commands/kernel/uname_-a']); kernel_str = uname_content.split()[2] if len(uname_content.split()) >= 3 else uname_content
        
        # [사용자 요청 & xsos 참고] /proc/stat의 btime을 사용하여 부팅 시간을 epoch 초 형식으로 가져옵니다.
        proc_stat_content = self._read_file(['proc/stat'])
        boot_time_str = "N/A"
        btime_match = re.search(r'^btime\s+(\d+)', proc_stat_content, re.MULTILINE)
        if btime_match:
            try:
                epoch_time = int(btime_match.group(1))
                # 로컬 타임존을 사용하여 datetime 객체로 변환
                boot_dt = datetime.datetime.fromtimestamp(epoch_time)
                # 'Fri Mar 21 19:28:29 KST 2025 (epoch: 1742552909)' 형식으로 포맷
                # 타임존 약어(%Z)는 시스템에 따라 다를 수 있습니다.
                boot_time_str = f"{boot_dt.strftime('%a %b %d %H:%M:%S %Z %Y')} (epoch: {epoch_time})"
            except (ValueError, TypeError) as e:
                logging.warning(f"부팅 시간 변환 중 오류 발생: {e}")
                boot_time_str = self._read_file(['sos_commands/general/uptime_-s']).strip() # 폴백
            
        return { 'hostname': self._read_file(['hostname']), 'os_release': self._read_file(['etc/redhat-release']), 'kernel': kernel_str, 'system_model': model_match.group(1).strip() if model_match else 'N/A', 'cpu': cpu_str, 'memory': f"{int(mem_total_match.group(1)) / 1024 / 1024:.1f} GiB" if mem_total_match else "N/A", 'uptime': uptime_str, 'boot_time': boot_time_str, 'report_creation_date': self.report_date.strftime('%a %b %d %H:%M:%S %Z %Y') if self.report_date else 'N/A' }

    def _parse_storage(self) -> List[Dict[str, Any]]:
        logging.info("  - [2/8] 스토리지 및 파일 시스템 정보 파싱 중...")
        df_output = self._read_file(['df', 'sos_commands/filesys/df_-alPh', 'sos_commands/filesys/df_-h']); storage_list = []
        for line in df_output.strip().split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 6 and parts[0].startswith('/'): storage_list.append({ "filesystem": parts[0], "size": parts[1], "used": parts[2], "avail": parts[3], "use_pct": parts[4], "mounted_on": parts[5] })
        return storage_list

    def _parse_process_stats(self) -> Dict[str, Any]:
        logging.info("  - [3/8] 프로세스 통계 파싱 중...")
        ps_content = self._read_file(['ps', 'sos_commands/process/ps_auxwww']); processes = []
        for line in ps_content.split('\n')[1:]:
            parts = line.split(maxsplit=10)
            if len(parts) >= 11:
                try: processes.append({ 'user': parts[0], 'pid': int(parts[1]), 'cpu_pct': float(parts[2]), 'mem_pct': float(parts[3]), 'rss_kb': int(parts[5]), 'stat': parts[7], 'command': parts[10] })
                except (ValueError, IndexError): continue
        user_stats = {}
        for p in processes:
            user = p['user']
            if user not in user_stats: user_stats[user] = {'count': 0, 'cpu_pct': 0.0, 'mem_pct': 0.0, 'rss_kb': 0}
            user_stats[user]['count'] += 1; user_stats[user]['cpu_pct'] += p['cpu_pct']; user_stats[user]['mem_pct'] += p['mem_pct']; user_stats[user]['rss_kb'] += p['rss_kb']
        top_users = sorted(user_stats.items(), key=lambda item: item[1]['cpu_pct'], reverse=True)[:5]
        return { 'total': len(processes), 'top_cpu': sorted(processes, key=lambda p: p['cpu_pct'], reverse=True)[:5], 'top_mem': sorted(processes, key=lambda p: p['rss_kb'], reverse=True)[:5], 'uninterruptible': [p for p in processes if 'D' in p['stat']], 'zombie': [p for p in processes if 'Z' in p['stat']], 'by_user': [{ 'user': user, **stats } for user, stats in top_users] }

    def _parse_listening_ports(self) -> List[Dict[str, Any]]:
        logging.info("    - [4a/8] 리스닝 포트 정보 파싱 중...")
        ss_content = self._read_file(['sos_commands/networking/ss_-tlpn'])
        ports = []
        if ss_content == 'N/A': return ports
        for line in ss_content.split('\n')[1:]:
            parts = line.split()
            if len(parts) < 5 or not parts[0].startswith('LISTEN'): continue
            try:
                address, port = parts[3].rsplit(':', 1)
                process_match = re.search(r'users:\(\("([^"]+)",', ' '.join(parts[4:]))
                process_name = process_match.group(1) if process_match else 'N/A'
                ports.append({'port': int(port), 'address': address, 'process': process_name})
            except (ValueError, IndexError):
                continue
        return ports

    def _parse_network_details(self) -> Dict[str, Any]:
        logging.info("  - [4/8] 네트워크 상세 정보 파싱 중...")
        details = {'interfaces': [], 'routing_table': [], 'ethtool': {}, 'bonding': [], 'netdev': [], 'listening_ports': self._parse_listening_ports()}; all_ifaces = set()
        netdev_content = self._read_file(['proc/net/dev'])
        for line in netdev_content.split('\n')[2:]:
            if ':' in line:
                iface, stats = line.split(':', 1)
                iface, stat_values = iface.strip(), stats.split()
                all_ifaces.add(iface)
                if len(stat_values) == 16: details['netdev'].append({ 'iface': iface, 'rx_bytes': int(stat_values[0]),'rx_packets': int(stat_values[1]), 'rx_errs': int(stat_values[2]), 'rx_drop': int(stat_values[3]), 'tx_bytes': int(stat_values[8]), 'tx_packets': int(stat_values[9]),'tx_errs': int(stat_values[10]),'tx_drop': int(stat_values[11]) })
        ip_addr_content = self._read_file(['sos_commands/networking/ip_addr', 'sos_commands/networking/ip_-d_address'])
        for block in re.split(r'^\d+:\s+', ip_addr_content, flags=re.MULTILINE)[1:]:
            iface_data = {}
            match = re.match(r'([\w.-]+):', block)
            if match:
                iface_name = match.group(1); iface_data['iface'] = iface_name; all_ifaces.add(iface_name)
            else: continue
            match = re.search(r'state\s+(\w+)', block)
            if match: iface_data['state'] = match.group(1).lower()
            match = re.search(r'link/\w+\s+([\da-fA-F:]+)', block)
            if match: iface_data['mac'] = match.group(1)
            match = re.search(r'inet\s+([\d.]+/\d+)', block)
            if match: iface_data['ipv4'] = match.group(1)
            # [사용자 요청] 'lo' 인터페이스를 제외하고 UP 상태인 인터페이스만 수집합니다.
            if iface_name != 'lo' and iface_data.get('state') == 'up':
                details['interfaces'].append(iface_data)
        bonding_dir = self.base_path / 'proc/net/bonding'
        if bonding_dir.is_dir():
            for bond_file in bonding_dir.iterdir():
                bond_content = bond_file.read_text(errors='ignore'); bond_info = {'device': bond_file.name, 'slaves_info': []}
                match = re.search(r'Bonding Mode:\s*(.*)', bond_content)
                if match: bond_info['mode'] = match.group(1).strip()
                match = re.search(r'MII Status:\s*(.*)', bond_content)
                if match: bond_info['mii_status'] = match.group(1).strip()
                for slave_block in bond_content.split('Slave Interface:')[1:]:
                    slave_info = {'name': slave_block.strip().split('\n')[0].strip()}
                    m = re.search(r'MII Status:\s*(.*)', slave_block)
                    if m: slave_info['mii_status'] = m.group(1).strip()
                    m = re.search(r'Speed:\s*(.*)', slave_block)
                    if m: slave_info['speed'] = m.group(1).strip()
                    bond_info['slaves_info'].append(slave_info)
                details['bonding'].append(bond_info)
        for iface_name in sorted(list(all_ifaces)):
            ethtool_i = self._read_file([f'sos_commands/networking/ethtool_-i_{iface_name}']); ethtool_main = self._read_file([f'sos_commands/networking/ethtool_{iface_name}']); ethtool_g = self._read_file([f'sos_commands/networking/ethtool_-g_{iface_name}']); iface_ethtool = {}
            m = re.search(r'driver:\s*(.*)', ethtool_i)
            if m: iface_ethtool['driver'] = m.group(1).strip()
            m = re.search(r'firmware-version:\s*(.*)', ethtool_i)
            if m: iface_ethtool['firmware'] = m.group(1).strip()
            m = re.search(r'Link detected:\s*(yes|no)', ethtool_main)
            if m: iface_ethtool['link'] = m.group(1)
            m = re.search(r'Speed:\s*(.*)', ethtool_main)
            if m: iface_ethtool['speed'] = m.group(1).strip()
            m = re.search(r'Duplex:\s*(.*)', ethtool_main)
            if m: iface_ethtool['duplex'] = m.group(1).strip()
            rx_max_match = re.search(r'RX:\s*(\d+)', ethtool_g)
            rx_now_match = re.search(r'Current hardware settings:[\s\S]*?RX:\s*(\d+)', ethtool_g)
            iface_ethtool['rx_ring'] = f"{rx_now_match.group(1)}/{rx_max_match.group(1)}" if rx_now_match and rx_max_match else 'N/A'
            details['ethtool'][iface_name] = iface_ethtool
        details['routing_table'] = self._parse_routing_table()
        return details

    def _parse_routing_table(self) -> List[Dict[str, str]]:
        logging.info("    - [4b/8] 라우팅 테이블 정보 파싱 중...")
        content = self._read_file(['sos_commands/networking/ip_route_show_table_all']); routes = []
        for line in content.split('\n'):
            parts = line.split();
            if not parts or parts[0] in ["broadcast", "local", "unreachable"]: continue
            route = {'destination': parts[0]}
            if 'via' in parts: route['gateway'] = parts[parts.index('via') + 1]
            if 'dev' in parts: route['device'] = parts[parts.index('dev') + 1]
            routes.append(route)
        return routes

    def _run_sar_command(self, sar_binary_path: str, sar_data_file: Path, options: str) -> str:
        """[안정성 강화 & 재시도 로직 추가] 지정된 sar 바이너리와 옵션으로 명령을 실행하고, 실패 시 3회 재시도합니다."""
        # [개선] SAR 명령 결과를 캐싱합니다.
        cache_key = f"{sar_binary_path}:{sar_data_file}:{options}"
        if cache_key in self._sar_cache:
            return self._sar_cache[cache_key]

        command_str = f"LANG=C {sar_binary_path} -f {sar_data_file} {options}"
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                env = os.environ.copy()
                result = subprocess.run(command_str, capture_output=True, text=True, check=True, env=env, shell=True, timeout=60)
                self._sar_cache[cache_key] = result.stdout
                return result.stdout # 성공 시 즉시 결과 반환
            except (subprocess.CalledProcessError, FileNotFoundError, AttributeError, subprocess.TimeoutExpired) as e:
                logging.warning(f"sar 명령어 실행 실패 (시도 {attempt + 1}/{max_retries}): {command_str}. 오류: {e}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt # 1, 2초 대기
                    logging.info(f"  -> {wait_time}초 후 재시도합니다...") # [사용자 요청] 재시도 대기 시간 로깅
                else:
                    logging.error(Color.error(f"sar 명령어 실행이 {max_retries}번의 시도 후에도 최종 실패했습니다: {command_str}"))
                    # [정확성 제안] 실패 시 빈 문자열 대신 예외를 발생시켜 폴백 로직이 동작하도록 함
                    raise e
        return "" # Should not be reached

    def _parse_additional_info(self) -> Dict[str, Any]:
        logging.info("  - [5/8] 추가 시스템 정보(커널 파라미터, SELinux 등) 파싱 중...")
        # [사용자 요청] sysctl -a 의 모든 커널 파라미터를 파싱합니다.
        all_sysctl_params = {k.strip(): v.strip() for k,v in (l.split('=',1) for l in self._read_file(['sos_commands/kernel/sysctl_-a']).split('\n') if '=' in l)}
        sestatus = {k.strip().lower().replace(' ','_'): v.strip() for k,v in (l.split(':',1) for l in self._read_file(['sos_commands/selinux/sestatus_-v']).split('\n') if ':' in l)}
        
        # [보안 분석 추가] 설치된 패키지 목록을 상세 정보(이름, 버전)와 함께 파싱합니다.
        # [사용자 요청] sosreport 버전에 따라 경로가 다를 수 있으므로, 여러 경로를 탐색합니다.
        rpm_content = self._read_file(['installed-rpms', './installed-rpms'])
        packages: List[Dict[str, str]] = []
        # [사용자 요청] 패키지 이름, 버전, 릴리즈, 아키텍처를 분리하는 정규식
        # 이름에 버전 숫자가 포함될 수 있고(e.g., python3), 릴리즈에 하이픈이 있을 수 있어(e.g., 1.el7_9),
        # 마지막 하이픈을 기준으로 버전-릴리즈를 분리하는 것이 더 안정적입니다.
        # 예: (name)-(version)-(release).(arch)
        # 정규식: (패키지명)-(버전)-(릴리즈).(아키텍처)
        # ^(.+)-([^-]+)-([^-]+)\.([^.]+)$
        # 위 정규식은 이름에 하이픈이 여러개인 경우를 잘못 처리할 수 있습니다.
        # 더 안정적인 방법: 마지막 하이픈 2개를 기준으로 분리
        # (name-version)-(release).(arch)
        # (.+)-([^-]+)\.([^.]+)$
        # (name)-(version-release).(arch)
        # (.+?)-(\d.*)
        for line in rpm_content.strip().split('\n'):
            if not line or line.startswith('gpg-pubkey'):
                continue
            # 패키지 정보 부분만 추출 (설치 날짜 제외)
            package_string = line.split()[0]
            # 마지막 하이픈을 기준으로 이름과 버전-릴리즈 분리
            match = re.match(r'(.+)-([^-]+-[^-]+)$', package_string)
            if match:
                name, version_release = match.groups()
                packages.append({'name': name, 'version': version_release})
        failed_services = [l.strip().split()[0] for l in self._read_file(['sos_commands/systemd/systemctl_list-units_--all']).split('\n') if 'failed' in l]
        
        # [보안 분석 추가] sshd_config 파싱
        sshd_config_content = self._read_file(['etc/ssh/sshd_config'])
        sshd_config = {k.strip(): v.strip() for k, v in (re.split(r'\s+', line, 1) for line in sshd_config_content.split('\n') if line.strip() and not line.strip().startswith('#')) if len(re.split(r'\s+', line, 1)) == 2}

        # [사용자 요청] 부팅 시 사용된 커널 파라미터(/proc/cmdline) 파싱
        boot_cmdline = self._read_file(['proc/cmdline'])

        # [BUG FIX] dmsetup 정보를 파싱하여 메타데이터에 추가합니다. HTMLReportGenerator에서 직접 파일을 읽지 않도록 수정합니다.
        dmsetup_info = self._read_file(['sos_commands/devicemapper/dmsetup_info_-c'])

        # [개선] sudoers 파일 내용을 읽어와서 configurations에 추가
        sudoers_content = self._read_file(['etc/sudoers'])

        return { "kernel_parameters": all_sysctl_params, "boot_cmdline": boot_cmdline, "selinux_status": sestatus, "installed_packages": packages, "failed_services": failed_services, "configurations": {"sshd_config": sshd_config, "dmsetup_info": dmsetup_info, "sudoers_content": sudoers_content} }

    # [사용자 요청] sar 데이터 형식의 비일관성을 해결하기 위해 스키마 기반 파싱을 도입합니다.
    # 각 sar 명령어 옵션에 대해 가능한 헤더 이름과 표준화된 키를 매핑합니다.
    SAR_HEADER_SCHEMA = {
        'cpu': {
            '%user': 'pct_user', '%nice': 'pct_nice', '%system': 'pct_system', '%iowait': 'pct_iowait',
            '%steal': 'pct_steal', '%idle': 'pct_idle'
        },
        'memory': {
            'kbmemfree': 'kbmemfree', 'kbmemused': 'kbmemused', '%memused': 'pct_memused',
            'kbbuffers': 'kbbuffers', 'kbcached': 'kbcached', 'kbcommit': 'kbcommit',
            '%commit': 'pct_commit', 'kbactive': 'kbactive', 'kbinact': 'kbinact',
            'kbdirty': 'kbdirty'
        },
        'load': {
            'runq-sz': 'runq_sz', 'plist-sz': 'plist_sz', 'ldavg-1': 'load_1',
            'ldavg-5': 'load_5', 'ldavg-15': 'load_15', 'blocked': 'blocked'
        },
        'disk': {
            'tps': 'tps', 'rtps': 'rtps', 'wtps': 'wtps', 
            'bread/s': 'bread_s', 'bwrtn/s': 'bwrtn_s', # RHEL 7
            'rkB/s': 'bread_s', 'wkB/s': 'bwrtn_s'      # RHEL 8
        },
        'disk_detail': {
            'tps': 'tps', 'rd_sec/s': 'rd_sec_s', 'wr_sec/s': 'wr_sec_s',
            'avgrq-sz': 'avgrq_sz', 'avgqu-sz': 'avgqu_sz', 'await': 'await',
            'svctm': 'svctm', '%util': 'pct_util', 'rkB/s': 'rkB_s', 'wkB/s': 'wkB_s',
            'areq-sz': 'avgrq_sz', 'aqu-sz': 'avgqu_sz',
            # [개선 & RHEL8 호환성] 로케일 및 버전에 따른 대체 헤더 추가
            'rd_sect/s': 'rd_sec_s', 'wr_sect/s': 'wr_sec_s',
            'rkB/s': 'rd_sec_s', 'wkB/s': 'wr_sec_s',
            'areq-sz': 'avgrq_sz', 'aqu-sz': 'avgqu_sz'
        },
        'swap': {
            'kbswpfree': 'kbswpfree', 'kbswpused': 'kbswpused', '%swpused': 'pct_swpused',
            'kbswpcad': 'kbswpcad', '%swpcad': 'pct_swpcad'
        },
        'network': {
            'rxpck/s': 'rxpck_s', 'txpck/s': 'txpck_s', 'rxkB/s': 'rxkB_s', 'txkB/s': 'txkB_s',
            # [RHEL8 호환성] RHEL 8에 추가된 네트워크 헤더
            'rxcmp/s': 'rxcmp_s', 'txcmp/s': 'txcmp_s', 'rxmcst/s': 'rxmcst_s', '%ifutil': 'pct_ifutil'
        },
        'file_handler': {
            'dentunusd': 'dentunusd', 'file-nr': 'file_nr', 'inode-nr': 'inode_nr', 'pty-nr': 'pty_nr'
        }
    }

    def _parse_sar_section(self, sar_binary_path: str, target_sar_file: Path, section: str, option: str) -> List[Dict]:
        """[신규] 지정된 섹션에 대해 sar 명령을 실행하고 결과를 파싱합니다."""
        # [효율성 제안] Pandas가 없으면 파싱을 건너뜁니다.
        if not IS_PANDAS_AVAILABLE:
            return []

        try:
            content = self._run_sar_command(sar_binary_path, target_sar_file, option)
        except Exception:
            return [] # 명령어 실행 실패 시 빈 리스트 반환

        lines = [line.strip() for line in content.strip().split('\n') if line.strip() and not line.startswith('Average:')]
        if len(lines) < 2:
            return []

        header_line = lines[0]
        # [BUG FIX] 헤더가 여러 줄에 걸쳐 있을 수 있는 경우(예: sar -n DEV)를 처리합니다.
        # 'Linux'로 시작하는 라인을 건너뛰고 실제 헤더를 찾습니다.
        header_index = 0
        # [BUG FIX] RHEL8의 '00:00:00 CPU ...'와 같은 헤더를 건너뛰지 않도록, 타임스탬프만 있는 라인을 찾는 조건을 수정합니다.
        # 실제 헤더는 타임스탬프 외에 다른 문자(예: CPU, IFACE)를 포함합니다.
        while header_index < len(lines) and (lines[header_index].startswith('Linux') or not re.search(r'[a-zA-Z]', lines[header_index])):
            header_index += 1
        
        if header_index >= len(lines): return []
        
        # [BUG FIX] RHEL8의 sar 출력은 헤더 라인에 타임스탬프가 포함될 수 있습니다.
        # 예: '00:00:00 CPU %user ...' 또는 '00:00:00 IFACE rxpck/s ...'
        # 타임스탬프 부분을 제외하고 실제 헤더만 추출합니다.
        header_line_full = lines[header_index].strip()
        header_parts_full = re.split(r'\s+', header_line_full)
        
        # 첫 번째 요소가 타임스탬프 형식인지 확인
        if re.match(r'^\d{2}:\d{2}:\d{2}$', header_parts_full[0]):
            header_parts = header_parts_full[1:] # 타임스탬프 제외
        else:
            header_parts = header_parts_full
        
        # [BUG FIX] 데이터 시작 라인을 더 정확하게 찾습니다.
        # 헤더 다음 라인부터 시작하되, 비어있거나 'Linux'로 시작하는 라인은 건너뜁니다.
        data_start_index = header_index + 1
        while data_start_index < len(lines) and (not lines[data_start_index].strip() or lines[data_start_index].startswith('Linux')):
            data_start_index += 1

        data_io = io.StringIO('\n'.join(lines[data_start_index:]))

        try:
            # [BUG FIX] 로케일에 따라 소수점이 쉼표(,)로 표시되는 경우를 처리하기 위해 decimal=',' 추가
            df = pd.read_csv(data_io, sep=r'\s+', header=None, engine='python', decimal=",")
            if df.empty:
                return []

            # --- [BUG FIX] RHEL8 호환성을 위한 컬럼 이름 설정 로직 개선 ---
            schema_keys = self.SAR_HEADER_SCHEMA.get(section, {})
            
            # 1. 최종 컬럼 이름을 담을 리스트 초기화
            cols = []
            
            # 2. 헤더의 첫 번째 열이 타임스탬프가 아닌 식별자(CPU, IFACE, DEV)인 경우를 처리
            first_header = header_parts[0] if header_parts else ''
            if first_header in ['CPU', 'IFACE', 'DEV']:
                # 데이터의 첫 번째 열은 타임스탬프, 두 번째 열이 식별자(CPU/DEV/IFACE)가 됩니다.
                # cols 리스트에 ['timestamp', 'CPU'] 와 같이 컬럼을 미리 추가합니다.
                cols.extend(['timestamp', first_header])
                # 실제 데이터 헤더는 식별자 다음부터 시작합니다.
                raw_headers_for_check = header_parts[1:] 
            else:
                # CPU/DEV/IFACE가 없는 경우 (예: sar -r), 첫 열은 타임스탬프입니다.
                cols = ['timestamp']
                # 모든 헤더 파트를 데이터 컬럼으로 사용합니다.
                raw_headers_for_check = header_parts

            # 3. 나머지 헤더들을 스키마에 따라 표준화하여 컬럼 목록에 추가합니다.
            cols.extend([schema_keys.get(h, h.replace('%', 'pct_').replace('/', '_').replace('-', '_')) for h in raw_headers_for_check])
            
            # 4. [안정성 강화] 데이터프레임의 실제 컬럼 수와 생성된 컬럼 이름 목록의 길이를 비교하여 안전하게 컬럼 이름을 할당합니다.
            #    이는 예상치 못한 출력 형식으로 인해 발생하는 오류를 방지합니다.
            num_cols_to_assign = min(len(df.columns), len(cols))
            df.columns = cols[:num_cols_to_assign]
            # 데이터프레임의 컬럼 수를 할당된 컬럼 수에 맞게 자릅니다.
            df = df.iloc[:, :num_cols_to_assign]

            # 타임스탬프 변환
            df['timestamp'] = pd.to_datetime(df['timestamp'], format='%H:%M:%S').dt.time
            df['timestamp'] = df.apply(lambda row: self.report_date.replace(hour=row['timestamp'].hour, minute=row['timestamp'].minute, second=row['timestamp'].second).astimezone(pytz.utc).isoformat() if IS_PYTZ_AVAILABLE else self.report_date.replace(hour=row['timestamp'].hour, minute=row['timestamp'].minute, second=row['timestamp'].second).isoformat(), axis=1)

            # 숫자형으로 변환
            for col in df.columns:
                if col not in ['timestamp', 'IFACE', 'DEV', 'CPU']:
                    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

            # 필터링
            if section == 'cpu' and 'CPU' in df.columns: df = df[df['CPU'] == 'all']
            if section == 'network' and 'IFACE' in df.columns: df = df[df['IFACE'] != 'lo']

            return df.to_dict('records')

        except Exception as e:
            logging.debug(f"'{section}' 섹션 Pandas 파싱 중 오류 발생 (블록 건너뜀): {e}")
            return []

    def _parse_sar_data_from_text(self) -> Dict[str, List[Dict]]:
        """[사용자 요청] 텍스트 기반 sar 파일(예: sos_commands/sar/sarDD)을 파싱합니다."""
        logging.info("  - [6b/8] 텍스트 sar 데이터 파싱 시도 (바이너리 파싱 실패 시 폴백)...")
        
        report_day = self.report_date.day  # type: ignore
        report_date_str = self.report_date.strftime('%Y%m%d')
        # [사용자 요청] 다양한 경로와 이름 형식의 텍스트 sar 파일을 순서대로 탐색합니다.
        possible_paths = [
            f'var/log/sa/sar{report_day:02d}', f'var/log/sa/sar{report_date_str}',
            f'sos_commands/sar/sar{report_day:02d}', f'sos_commands/sar/sar{report_date_str}'
        ]
        
        content, found_path = next(((self._read_file([p]), p) for p in possible_paths if self._read_file([p]) != 'N/A'), ('N/A', None))
        if not found_path:
            logging.warning(Color.warn(f"  - 날짜에 맞는 텍스트 sar 파일을 찾을 수 없어 텍스트 파싱을 건너뜁니다."))
            return {}

        logging.info(f"  - 사용할 텍스트 sar 파일: {found_path}")

        all_sar_data: Dict[str, List[Dict]] = {}
        current_section = None
        header_cols = []

        for line in content.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('Average:'):
                if line.startswith('Average:'): header_cols = []
                continue

            parts = re.split(r'\s+', line)
            logging.debug(f"  [TEXT] Processing line: {line}")
            # [BUG FIX] 헤더 라인 식별 로직 강화
            is_header_line = (parts[0] == 'Linux') or (re.match(r'^\d{2}:\d{2}:\d{2}(?!\d)', parts[0]) and any(p in ['CPU', 'IFACE', 'DEV'] or '%' in p or '/' in p or '-' in p for p in parts[1:]))
            time_end_idx_check = 2 if len(parts) > 1 and parts[1] in ['AM', 'PM'] else 1
            is_data_line = re.match(r'^\d{2}:\d{2}:\d{2}(?!\d)', parts[0]) and not is_header_line and any(p.replace('.', '', 1).isdigit() for p in parts[time_end_idx_check:])

            if is_header_line:
                raw_headers = parts[time_end_idx_check:]
                logging.debug(f"    -> Identified as HEADER line.")
                # 헤더를 보고 현재 섹션이 무엇인지 추론
                for section, schema in self.SAR_HEADER_SCHEMA.items():
                    if any(h in schema for h in raw_headers):
                        current_section = section
                        # [BUG FIX] 'disk'와 'disk_detail' 구분 로직 추가
                        # 'disk'와 'disk_detail'은 'tps' 헤더를 공유하므로, 'rd_sec/s'와 같은
                        # disk_detail에만 있는 헤더의 존재 여부로 두 섹션을 구분합니다.
                        if current_section == 'disk' and any(h in self.SAR_HEADER_SCHEMA['disk_detail'] for h in raw_headers if h != 'tps'):
                            current_section = 'disk_detail'
                        if current_section == 'disk' and any(h in self.SAR_HEADER_SCHEMA['disk_detail'] for h in raw_headers if h != 'tps'):
                            current_section = 'disk_detail'
                        schema_keys = self.SAR_HEADER_SCHEMA.get(current_section, {})
                        
                        first_col_header = parts[time_end_idx_check-1]
                        header_cols = []
                        if first_col_header in ['CPU', 'DEV', 'IFACE']:
                            header_cols.append(first_col_header)

                        for raw_header in raw_headers:
                            if raw_header not in ['IFACE', 'DEV', 'CPU']:
                                header_cols.append(schema_keys.get(raw_header, raw_header.replace('%', 'pct_').replace('/', '_').replace('-', '_')))
                        
                        logging.debug(f"    -> Section: '{current_section}', Parsed Headers: {header_cols}")
                        if current_section not in all_sar_data: all_sar_data[current_section] = []
                        break

            if is_data_line and header_cols and current_section:
                logging.debug(f"    -> Identified as DATA line for section '{current_section}'.")
                time_end_idx = time_end_idx_check
                ts_str = " ".join(parts[:time_end_idx])
                try: dt_obj = datetime.datetime.strptime(ts_str, '%I:%M:%S %p' if time_end_idx == 2 else '%H:%M:%S'); timestamp_iso = self.report_date.replace(hour=dt_obj.hour, minute=dt_obj.minute, second=dt_obj.second).isoformat()
                except ValueError: continue # yapf: disable

                values = parts[time_end_idx:]
                # [BUG FIX] 헤더에 'DEV'가 있지만 실제 데이터 라인에 장치명이 없는 경우를 처리
                if 'DEV' in header_cols and len(values) == len(header_cols) -1: values.insert(0, 'N/A')
                entry = {'timestamp': timestamp_iso}
                for i in range(min(len(header_cols), len(values))):
                    header = header_cols[i]
                    value = values[i]
                    entry[header] = value if header in ['IFACE', 'DEV', 'CPU'] else self._safe_float(value)

                if current_section == 'disk_detail' and 'DEV' in entry and isinstance(entry['DEV'], str) and entry['DEV'].startswith('dev'):
                    major, minor = entry['DEV'][3:].split('-')
                    # [사용자 요청] 장치명 매핑에 실패하면 원본 dev-x-y 이름을 device_name으로 사용합니다. (self.device_map 사용)
                    entry['device_name'] = self.device_map.get(f"{major}:{minor}", entry['DEV'])
                
                # [사용자 요청] CPU 데이터는 'all'만, 네트워크 데이터는 'lo' 제외
                if current_section == 'cpu' and entry.get('CPU') != 'all':
                    continue
                if current_section == 'network' and entry.get('IFACE') == 'lo':
                    continue
                all_sar_data[current_section].append(entry); logging.debug(f"    -> Parsed entry: {entry}")

        if all_sar_data:
            logging.info("  - 텍스트 sar 파일에서 데이터 수집 완료:")
            for section, data_list in all_sar_data.items():
                logging.info(f"    -> '{section}' 데이터 {len(data_list)}개 수집")

        return all_sar_data

    def _parse_sar_data(self) -> Dict[str, List[Dict]]:
        logging.info("  - [6/8] SAR 성능 데이터 파싱 시작...")
        logging.info(f"sar 데이터 추출 기준 날짜: {self.report_date.strftime('%Y-%m-%d')}")

        os_release_content = self._read_file(['etc/redhat-release'])
        rhel_version_match = re.search(r'release\s+(\d+)', os_release_content)
        rhel_version = rhel_version_match.group(1) if rhel_version_match else "7"
        sar_binary_path = f"/usr/bin/sar_{rhel_version}"

        if not Path(sar_binary_path).exists():
            logging.warning(Color.warn(f"sar 실행 파일 '{sar_binary_path}'를 찾을 수 없습니다. 텍스트 파일 파싱으로 대체합니다."))
            return self._parse_sar_data_from_text()

        sa_dir = self.base_path / 'var/log/sa'
        if not sa_dir.is_dir():
            logging.warning(Color.warn(f"sar 데이터 디렉토리({sa_dir})를 찾을 수 없습니다. 텍스트 파일 파싱으로 대체합니다."))
            return self._parse_sar_data_from_text()

        report_day = self.report_date.day
        report_date_str = self.report_date.strftime('%Y%m%d')
        possible_filenames = [f"sa{report_day:02d}", f"sa{report_date_str}"]
        target_sar_file = next((sa_dir / fn for fn in possible_filenames if (sa_dir / fn).exists()), None)

        if not target_sar_file:
            logging.warning(Color.warn(f"날짜에 맞는 sar 바이너리 파일({', '.join(possible_filenames)})을(를) 찾을 수 없습니다. 텍스트 파일 파싱으로 대체합니다."))
            return self._parse_sar_data_from_text()

        logging.info(f"  - 사용할 sar 바이너리: {sar_binary_path}, 데이터 파일: {target_sar_file.name}")

        sar_options_map = {
            'cpu': '-u', 'memory': '-r', 'load': '-q', 'disk': '-b',
            'disk_detail': '-d', 'swap': '-S', 'network': '-n DEV', 'file_handler': '-v'
        }

        merged_data: Dict[str, List[Dict]] = {}
        for section, option in sar_options_map.items():
            logging.info(f"  -> '{section}' ({option}) 데이터 파싱 중...")
            section_data = self._parse_sar_section(sar_binary_path, target_sar_file, section, option)
            merged_data[section] = section_data

        text_data = self._parse_sar_data_from_text()
        for section, data in text_data.items():
            if section not in merged_data or not merged_data[section]:
                logging.info(f"  -> '{section}' 섹션 데이터를 텍스트 소스에서 보충합니다. (데이터 {len(data)}개)")
                merged_data[section] = data

        # [사용자 요청] 로그 상세화: 각 항목별 추출된 데이터 개수 출력
        summary = ", ".join([f"{key}: {len(value)}" for key, value in merged_data.items()])
        if summary:
            # [사용자 요청] 로그를 더 보기 쉽게 여러 줄로 출력
            logging.info(Color.info("SAR 데이터 파싱 완료. 수집된 데이터 포인트:"))
            for key, value in merged_data.items():
                logging.info(Color.info(f"  - {key}: {len(value)}개"))
        else:
            logging.warning(Color.warn("SAR 데이터 파싱 완료. 수집된 데이터 포인트가 없습니다."))

        for section, data in merged_data.items():
            if not data:
                logging.warning(Color.warn(f"  -> '{section}' 섹션에 대한 sar 데이터를 수집하지 못했습니다. 관련 그래프가 생성되지 않을 수 있습니다."))
        return merged_data

    def _find_sar_data_around_time(self, sar_section_data: List[Dict], target_dt: datetime.datetime, window_minutes: int = 2) -> Optional[Dict]:
        if not sar_section_data or not IS_PYTZ_AVAILABLE: return None
        closest_entry, min_delta = None, timedelta.max
        target_dt_utc = target_dt.astimezone(pytz.utc) if IS_PYTZ_AVAILABLE and target_dt.tzinfo else target_dt
        for entry in sar_section_data: # noqa: E501
            try:
                entry_dt = datetime.datetime.fromisoformat(entry['timestamp']); delta = abs(entry_dt - target_dt_utc)
                if delta < min_delta: min_delta, closest_entry = delta, entry
            except (ValueError, KeyError): continue
        return closest_entry.copy() if closest_entry and min_delta <= timedelta(minutes=window_minutes) else None

    def _analyze_logs_and_correlate_events(self, sar_data: Dict) -> Dict:
        logging.info("  - [7/8] 주요 로그 이벤트 분석 및 SAR 데이터와 연관 관계 분석 중...")
        log_content = self._read_file(['var/log/messages', 'var/log/syslog']); critical_events = []
        if log_content == 'N/A': return {"critical_log_events": []}
        for line in log_content.split('\n'):
            match = re.match(r'^([A-Za-z]{3}\s+\d{1-2}\s+\d{2}:\d{2}:\d{2})', line)
            if match:
                try: log_dt = datetime.datetime.strptime(f"{self.report_date.year} {match.group(1)}", '%Y %b %d %H:%M:%S')
                except ValueError: continue
                event_type, context = None, {}
                if 'i/o error' in line.lower():
                    event_type = "I/O Error"
                    if sar_context := self._find_sar_data_around_time(sar_data.get('disk', []), log_dt): context['sar_disk'] = sar_context
                elif 'out of memory' in line.lower():
                    event_type = "Out of Memory"
                    if sar_context := self._find_sar_data_around_time(sar_data.get('memory', []), log_dt): context['sar_memory'] = sar_context
                if event_type: critical_events.append({"event_type": event_type, "timestamp": log_dt.isoformat(), "log_message": line, "context": context})
        return {"critical_log_events": critical_events}

    def _analyze_performance_bottlenecks(self, sar_data: Dict) -> Dict:
        logging.info("  - [8/8] 성능 병목 현상 분석 중...")
        analysis = {}
        cpu_data = sar_data.get('cpu')
        if cpu_data:
            if high_iowait := [d for d in cpu_data if d.get('pct_iowait', 0) > 20]: analysis['io_bottleneck'] = f"CPU I/O Wait이 20%를 초과한 경우가 {len(high_iowait)}번 감지되었습니다."
        load_data = sar_data.get('load')
        if load_data:
            if self.cpu_cores_count > 0 and (high_load := [d for d in load_data if d.get('ldavg-5', 0) > self.cpu_cores_count * 1.5]): analysis['high_load_average'] = f"5분 평균 부하가 CPU 코어 수의 1.5배를 초과한 경우가 {len(high_load)}번 감지되었습니다."
        swap_data = sar_data.get('swap')
        if swap_data:
            if swap_data and (max_swap := max(d.get('pct_swpused',0) for d in swap_data)) > 10: analysis['swap_usage'] = f"최대 스왑 사용률이 {max_swap:.1f}%에 달했습니다."
        return analysis

    def _parse_and_patternize_logs(self) -> Dict[str, Any]:
        """
        [핵심 개선] /var/log/의 모든 로그를 지능적으로 패턴화하고, 발생 빈도 기반의 이상 탐지를 통해
        유의미한 로그만 추출하여 데이터 크기를 획기적으로 줄입니다.
        """
        log_step("2. 스마트 로그 분석 및 패턴화")
        log_dir = self.base_path / 'var/log'
        if not log_dir.is_dir():
            logging.warning(Color.warn(f"로그 디렉터리 '{log_dir}'를 찾을 수 없습니다. 스마트 로그 분석을 건너뜁니다."))
            return {}

        # [개선] 패턴 정규화 규칙을 강화하여 중복 제거 효율을 극대화합니다.
        PATTERNS_TO_NORMALIZE = [
            (re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d+)?\b'), '<IP_ADDRESS>'), # IPv4 주소 및 포트
            (re.compile(r'\[\s*\d+\.\d+\]'), '[<KNL_TIMESTAMP>]'), # 커널 타임스탬프
            (re.compile(r'\b([a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12})\b', re.IGNORECASE), '<UUID>'), # UUID
            (re.compile(r'pid\s*=\s*\d+'), 'pid=<PID>'), # "pid=" 형식
            (re.compile(r'\[\d+\]:'), '[<PID>]:'), # "[pid]:" 형식
            (re.compile(r'(\b[A-Za-z]{3}\s+\d{1,2}\s+)?\d{2}:\d{2}:\d{2}'), '<TIMESTAMP>'), # "HH:MM:SS" 형식의 시간
            (re.compile(r'\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?\b'), '<ISO_TIMESTAMP>'), # ISO 8601 타임스탬프
            (re.compile(r'0x[0-9a-fA-F]+'), '<HEX_ADDR>'), # 16진수 주소/값
            (re.compile(r'sd[a-z]\d*'), '<DEVICE>'), # 디스크 장치명 (sda, sdb1 등)
            (re.compile(r'session\s\d+'), 'session <SESSION_ID>'), # 세션 ID
            # [사용자 요청] Pacemaker/Corosync 관련 패턴 추가
            (re.compile(r'pengine-[0-9]+'), 'pengine-<PID>'),
            (re.compile(r'cib-[0-9]+'), 'cib-<PID>'),
            (re.compile(r'crmd-[0-9]+'), 'crmd-<PID>'),
            (re.compile(r'pacemaker-schedulerd\[\d+\]'), 'pacemaker-schedulerd[<PID>]'),
            (re.compile(r'pacemaker-controld\[\d+\]'), 'pacemaker-controld[<PID>]'),
            (re.compile(r'pacemaker-execd\[\d+\]'), 'pacemaker-execd[<PID>]'),
            (re.compile(r'stonith-ng-[0-9]+'), 'stonith-ng-<PID>'),
            (re.compile(r'corosync\[\d+\]'), 'corosync[<PID>]'),
            (re.compile(r'pacemakerd\[\d+\]'), 'pacemakerd[<PID>]'),
            (re.compile(r'transition [0-9]+'), 'transition <ID>'),
            # [사용자 요청] DRBD 관련 로그 패턴 추가
            (re.compile(r'drbd\s+[\w_]+/\d+\s+drbd\d+'), 'drbd <RESOURCE>/<VOL> <DEVICE>'),
            (re.compile(r'drbd\s+[\w_]+:'), 'drbd <RESOURCE>:'),
            (re.compile(r'drbd\s+[\w_]+\s+[\w\d_]+:'), 'drbd <RESOURCE> <PEER_HOST>:'),
            (re.compile(r'conn\(\s*[\w\s]+->\s*[\w\s]+\s*\)'), 'conn(<STATE> -> <STATE>)'),
            (re.compile(r'disk\(\s*[\w\s]+->\s*[\w\s]+\s*\)'), 'disk(<STATE> -> <STATE>)'),
            (re.compile(r'peer\(\s*[\w\s]+->\s*[\w\s]+\s*\)'), 'peer(<STATE> -> <STATE>)'),
            (re.compile(r'pdsk\(\s*[\w\s]+->\s*[\w\s]+\s*\)'), 'pdsk(<STATE> -> <STATE>)'),
            (re.compile(r'repl\(\s*[\w\s]+->\s*[\w\s]+\s*\)'), 'repl(<STATE> -> <STATE>)'),
            (re.compile(r'role\(\s*[\w\s]+->\s*[\w\s]+\s*\)'), 'role(<STATE> -> <STATE>)'),
            (re.compile(r'([0-9a-fA-F]{16}:){3}[0-9a-fA-F]{16}'), '<DRBD_UUID_CHAIN>'),
            (re.compile(r'\b[0-9a-fA-F]{16}\b'), '<DRBD_UUID>'),
            (re.compile(r'version\s\d+\s'), 'version <NUM> '),
            (re.compile(r'capacity\s*==\s*\d+'), 'capacity == <NUM>'),
            (re.compile(r'size\s*=\s*[\d.]+\s*\w+\s*\([\d.]+\s*\w+\)'), 'size = <SIZE>'),
            (re.compile(r'agreed network protocol version\s+\d+'), 'agreed network protocol version <VERSION>'),
            (re.compile(r'state change\s+\d+'), 'state change <ID>'),
            (re.compile(r't=\d+'), 't=<TID>'),
            (re.compile(r'call=\d+'), 'call=<CALL_ID>'),
            # [사용자 요청] DRBD 관련 패턴 추가
            (re.compile(r'drbd \d+'), 'drbd <RES_ID>'),
        ]

        # 1. 모든 로그 라인을 읽어 패턴화하고 빈도수 계산
        all_patterns = Counter()
        pattern_examples = {} # 각 패턴의 첫 번째 원본 로그 예시 저장
        log_files = [f for f in log_dir.iterdir() if f.is_file() and f.stat().st_size > 0]

        for log_file in log_files:
            if any(log_file.name.endswith(ext) for ext in ['.gz', '.xz', '.bz2', 'lastlog', 'wtmp', 'btmp']):
                continue
            try:
                content = log_file.read_text(encoding='utf-8', errors='ignore')
                for line in content.split('\n'):
                    if not line.strip(): continue
                    
                    normalized_pattern = line
                    for regex, placeholder in PATTERNS_TO_NORMALIZE:
                        normalized_pattern = regex.sub(placeholder, normalized_pattern)
                    
                    final_pattern = re.sub(r'\s+', ' ', normalized_pattern).strip()
                    
                    # 패턴과 파일명을 함께 키로 사용하여 파일별로 그룹화
                    pattern_key = (log_file.name, final_pattern)
                    all_patterns[pattern_key] += 1
                    if pattern_key not in pattern_examples:
                        pattern_examples[pattern_key] = line # 원본 로그 예시 저장
            except Exception as e:
                logging.warning(f"  - 로그 파일 '{log_file.name}' 처리 중 오류 발생: {e}")

        # 2. 빈도수 기반으로 유의미한 로그 필터링
        smart_log_analysis = {}
        ANOMALY_THRESHOLD = 5
        # [사용자 요청] HA 및 DRBD 관련 키워드 추가
        ERROR_KEYWORDS = re.compile( # [개선] Pacemaker 오류를 더 잘 탐지하기 위해 키워드 추가
            r'\b(error|failed|failure|critical|panic|denied|segfault|stonith|fencing|fence|split-brain|standby|primary|secondary|sync|failover|quorum|unfenced|inconsistent|timed out|target is busy|unexpected|couldn\'t)\b',
            re.IGNORECASE)

        for (filename, pattern), count in all_patterns.items():
            # 희귀 패턴(Anomaly)이거나, 자주 발생하지만 오류 키워드를 포함하는 패턴(Error Storm)만 선택
            if count <= ANOMALY_THRESHOLD or ERROR_KEYWORDS.search(pattern):
                if filename not in smart_log_analysis:
                    smart_log_analysis[filename] = []
                smart_log_analysis[filename].append({
                    "pattern": pattern,
                    "count": count,
                    "example": pattern_examples[(filename, pattern)]
                })

        # 파일별로 count 기준으로 정렬
        for filename in smart_log_analysis:
            smart_log_analysis[filename].sort(key=lambda x: x['count'], reverse=True)

        logging.info(Color.info(f"스마트 로그 분석 완료. {len(smart_log_analysis)}개 파일에서 유의미한 로그 패턴 추출."))
        return {"smart_log_analysis": smart_log_analysis}

    def parse_all(self) -> tuple[Dict[str, Any], Dict[str, Any]]:
        log_step("1단계: 로컬 데이터 파싱 및 분석")
        metadata = { "system_info": self._parse_system_details(), "storage": self._parse_storage(), "processes": self._parse_process_stats(), "network": self._parse_network_details(), **self._parse_additional_info() }
        sar_data = self._parse_sar_data()
        log_analysis = self._analyze_logs_and_correlate_events(sar_data); perf_analysis = self._analyze_performance_bottlenecks(sar_data)
        smart_log_analysis = self._parse_and_patternize_logs() # [신규] 스마트 로그 분석 호출
        metadata.update(log_analysis)
        metadata.update(smart_log_analysis) # [신규] 스마트 로그 분석 결과를 메타데이터에 추가
        metadata["performance_analysis"] = perf_analysis # 분석 결과를 메타데이터에 추가
        logging.info(Color.success("\n로컬 데이터 파싱 및 분석 완료."))
        return metadata, sar_data
class HTMLReportGenerator:
    def __init__(self, metadata: Dict, sar_data: Dict, ai_analysis: Dict, hostname: str, report_date: datetime.datetime, device_map: Dict):
        self.metadata, self.sar_data, self.ai_analysis, self.hostname = metadata, sar_data, ai_analysis, hostname
        self.report_date = report_date
        self.device_map = device_map # [BUG FIX] device_map을 클래스 속성으로 초기화합니다.

    def _generate_graphs(self) -> Dict[str, Any]:
        """[안정성 강화] 재시도 로직을 적용하여 각 그래프를 생성합니다."""
        if not IS_GRAPHING_ENABLED: return {}
        if not IS_PLOTLY_AVAILABLE: logging.warning(Color.warn("  - Plotly 라이브러리가 없어 그래프 생성을 건너뜁니다.")); return {}
        log_step("그래프 생성 시작")
        graphs, sar = {'static': {}, 'interactive': {}}, self.sar_data

        graph_tasks = [
            ('cpu', 'CPU Usage', self._generate_cpu_graph, ()),
            ('memory', 'Memory Usage', self._generate_memory_graph, ()),
            ('load', 'System Load Average', self._generate_load_graph, ()),
            ('disk_detail', 'Block Device I/O', self._generate_disk_detail_graph, ()),
            ('io_usage', 'I/O Usage', self._generate_io_usage_graph, ()),
            ('swap', 'Swap Usage', self._generate_swap_graph, ()),
            ('network_representative', 'Network Traffic', self._generate_network_graph, ()),
            ('file_handler', 'File Handler', self._generate_file_handler_graph, ()),
        ]

        # [효율성 제안] 그래프 생성을 병렬로 처리
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_key = {executor.submit(self._retry_on_failure, task_func, name, *args): key for key, name, task_func, args in graph_tasks}
            for future in as_completed(future_to_key):
                key = future_to_key[future]
                try:
                    graphs[key] = future.result()
                except Exception as exc:
                    logging.error(f"  - '{key}' 그래프 생성 중 예외 발생: {exc}")

        return graphs

    def _retry_on_failure(self, func, name: str, *args, max_retries: int = 3):
        """[신규] 함수 실행 실패 시 재시도하는 래퍼. 그래프 생성에 사용됩니다."""
        for attempt in range(max_retries):
            try:
                logging.info(Color.info(f"  - 그래프 생성 중: {name}"))
                result = func(*args) # type: ignore
                # 그래프 생성이 성공했지만 데이터가 없어 None을 반환한 경우, 재시도 없이 종료
                if result is None and attempt == 0:
                    return None
                # 성공 시 결과 반환
                return result
            except Exception as e:
                logging.warning(f"'{name}' 그래프 생성 실패 (시도 {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt  # 1, 2초 대기
                    logging.info(f"  -> {wait_time}초 후 재시도합니다...")
                    time.sleep(wait_time)
                else:
                    logging.error(Color.error(f"  - '{name}' 그래프 생성이 {max_retries}번의 시도 후에도 최종 실패했습니다."))
                    traceback.print_exc(limit=1)
        return None # 모든 재시도 실패

    # --- 그래프 생성 로직을 별도 함수로 분리 ---
    def _generate_cpu_graph(self):
        return self._create_hybrid_plot(self.sar_data.get('cpu'), 'CPU Usage (%)', {'pct_user': 'User', 'pct_system': 'System', 'pct_iowait': 'I/O Wait', 'pct_idle': 'Idle'}, is_stack=True, is_percentage=True)

    def _generate_memory_graph(self):
        return self._create_hybrid_plot(self.sar_data.get('memory'), 'Memory Usage (KB)', {'kbmemused': 'Used', 'kbmemfree': 'Free', 'kbbuffers': 'Buffers', 'kbcached': 'Cached'})

    def _generate_load_graph(self):
        load_data = self.sar_data.get('load')
        # [개선] 데이터가 부족하여 그래프를 생성하지 못하는 경우, 명확한 경고 로그를 추가합니다.
        if not load_data or len(load_data) < 2:
            logging.warning(Color.warn("  - 경고: 'load' 데이터가 부족하여 Load Average 그래프를 생성할 수 없습니다."))
            return None
        load_labels = {'load_1': '1-min', 'load_5': '5-min', 'load_15': '15-min'} # [BUG FIX] is_percentage 추가
        return self._create_hybrid_plot(load_data, 'System Load Average', load_labels, is_stack=False, y_axis_title="Load", is_percentage=False)

    def _find_representative_disk(self) -> Optional[str]:
        """
        [신규] 루트('/') 파일시스템에 해당하는 대표 블록 디바이스의 sar 장치명(예: dev253-0)을 찾습니다.
        1. df 정보에서 루트 파일시스템의 장치명(예: rhel-root)을 찾습니다.
        2. dmsetup 정보에서 Major, Minor 번호를 찾습니다.
        3. sar에서 사용하는 dev<Major>-<Minor> 형식의 장치명을 반환합니다.
        """
        root_fs_info = next((s for s in self.metadata.get('storage', []) if s.get('mounted_on') == '/'), None)
        if not (root_fs_info and root_fs_info.get('filesystem')):
            return None

        # 1. df에서 장치명 추출 (예: /dev/mapper/rhel-root -> rhel-root)
        df_device_name = os.path.basename(root_fs_info.get('filesystem'))

        # 2. dmsetup 정보에서 Major, Minor 번호 찾기
        dmsetup_info = self.metadata.get('configurations', {}).get('dmsetup_info', '')
        # 정규식: 라인 시작, 장치명, 하나 이상의 공백, Major, 콜론, Minor
        # 예: "rhel-root        253   0 L--w..." -> ('253', '0')
        maj_min_match = re.search(rf'^{re.escape(df_device_name)}\s+(\d+)\s+(\d+)', dmsetup_info, re.MULTILINE)

        if maj_min_match:
            major, minor = maj_min_match.groups()
            # 3. sar 장치명 형식으로 조합하여 반환 (예: dev253-0)
            return f"dev{major}-{minor}"
        
        # LVM이 아닌 일반 파티션(예: /dev/sda1)의 경우, df_device_name을 그대로 사용
        # sar 데이터에 'sda1'과 같은 이름이 있는지 확인
        # [BUG FIX] 'device_name' 대신 'DEV' 필드를 사용해야 합니다.
        all_sar_devices = {d.get('DEV') for d in self.sar_data.get('disk_detail', [])}
        if df_device_name in all_sar_devices:
            logging.info(f"  - Found representative disk for root filesystem ('/'): {df_device_name}")
            return df_device_name

        return None

    def _generate_disk_detail_graph(self):
        disk_detail_data = self.sar_data.get('disk_detail', []) or []
        if not disk_detail_data or len(disk_detail_data) < 2:
            logging.warning(Color.warn("  - 경고: 'disk_detail' 데이터가 부족하여 Block Device I/O 그래프를 생성할 수 없습니다."))
            return None

        # [사용자 요청 반영] 루트('/') 파일시스템의 sar 장치명을 찾는 로직 개선
        # [수정] _find_representative_disk 함수를 호출하여 대표 디바이스를 찾습니다.
        root_device_name = self._find_representative_disk()
        representative_disk_data = []
        if root_device_name:
            representative_disk_data = [d for d in disk_detail_data if d.get('DEV') == root_device_name]
        if representative_disk_data:
            # [사용자 요청] dev{major}-{minor}를 문자 장치명으로 변환
            major, minor = root_device_name[3:].split('-')
            display_name = self.device_map.get(f"{major}:{minor}", root_device_name)
            logging.info(f"  - 대표 블록 장치 '{display_name}'(from {root_device_name})의 I/O 그래프를 생성합니다.")
            title = f"Block Device I/O - {display_name} (Rep.)"
            static_title = f"Block Device I/O - {display_name}"
            # [수정] rd_sec_s/wr_sec_s 대신 rkB_s/wkB_s를 사용하고 await를 함께 표시
            labels = {'rkB_s': 'Read kB/s', 'wkB_s': 'Write kB/s', 'await': 'await (ms)'}
            return self._create_hybrid_plot(representative_disk_data, title, labels, is_stack=False, y_axis_title='Value', static_title=static_title, is_percentage=False)
        else:
            # [수정] 대표 장치를 찾지 못하면 모든 장치의 데이터를 합산하여 그래프를 생성합니다.
            logging.info("  - 대표 블록 장치를 찾지 못했습니다. 모든 장치의 I/O 데이터를 합산하여 그래프를 생성합니다.")
            aggregated_data = {}
            for d in disk_detail_data:
                ts = d['timestamp']
                if ts not in aggregated_data:
                    # [수정] await 항목 추가
                    aggregated_data[ts] = {'timestamp': ts, 'rkB_s': 0, 'wkB_s': 0, 'await': 0}
                # [BUG FIX] _safe_float를 사용하여 안전하게 숫자 변환
                aggregated_data[ts]['rkB_s'] += self._safe_float(d.get('rkB_s', 0)) # type: ignore
                aggregated_data[ts]['wkB_s'] += self._safe_float(d.get('wkB_s', 0)) # type: ignore
                aggregated_data[ts]['await'] += self._safe_float(d.get('await', 0)) # type: ignore
            
            aggregated_list = list(aggregated_data.values())
            if len(aggregated_list) >= 2:
                labels = {'rkB_s': 'Total Read kB/s', 'wkB_s': 'Total Write kB/s', 'await': 'Avg await (ms)'}
                return self._create_hybrid_plot(aggregated_list, 'Total Block Device I/O (All Devices)', labels, is_stack=False, y_axis_title='Value', static_title='Total Block Device I/O', is_percentage=False) # type: ignore
            return None

    def _generate_io_usage_graph(self):
        disk_data = self.sar_data.get('disk')
        # [개선] 데이터가 부족하여 그래프를 생성하지 못하는 경우, 명확한 경고 로그를 추가합니다.
        if not disk_data or len(disk_data) < 2: # type: ignore
            logging.warning(Color.warn("  - 경고: 'disk' 데이터가 부족하여 I/O Usage 그래프를 생성할 수 없습니다."))
            return None
        if disk_data[0].get('bread_s') is not None: # type: ignore
            return self._create_hybrid_plot(disk_data, 'I/O Usage (blocks/s)', {'bread_s': 'Read Blocks/s', 'bwrtn_s': 'Write Blocks/s'}, is_stack=False, is_percentage=False)
        else:
            logging.info("  - 'bread_s' 데이터를 찾을 수 없어 'tps' 기준으로 I/O Usage 그래프를 생성합니다.")
            return self._create_hybrid_plot(disk_data, 'I/O Usage (transactions/s)', {'tps': 'Transactions/s'}, is_stack=False, is_percentage=False)

    def _generate_swap_graph(self):
        swap_data = self.sar_data.get('swap')
        if not swap_data: return None
        return self._create_hybrid_plot(swap_data, 'Swap Usage (%)', {'pct_swpused': 'Used %'}, is_percentage=True)

    def _generate_network_graph(self):
        network_data = self.sar_data.get('network')
        # [개선] 데이터가 부족하여 그래프를 생성하지 못하는 경우, 명확한 경고 로그를 추가합니다.
        if not network_data or len(network_data) < 2:
            logging.warning(Color.warn("  - 경고: 'network' 데이터가 부족하여 Network Traffic 그래프를 생성할 수 없습니다."))
            return None
        
        net_by_iface = {}; [net_by_iface.setdefault(d.get('IFACE'), []).append(d) for d in network_data if d.get('IFACE')]
        up_interfaces_info = [iface for iface in self.metadata.get('network', {}).get('interfaces', []) if iface.get('state') == 'up']
        # [BUG FIX] 'UP' 상태인 인터페이스와 sar 데이터에 기록된 모든 인터페이스를 함께 고려하여 대표 인터페이스를 찾습니다.
        up_interface_names = {iface['iface'] for iface in up_interfaces_info if 'iface' in iface}
        all_possible_ifaces = sorted(list(up_interface_names.union(net_by_iface.keys())))

        # [요청 반영] bond0가 있고 UP 상태이면 우선 사용, 아니면 UP 상태인 첫번째 인터페이스 사용
        is_bond0_up = 'bond0' in up_interface_names
        representative_iface = 'bond0' if is_bond0_up else next((iface['iface'] for iface in up_interfaces_info if iface.get('iface') in all_possible_ifaces), None)

        if representative_iface and representative_iface in net_by_iface and len(net_by_iface.get(representative_iface, [])) >= 2:
            logging.info(f"  - 대표 네트워크 인터페이스 '{representative_iface}'의 트래픽 그래프를 생성합니다.")
            data = net_by_iface[representative_iface]
            if any('rxkB_s' in d or 'txkB_s' in d for d in data):
                title = f'Network Traffic - {representative_iface} (Rep.)'
                static_title = f'Network Traffic - {representative_iface} (Rep.)'
                return self._create_hybrid_plot(data, title, {'rxkB_s': 'RX kB/s', 'txkB_s': 'TX kB/s'}, y_axis_title='kB/s', static_title=static_title, is_percentage=False)
        else:
            # [해결책 제안 반영] 대표 인터페이스가 없으면 'lo'를 제외한 모든 인터페이스의 트래픽을 합산합니다.
            logging.info("  - 대표 네트워크 인터페이스를 찾지 못했습니다. 모든 인터페이스('lo' 제외)의 트래픽을 합산합니다.")
            aggregated_data = {}
            for iface, data in net_by_iface.items():
                if iface == 'lo': continue
                for d in data:
                    ts = d['timestamp']
                    if ts not in aggregated_data:
                        aggregated_data[ts] = {'timestamp': ts, 'rxkB_s': 0, 'txkB_s': 0}
                    aggregated_data[ts]['rxkB_s'] += self._safe_float(d.get('rxkB_s', 0))
                    aggregated_data[ts]['txkB_s'] += self._safe_float(d.get('txkB_s', 0))
            aggregated_list = list(aggregated_data.values())
            if len(aggregated_list) >= 2:
                return self._create_hybrid_plot(aggregated_list, 'Total Network Traffic (All Interfaces)', {'rxkB_s': 'Total RX kB/s', 'txkB_s': 'Total TX kB/s'}, y_axis_title='kB/s', static_title='Total Network Traffic', is_percentage=False)
            return None

    def _generate_file_handler_graph(self):
        file_handler_data = self.sar_data.get('file_handler')
        if not file_handler_data: return None
        return self._create_hybrid_plot(file_handler_data, 'File and Inode Handlers', {'file_nr': 'File Handlers', 'inode_nr': 'Inode Handlers'}, is_stack=False)

    def _generate_individual_disk_graphs_page(self, sar_data: Dict) -> Optional[str]:
        """[수정] 개별 디스크 장치에 대한 상세 I/O 그래프 HTML 페이지를 생성합니다. 메인 리포트와 동일하게 정적 이미지와 팝업 동적 그래프를 모두 생성합니다."""
        if not IS_PLOTLY_AVAILABLE or 'disk_detail' not in sar_data:
            return None

        disk_detail_data = sar_data['disk_detail']
        # [추가] 생성된 동적 그래프 HTML을 별도 파일로 저장하기 위한 딕셔너리
        popup_files_to_create: Dict[str, str] = {}
        graphs_by_dev = {}
        
        # 장치별로 데이터 그룹화
        dev_data = {}
        for entry in disk_detail_data:
            original_dev_name = entry.get('DEV')
            if not original_dev_name:
                continue

            # [사용자 요청] dev{major}-{minor} 형식의 장치명을 문자 형태의 장치명으로 변환
            display_name = original_dev_name
            if original_dev_name.startswith('dev') and '-' in original_dev_name:
                major, minor = original_dev_name[3:].split('-')
                display_name = self.device_map.get(f"{major}:{minor}", original_dev_name)
            
            dev_data.setdefault(display_name, []).append(entry)

        # 각 장치에 대해 그래프 생성
        for dev_name, data in dev_data.items():
            if len(data) < 2: continue # 데이터가 너무 적으면 건너뛰기
            # [수정] 메인 리포트와의 일관성을 위해 그래프를 2개로 통합합니다.
            graphs_by_dev[dev_name] = {
                'tps': self._create_hybrid_plot(data, f'Transactions per second ({dev_name})', {'tps': 'TPS'}, is_stack=False, is_percentage=False),
                # [수정] I/O 처리량과 대기 시간을 하나의 그래프에 표시합니다.
                'io': self._create_hybrid_plot(data, f'I/O Throughput & Wait ({dev_name})', {'rkB_s': 'Read kB/s', 'wkB_s': 'Write kB/s', 'await': 'await (ms)'}, is_stack=False, y_axis_title='Value', is_percentage=False),
            }

        # HTML 페이지 생성
        graph_html_parts = []
        for dev_name, graphs in graphs_by_dev.items():
            graph_html_parts.append(f'<div class="device-section"><h2>Device: {dev_name}</h2><div class="graph-grid">')
            for graph_key, graph_tuple in graphs.items():
                if graph_tuple and isinstance(graph_tuple, tuple) and len(graph_tuple) == 2:
                    base64_png, interactive_html = graph_tuple
                    
                    # 팝업 파일 이름 생성 및 저장할 내용 추가
                    popup_filename = f"popup_disk_{dev_name}_{graph_key}_{self.hostname}.html"
                    if interactive_html:
                        popup_files_to_create[popup_filename] = interactive_html

                    # HTML 본문 생성
                    if base64_png:
                        graph_html = f'<img src="data:image/png;base64,{base64_png}" alt="{dev_name} {graph_key}" style="width:100%; cursor:pointer;" onclick="openGraphPopup(\'{popup_filename}\')">'
                    elif interactive_html: # 정적 이미지가 없을 경우 동적 그래프를 직접 표시
                        graph_html = f'<div class="graph-container">{interactive_html}</div>'
                    else:
                        graph_html = '<p class="no-data-message">그래프 데이터 없음</p>'
                    
                    graph_html_parts.append(f'<div class="graph-container">{graph_html}</div>')

            graph_html_parts.append('</div></div>')

        # [수정] openGraphPopup 스크립트 추가
        html_content = f"""<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><title>Block Device I/O Details</title><style>
            body {{ font-family: sans-serif; background-color: #f0f2f5; margin: 0; padding: 2rem; }}
            h1 {{ text-align: center; color: #333; }}
            .device-section {{ background: #fff; border-radius: 8px; margin-bottom: 2rem; padding: 1.5rem; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
            .device-section h2 {{ margin-top: 0; border-bottom: 1px solid #eee; padding-bottom: 1rem; }}
            .graph-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(500px, 1fr)); gap: 1.5rem; }}
            .graph-container {{ min-height: 400px; border: 1px solid #ddd; border-radius: 8px; padding: 1rem; }}
            .no-data-message {{ text-align: center; color: #888; padding: 2rem; }}
            </style><script>function openGraphPopup(filename) {{ window.open(filename, 'GraphPopup', 'width=1200,height=600,scrollbars=yes,resizable=yes'); }}</script></head><body><h1>Block Device I/O Details</h1>{''.join(graph_html_parts)}</body></html>"""
        
        return html_content, popup_files_to_create

    def _generate_individual_nic_graphs_page(self, sar_data: Dict, metadata: Dict) -> Optional[str]:
        """[신규] 개별 NIC에 대한 상세 그래프 HTML 페이지를 생성합니다."""
        if not IS_PLOTLY_AVAILABLE or 'network' not in sar_data:
            return None

        net_by_iface = {}; [net_by_iface.setdefault(d.get('IFACE'), []).append(d) for d in sar_data['network'] if d.get('IFACE')]
        up_interfaces_info = [iface for iface in metadata.get('network', {}).get('interfaces', []) if iface.get('state') == 'up']
        up_interface_names = sorted([iface['iface'] for iface in up_interfaces_info if 'iface' in iface])

        # [추가] 생성된 동적 그래프 HTML을 별도 파일로 저장하기 위한 딕셔너리
        popup_files_to_create: Dict[str, str] = {}
        graphs_by_nic = {}
        for iface in up_interface_names:
            if iface in net_by_iface:
                data = net_by_iface[iface]
                if len(data) > 1:
                    graphs_by_nic[iface] = self._create_hybrid_plot(data, f'Network Traffic - {iface}', {'rxkB_s': 'RX kB/s', 'txkB_s': 'TX kB/s'}, is_stack=False, y_axis_title='kB/s', is_percentage=False)

        graph_html_parts = []
        for nic_name, graph_tuple in graphs_by_nic.items():
            if graph_tuple and isinstance(graph_tuple, tuple) and len(graph_tuple) == 2:
                base64_png, interactive_html = graph_tuple
                
                popup_filename = f"popup_nic_{nic_name}_{self.hostname}.html"
                if interactive_html:
                    popup_files_to_create[popup_filename] = interactive_html

                if base64_png:
                    graph_html = f'<img src="data:image/png;base64,{base64_png}" alt="Network Traffic {nic_name}" style="width:100%; cursor:pointer;" onclick="openGraphPopup(\'{popup_filename}\')">'
                elif interactive_html:
                    graph_html = f'<div class="graph-container">{interactive_html}</div>'
                else:
                    graph_html = '<p class="no-data-message">그래프 데이터 없음</p>'
                
                graph_html_parts.append(f'<div class="nic-section">{graph_html}</div>')

        html_content = f"""<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><title>Network Interface Details</title><style>
            body {{ font-family: sans-serif; background-color: #f0f2f5; margin: 0; padding: 2rem; }} h1 {{ text-align: center; color: #333; }}
            .nic-section {{ background: #fff; border-radius: 8px; margin-bottom: 2rem; padding: 1.5rem; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
            .graph-container {{ min-height: 400px; }}
            .no-data-message {{ text-align: center; color: #888; padding: 2rem; }}
             </style><script>function openGraphPopup(filename) {{ window.open(filename, 'GraphPopup', 'width=1200,height=600,scrollbars=yes,resizable=yes'); }}</script></head><body><h1>Network Interface Details</h1>{''.join(graph_html_parts)}</body></html>"""
        
        return html_content, popup_files_to_create

    def _create_hybrid_plot(self, data: Optional[List[Dict]], title: str, labels: Dict[str, str], is_stack: bool = False, y_axis_title: str = "Value", static_title: Optional[str] = None, is_percentage: bool = False):
        """[대체 구현] Matplotlib과 Plotly를 사용하여 하이브리드 그래프(정적+동적)를 생성합니다."""
        # [해결책 제안 반영] 데이터가 없거나, 유효한 데이터 포인트가 2개 미만이면 그래프를 생성하지 않습니다.
        if not data or not isinstance(data, list) or len(data) < 2 or not IS_GRAPHING_ENABLED:
            return (None, None)
        
        # [해결책 제안 반영] 그래프를 그릴 키가 데이터에 하나라도 존재하는지 확인합니다.
        # [정확성 제안] 데이터 완전성 체크: 50% 이상 데이터가 누락된 경우 그래프 생성 건너뛰기
        valid_points = sum(1 for d in data if any(key in d for key in labels))
        if valid_points < len(data) * 0.5:
            logging.warning(Color.warn(f"  - 경고: '{title}' 그래프는 데이터의 50% 이상이 누락되어 생성되지 않습니다."))
            return (None, None)

        has_data_to_plot = any(key in data[0] for key in labels.keys())
        if not has_data_to_plot:
            return (None, None)
            
        if 'Swap Usage' in title and data and 'pct_swpused' not in data[0]:
            for entry in data:
                total = entry.get('kbswptot', 0)
                used = entry.get('kbswpused', 0)
                if total > 0 and used >= 0:
                    entry['pct_swpused'] = (used / total) * 100
                # kbswptot가 없는 구버전 sar의 경우
                elif 'kbswpfree' in entry and 'kbswpused' in entry:
                    total_fallback = entry['kbswpfree'] + entry['kbswpused']
                    if total_fallback > 0:
                        entry['pct_swpused'] = (entry['kbswpused'] / total_fallback) * 100

        # [안정성 강화] 정적/동적 그래프 생성을 독립적으로 분리하여 한쪽의 실패가 다른 쪽에 영향을 주지 않도록 합니다.
        static_img_b64 = None
        if IS_MATPLOTLIB_AVAILABLE:
            try:
                title_for_static = static_title if static_title else title
                title_for_static_eng = re.sub(r'[가-힣()]', '', title_for_static).strip()
                static_img_b64 = self._create_static_plot_matplotlib(data, title_for_static_eng, labels, is_stack, y_axis_title, is_percentage=is_percentage)
            except Exception as e:
                logging.warning(f"  - 경고: '{title}'의 정적 이미지(matplotlib) 생성 실패: {e}. 동적 그래프만 사용합니다.")
                static_img_b64 = None

        interactive_html = None
        if IS_PLOTLY_AVAILABLE:
            try:
                interactive_html = self._create_plot_plotly(data, title, labels, is_stack, y_axis_title, is_percentage=is_percentage)
            except Exception as e:
                logging.warning(f"  - 경고: '{title}'의 동적 그래프(plotly) 생성 실패: {e}. 정적 이미지를 대체로 사용합니다.")
                interactive_html = None

        return (static_img_b64, interactive_html)

    def _create_static_plot_matplotlib(self, data: Optional[List[Dict]], title: str, labels: Dict[str, str], is_stack: bool = False, y_axis_title: str = "Value", is_percentage: bool = False) -> Optional[str]:
        """[사용자 요청] Matplotlib을 사용하여 정적 PNG 이미지를 생성합니다. 모든 텍스트를 영문으로 처리하여 한글 깨짐을 방지합니다."""
        # [해결책 제안 반영] 데이터 유효성 검사 강화
        if not data or not isinstance(data, list) or len(data) < 2 or not IS_MATPLOTLIB_AVAILABLE:
            return None
        if not any(key in data[0] for key in labels):
            return None

        # [정확성 제안] 타임존 정보가 포함된 ISO 포맷의 타임스탬프를 파싱합니다.
        timestamps = []
        for d in data:
            if 'timestamp' in d:
                timestamps.append(datetime.datetime.fromisoformat(d['timestamp']))
        if not timestamps: return None

        fig, ax = plt.subplots(figsize=(10, 5))
        
        all_values = []
        plot_labels = []
        plot_labels_eng = []
        for key, label in labels.items():
            values = [self._safe_float(d.get(key, 0)) for d in data]
            all_values.append(values)
            plot_labels.append(label)
            plot_labels_eng.append(re.sub(r'[가-힣/()]', '', label).strip()) # [수정] 한글과 슬래시(/)를 제거하여 영문 레이블 생성
            
        if is_stack:
            # CPU Usage의 Idle은 스택에서 제외
            idle_index = -1
            if 'pct_idle' in labels and 'CPU Usage' in title:
                idle_index = list(labels.keys()).index('pct_idle')
            
            stack_values = [v for i, v in enumerate(all_values) if i != idle_index]
            stack_labels = [l for i, l in enumerate(plot_labels) if i != idle_index]
            ax.stackplot(timestamps, stack_values, labels=plot_labels_eng, alpha=0.8)

            if idle_index != -1:
                ax.plot(timestamps, all_values[idle_index], label=plot_labels_eng[idle_index], linewidth=2.5)
        else:
            for values, label in zip(all_values, plot_labels_eng):
                ax.plot(timestamps, values, label=label, linewidth=2.5)

        ax.set_title(title, fontsize=14, loc='left', pad=20)
        ax.set_ylabel(re.sub(r'[가-힣/()]', '', y_axis_title).strip()) # [수정] Y축 레이블도 영문으로 변경
        # [사용자 요청] 백분율 그래프의 Y축 범위를 0-100으로 고정합니다.
        if is_percentage:
            ax.set_ylim(0, 100)

        ax.grid(True, linestyle='--', alpha=0.6) # [수정] 범례 위치 조정
        ax.legend(loc='upper right', bbox_to_anchor=(1, 1.18), ncol=len(labels)//2 or 1)
        fig.tight_layout(rect=[0, 0, 1, 0.93])

        buf = io.BytesIO()
        fig.savefig(buf, format='png', dpi=90)
        plt.close(fig)
        buf.seek(0)
        return base64.b64encode(buf.getvalue()).decode('utf-8')

    def _create_plot_plotly(self, data: Optional[List[Dict]], title: str, labels: Dict[str, str], is_stack: bool = False, y_axis_title: str = "Value", is_percentage: bool = False) -> Optional[str]:
        """[기능 유지] Plotly를 사용하여 동적/상호작용 그래프 HTML을 생성합니다."""
        # [해결책 제안 반영] 데이터 유효성 검사 강화
        if not data or not isinstance(data, list) or len(data) < 2 or not IS_PLOTLY_AVAILABLE:
            return None
        
        # 데이터 포인트에 labels에 지정된 키 중 하나라도 포함되어 있는지 확인
        if not any(key in data[0] for key in labels):
            return None

        # [정확성 제안] 타임존 정보가 포함된 ISO 포맷의 타임스탬프를 파싱합니다.
        timestamps = []
        for d in data:
            if 'timestamp' in d:
                timestamps.append(datetime.datetime.fromisoformat(d['timestamp']))

        fig = go.Figure()
        
        # 세련된 색상 팔레트
        colors = ['#007bff', '#17a2b8', '#28a745', '#ffc107', '#dc3545', '#6c757d']

        for i, (key, label) in enumerate(labels.items()):
            values = [self._safe_float(d.get(key, 0)) for d in data]
            
            # [사용자 요청] CPU 그래프의 'Idle' 항목은 배경색 없이 라인만 표시
            is_idle_trace = (key == 'pct_idle' and 'CPU Usage' in title)
            
            trace_args = {
                "x": timestamps,
                "y": values,
                "name": label,
                "mode": 'lines',
                "line": dict(width=2.5, color=colors[i % len(colors)]),
                # 마우스 호버 시 표시될 정보 맞춤 설정합니다.
                "hovertemplate": f'<b>{label}</b><br>%{{x|%H:%M:%S}}<br>%{{y:.2f}}<extra></extra>'
            }

            if is_stack and not is_idle_trace:
                trace_args['stackgroup'] = 'one'

            fig.add_trace(go.Scatter(**trace_args))

        fig.update_layout(
            title=dict(text=f'<b>{title}</b>', x=0.5, font=dict(size=18)),
            xaxis_title=None,
            yaxis_title=y_axis_title,
            # [사용자 요청] 백분율 그래프의 Y축 범위를 0-100으로 고정합니다.
            yaxis=dict(
                range=[0, 100] if is_percentage else None,
                title=y_axis_title
            ),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            margin=dict(l=50, r=30, t=80, b=50),
            hovermode="x unified", # x축 기준으로 모든 데이터 표시
            plot_bgcolor='rgba(247,248,252,1)', # 그래프 배경색
            paper_bgcolor='rgba(255,255,255,1)', # 전체 배경색
            font=dict(family="Arial, Noto Sans KR, sans-serif")
        )
        
        # x축 눈금 및 그리드 설정
        fig.update_xaxes(
            showgrid=True, gridwidth=1, gridcolor='#e9ecef',
            tickformat='%H:%M' # 시간:분 형식
        )
        # y축 그리드 설정
        fig.update_yaxes(showgrid=True, gridwidth=1, gridcolor='#e9ecef')

        return pio.to_html(fig, full_html=False, include_plotlyjs='cdn')

    def _safe_float(self, value):
        try: return float(value)
        except (ValueError, TypeError): return 0.0

    def generate(self, generated_graphs: Dict) -> str:
        # [수정] _generate_graphs는 이제 (base64_png, interactive_html) 튜플 또는 (None, interactive_html)을 반환합니다.
        # raw_graphs = self._generate_graphs() # [개선] 이제 외부에서 생성된 그래프 데이터를 받습니다.
        
        graphs_for_template = {}
        for key, result in generated_graphs.items():
            if result and isinstance(result, tuple) and len(result) == 2:
                graphs_for_template[key] = result

        template_data = {
            "hostname": self.hostname, 
            "sar_data": self.sar_data, # [BUG FIX] disk_detail 팝업 활성화를 위해 sar_data를 템플릿에 전달합니다.
            "ai_analysis": self.ai_analysis,
            "graphs": generated_graphs, # [수정] Plotly HTML을 직접 전달
            "security_advisories": self.metadata.get('security_advisories', []),
            **self.metadata
        }
        return get_html_template(template_data)

class DataAnonymizer:
    def __init__(self):
        self.ip_map, self.hostname_map = {}, {}
        self.ipv4_regex = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.fqdn_regex = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
    def _anonymize_ip(self, match):
        ip = match.group(0)
        if ip.startswith('127.'): return ip
        if ip not in self.ip_map: self.ip_map[ip] = f"ANON_IP_{len(self.ip_map) + 1}"
        return self.ip_map[ip]
    def _anonymize_hostname(self, match):
        hostname = match.group(0).lower()
        if hostname in ['localhost']: return hostname
        if hostname not in self.hostname_map: self.hostname_map[hostname] = f"ANON_HOSTNAME_{len(self.hostname_map) + 1}"
        return self.hostname_map[hostname]
    def anonymize_data(self, data: Any, specific_hostnames: List[str] = []) -> Any:
        if isinstance(data, dict): return {k: self.anonymize_data(v, specific_hostnames) for k, v in data.items()}
        if isinstance(data, list): return [self.anonymize_data(item, specific_hostnames) for item in data]
        if isinstance(data, str):
            text = data
            for hostname in specific_hostnames:
                if hostname and hostname.lower() != 'localhost':
                    text = re.sub(r'\b' + re.escape(hostname) + r'\b', self._anonymize_hostname, text, flags=re.IGNORECASE)
            text = self.ipv4_regex.sub(self._anonymize_ip, text)
            text = self.fqdn_regex.sub(self._anonymize_hostname, text)
            return text
        return data

class AIAnalyzer:
    """
    [신규] AIBox 서버와 통신하여 sosreport 데이터를 분석하고,
    보안 위협 정보를 가져오는 클래스.
    """
    def __init__(self, server_url: str, report_date: Optional[datetime.datetime]):
        self.server_url = server_url.rstrip('/')
        self.report_date_str = report_date.strftime('%Y-%m-%d') if report_date else "N/A"
        self.tokenizer = None
        if IS_TIKTOKEN_AVAILABLE:
            try:
                # 토크나이저를 미리 로드하여 성능 향상
                self.tokenizer = tiktoken.get_encoding("cl100k_base")
            except Exception as e:
                logging.warning(f"tiktoken 토크나이저 로딩 실패: {e}. 문자 길이 기반으로 폴백합니다.")

    def _safe_float(self, value: Any) -> float:
        """입력값을 float으로 안전하게 변환합니다."""
        if isinstance(value, (int, float)):
            return float(value)
        try:
            # locale에 따라 소수점이 쉼표(,)로 표현되는 경우를 처리합니다.
            return float(str(value).replace(',', '.'))
        except (ValueError, TypeError):
            return 0.0

    def _make_request(self, endpoint: str, data: Dict, timeout: int = 600) -> Dict:
        """AIBox 서버에 POST 요청을 보내고 JSON 응답을 반환합니다."""
        url = f"{self.server_url}/api/{endpoint}"
        try:
            logging.info(f"AI 서버에 분석 요청: {url}")
            response = requests.post(url, json=data, timeout=timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(Color.error(f"AI 서버({url}) 통신 오류: {e}"))
            # [안정성 강화] 서버 통신 실패 시, AI 분석 결과가 없음을 나타내는 기본 구조를 반환합니다.
            return {
                "summary": "AI 분석 서버와 통신하지 못했습니다. 네트워크 연결 및 서버 상태를 확인하세요.",
                "critical_issues": [], "warnings": [], "recommendations": []
            }

    def _perform_sar_smart_analysis(self, sar_data: Dict[str, Any], cpu_cores: int) -> Dict[str, Any]:
        """
        [신규] SAR 데이터에서 임계치를 초과하는 성능 지표만 필터링하는 '스마트 분석'을 수행합니다.
        AI 분석에 유의미한 데이터만 선별하여 분석 효율을 높입니다.
        """
        logging.info("  - SAR 데이터 스마트 분석 시작 (임계치 기반 필터링)...")
        problematic_data: Dict[str, Any] = {}
        
        # CPU: iowait > 20%
        if cpu_data := sar_data.get('cpu'):
            high_iowait = [d for d in cpu_data if d.get('pct_iowait', 0) > 20]
            if high_iowait: problematic_data['cpu_high_iowait'] = high_iowait

        # Load: 5분 평균 부하 > CPU 코어 수
        if load_data := sar_data.get('load'):
            high_load = [d for d in load_data if d.get('ldavg-5', 0) > cpu_cores]
            if high_load: problematic_data['load_average_high'] = high_load

        # Disk: util > 80% or await > 20ms
        if disk_data := sar_data.get('disk_detail'):
            disk_bottleneck = [d for d in disk_data if d.get('pct_util', 0) > 80 or d.get('await', 0) > 20]
            if disk_bottleneck: problematic_data['disk_bottleneck'] = disk_bottleneck

        # Memory: memused > 90%
        if mem_data := sar_data.get('memory'):
            high_mem = [d for d in mem_data if d.get('pct_memused', 0) > 90]
            if high_mem: problematic_data['memory_pressure'] = high_mem

        # Swap: swpused > 10%
        if swap_data := sar_data.get('swap'):
            swap_usage = [d for d in swap_data if d.get('pct_swpused', 0) > 10]
            if swap_usage: problematic_data['swap_activity'] = swap_usage

        if problematic_data:
            summary_text = f"SAR 데이터 스마트 분석 결과, {len(problematic_data)}개 영역에서 성능 저하 의심 지표가 발견되었습니다: {', '.join(problematic_data.keys())}"
            logging.info(Color.warn(f"    -> {summary_text}"))
            # AI가 컨텍스트를 이해할 수 있도록 요약 정보를 추가
            problematic_data['sar_smart_analysis_summary'] = summary_text
            return problematic_data
        else:
            logging.info("    -> SAR 데이터에서 특이점을 발견하지 못했습니다. AI 분석에서 SAR 데이터는 제외됩니다.")
            # 특이점이 없으면 빈 딕셔너리를 반환하여 AI 요청 데이터 양을 줄임
            return {}

    def _create_chunk_analysis_prompt(self, chunk_name: str, chunk_data: Any) -> str:
        """[신규] 개별 데이터 청크(묶음) 분석을 위한 프롬프트를 생성합니다."""
        return f"""
[시스템 역할]
당신은 Red Hat Enterprise Linux(RHEL) 시스템의 특정 데이터 조각을 면밀히 분석하여 사소한 이상 징후나 잠재적 문제점까지도 찾아내는 진단 전문가입니다. 당신의 목표는 현재의 명백한 문제뿐만 아니라, 미래에 문제가 될 수 있는 모든 가능성을 식별하는 것입니다.

[분석 대상 데이터]
- 데이터 섹션: {chunk_name}
- 데이터 내용:
```json
{json.dumps(chunk_data, indent=2, ensure_ascii=False, default=str)}
```

[요청]
위 데이터에서 가장 중요하거나 비정상적인 특징, 잠재적인 문제점을 나타내는 핵심 사항을 2~3개의 불릿 포인트로 요약해 주십시오.
"""

    def _create_final_analysis_prompt(self, summaries: Dict[str, str]) -> str:
        """[신규] 개별 청크 요약본들을 종합하여 최종 분석을 위한 프롬프트를 생성합니다."""
        # [BUG FIX] SyntaxError: 'return' outside function 오류를 수정합니다.
        # 함수 본문이 올바르게 들여쓰기 되도록 수정합니다.
        summaries_text = "\n".join(f"- **{name}**: {summary}" for name, summary in summaries.items())

        return f"""[시스템 역할]
당신은 20년 경력의 Red Hat Certified Architect(RHCA)이자 리눅스 성능 분석 전문가입니다. 주어진 시스템 데이터의 각 섹션별 요약본을 종합하여, 시스템의 상태를 진단하고 문제의 근본 원인을 찾아 구체적인 해결 방안을 제시해야 합니다.
**특히, HA 클러스터(Pacemaker, Corosync) 및 DRBD 관련 데이터가 있는 경우, 클러스터의 안정성, 리소스 상태, 잠재적 위험(예: split-brain, 리소스 모니터링 실패, failover 문제)을 최우선으로 분석해야 합니다.**

[분석 대상: 시스템 데이터 섹션별 요약]
{summaries_text}

[출력 형식]
위 요약본들을 종합적으로 분석하여, 다음의 키를 가진 단일 JSON 객체로만 반환하십시오. 다른 설명은 절대 추가하지 마세요.

`summary` 필드는 다음의 마크다운 구조를 반드시 사용해야 합니다. 각 섹션은 '###' 헤더로 시작해야 합니다.
### 종합 평가 (Overall Assessment)
<시스템의 전반적인 상태에 대한 1~2 문장의 평가 (예: '양호', '주의', '심각') 및 핵심 근거>
### 주요 발견 사항 (Key Findings)
* <가장 중요한 발견점 1>
* <가장 중요한 발견점 2>
### 최우선 권장 사항 (Top Priority Recommendation)
<가장 시급하게 조치해야 할 단 한 가지의 핵심 권장 사항>

```json
{{{{
  "summary": "위의 마크다운 구조에 따라 시스템의 전반적인 상태, 주요 발견 사항, 핵심 권장 사항을 요약합니다.",
  "critical_issues": ["시스템 안정성에 즉각적인 영향을 미치는 심각한 문제점 목록 (예: Kernel panic, OOM Killer 발생, 클러스터 장애, Split-brain)"],
  "warnings": ["주의가 필요하거나 잠재적인 문제로 발전할 수 있는 경고 사항 목록 (예: 높은 I/O 대기, 특정 로그의 반복적인 오류)"],
  "recommendations": [ {{{{ "priority": "높음/중간/낮음", "category": "성능/안정성/보안/구성", "issue": "구체적인 문제점 기술", "solution": "문제 해결을 위한 구체적이고 실행 가능한 단계별 가이드 또는 명령어", "related_logs": ["분석의 근거가 된 특정 로그 메시지 (있는 경우)"] }}}} ]
}}}}
```"""

    def _create_final_analysis_prompt(self, summaries: Dict[str, str]) -> str:
        """[신규] 개별 청크 요약본들을 종합하여 최종 분석을 위한 프롬프트를 생성합니다."""
        summaries_text = "\n".join(f"- **{name}**: {summary}" for name, summary in summaries.items())

        # [사용자 요청] AI의 역할을 RHEL 시스템 전반을 분석하는 최고 전문가로 재정의하고, HA/DRBD는 심층 분석의 한 부분으로 조정합니다.
        return f"""[시스템 역할]
당신은 20년 경력의 Red Hat Certified Architect(RHCA)이자, 고객에게 시스템 장애의 근본 원인을 보고하고 해결책을 제시하는 최고 수준의 기술 컨설턴트입니다. 당신의 분석은 단순한 사실 나열을 넘어, 각 데이터 간의 인과 관계를 추론하고, 비즈니스 영향까지 고려한 깊이 있는 통찰력을 제공해야 합니다.

[분석 방법론]
1.  **전체 시스템 상태 평가 (Holistic Review):** 먼저 CPU, 메모리, I/O, 네트워크 등 전반적인 시스템 성능 지표와 커널 로그(dmesg), 시스템 로그를 종합적으로 검토하여 시스템의 전반적인 건강 상태와 이상 징후를 파악합니다.
2.  **고가용성(HA) 클러스터 심층 분석 (Deep Dive):** 만약 `ha_cluster_info` 또는 `drbd_info` 데이터가 있다면, 1단계에서 파악한 시스템 문제와 연관 지어 클러스터의 문제를 분석합니다.
    *   **Pacemaker:** `Failed Actions`, `OFFLINE` 노드, `stonith` 로그를 분석하여 클러스터 불안정의 원인을 찾습니다. 리소스 모니터링 실패(`monitor error`, `Timed Out`)가 시스템의 다른 문제(예: I/O 병목)와 관련이 있는지 추론해야 합니다.
    *   **DRBD:** `cs`(Connection State), `ro`(Roles), `ds`(Disk States)의 상태 변화를 추적합니다. `StandAlone` 또는 `Split-Brain` 상태가 감지되면, 그 원인이 네트워크 문제인지, 디스크 I/O 오류인지, 아니면 관리자의 수동 개입 때문인지 종합적으로 판단해야 합니다.
3.  **근본 원인 추론 (Root Cause Analysis):** 각 데이터 조각을 독립적으로 보지 말고, "높은 I/O 대기(high iowait)가 디스크 응답 시간 지연을 초래했고, 이로 인해 DRBD 연결이 끊어지면서(StandAlone) 최종적으로 Pacemaker 리소스가 타임아웃 오류를 일으켰다"와 같이 문제의 원인과 결과를 연결하는 시나리오를 구성해야 합니다.
4.  **고객 중심의 해결책 제시 (Customer-Centric Solution):**
    *   **비즈니스 영향:** 발견된 문제가 비즈니스에 미치는 영향(예: 서비스 중단, 데이터 정합성 문제)을 명확히 설명합니다.
    *   **우선순위:** 해결책에 대해 '긴급', '높음', '중간', '낮음'과 같은 명확한 우선순위를 부여합니다.
    *   **재발 방지:** 단기적인 해결책뿐만 아니라, 근본적인 문제 해결과 재발 방지를 위한 중장기적인 개선 방안(예: 커널 파라미터 튜닝, 모니터링 강화)을 함께 제시합니다.

[분석 대상: 시스템 데이터 섹션별 요약]
{summaries_text}

[출력 형식]
위 요약본들을 종합적으로 분석하여, 다음의 키를 가진 단일 JSON 객체로만 반환하십시오. 다른 설명은 절대 추가하지 마세요.

`summary` 필드는 다음의 마크다운 구조를 반드시 사용해야 합니다. 각 섹션은 '###' 헤더로 시작해야 합니다.
### 종합 평가 (Overall Assessment)
<시스템의 전반적인 상태에 대한 1~2 문장의 평가 (예: '양호', '주의', '심각') 및 핵심 근거>
### 주요 발견 사항 (Key Findings)
* <가장 중요한 발견점 1>
* <가장 중요한 발견점 2>
### 최우선 권장 사항 (Top Priority Recommendation)
<가장 시급하게 조치해야 할 단 한 가지의 핵심 권장 사항>

```json
{{{{
  "summary": "위의 마크다운 구조에 따라 시스템의 전반적인 상태, 주요 발견 사항, 핵심 권장 사항을 요약합니다.",
  "critical_issues": ["시스템 안정성에 즉각적인 영향을 미치는 심각한 문제점 목록 (예: Kernel panic, OOM Killer 발생, 클러스터 장애, Split-brain)"],
  "warnings": ["주의가 필요하거나 잠재적인 문제로 발전할 수 있는 경고 사항 목록 (예: 높은 I/O 대기, 특정 로그의 반복적인 오류)"],
  "recommendations": [ {{{{ "priority": "높음/중간/낮음", "category": "성능/안정성/보안/구성", "issue": "구체적인 문제점 기술", "solution": "문제 해결을 위한 구체적이고 실행 가능한 단계별 가이드 또는 명령어", "related_logs": ["분석의 근거가 된 특정 로그 메시지 (있는 경우)"] }}}} ]
}}}}
```"""

    def get_structured_analysis(self, metadata_path: Path, sar_data_path: Path, anonymize: bool = False) -> Dict[str, Any]:
        """
        [핵심 개선] 분할 정복(Divide and Conquer) 방식으로 AI 분석을 수행합니다.
        1. 데이터를 작은 묶음(chunk)으로 나누어 개별적으로 요약 분석을 요청합니다. (병렬 처리)
        2. 요약된 결과들을 모아 최종 종합 분석을 요청합니다.
        """
        # [개선] LLM 컨텍스트 크기를 '토큰' 기준으로 설정 (예: 128k 모델의 경우, 안전 마진 고려 120,000 토큰)
        # 실제 청킹은 서버의 LLMChunker가 담당하지만, 클라이언트에서도 1차적으로 분할하여
        # 단일 요청의 크기가 너무 커지는 것을 방지합니다.
        MAX_TOKENS_PER_REQUEST = 120000
        BASE_PROMPT_TOKENS = 2000  # 프롬프트 기본 구조가 차지하는 토큰 (보수적 추정)

        log_step("AI 시스템 분석 요청 (지능형 청크 분할)")
        try:
            with open(metadata_path, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
            with open(sar_data_path, 'r', encoding='utf-8') as f:
                sar_data = json.load(f)

            if anonymize:
                logging.info(Color.info("  - 민감 정보 익명화(Anonymization) 진행 중..."))
                anonymizer = DataAnonymizer()
                hostnames = [metadata.get('system_info', {}).get('hostname', '')]
                metadata = anonymizer.anonymize_data(metadata, hostnames)
                sar_data = anonymizer.anonymize_data(sar_data, hostnames)
            
            # [핵심 개선] SAR 데이터에 대한 스마트 분석 수행
            # CPU 코어 수 파싱 (문자열 'x' 기준)
            cpu_info_str = metadata.get('system_info', {}).get('cpu', '1 x')
            try: # noqa: E501
                cpu_cores = int(cpu_info_str.split('x')[0].strip())
            except (ValueError, IndexError):
                cpu_cores = 1 # 파싱 실패 시 기본값
            
            smart_sar_results = self._perform_sar_smart_analysis(sar_data, cpu_cores)

            # [핵심 개선] AI 요청 데이터 최적화
            # 1. AI 분석에 필요한 핵심 데이터만 선별합니다.
            essential_data = {
                "system_info": metadata.get("system_info"),
                # [사용자 요청] HA 클러스터 및 DRBD 정보 추가
                "ha_cluster_info": metadata.get("ha_cluster_info"),
                "drbd_info": metadata.get("drbd_info"),
                "performance_analysis": metadata.get("performance_analysis"),
                "critical_log_events": metadata.get("critical_log_events"),
                "smart_sar_analysis": smart_sar_results,
                # 2. 매우 큰 데이터는 상위 5개 항목만 잘라서 보냅니다.
                "smart_log_analysis": {k: v[:5] for k, v in metadata.get("smart_log_analysis", {}).items()}
            }

            chunk_summaries = {}
            tasks = []

            for chunk_name, chunk_data in essential_data.items():
                if not chunk_data: continue

                chunk_str = json.dumps(chunk_data, ensure_ascii=False, default=str)
                
                # 토큰 계산은 서버의 LLMChunker가 더 정확하게 수행하므로, 여기서는 문자 길이로 대략적인 크기만 확인합니다.
                # 1 토큰을 약 2.5자로 가정하여, 매우 큰 청크만 분할합니다.
                chunk_size_approx = len(chunk_str)
                max_size_approx = (MAX_TOKENS_PER_REQUEST - BASE_PROMPT_TOKENS) * 2

                if chunk_size_approx <= max_size_approx:
                    tasks.append((chunk_name, chunk_data))
                else:
                    logging.warning(f"    - '{chunk_name}' 섹션이 너무 커서({chunk_size_approx}자) 하위 청크로 분할합니다.")
                    
                    # [개선] 청크 분할 로직 고도화
                    if isinstance(chunk_data, list):
                        # 리스트는 100개 아이템 단위로 분할
                        for i in range(0, len(chunk_data), 100):
                            tasks.append((f"{chunk_name}_{i//100+1}", chunk_data[i:i+100]))
                    elif isinstance(chunk_data, dict):
                        items = list(chunk_data.items())
                        # 딕셔너리는 200개 아이템 단위로 분할
                        for i in range(0, len(items), 200):
                            tasks.append((f"{chunk_name}_{i//200+1}", dict(items[i:i+200])))

            logging.info(f"  - [1/2] {len(tasks)}개 데이터 묶음(chunk)에 대한 병렬 요약 분석 시작...")
            # [개선] 병렬 처리 워커 수를 늘려 동시 요청 수를 증가시킴
            with ThreadPoolExecutor(max_workers=10, thread_name_prefix='Chunk_Summarizer') as executor:
                future_to_chunk = {executor.submit(self._make_request, 'sos/analyze_system', {"prompt": self._create_chunk_analysis_prompt(name, data)}): name for name, data in tasks}

                for future in as_completed(future_to_chunk):
                    chunk_name = future_to_chunk[future]
                    try:
                        result = future.result()
                        # [디버깅 강화] AI 서버로부터 받은 응답의 타입과 내용을 로그로 기록합니다.
                        logging.debug(f"    [DEBUG] '{chunk_name}' 응답 수신: Type={type(result)}, Content={str(result)[:200]}")

                        # [안정성 강화] AI 응답이 딕셔너리 형태인지 확인합니다.
                        if isinstance(result, dict):
                            # AI 응답에서 실제 요약 텍스트를 추출합니다.
                            summary_text = result.get('summary', str(result))
                            chunk_summaries[chunk_name] = summary_text
                            logging.info(f"    -> '{chunk_name}' 섹션 요약 분석 완료.")
                        else:
                            # 딕셔너리가 아닐 경우, 오류로 기록하고 응답 내용을 그대로 저장합니다.
                            error_message = f"'{chunk_name}' 섹션의 AI 응답이 예상된 딕셔너리 형식이 아닙니다 (Type: {type(result)})."
                            logging.error(error_message)
                            chunk_summaries[chunk_name] = f"분석 오류: {error_message}\n응답 내용: {str(result)}"
                    except Exception as e:
                        logging.error(f"'{chunk_name}' 섹션 요약 중 오류 발생: {e}")
                        chunk_summaries[chunk_name] = f"오류: {e}"

            # 2단계: 요약본을 취합하여 최종 분석 요청
            logging.info("  - [2/2] 요약본 취합 및 최종 종합 분석 시작...")

            # [핵심 개선] 최종 분석 요청 시, 모든 요약본을 하나의 프롬프트에 담아 전송합니다.
            # 서버의 LLMChunker가 컨텍스트 크기에 맞춰 자동으로 분할 및 병합 처리를 수행합니다.
            # 이 방식은 클라이언트 로직을 단순화하고, 서버에서 더 정확한 토큰 기반 청킹을 가능하게 합니다.
            final_prompt = self._create_final_analysis_prompt(chunk_summaries)
            final_analysis = self._make_request('sos/analyze_system', {"prompt": final_prompt})

            return final_analysis

        except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.error(Color.error(f"AI 분석을 위한 데이터 파일을 읽는 중 오류 발생: {e}"))
            return {"summary": "분석 데이터 파일을 처리할 수 없어 AI 분석을 수행하지 못했습니다.", "critical_issues": [], "warnings": [], "recommendations": []}

    def fetch_security_news(self, metadata: Dict, output_dir: Path) -> List[Dict]: # noqa: E501
        """[보안 분석 v4] 설치된 패키지 정보를 기반으로 시스템에 영향을 미치는 CVE를 분석하고, AI를 통해 우선순위를 선정합니다."""
        log_step("3단계: AI 기반 보안 위협 분석")

        installed_packages = metadata.get('installed_packages', [])
        if not installed_packages:
            logging.warning(Color.warn("  - 설치된 패키지 정보가 없어 보안 분석을 건너뜁니다."))
            return []

        # --- 1단계: 로컬 CVE 데이터 수집 및 1차 분류 (기간) ---
        logging.info(Color.info("\n--- 1단계: 로컬 CVE 데이터 수집 및 1차 분류 (기간) ---"))
        # [요청 반영] cve_data.json 파일 경로를 ./cve_data.json으로 지정
        cve_data_path = Path('./cve_data.json')
        if not cve_data_path.exists():
            # [사용자 요청] security.py의 안정적인 오류 처리 로직을 적용합니다.
            logging.error(Color.error(f"  - CVE 데이터 파일({cve_data_path})을 찾을 수 없어 보안 분석을 건너뜁니다."))
            return []

        with open(cve_data_path, 'r', encoding='utf-8') as f:
            cve_summaries = json.load(f)
        logging.info(f"  - 로컬 CVE 데이터 로드 완료: 총 {len(cve_summaries)}개")

        start_date = datetime.datetime.now() - timedelta(days=180)
        recent_cves = []
        for cve in cve_summaries:
            if not ('public_date' in cve and cve['public_date']): continue
            try:
                public_dt = datetime.datetime.fromisoformat(cve['public_date'].replace('Z', '+00:00'))
                if public_dt.replace(tzinfo=None) >= start_date:
                    recent_cves.append(cve)
            except ValueError:
                continue
        logging.info(f"  - 1차 분류(최근 180일) 완료. 후보 CVE: {len(recent_cves)}개")

        # --- 2단계: CVE 상세 정보 수집 및 2차 분류 (Severity/CVSS) ---
        logging.info(Color.info("\n--- 2단계: CVE 상세 정보 수집 및 2차 분류 (Severity/CVSS) ---"))
        cves_with_details = []
        # [사용자 요청] 스레드 안전성을 위해 Lock 객체를 생성합니다.
        cve_details_lock = threading.Lock()

        # [BUG FIX] CVE 상세 정보 조회 로직 강화 (로컬 실패 시 외부 API로 폴백)
        # 1단계: 로컬 서버에서 먼저 조회
        logging.info(f"  - {len(recent_cves)}개 CVE 상세 정보 수집 중 (From: http://127.0.0.1:5000/AIBox/cve/)...")
        failed_cve_ids = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_cve = {executor.submit(requests.get, f"http://127.0.0.1:5000/AIBox/cve/{cve['CVE']}.json", timeout=10): cve for cve in recent_cves} # noqa: E501
            for future in as_completed(future_to_cve):
                cve_summary = future_to_cve[future]
                try:
                    response = future.result()
                    if response.ok:
                        detail_data = response.json()
                        # [BUG FIX] 상세 정보의 CVE ID 키가 'name'으로 되어 있어 'CVE'로 통일합니다.
                        # 이렇게 하지 않으면, 기존 cve_summary의 'name' 필드(패키지명)를 덮어쓰게 됩니다.
                        if 'name' in detail_data and detail_data['name'].startswith('CVE-'):
                            detail_data['CVE'] = detail_data.pop('name')

                        with cve_details_lock:
                            # [BUG FIX] 원본 요약 정보와 상세 정보를 병합하여 CVE ID 누락 방지
                            cves_with_details.append({**cve_summary, **detail_data})
                except requests.RequestException as e:
                    logging.warning(f"    -> 로컬 CVE 상세 정보 조회 실패: {cve_summary.get('CVE')}, 오류: {e}")
                    failed_cve_ids.append(cve_summary)
        
        # 2단계: 로컬 조회 실패 건에 대해 Red Hat 공식 API로 재시도
        if failed_cve_ids:
            logging.info(f"  - 로컬 조회 실패 {len(failed_cve_ids)}건에 대해 외부 API로 재시도합니다...")
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_cve = {executor.submit(requests.get, f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve['CVE']}.json", timeout=20): cve for cve in failed_cve_ids}
                for future in as_completed(future_to_cve):
                    cve_summary = future_to_cve[future]
                    try:
                        response = future.result()
                        if response.ok:
                            detail_data = response.json()
                            # 외부 API 조회 결과에 대해서도 동일한 키 통일 작업을 수행합니다.
                            if 'name' in detail_data and detail_data['name'].startswith('CVE-'):
                                detail_data['CVE'] = detail_data.pop('name')

                            with cve_details_lock:
                                cves_with_details.append({**cve_summary, **detail_data})
                    except requests.RequestException as e:
                        logging.error(f"    -> 외부 API 조회 최종 실패: {cve_summary.get('CVE')}, 오류: {e}")

        logging.info(f"  - CVE 상세 정보 수집 완료: {len(cves_with_details)}개")

        cves_after_2nd_filter = []
        for cve in cves_with_details:
            # [BUG FIX] CVE JSON 데이터의 심각도 필드 이름이 'threat_severity'이므로, 이를 참조하도록 수정합니다.
            # 'severity' 필드는 존재하지 않아 필터링이 제대로 동작하지 않았습니다.
            severity = cve.get('threat_severity', '').lower()
            
            # [사용자 요청 반영] security.py의 안정적인 점수 파싱 로직을 그대로 적용합니다.
            # cvss3 필드가 딕셔너리가 아닌 경우도 처리하여 정확도를 높입니다.
            cvss3_score = 0.0
            cvss3_data = cve.get('cvss3', {})
            score_str = None
            if isinstance(cvss3_data, dict): # cvss3가 딕셔너리인 경우
                score_str = cvss3_data.get('cvss3_base_score')
            if not score_str: # cvss3_base_score가 없거나, cvss3가 딕셔너리가 아닌 경우
                score_str = cve.get('cvss3_score') # 최상위 레벨의 cvss3_score 확인
            if score_str:
                cvss3_score = self._safe_float(score_str)

            if severity in ['critical', 'important'] and cvss3_score >= 7.0:
                cves_after_2nd_filter.append(cve)
        logging.info(f"  - 2차 분류(Severity/CVSS) 완료. 후보 CVE: {len(cves_after_2nd_filter)}개")

        # --- 3단계: 시스템 패키지 연관성 분석 (3차 분류) ---
        logging.info(Color.info("\n--- 3단계: 시스템 패키지 연관성 분석 (3차 분류) ---"))
        # [요청 반영] AI 분석의 정확도를 높이기 위해, 'name'과 'version'을 조합한 전체 패키지 문자열 목록을 생성합니다.
        # 예: 'NetworkManager-1.18.8-1.el7.x86_64'        
        installed_package_full_names = {f"{pkg['name']}-{pkg['version']}" for pkg in installed_packages}
        installed_package_names_only = {pkg['name'] for pkg in installed_packages}
        
        cves_after_3rd_filter = []
        # [사용자 요청] 어떤 패키지로 인해 CVE가 선정되었는지 추적하기 위한 디버그 로그를 추가합니다.
        for cve in cves_after_2nd_filter:
            is_relevant = False
            relevant_package_for_debug = "N/A"
            # [BUG FIX] cve.get('package_state')가 None을 반환할 경우 TypeError가 발생하는 문제를 해결합니다.
            # 'or []'를 사용하여 None일 경우 빈 리스트로 처리하도록 합니다.
            for state in (cve.get('package_state') or []):
                # [핵심 개선] 'Affected' 상태인 패키지에 대해서만 연관성을 검사합니다.
                if state.get('fix_state') == 'Affected':                    
                    # CVE 데이터의 패키지 이름(예: 'httpd-tools-2.4.37-56.el8_8.3.x86_64')에서
                    # 버전과 아키텍처를 제외한 순수 패키지 이름(예: 'httpd-tools')을 추출합니다.
                    # 정규식은 이름 뒤에 오는 첫 번째 숫자 또는 하이픈+숫자 부분을 버전의 시작으로 간주합니다.
                    cve_pkg_name_match = re.match(r'^[a-zA-Z0-9_.-]+(?=-\d)', state.get('package_name', ''))
                    if cve_pkg_name_match:
                        cve_pkg_name = cve_pkg_name_match.group(0)
                    else:
                        # 버전 정보가 없는 패키지 이름(예: 'kernel')의 경우, 전체 이름을 사용합니다.
                        cve_pkg_name = state.get('package_name', '')

                    # 추출된 CVE 패키지 이름이 시스템에 설치된 패키지 이름 목록과 정확히 일치하는지 확인합니다.
                    if cve_pkg_name and cve_pkg_name in installed_package_names_only:
                        is_relevant = True
                        relevant_package_for_debug = cve_pkg_name
                        break
            if is_relevant:
                logging.info(f"    [DEBUG] CVE {cve.get('CVE')} is relevant due to package: {relevant_package_for_debug}")

            if is_relevant:
                cves_after_3rd_filter.append(cve)
        logging.info(f"  - 3차 분류(패키지 연관성) 완료. 최종 AI 분석 대상 CVE: {len(cves_after_3rd_filter)}개")

        if not cves_after_3rd_filter:
            logging.warning(Color.warn("  - 시스템에 영향을 미칠 가능성이 있는 CVE를 찾지 못했습니다."))
            return []
        
        # --- 4단계: AI 최종 분석 및 선정 ---
        logging.info(Color.info("\n--- 4단계: AI 최종 분석 및 선정 ---"))

        # [사용자 요청] 2단계 AI 분석 프로세스 도입
        # 1단계: 예선 분석 - 각 청크에서 중요한 CVE 후보를 선별
        logging.info(f"  - [1/2] 예선 분석: {len(cves_after_3rd_filter)}개 CVE를 묶음으로 나누어 주요 후보 선별...")
        preliminary_candidates = []
        preliminary_candidates_lock = threading.Lock()
        
        CHUNK_SIZE = 20
        cve_chunks = [cves_after_3rd_filter[i:i + CHUNK_SIZE] for i in range(0, len(cves_after_3rd_filter), CHUNK_SIZE)]

        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_chunk = {executor.submit(self._preliminary_cve_analysis, chunk): chunk for chunk in cve_chunks}
            # [BUG FIX] NameError: name 'future_to_chunk_index' is not defined 오류 수정
            for future in as_completed(future_to_chunk):
                chunk = future_to_chunk[future]
                try:
                    # AI는 이 청크에서 중요하다고 판단한 CVE ID 목록을 반환
                    selected_cve_ids = future.result()
                    logging.info(f"    -> 예선 묶음 분석 완료. AI가 {len(selected_cve_ids)}개 후보 선정: {selected_cve_ids}")
                    with preliminary_candidates_lock:
                        # 원본 CVE 데이터를 후보 목록에 추가
                        for cve in chunk:
                            if cve.get('CVE') in selected_cve_ids:
                                preliminary_candidates.append(cve)
                except Exception as e:
                    logging.error(f"    -> 예선 묶음 분석 중 오류 발생: {e}")

        # 중복 제거 (다른 청크에서 동일 CVE가 선택될 수 있음)
        preliminary_finalists = list({cve['CVE']: cve for cve in preliminary_candidates}.values())
        logging.info(f"  - 예선 분석 완료. 총 {len(preliminary_finalists)}개의 최종 후보가 선정되었습니다.")

        if not preliminary_finalists:
            logging.warning(Color.warn("  - AI가 시스템에 영향을 미칠 가능성이 있는 CVE를 찾지 못했습니다."))
            return []

        # 2단계: 결선 분석 - 예선 통과자들을 대상으로 최종 분석 및 "패키지당 1개" 규칙 적용
        logging.info(f"  - [2/2] 결선 분석: {len(preliminary_finalists)}개 후보를 대상으로 최종 우선순위 선정...")
        final_cves = self._final_cve_analysis(preliminary_finalists, installed_package_full_names, metadata)

        # [BUG FIX] AI가 반환한 정보에 원본 CVE의 상세 정보(공개일, CVSS 점수 등)를 병합합니다.
        # 이렇게 해야 HTML 템플릿에서 올바른 데이터를 사용할 수 있습니다.
        cve_details_map = {cve['CVE']: cve for cve in preliminary_finalists if 'CVE' in cve}
        enriched_final_cves = []
        for advisory in final_cves:
            cve_id = advisory.get('cve_id')
            if cve_id in cve_details_map:
                # 원본 상세 정보 위에 AI 분석 결과를 덮어씁니다.
                enriched_advisory = {**cve_details_map[cve_id], **advisory}
                enriched_final_cves.append(enriched_advisory)

        # [사용자 요청] 패키지당 하나의 CVE만 선정하도록 최종 필터링 로직 추가
        final_report_cves = []
        seen_packages = set()

        # AI가 정렬한 순서대로 순회
        for cve in enriched_final_cves:
            # AI 분석 결과에서 패키지 이름을 가져옴
            package_name = cve.get('package')
            if not package_name:
                continue

            # 이미 이 패키지에 대한 CVE가 선정되지 않았다면
            if package_name not in seen_packages:
                final_report_cves.append(cve)
                seen_packages.add(package_name)

        # 최종 정렬 (심각도, CVSS 점수 순) 및 상위 20개 반환
        final_report_cves.sort(key=lambda x: (x.get('severity') == 'critical', self._safe_float(x.get('cvss_score', 0.0))), reverse=True)
        logging.info(Color.success(f"\nAI 종합 분석 완료. 최종 {len(final_report_cves)}개의 고유 패키지 기반 긴급 보안 위협을 선정했습니다."))
        return final_report_cves[:20]
    
    def _add_installed_version_to_advisories(self, advisories: List[Dict], installed_packages: List[Dict]) -> List[Dict]:
        """[신규] AI가 선정한 보안 권고 목록에 실제 설치된 패키지 버전 정보를 추가합니다."""
        # 패키지 이름으로 버전을 빠르게 찾기 위한 맵 생성
        # 예: {'kernel': '3.10.0-1160.el7.x86_64', 'openssh': '7.4p1-21.el7.x86_64'}
        package_version_map = {pkg['name']: pkg['version'] for pkg in installed_packages}

        for advisory in advisories:
            package_name = advisory.get('package')
            if package_name and package_name in package_version_map:
                # 'installed_version' 키에 설치된 버전 정보 추가
                advisory['installed_version'] = package_version_map[package_name]
        
        return advisories


    def _preliminary_cve_analysis(self, cve_chunk: List[Dict]) -> List[str]:
        """[신규] 1단계 예선 분석을 위한 프롬프트를 생성하고 AI를 호출합니다."""
        # AI에게 전달할 데이터 형식에 맞게 입력 데이터를 가공합니다.
        cves_for_prompt = []
        for cve in cve_chunk:
            # [BUG FIX] cve 객체가 None인 경우를 처리하여 TypeError를 방지합니다.
            if not cve:
                logging.warning("None 타입의 CVE 데이터가 감지되어 건너뜁니다.")
                continue

            # [BUG FIX] security.py의 안정적인 프롬프트 생성 로직을 적용하여 AI 분석 정확도를 높입니다.
            # CVE 요약, CVSS 벡터, 영향받는 패키지 등 AI가 중요도를 판단하는 데 필수적인 정보를 추가합니다.
            cvss_score = (cve.get('cvss3', {}) or {}).get('cvss3_base_score') or cve.get('cvss3_score') or 'N/A'
            cvss_vector = (cve.get('cvss3', {}) or {}).get('cvss3_vector') or 'N/A'
            summary = " ".join(cve.get('details', [])) or cve.get('statement', '')
            affected_packages = list(set(re.match(r'([^-\s]+)', p.get('package_name', '')).group(1) for p in cve.get('package_state', []) if p.get('fix_state') == 'Affected' and re.match(r'([^-\s]+)', p.get('package_name', ''))))

            cves_for_prompt.append({
                "cve_id": cve.get('CVE', 'N/A'),
                "severity": cve.get('threat_severity', 'N/A'),
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "summary": summary,
                "affected_packages": affected_packages
            })

        prompt = f"""[시스템 역할]
당신은 Red Hat Enterprise Linux(RHEL) 시스템의 보안을 책임지는 최고 수준의 사이버 보안 분석가입니다.

[임무]
아래에 제공된 CVE 목록 중에서, CVSS 점수, 심각도, 패키지 중요도('kernel', 'glibc', 'openssh' 등)를 종합적으로 고려하여, **가장 중요하고 시급하다고 판단되는 CVE의 ID 목록**을 반환하십시오.

[제한 조건]
- **패키지별 대표 선정:** 동일한 패키지(예: 'kernel')에 여러 취약점이 있다면, 그중 가장 위험한 **단 하나의 CVE만** 대표로 선정해야 합니다.

[입력 데이터: CVE 목록]
```json
{json.dumps(cves_for_prompt, indent=2, ensure_ascii=False, default=str)}
```

[출력 형식]
**가장 중요한 순서대로 CVE ID 문자열을 포함하는 JSON 배열 하나만 출력하십시오.** 다른 설명은 절대 추가하지 마세요.
```json
["CVE-XXXX-YYYY", "CVE-AAAA-BBBB", "CVE-CCCC-DDDD"]
```"""
        response = self._make_request('cve/analyze', {"prompt": prompt})
        # AI 응답이 JSON 배열이 아닐 경우를 대비하여 안전하게 처리
        # [BUG FIX] AI가 JSON 객체(dict)로 응답하는 경우, 'raw_response'나 다른 키에서 CVE 목록을 추출하도록 수정합니다.
        if isinstance(response, list): # 가장 이상적인 경우
            return response
        elif isinstance(response, dict):
            # 1. 'selected_cves' 키 확인 (기존 호환성)
            if 'selected_cves' in response and isinstance(response['selected_cves'], list):
                return response['selected_cves']
            # 2. 'raw_response' 키에서 정규식으로 CVE ID 추출 (가장 안정적인 폴백)
            raw_text = response.get('raw_response', str(response))
            extracted_cves = re.findall(r'CVE-\d{4}-\d{4,}', raw_text)
            if extracted_cves:
                logging.warning(f"AI 응답이 리스트가 아니었지만, 텍스트에서 {len(extracted_cves)}개의 CVE 목록을 추출했습니다.")
                return extracted_cves
        
        logging.warning(f"AI 예선 분석에서 유효한 CVE 목록을 추출하지 못했습니다. 응답: {str(response)[:200]}")
        return []

    def _final_cve_analysis(self, cve_candidates: List[Dict], installed_package_full_names: set, metadata: Dict) -> List[Dict]:
        """[신규] 2단계 결선 분석을 위한 프롬프트를 생성하고 AI를 호출합니다."""
        cves_for_prompt = []
        for cve in cve_candidates:
            cvss_score = (cve.get('cvss3', {}) or {}).get('cvss3_base_score') or cve.get('cvss3_score') or 'N/A'
            cves_for_prompt.append({
                "cve_id": cve.get('CVE', 'N/A'),
                "severity": cve.get('threat_severity', 'N/A'),
                "cvss_score": cvss_score,
                "package_state": cve.get('package_state', [])
            })

        prompt = f"""[시스템 역할]
당신은 Red Hat Enterprise Linux의 보안 전문가입니다. 주어진 CVE 목록과 시스템에 설치된 패키지 정보를 바탕으로, **현재 시스템에 가장 시급하게 패치가 필요한 보안 위협**을 분석하고 선정해야 합니다.

[분석 가이드라인]
1.  **외부 위협 인텔리전스 수집 (Web Search)**: 각 CVE에 대해 웹 검색을 수행하여 다음 정보를 수집합니다.
    *   **CISA KEV (Known Exploited Vulnerabilities) 등재 여부 (매우 중요)**
    *   **PoC (Proof-of-Concept) 코드 공개 여부** (예: Exploit-DB, GitHub)
    *   **EPSS (Exploit Prediction Scoring System) 점수 및 백분위**
2.  **긴급도 및 우선순위 평가**: CVSS 점수뿐만 아니라, 위에서 수집한 외부 위협 인텔리전스를 종합적으로 고려하여 가장 시급하게 패치해야 할 위협의 우선순위를 정합니다. (CISA KEV 등재 > PoC 공개 > 높은 EPSS 점수 > 높은 CVSS 점수 순으로 중요)
3.  **패키지별 대표 선정 (매우 중요)**: 동일한 패키지(예: 'kernel')에 여러 취약점이 있다면, 그중에서 가장 위험하고 시급한 **단 하나의 CVE만** 대표로 선정해야 합니다.
4.  **상세 분석 및 결과 포맷팅**: 분석 결과를 바탕으로, 각 위협에 대해 아래 '출력 형식'에 맞는 JSON 객체로 결과를 정리합니다.
    *   `threat_tags`: "RCE", "Privilege Escalation" 등 위협 유형을 식별합니다. CISA KEV에 등재되었다면 **반드시 "Exploited in wild" 태그를 포함**해야 합니다.
    *   `description`: 비전문가도 이해할 수 있도록 1~2 문장의 간결한 한국어 요약이어야 합니다.
    *   `selection_reason`: **웹 검색으로 찾은 CISA KEV, PoC, EPSS 정보를 핵심 근거로** 사용하여, 왜 이 CVE가 다른 CVE들보다 우선적으로 처리되어야 하는지 구체적인 이유를 한국어로 설명합니다.

[입력 데이터]
- **시스템 정보:**
  - OS Version: {metadata.get('system_info', {}).get('os_release', 'N/A')}
  - Kernel: {metadata.get('system_info', {}).get('kernel', 'N/A')}
  - 설치된 패키지 목록 (일부): {json.dumps(list(installed_package_full_names)[:10], indent=2, ensure_ascii=False, default=str)} # noqa: E501
- **분석 대상 CVE 후보 목록:**
```json
{json.dumps(cves_for_prompt, indent=2, ensure_ascii=False, default=str)}
```

[출력 형식]
분석 결과를 다음의 키를 가진 단일 JSON 객체로만 반환하십시오. **객체의 최상위 키는 "security_advisories" 이어야 하며, 값은 우선순위에 따라 정렬된 CVE 정보의 배열이어야 합니다.** 다른 설명은 절대 추가하지 마세요.
```json
{{
  "security_advisories": [ // 시스템에 실제 영향을 주는 CVE만 포함
    {{ "cve_id": "<CVE-ID>", "severity": "<심각/중요>", "package": "<영향받는 패키지명>", "description": "<취약점에 대한 간결한 한국어 요약>" }}
  ]
}}```"""
        logging.debug(f"AI Security Analysis Prompt:\n{prompt}")

        response = self._make_request('cve/analyze', {"prompt": prompt})
        logging.debug(f"AI Security Analysis Response:\n{json.dumps(response, indent=2, ensure_ascii=False)}")
        advisories = response.get('security_advisories', []) or []
        return advisories

def _initialize_matplotlib_font():
    """
    [사용자 요청 반영] Matplotlib의 폰트 설정을 초기화합니다.
    지정된 경로의 'NanumGothicBold.ttf' 폰트를 로드하여 그래프에 적용합니다.
    폰트 파일이 없을 경우, 기본 폰트를 사용하고 경고를 기록합니다.
    """
    if not IS_MATPLOTLIB_AVAILABLE:
        return

    try:
        plt.rcParams['axes.unicode_minus'] = False

        # 스크립트가 위치한 디렉토리를 기준으로 폰트 파일 경로를 설정합니다.
        script_dir = Path(__file__).parent
        font_path = script_dir / 'fonts' / 'NanumGothicBold.ttf'

        if font_path.exists():
            # 폰트 매니저에 폰트 추가
            fm.fontManager.addfont(font_path)
            # Matplotlib의 기본 폰트로 설정
            plt.rcParams['font.family'] = 'NanumGothic'
            logging.info(f"Matplotlib에 커스텀 폰트 'NanumGothic'를 로드했습니다: {font_path}")
        else:
            logging.warning(Color.warn(f"지정된 폰트 파일을 찾을 수 없습니다: {font_path}. Matplotlib의 기본 폰트를 사용합니다. 그래프의 한글이 깨질 수 있습니다."))

    except Exception as e:
        logging.error(f"Matplotlib 폰트 설정 중 예외 발생: {e}. 그래프의 한글이 깨질 수 있습니다.", exc_info=True)

#--- 메인 실행 로직 ---
def main(args: argparse.Namespace):
    # [안정성 강화] 분석 시작 전, 입력된 파일 경로가 유효한지 먼저 확인합니다.
    tar_path = Path(args.tar_path)
    if not tar_path.is_file():
        logging.error(Color.error(f"치명적인 오류 발생: 입력된 파일 경로를 찾을 수 없습니다: '{args.tar_path}'"))
        logging.error(Color.error(f"스크립트가 실행된 현재 작업 디렉토리: '{os.getcwd()}'"))
        logging.error(Color.error("파일의 절대 경로를 사용하거나, 파일이 있는 디렉토리에서 스크립트를 실행해 주세요."))
        sys.exit(1)

    log_step(f"'{tar_path.name}' 분석 시작")
    extract_path = Path(tempfile.mkdtemp(prefix="sos-"))
    logging.info(Color.info(f"임시 디렉터리 생성: {extract_path}"))
    try:
        logging.info(f"[STEP] EXTRACTING: '{tar_path.name}' 압축 해제 중...")
        with tarfile.open(args.tar_path, 'r:*') as tar: tar.extractall(path=extract_path)
        logging.info(Color.success("압축 해제 완료."))

        parser = SosreportParser(extract_path)
        logging.info("[STEP] PARSING: Sosreport 파서 초기화 완료. 데이터 파싱을 시작합니다.")
        metadata, sar_data = parser.parse_all()
        
        output_dir = Path(args.output); output_dir.mkdir(exist_ok=True)
        hostname = metadata.get('system_info', {}).get('hostname', 'unknown')

        # [사용자 요청] AI 분석 전 metadata.json 파일을 먼저 저장합니다.
        # [수정] sar_data.json도 AI 분석 전에 저장합니다.
        metadata_path = output_dir / f"metadata-{hostname}.json"
        sar_data_path = output_dir / f"sar_data-{hostname}.json"
        metadata_path.write_text(json.dumps(metadata, indent=2, default=json_serializer, ensure_ascii=False), encoding='utf-8')
        sar_data_path.write_text(json.dumps(sar_data, indent=2, default=json_serializer, ensure_ascii=False), encoding='utf-8')
        logging.info(Color.success(f"파싱된 데이터 파일 저장 완료: {metadata_path.name}, {sar_data_path.name}"))

        # [BUG FIX] --server-url에 포함된 특정 API 경로를 제거하여 기본 URL만 사용하도록 수정합니다.
        # 이렇게 하면 AIAnalyzer가 여러 다른 API 엔드포인트(cve/analyze, sos/analyze_system)를 올바르게 호출할 수 있습니다.
        base_server_url = args.server_url
        # [BUG FIX] URL에서 '/api/...' 부분을 제거하여 순수 base URL만 남깁니다.
        if '/api/' in base_server_url:
            base_server_url = base_server_url.split('/api/')[0] # type: ignore

        ai_analyzer = AIAnalyzer(base_server_url, parser.report_date)
        logging.info("[STEP] ANALYZING: 병렬 AI 분석을 시작합니다.")
        log_step("2단계: 병렬 AI 분석 (시스템 & 보안)")
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix='AI_Analysis') as executor:
            future_ai = executor.submit(ai_analyzer.get_structured_analysis, metadata_path, sar_data_path, args.anonymize)
            future_sec = executor.submit(ai_analyzer.fetch_security_news, metadata, output_dir)
            
            structured_analysis = future_ai.result()
            security_advisories = future_sec.result() # type: ignore

            # [BUG FIX] _add_installed_version_to_advisories는 AIAnalyzer 클래스의 메서드이므로, ai_analyzer 인스턴스를 통해 호출해야 합니다.
            # [사용자 요청] AI가 선정한 보안 위협 목록에 설치된 패키지 버전 정보를 추가합니다.
            advisories_with_version = ai_analyzer._add_installed_version_to_advisories(security_advisories, metadata.get('installed_packages', []))
            metadata['security_advisories'] = advisories_with_version

        logging.info(Color.success("모든 AI 분석 작업 완료."))

        # [보안 분석 추가] 로컬 보안 분석기 실행
        log_step("4단계: 로컬 보안 감사 및 규칙 기반 진단")
        security_analyzer = SecurityAnalyzer()
        security_findings = security_analyzer.analyze(metadata)
        structured_analysis['security_audit_findings'] = security_findings

        # [개선] 규칙 기반 분석(Knowledge Base) 실행
        kb = KnowledgeBase(rules_dir='rules')
        kb_findings = kb.analyze(metadata)
        structured_analysis['kb_findings'] = kb_findings
        logging.info(Color.success("로컬 감사 및 진단 완료."))
            
        logging.info("[STEP] GENERATING_REPORT: 최종 보고서 생성을 시작합니다.")
        log_step("5단계: 최종 보고서 생성")
        reporter = HTMLReportGenerator(metadata, sar_data, structured_analysis, hostname, parser.report_date, parser.device_map)
        
        # [사용자 요청] 그래프 생성 시, 저장된 sar_data.json 파일을 다시 읽어 사용합니다.
        logging.info(f"  - 그래프 생성을 위해 '{sar_data_path.name}' 파일 로딩 중...")
        try:
            with open(sar_data_path, 'r', encoding='utf-8') as f:
                sar_data_for_graph = json.load(f)
            reporter.sar_data = sar_data_for_graph # 리포터의 sar_data를 파일에서 읽은 것으로 교체
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.error(Color.error(f"sar_data.json 파일을 읽는 중 오류 발생: {e}. 그래프 생성이 제한될 수 있습니다."))

        generated_graphs = reporter._generate_graphs()
        logging.info("  - 메인 보고서 HTML 콘텐츠 생성 중...")
        html_content = reporter.generate(generated_graphs)
        
        report_path = output_dir / f"report-{hostname}.html"
        report_path.write_text(html_content, encoding='utf-8')
        logging.info(Color.success(f"  - 메인 HTML 보고서 저장 완료: {report_path}"))
        
        # [사용자 요청] 동적 그래프 팝업 HTML 파일 저장
        for key, result in generated_graphs.items():
            if result and isinstance(result, tuple) and len(result) == 2:
                _, interactive_html = result
                if interactive_html:
                    popup_filename = f"popup_{key}_{hostname}.html"
                    popup_path = output_dir / popup_filename
                    logging.info(f"  - 동적 그래프 팝업 파일 저장: {popup_filename}")
                    popup_path.write_text(f'<!DOCTYPE html><html><head><title>{key.replace("_", " ").title()}</title></head><body style="margin:0;padding:0;">{interactive_html}</body></html>', encoding='utf-8')

        # [신규] 개별 디스크 I/O 그래프 페이지 생성
        logging.info("  - 디스크 상세 정보 팝업 페이지 생성 중...")
        disk_report_result = reporter._generate_individual_disk_graphs_page(sar_data)
        if disk_report_result:
            individual_disk_report_html, disk_popups = disk_report_result
            disk_report_path = output_dir / f"sar_gui_disk-{hostname}.html"
            disk_report_path.write_text(individual_disk_report_html, encoding='utf-8')
            logging.info(Color.success(f"  - 개별 디스크 I/O 보고서 저장 완료: {disk_report_path}"))
            # 디스크 팝업 파일 저장
            for popup_filename, popup_html in disk_popups.items():
                popup_path = output_dir / popup_filename
                logging.info(f"  - 디스크 상세 동적 그래프 팝업 파일 저장: {popup_filename}")
                popup_path.write_text(f'<!DOCTYPE html><html><head><title>Disk Detail</title></head><body style="margin:0;padding:0;">{popup_html}</body></html>', encoding='utf-8')

        # [신규] 개별 NIC 그래프 페이지 생성
        logging.info("  - 네트워크 상세 정보 팝업 페이지 생성 중...")
        nic_report_result = reporter._generate_individual_nic_graphs_page(sar_data, metadata)
        if nic_report_result:
            individual_nic_report_html, nic_popups = nic_report_result
            nic_report_path = output_dir / f"sar_nic_detail-{hostname}.html"
            nic_report_path.write_text(individual_nic_report_html, encoding='utf-8')
            logging.info(Color.success(f"  - 개별 NIC 보고서 저장 완료: {nic_report_path}"))
            # NIC 팝업 파일 저장
            for popup_filename, popup_html in nic_popups.items():
                popup_path = output_dir / popup_filename
                logging.info(f"  - NIC 상세 동적 그래프 팝업 파일 저장: {popup_filename}")
                popup_path.write_text(f'<!DOCTYPE html><html><head><title>NIC Detail</title></head><body style="margin:0;padding:0;">{popup_html}</body></html>', encoding='utf-8')
        logging.info(Color.success(f"\n모든 보고서 및 데이터 파일 생성이 완료되었습니다. 경로: {output_dir}"))

    except Exception as e:
        # [BUG FIX] sys.exit(1)을 호출하면 서버가 오류의 원인을 알 수 없습니다.
        # 대신, 오류 로그를 표준 출력으로 명확히 남겨 서버가 실패 원인을 파악하도록 합니다.
        logging.error(Color.error(f"치명적인 오류 발생: {e}"), exc_info=True)
        # sys.exit(1) # 이 부분을 제거합니다.
    finally:
        log_step("분석 프로세스 종료")
        if extract_path.exists(): 
            shutil.rmtree(extract_path, ignore_errors=True)
            logging.info(Color.info(f"임시 디렉터리 삭제 완료: {extract_path}"))
            

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Smart sosreport Analyzer")
    # [BUG FIX] 서버에서 모든 인자를 명령줄로 전달하는 방식으로 통일합니다.
    # 위치 인자로 파일 경로를 받고, --server-url과 --output을 옵션 인자로 받도록 수정합니다.
    parser.add_argument("tar_path", help="분석할 sosreport tar 아카이브 경로")
    parser.add_argument("--server-url", help="AI 분석을 위한 ABox_Server.py의 API 엔드포인트 URL")
    parser.add_argument("--output", default="output", help="보고서 및 데이터 저장 디렉토리")
    parser.add_argument("--anonymize", action='store_true', help="서버 전송 전 민감 정보 익명화")
    parser.add_argument("--debug", action='store_true', help="디버그 레벨 로그를 활성화합니다.")
    
    args = parser.parse_args()

    # [BUG FIX] 필수 인자인 tar_path와 server_url이 모두 제공되었는지 확인합니다.
    if not args.tar_path or not args.server_url:
        logging.error(Color.error("치명적인 오류: 스크립트 실행 시 'tar_path'와 '--server-url' 인자가 모두 필요합니다."))
        sys.exit(1)

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.info(Color.warn("디버그 로깅이 활성화되었습니다."))

    # [개선] 프로그램 시작 시 Matplotlib 폰트를 한 번만 설정합니다.
    _initialize_matplotlib_font()
    
    main(args)