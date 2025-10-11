#!/usr/bin/env python3
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
from datetime import timedelta, date
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from html_template import get_html_template

# --- Matplotlib 라이브러리 설정 ---
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.font_manager as fm
    import matplotlib.ticker as mticker
    IS_GRAPHING_ENABLED = True
except ImportError:
    matplotlib, plt, fm, mticker = None, None, None, None
    IS_GRAPHING_ENABLED = False

# --- 로깅 및 콘솔 출력 설정 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[logging.StreamHandler(sys.stdout)])

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

def log_step(message: str):
    print(f"\n{Color.header(f'===== {message} =====')}")

def json_serializer(obj):
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    raise TypeError(f"Object of type '{type(obj).__name__}' is not JSON serializable")

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

class SosreportParser:
    def __init__(self, extract_path: Path):
        subdirs = [d for d in extract_path.iterdir() if d.is_dir()]
        if not subdirs: raise FileNotFoundError(f"sosreport 베이스 디렉토리를 찾을 수 없습니다: {extract_path}")
        self.base_path = subdirs[0]
        self.report_date = datetime.datetime.now()
        self.cpu_cores_count = 0
        self.device_map = self._create_device_map() # [개선] 장치명 매핑 정보 생성
        self.dmesg_content = self._read_file(['dmesg', 'sos_commands/kernel/dmesg'])
        self._initialize_report_date()
        self._initialize_cpu_cores()

    def _read_file(self, possible_paths: List[str], default: str = 'N/A') -> str:
        for path_suffix in possible_paths:
            full_path = self.base_path / path_suffix
            if full_path.exists():
                try: return full_path.read_text(encoding='utf-8', errors='ignore').strip()
                except Exception: continue
        return default

    def _initialize_report_date(self):
        date_content = self._read_file(['sos_commands/date/date', 'date'])
        try:
            match = re.search(r'([A-Za-z]{3})\s+[A-Za-z]{3}\s+(\d{1,2})\s+[\d:]+\s+.*?(\d{4})', date_content)
            if match:
                month_abbr, day, year = match.groups()
                month_map = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
                if month_abbr in month_map: self.report_date = datetime.datetime(int(year), month_map[month_abbr], int(day))
        except Exception: pass

    def _initialize_cpu_cores(self):
        lscpu_output = self._read_file(['lscpu', 'sos_commands/processor/lscpu'])
        if match := re.search(r'^CPU\(s\):\s+(\d+)', lscpu_output, re.MULTILINE): self.cpu_cores_count = int(match.group(1))

    def _create_device_map(self) -> Dict[str, str]:
        """
        [신규] proc/partitions와 dmsetup 정보를 결합하여 (major, minor) -> device_name 매핑을 생성합니다.
        """
        device_map = {}
        # 1. /proc/partitions 파싱
        partitions_content = self._read_file(['proc/partitions'])
        for line in partitions_content.split('\n')[2:]:
            parts = line.split()
            if len(parts) == 4:
                major, minor, name = parts[0], parts[1], parts[3]
                device_map[f"{major}:{minor}"] = name

        # 2. dmsetup 정보 파싱
        dmsetup_content = self._read_file(['sos_commands/devicemapper/dmsetup_info_-c'])
        for line in dmsetup_content.split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 3:
                name, major, minor = parts[0], parts[1], parts[2]
                # dmsetup 출력의 major/minor는 ':'로 구분되어 있을 수 있음
                major = major.replace(':', '')
                device_map[f"{major}:{minor}"] = name

        return device_map

    def _safe_float(self, value: str) -> float:
        try: return float(value.replace(',', '.'))
        except (ValueError, TypeError): return 0.0

    def _parse_system_details(self) -> Dict[str, Any]:
        lscpu_output = self._read_file(['lscpu', 'sos_commands/processor/lscpu']); meminfo = self._read_file(['proc/meminfo']); dmidecode = self._read_file(['dmidecode', 'sos_commands/hardware/dmidecode'])
        mem_total_match = re.search(r'MemTotal:\s+(\d+)\s+kB', meminfo); cpu_model_match = re.search(r'Model name:\s+(.+)', lscpu_output); model_match = re.search(r'Product Name:\s*(.*)', dmidecode)
        cpu_str = f"{self.cpu_cores_count} x {cpu_model_match.group(1).strip()}" if self.cpu_cores_count > 0 and cpu_model_match else 'N/A'
        uptime_content = self._read_file(['uptime', 'sos_commands/general/uptime']); uptime_str = "N/A"
        if uptime_match := re.search(r'up\s+(.*?),\s*\d+\s+user', uptime_content): uptime_str = uptime_match.group(1).strip()
        uname_content = self._read_file(['uname', 'sos_commands/kernel/uname_-a']); kernel_str = uname_content.split()[2] if len(uname_content.split()) >= 3 else uname_content
        
        # [개선] xsos를 참고하여 'uptime -s'를 사용하여 부팅 시간을 더 정확하게 파싱합니다.
        uptime_s_content = self._read_file(['sos_commands/general/uptime_-s'])
        last_boot_str = "N/A"
        if uptime_s_content != 'N/A':
            last_boot_str = uptime_s_content.strip()
        else: # 폴백: 기존 방식 사용
            last_boot_str = self._read_file(['sos_commands/boot/who_-b']).replace('system boot', '').strip()
            
        return { 'hostname': self._read_file(['hostname']), 'os_release': self._read_file(['etc/redhat-release']), 'kernel': kernel_str, 'system_model': model_match.group(1).strip() if model_match else 'N/A', 'cpu': cpu_str, 'memory': f"{int(mem_total_match.group(1)) / 1024 / 1024:.1f} GiB" if mem_total_match else "N/A", 'uptime': uptime_str, 'last_boot': last_boot_str }

    def _parse_storage(self) -> List[Dict[str, Any]]:
        df_output = self._read_file(['df', 'sos_commands/filesys/df_-alPh']); storage_list = []
        for line in df_output.strip().split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 6 and parts[0].startswith('/'): storage_list.append({ "filesystem": parts[0], "size": parts[1], "used": parts[2], "avail": parts[3], "use_pct": parts[4], "mounted_on": parts[5] })
        return storage_list

    def _parse_process_stats(self) -> Dict[str, Any]:
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
        details = {'interfaces': [], 'routing_table': [], 'ethtool': {}, 'bonding': [], 'netdev': [], 'listening_ports': self._parse_listening_ports()}; all_ifaces = set()
        netdev_content = self._read_file(['proc/net/dev'])
        for line in netdev_content.split('\n')[2:]:
            if ':' in line:
                iface, stats = line.split(':', 1); iface, stat_values = iface.strip(), stats.split(); all_ifaces.add(iface)
                if len(stat_values) == 16: details['netdev'].append({ 'iface': iface, 'rx_bytes': int(stat_values[0]),'rx_packets': int(stat_values[1]), 'rx_errs': int(stat_values[2]), 'rx_drop': int(stat_values[3]), 'tx_bytes': int(stat_values[8]), 'tx_packets': int(stat_values[9]),'tx_errs': int(stat_values[10]),'tx_drop': int(stat_values[11]) })
        ip_addr_content = self._read_file(['sos_commands/networking/ip_addr', 'sos_commands/networking/ip_-d_address'])
        for block in re.split(r'^\d+:\s+', ip_addr_content, flags=re.MULTILINE)[1:]:
            iface_data = {}
            if match := re.match(r'([\w.-]+):', block): iface_name = match.group(1); iface_data['iface'] = iface_name; all_ifaces.add(iface_name)
            else: continue
            if match := re.search(r'state\s+(\w+)', block): iface_data['state'] = match.group(1).lower()
            if match := re.search(r'link/\w+\s+([\da-fA-F:]+)', block): iface_data['mac'] = match.group(1)
            if match := re.search(r'inet\s+([\d.]+/\d+)', block): iface_data['ipv4'] = match.group(1)
            details['interfaces'].append(iface_data)
        bonding_dir = self.base_path / 'proc/net/bonding'
        if bonding_dir.is_dir():
            for bond_file in bonding_dir.iterdir():
                bond_content = bond_file.read_text(errors='ignore'); bond_info = {'device': bond_file.name, 'slaves_info': []}
                if match := re.search(r'Bonding Mode:\s*(.*)', bond_content): bond_info['mode'] = match.group(1).strip()
                if match := re.search(r'MII Status:\s*(.*)', bond_content): bond_info['mii_status'] = match.group(1).strip()
                for slave_block in bond_content.split('Slave Interface:')[1:]:
                    slave_info = {'name': slave_block.strip().split('\n')[0].strip()}
                    if m := re.search(r'MII Status:\s*(.*)', slave_block): slave_info['mii_status'] = m.group(1).strip()
                    if m := re.search(r'Speed:\s*(.*)', slave_block): slave_info['speed'] = m.group(1).strip()
                    bond_info['slaves_info'].append(slave_info)
                details['bonding'].append(bond_info)
        for iface_name in sorted(list(all_ifaces)):
            ethtool_i = self._read_file([f'sos_commands/networking/ethtool_-i_{iface_name}']); ethtool_main = self._read_file([f'sos_commands/networking/ethtool_{iface_name}']); ethtool_g = self._read_file([f'sos_commands/networking/ethtool_-g_{iface_name}']); iface_ethtool = {}
            if m := re.search(r'driver:\s*(.*)', ethtool_i): iface_ethtool['driver'] = m.group(1).strip()
            if m := re.search(r'firmware-version:\s*(.*)', ethtool_i): iface_ethtool['firmware'] = m.group(1).strip()
            if m := re.search(r'Link detected:\s*(yes|no)', ethtool_main): iface_ethtool['link'] = m.group(1)
            if m := re.search(r'Speed:\s*(.*)', ethtool_main): iface_ethtool['speed'] = m.group(1).strip()
            if m := re.search(r'Duplex:\s*(.*)', ethtool_main): iface_ethtool['duplex'] = m.group(1).strip()
            rx_max_match = re.search(r'RX:\s*(\d+)', ethtool_g)
            rx_now_match = re.search(r'Current hardware settings:[\s\S]*?RX:\s*(\d+)', ethtool_g)
            iface_ethtool['rx_ring'] = f"{rx_now_match.group(1)}/{rx_max_match.group(1)}" if rx_now_match and rx_max_match else 'N/A'
            details['ethtool'][iface_name] = iface_ethtool
        details['routing_table'] = self._parse_routing_table()
        return details

    def _parse_routing_table(self) -> List[Dict[str, str]]:
        content = self._read_file(['sos_commands/networking/ip_route_show_table_all']); routes = []
        for line in content.split('\n'):
            parts = line.split();
            if not parts or parts[0] in ["broadcast", "local", "unreachable"]: continue
            route = {'destination': parts[0]}
            if 'via' in parts: route['gateway'] = parts[parts.index('via') + 1]
            if 'dev' in parts: route['device'] = parts[parts.index('dev') + 1]
            routes.append(route)
        return routes

    def _parse_additional_info(self) -> Dict[str, Any]:
        sysctl = {k.strip(): v.strip() for k,v in (l.split('=',1) for l in self._read_file(['sos_commands/kernel/sysctl_-a']).split('\n') if '=' in l)}
        sestatus = {k.strip().lower().replace(' ','_'): v.strip() for k,v in (l.split(':',1) for l in self._read_file(['sos_commands/selinux/sestatus_-v']).split('\n') if ':' in l)}
        rpms = sorted(list(set(l.strip() for l in self._read_file(['installed-rpms']).split('\n') if l.strip() and not l.startswith('gpg-pubkey'))))
        failed_services = [l.strip().split()[0] for l in self._read_file(['sos_commands/systemd/systemctl_list-units_--all']).split('\n') if 'failed' in l]
        return { "kernel_parameters": {k: sysctl.get(k, 'N/A') for k in ['vm.swappiness', 'net.core.somaxconn', 'fs.file-max']}, "selinux_status": sestatus, "installed_packages": rpms, "failed_services": failed_services }

    def _parse_sar_data(self) -> Dict[str, List[Dict]]:
        report_day_str = self.report_date.strftime('%d'); content = self._read_file([f'var/log/sa/sar{report_day_str}', f'sos_commands/sar/sar{report_day_str}', 'sos_commands/monitoring/sar_-A'])
        if content == 'N/A' or not content.strip(): return {}
        data: Dict[str, List[Dict]] = {}; header_map, current_section = {}, None
        section_keys = {
            'disk_detail': {'avgrq-sz', 'avgqu-sz', 'await', 'svctm', '%util'},
            'cpu': {'%user', '%usr', '%system', '%iowait', '%idle'},
            'memory': {'kbmemfree', 'kbmemused', '%memused'},
            'disk': {'tps', 'rtps', 'wtps', 'rkB/s', 'wkB/s', 'rd_sec/s', 'wr_sec/s', 'bread/s', 'bwrtn/s'},
            'load': {'runq-sz', 'ldavg-1', 'ldavg-5'},
            'swap': {'kbswpfree', 'kbswpused', '%swpused'},
            'network': {'IFACE', 'rxpck/s', 'txpck/s', 'rxkB/s', 'txkB/s'}
        }
        for line in content.strip().replace('\r\n', '\n').split('\n'):
            line = line.strip()
            if not line or line.startswith(('Average:', 'Linux')): header_map, current_section = {}, None; continue
            is_header = re.match(r'^\d{2}:\d{2}:\d{2}(?:\s+PM|AM)?', line) and any(k in line for k in ['CPU', '%', 'IFACE', 'kb', 'tps', 'ldavg', 'runq-sz'])
            if is_header:
                parts = re.split(r'\s+', line); metric_start_idx = 2 if len(parts) > 1 and parts[1] in ['AM', 'PM'] else 1
                header_cols_raw = parts[metric_start_idx:]
                header_cols = [p.replace('%', 'pct_').replace('/', '_').replace('%usr', 'pct_user') for p in header_cols_raw]
                header_map = {col: i for i, col in enumerate(header_cols)}
                current_section = None # 섹션 재탐색을 위해 초기화
                
                # [BUG FIX] `sar -d`와 `sar -b`를 명확히 구분합니다.
                # `sar -d`는 'DEV'와 '%util' 또는 'avgqu-sz'를 포함합니다.
                # `sar -b`는 'bread/s' 또는 'bwrtn/s'를 포함하지만 'DEV'는 없습니다.
                is_disk_detail = 'DEV' in header_cols_raw and ('%util' in header_cols_raw or 'avgqu-sz' in header_cols_raw)
                is_disk_io = ('bread/s' in header_cols_raw or 'bwrtn/s' in header_cols_raw) and 'DEV' not in header_cols_raw

                if is_disk_detail:
                    current_section = 'disk_detail'
                elif is_disk_io:
                    current_section = 'disk'
                else:
                    for sec, keys in section_keys.items():
                        if sec not in ['disk', 'disk_detail'] and any(key in header_cols_raw for key in keys):
                            current_section = sec; break
                continue
            if current_section and header_map and (parts := re.split(r'\s+', line)) and re.match(r'^\d{2}:\d{2}:\d{2}', parts[0]):
                ts_end_idx = 2 if len(parts) > 1 and parts[1] in ['AM', 'PM'] else 1
                ts_str = " ".join(parts[:ts_end_idx])
                
                # [핵심 개선] 파싱 단계에서 timestamp를 완전한 datetime 객체로 변환 후 ISO 형식 문자열로 저장합니다.
                try:
                    format_str = '%I:%M:%S %p' if 'M' in ts_str else '%H:%M:%S'
                    dt_obj = datetime.datetime.strptime(ts_str, format_str)
                    full_dt = self.report_date.replace(hour=dt_obj.hour, minute=dt_obj.minute, second=dt_obj.second)
                    timestamp_iso = full_dt.isoformat()
                except ValueError:
                    continue # 시간 파싱 실패 시 해당 라인 건너뛰기

                values = parts[ts_end_idx:]
                entry = {'timestamp': timestamp_iso}
                for h, i in header_map.items():
                    if i < len(values):
                        entry[h] = self._safe_float(values[i]) if h not in ['IFACE', 'DEV', 'CPU'] else values[i]
                
                # [개선] DEV 컬럼이 있으면 실제 장치명으로 변환
                if 'DEV' in entry and entry['DEV'].startswith('dev'):
                    major, minor = entry['DEV'][3:].split('-') # type: ignore
                    device_name = self.device_map.get(f"{major}:{minor}")
                    if device_name:
                        entry['device_name'] = device_name

                if current_section == 'cpu' and entry.get('CPU') != 'all': continue
                if current_section == 'network' and entry.get('IFACE') == 'lo': continue
                data.setdefault(current_section, []).append(entry)
        
        # [개선] 파싱된 데이터 개수를 요약하여 출력
        summary = ", ".join([f"{key}: {len(value)}" for key, value in data.items()])
        logging.info(f"SAR 데이터 파싱 완료. [{summary}]")
        return data

    def _find_sar_data_around_time(self, sar_section_data: List[Dict], target_dt: datetime.datetime, window_minutes: int = 2) -> Optional[Dict]:
        if not sar_section_data: return None
        closest_entry, min_delta = None, timedelta.max
        for entry in sar_section_data:
            try:
                ts_str = entry['timestamp']; dt = datetime.datetime.strptime(ts_str, '%I:%M:%S %p') if 'M' in ts_str else datetime.datetime.strptime(ts_str, '%H:%M:%S')
                entry_dt = self.report_date.replace(hour=dt.hour, minute=dt.minute, second=dt.second); delta = abs(entry_dt - target_dt)
                if delta < min_delta: min_delta, closest_entry = delta, entry
            except (ValueError, KeyError): continue
        return closest_entry.copy() if closest_entry and min_delta <= timedelta(minutes=window_minutes) else None

    def _analyze_logs_and_correlate_events(self, sar_data: Dict) -> Dict:
        log_content = self._read_file(['var/log/messages', 'var/log/syslog']); critical_events = []
        if log_content == 'N/A': return {"critical_log_events": []}
        for line in log_content.split('\n'):
            if match := re.match(r'^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line):
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
        analysis = {}
        if cpu_data := sar_data.get('cpu'):
            if high_iowait := [d for d in cpu_data if d.get('pct_iowait', 0) > 20]: analysis['io_bottleneck'] = f"CPU I/O Wait이 20%를 초과한 경우가 {len(high_iowait)}번 감지되었습니다."
        if load_data := sar_data.get('load'):
            if self.cpu_cores_count > 0 and (high_load := [d for d in load_data if d.get('ldavg-5', 0) > self.cpu_cores_count * 1.5]): analysis['high_load_average'] = f"5분 평균 부하가 CPU 코어 수의 1.5배를 초과한 경우가 {len(high_load)}번 감지되었습니다."
        if swap_data := sar_data.get('swap'):
            if swap_data and (max_swap := max(d.get('pct_swpused',0) for d in swap_data)) > 10: analysis['swap_usage'] = f"최대 스왑 사용률이 {max_swap:.1f}%에 달했습니다."
        return analysis

    def parse_all(self) -> tuple[Dict[str, Any], Dict[str, Any]]:
        log_step("sosreport 데이터 파싱 시작")
        metadata = { "system_info": self._parse_system_details(), "storage": self._parse_storage(), "processes": self._parse_process_stats(), "network": self._parse_network_details(), **self._parse_additional_info() }
        sar_data = self._parse_sar_data()
        log_analysis = self._analyze_logs_and_correlate_events(sar_data); perf_analysis = self._analyze_performance_bottlenecks(sar_data)
        metadata.update(log_analysis); metadata["performance_analysis"] = perf_analysis
        logging.info(Color.success("모든 데이터 파싱 및 추가 분석 완료."))
        return metadata, sar_data

class AIAnalyzer:
    def __init__(self, api_url: str, report_date: datetime.datetime):
        self.api_url = api_url.rstrip('/')
        self.report_date = report_date
        self.session = requests.Session()
        self.session.headers.update({'Content-Type': 'application/json', 'Accept': 'application/json'})

    def _create_system_analysis_prompt(self, metadata: Dict) -> str:
        data_to_send = {
            "system_info": metadata.get("system_info"),
            "performance_analysis": metadata.get("performance_analysis"),
            "critical_log_events": metadata.get("critical_log_events"),
            "kernel_parameters": metadata.get("kernel_parameters"),
            "selinux_status": metadata.get("selinux_status"),
        }
        data_str = json.dumps(data_to_send, indent=2, ensure_ascii=False, default=str)

        return f"""당신은 Red Hat Enterprise Linux 시스템의 문제를 해결하는 최고 수준의 전문가입니다. 다음 sosreport에서 추출한 데이터를 종합적으로 검토하여, 전문가 수준의 진단과 해결책을 한국어로 제공해주세요.

## 분석 데이터
```json
{data_str}
```

## 분석 가이드라인
1.  **critical_log_events 최우선 분석**: 각 이벤트의 `log_message`와 `correlated_context`를 함께 분석하여 문제의 **근본 원인**을 추론하세요.
2.  **performance_analysis 결과와 연계**: 진단된 성능 병목 현상을 다른 데이터와 연관 지어 설명하세요.
3.  **kernel_parameters 및 SELinux 확인**: 비표준 커널 파라미터나 SELinux 상태가 문제와 관련 있는지 분석하세요. SELinux가 `Enforcing` 모드가 아니면 보안 위험으로 반드시 언급해야 합니다.

## 최종 출력 형식
**모든 내용은 반드시 자연스러운 한국어로 작성해주세요.**

```json
{{
  "critical_issues": ["상관관계 분석 및 성능 분석을 기반으로 식별된 심각한 문제들의 구체적인 설명"],
  "warnings": ["주의가 필요한 로그 패턴, 서비스 실패, 커널 설정 등의 사항"],
  "recommendations": [
    {{
      "priority": "높음|중간|낮음",
      "category": "성능|보안|안정성|유지보수",
      "issue": "근본 원인에 대한 설명 (데이터 기반)",
      "solution": "구체적이고 실행 가능한 해결 방안"
    }}
  ],
  "summary": "시스템 상태와 핵심 문제, 가장 시급한 권장사항에 대한 종합 요약"
}}
```
**중요**: 당신의 전체 응답은 오직 위 형식의 단일 JSON 객체여야 합니다.
"""

    def get_structured_analysis(self, metadata: Dict, anonymize: bool) -> Dict:
        log_step("전문가 프롬프트 기반 AI 시스템 분석 요청")
        
        data_for_prompt = metadata
        if anonymize:
            anonymizer = DataAnonymizer()
            hostnames = [metadata.get("system_info", {}).get("hostname", "")]
            data_for_prompt = anonymizer.anonymize_data(metadata, specific_hostnames=hostnames)
            logging.info("데이터 익명화 완료.")

        prompt = self._create_system_analysis_prompt(data_for_prompt)
        payload = {"prompt": prompt, "data": data_for_prompt}

        try:
            logging.info(f"AI 분석 서버로 요청 전송: {self.api_url}")
            response = self.session.post(self.api_url, json=payload, timeout=300)
            response.raise_for_status()

            # [개선] 서버 응답이 JSON이 아닐 경우를 대비한 예외 처리 강화
            try:
                analysis_result = response.json()
            except json.JSONDecodeError:
                logging.error("서버로부터 유효한 JSON 응답을 받지 못했습니다. HTML 오류 페이지일 수 있습니다.")
                logging.error(f"서버 응답 내용 (첫 500자): {response.text[:500]}")
                # JSON 파싱 실패 시, 오류를 포함한 기본 구조를 반환하여 프로그램 중단을 방지합니다.
                return {
                    "summary": "AI 분석 서버로부터 유효한 응답을 받지 못했습니다.",
                    "critical_issues": ["서버가 JSON이 아닌 응답을 반환했습니다. 서버 로그를 확인하세요."],
                    "warnings": [], "recommendations": []
                }

            logging.info(Color.success("서버로부터 AI 분석 결과 수신 완료."))
            return analysis_result

        except requests.exceptions.RequestException as e:
            logging.error(f"AI 분석 서버 통신 오류: {e}")
            error_details = str(e)
            if e.response is not None:
                try: error_details = e.response.json().get('details', e.response.text)
                except json.JSONDecodeError: error_details = e.response.text[:500]
            
            return {
                "summary": f"AI 분석 서버와 통신하는 데 실패했습니다.",
                "critical_issues": [f"서버 통신 오류: {error_details}"],
                "warnings": [], "recommendations": []
            }

    def fetch_security_news(self, metadata: Dict) -> List[Dict]:
        log_step("스마트 보안 위협 분석 시작 (컨텍스트 기반 엔진)")
        
        all_findings = []
        
        if metadata.get("selinux_status", {}).get("current_mode") != "enforcing":
            all_findings.append({
                "type": "Configuration", "id": "SELINUX_DISABLED", "severity": "Critical",
                "package": "selinux-policy", "description": "SELinux가 enforcing 모드가 아닙니다. 시스템이 주요 보안 위협에 노출될 수 있습니다."
            })
        
        db_ports = {3306: "mysql/mariadb", 5432: "postgresql"}
        for port_info in metadata.get("network", {}).get("listening_ports", []):
            if port_info.get("port") in db_ports and port_info.get("address") in ["0.0.0.0", "::"]:
                 all_findings.append({
                    "type": "Configuration", "id": f"DB_PORT_PUBLIC_{port_info['port']}", "severity": "Critical",
                    "package": db_ports[port_info['port']], "description": f"데이터베이스 포트({port_info['port']})가 모든 네트워크 인터페이스에 열려있어 외부 공격에 노출될 수 있습니다."
                })

        CVE_DATA_PATH = "/data/iso/AIBox/cve_data.json"
        if not Path(CVE_DATA_PATH).exists():
            logging.warning(f"CVE 데이터 파일({CVE_DATA_PATH})을 찾을 수 없어 CVE 분석을 건너<binary data, 2 bytes><binary data, 1 bytes><binary data, 1 bytes>니다.")
        else:
            try:
                with open(CVE_DATA_PATH, 'r', encoding='utf-8') as f: cve_data = json.load(f)
                critical_components = {'kernel', 'glibc', 'openssl', 'httpd', 'nginx', 'java', 'python', 'bash', 'sudo', 'systemd', 'qemu-kvm', 'mariadb', 'postgresql'}
                installed_critical_pkgs = { re.match(r'([a-zA-Z0-9_-]+)', pkg).group(1) for pkg in metadata.get("installed_packages", []) if re.match(r'([a-zA-Z0-9_-]+)', pkg) and re.match(r'([a-zA-Z0-9_-]+)', pkg).group(1) in critical_components }
                logging.info(f"분석 대상 핵심 컴포넌트: {', '.join(sorted(list(installed_critical_pkgs)))}")

                relevant_cves = []
                for cve in cve_data:
                    if cve.get('severity') not in ['critical', 'important']: continue
                    affected_pkgs = {p.split(':')[0] for p in cve.get('affected_packages', [])}
                    if installed_critical_pkgs.intersection(affected_pkgs):
                        relevant_cves.append(cve)
                
                logging.info(f"{len(relevant_cves)}개의 관련 CVE를 찾았습니다. AI 기반 우선순위 분석 시작.")

                if relevant_cves:
                    for cve in relevant_cves:
                        score = 0
                        if cve.get('severity') == 'critical': score += 100
                        if isinstance(cve.get('cvss3'), dict):
                             try:
                                score_str = cve['cvss3'].get('cvss3_base_score')
                                if score_str: score += float(score_str) * 10
                             except (ValueError, TypeError): pass
                        cve['priority_score'] = score
                    
                    prioritized_cves = sorted(relevant_cves, key=lambda x: x.get('priority_score', 0), reverse=True)

                    for cve in prioritized_cves:
                        all_findings.append({
                            "type": "CVE", "id": cve.get('CVE'), "severity": cve.get('severity', 'N/A').capitalize(),
                            "package": ', '.join(sorted(list({p.split(':')[0] for p in cve.get('affected_packages', [])}))) or 'N/A',
                            "description": cve.get('bugzilla_description', 'N/A').split('\n\nStatement:')[0]
                        })

            except (json.JSONDecodeError, FileNotFoundError) as e:
                logging.error(f"CVE 데이터 파일을 처리하는 중 오류 발생: {e}")

        severity_map = {'Critical': 0, 'Important': 1}
        sorted_findings = sorted(all_findings, key=lambda x: severity_map.get(x.get('severity'), 2))
        top_findings = sorted_findings[:10]

        logging.info(Color.success(f"스마트 보안 분석 완료. 총 {len(all_findings)}개의 잠재 위협 발견, 상위 {len(top_findings)}개 선정."))
        
        return [{'cve_id': f.get('id'),'severity': f.get('severity'),'package': f.get('package'),'description': f.get('description')} for f in top_findings]


class HTMLReportGenerator:
    def __init__(self, metadata: Dict, sar_data: Dict, ai_analysis: Dict, hostname: str, report_date: datetime.datetime):
        self.metadata, self.sar_data, self.ai_analysis, self.hostname = metadata, sar_data, ai_analysis, hostname
        self._setup_korean_font()
        self.report_date = report_date # [BUG FIX] report_date 속성을 초기화합니다.

    def _setup_korean_font(self):
        if not IS_GRAPHING_ENABLED: return
        font_paths = ['/usr/share/fonts/nanum/NanumGothicBold.ttf', 'NanumGothicBold.ttf']
        font_path = next((path for path in font_paths if Path(path).exists()), None)
        if font_path:
            try:
                fm.fontManager.addfont(font_path)
                plt.rc('font', family='NanumGothic', size=10); plt.rc('axes', unicode_minus=False)
            except Exception as e: logging.warning(f"한글 폰트 로드 실패: {e}")
        else:
             logging.warning("나눔고딕 폰트를 찾을 수 없습니다. 'yum install nanum-gothic-fonts' 등으로 설치해주세요.")

    def _generate_graphs(self) -> Dict[str, Any]:
        if not IS_GRAPHING_ENABLED: return {}
        log_step("그래프 생성 시작")
        graphs, sar = {}, self.sar_data
        
        logging.info("  - 그래프 생성 중: CPU Usage")
        graphs['cpu'] = self._create_plot(sar.get('cpu'), 'CPU Usage (%)', {'pct_user': 'User', 'pct_system': 'System', 'pct_iowait': 'I/O Wait'}, True)
        logging.info("  - 그래프 생성 중: Memory Usage")
        graphs['memory'] = self._create_plot(sar.get('memory'), 'Memory Usage (KB)', {'kbmemused': 'Used', 'kbcached': 'Cached'})
        logging.info("  - 그래프 생성 중: System Load Average")
        graphs['load'] = self._create_plot(sar.get('load'), 'System Load Average', {'ldavg-1': '1-min', 'ldavg-5': '5-min', 'ldavg-15': '15-min'})

        # [요청 반영] Disk I/O 그래프 생성 로직 수정
        if sar.get('disk'):
            logging.info("  - 그래프 생성 중: Disk I/O")

        disk_data = sar.get('disk')
        if disk_data and disk_data[0]:
            aggregated_disk_data = {}
            for entry in disk_data:
                ts = entry['timestamp']
                if ts not in aggregated_disk_data:
                    # 복사 시 숫자형 데이터만 초기화
                    aggregated_disk_data[ts] = {k: v for k, v in entry.items() if not isinstance(v, (int, float))}
                    aggregated_disk_data[ts].update({k: 0 for k, v in entry.items() if isinstance(v, (int, float))})
                else:
                    for key, value in entry.items():
                        if isinstance(value, (int, float)):
                            aggregated_disk_data[ts][key] = aggregated_disk_data[ts].get(key, 0) + value

            aggregated_list = list(aggregated_disk_data.values())

            # [요청 반영] bread/s, bwrtn/s 우선 처리
            # [BUG FIX] 파싱 시 '/'가 '_'로 변환되므로, 변환된 키('bread_s', 'bwrtn_s')를 사용해야 합니다.
            #           기존 코드에서 'bread/s'를 찾으려고 해서 그래프가 생성되지 않았습니다.
            if 'bread_s' in aggregated_list[0] and 'bwrtn_s' in aggregated_list[0]:
                graphs['disk'] = self._create_plot(aggregated_list, 'Disk I/O (blocks/s)', {'bread_s': 'Read Blocks/s', 'bwrtn_s': 'Write Blocks/s'})
            elif 'rd_sec_s' in aggregated_list[0]: graphs['disk'] = self._create_plot(aggregated_list, 'Disk I/O (sectors/s)', {'rd_sec_s': 'Read', 'wr_sec_s': 'Write'})
            elif 'rkB_s' in aggregated_list[0]: graphs['disk'] = self._create_plot(aggregated_list, 'Disk I/O (kB/s)', {'rkB_s': 'Read', 'wkB_s': 'Write'})

        if sar.get('swap'):
            logging.info("  - 그래프 생성 중: Swap Usage")
        graphs['swap'] = self._create_plot(sar.get('swap'), 'Swap Usage (%)', {'pct_swpused': 'Used %'})
        
        # [요청 반영] Network Traffic 그래프를 rxkB/s, txkB/s 기준으로 생성
        if sar.get('network'):
            logging.info("  - 그래프 생성 중: Network Traffic")
            graphs['network'] = {}
            net_by_iface = {}; [net_by_iface.setdefault(d.get('IFACE'), []).append(d) for d in sar['network'] if d.get('IFACE')]
            up_interfaces = {iface['iface'] for iface in self.metadata.get('network', {}).get('interfaces', []) if iface.get('state') == 'up'}
            for iface, data in net_by_iface.items():
                # rxkB_s 또는 txkB_s 데이터가 있는지 확인
                if iface in up_interfaces and len(data) > 1 and any('rxkB_s' in d or 'txkB_s' in d for d in data):
                    logging.info(f"    - 생성: Network Traffic ({iface})")
                    graphs['network'][iface] = self._create_plot(data, f'Network Traffic: {iface} (kB/s)', {'rxkB_s': 'RX kB/s', 'txkB_s': 'TX kB/s'})
        return graphs

    def _generate_individual_disk_graphs_page(self, sar_data: Dict) -> Optional[str]:
        """[신규] 개별 디스크 장치에 대한 상세 I/O 그래프 HTML 페이지를 생성합니다."""
        if not IS_GRAPHING_ENABLED or 'disk_detail' not in sar_data:
            return None

        disk_detail_data = sar_data['disk_detail']
        graphs_by_dev = {}
        
        # 장치별로 데이터 그룹화
        dev_data = {}
        for entry in disk_detail_data:
            dev_name = entry.get('device_name') or entry.get('DEV')
            if dev_name:
                dev_data.setdefault(dev_name, []).append(entry)

        # 각 장치에 대해 그래프 생성
        for dev_name, data in dev_data.items():
            if len(data) < 2: continue # 데이터가 너무 적으면 건너뛰기

            # 각 장치에 대해 3개의 그래프 생성
            graphs_by_dev[dev_name] = {
                'tps': self._create_plot(data, f'Transactions per second ({dev_name})', {'tps': 'TPS'}),
                'io': self._create_plot(data, f'I/O Sectors/s ({dev_name})', {'rd_sec_s': 'Read', 'wr_sec_s': 'Write'}),
                'util': self._create_plot(data, f'Queue and Utilization ({dev_name})', {'avgqu-sz': 'Queue Size', 'pct_util': '%Util'})
            }

        # HTML 페이지 생성
        graph_html_parts = []
        for dev_name, graphs in graphs_by_dev.items():
            graph_html_parts.append(f'<div class="device-section"><h2>Device: {dev_name}</h2><div class="graph-grid">')
            for title, b64_img in graphs.items():
                if b64_img:
                    graph_html_parts.append(f'<div class="graph-container"><img src="data:image/png;base64,{b64_img}" alt="{title} graph"></div>')
            graph_html_parts.append('</div></div>')

        return f"""<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><title>Block Device I/O Details</title><style>
            body {{ font-family: sans-serif; background-color: #f0f2f5; margin: 0; padding: 2rem; }}
            h1 {{ text-align: center; color: #333; }}
            .device-section {{ background: #fff; border-radius: 8px; margin-bottom: 2rem; padding: 1.5rem; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
            .device-section h2 {{ margin-top: 0; border-bottom: 1px solid #eee; padding-bottom: 1rem; }}
            .graph-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 1.5rem; }}
            .graph-container img {{ max-width: 100%; height: auto; }}
            </style></head><body><h1>Block Device I/O Details</h1>{''.join(graph_html_parts)}</body></html>"""

    def _create_plot(self, data, title, labels, is_stack=False):
        if not data: return None

        # [개선] ISO 형식의 timestamp 문자열을 datetime 객체로 변환합니다.
        timestamps_str = [d['timestamp'] for d in data]
        timestamps_dt = []
        for ts_str in timestamps_str:
            try:
                timestamps_dt.append(datetime.datetime.fromisoformat(ts_str))
            except ValueError:
                timestamps_dt.append(ts_str) # 파싱 실패 시 원본 문자열 사용 (폴백)

        fig, ax = plt.subplots(figsize=(12, 6))
        if is_stack: ax.stackplot(timestamps_dt, [[self._safe_float(d.get(k, 0)) for d in data] for k in labels.keys()], labels=list(labels.values()))
        else:
            for key, label in labels.items(): ax.plot(timestamps_dt, [self._safe_float(d.get(key, 0)) for d in data], label=label)
        ax.set_title(title, fontsize=14, weight='bold'); ax.legend(fontsize='small'); ax.grid(True, linestyle='--', alpha=0.6)
        
        # [요청 반영] x축 포맷을 'HH:MM' 형식으로 지정합니다.
        ax.xaxis.set_major_formatter(matplotlib.dates.DateFormatter('%H:%M', tz=self.report_date.tzinfo))
        ax.xaxis.set_major_locator(mticker.MaxNLocator(nbins=10, prune='both'))
        plt.xticks(rotation=30, ha='right')
        # [개선] 레이블이 잘리지 않도록 tight_layout()을 savefig 전에 호출합니다.
        plt.tight_layout()
        buf = io.BytesIO(); plt.savefig(buf, format='png'); plt.close(fig)
        return base64.b64encode(buf.getvalue()).decode('utf-8')

    def _create_plot_dual_axis(self, data, title, labels1, labels2):
        if not data: return None
        fig, ax1 = plt.subplots(figsize=(12, 6)); ax2 = ax1.twinx()

        # [개선] ISO 형식의 timestamp 문자열을 datetime 객체로 변환합니다.
        timestamps_str = [d['timestamp'] for d in data]
        timestamps_dt = []
        for ts_str in timestamps_str:
            try:
                timestamps_dt.append(datetime.datetime.fromisoformat(ts_str))
            except ValueError:
                timestamps_dt.append(ts_str)

        colors1 = ['tab:blue', 'tab:cyan']; colors2 = ['tab:red', 'tab:orange']
        for (key, label), color in zip(labels1.items(), colors1): ax1.plot(timestamps_dt, [self._safe_float(d.get(key,0)) for d in data], label=label, color=color)
        for (key, label), color in zip(labels2.items(), colors2): ax2.plot(timestamps_dt, [self._safe_float(d.get(key,0)) for d in data], label=label, linestyle='--', color=color)
        ax1.set_title(title, fontsize=14, weight='bold'); ax1.set_ylabel('Packets/s'); ax2.set_ylabel('kB/s')
        lines1, labels1 = ax1.get_legend_handles_labels(); lines2, labels2 = ax2.get_legend_handles_labels()
        ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left', fontsize='small'); plt.tight_layout(); ax1.grid(True, linestyle='--', alpha=0.6)
        ax1.xaxis.set_major_formatter(matplotlib.dates.DateFormatter('%H:%M', tz=self.report_date.tzinfo))
        ax1.xaxis.set_major_locator(mticker.MaxNLocator(nbins=10, prune='both'))
        plt.setp(ax1.get_xticklabels(), rotation=30, ha='right')
        buf = io.BytesIO(); plt.savefig(buf, format='png'); plt.close(fig)
        return base64.b64encode(buf.getvalue()).decode('utf-8')

    def _safe_float(self, value):
        try: return float(value)
        except (ValueError, TypeError): return 0.0

    def generate(self) -> str:
        graphs = self._generate_graphs()
        template_data = {
            "hostname": self.hostname, 
            "ai_analysis": self.ai_analysis,
            "graphs": graphs,
            "security_advisories": self.metadata.get('security_advisories', []),
            **self.metadata
        }
        return get_html_template(template_data)

#--- 메인 실행 로직 ---
def main(args: argparse.Namespace):
    extract_path = Path(tempfile.mkdtemp(prefix="sos-"))
    try:
        log_step(f"'{args.tar_path}' 압축 해제 중")
        with tarfile.open(args.tar_path, 'r:*') as tar: tar.extractall(path=extract_path)

        parser = SosreportParser(extract_path)
        metadata, sar_data = parser.parse_all()
        
        hostname = metadata.get('system_info', {}).get('hostname', 'unknown')

        ai_analyzer = AIAnalyzer(args.server_url, parser.report_date)
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_ai = executor.submit(ai_analyzer.get_structured_analysis, metadata, args.anonymize)
            future_sec = executor.submit(ai_analyzer.fetch_security_news, metadata)
            structured_analysis = future_ai.result()
            security_advisories = future_sec.result()
            metadata['security_advisories'] = security_advisories
            
        reporter = HTMLReportGenerator(metadata, sar_data, structured_analysis, hostname, parser.report_date)
        html_content = reporter.generate()

        output_dir = Path(args.output); output_dir.mkdir(exist_ok=True)
        
        report_path = output_dir / f"report-{hostname}.html"
        report_path.write_text(html_content, encoding='utf-8')
        logging.info(Color.success(f"HTML 보고서 저장 완료: {report_path}"))

        # [신규] 개별 디스크 I/O 그래프 페이지 생성
        individual_disk_report_html = reporter._generate_individual_disk_graphs_page(sar_data)
        if individual_disk_report_html:
            disk_report_path = output_dir / f"sar_gui_disk-{hostname}.html"
            disk_report_path.write_text(individual_disk_report_html, encoding='utf-8')
            logging.info(Color.success(f"개별 디스크 I/O 보고서 저장 완료: {disk_report_path}"))
        
        (output_dir / f"metadata-{hostname}.json").write_text(json.dumps(metadata, indent=2, default=json_serializer, ensure_ascii=False), encoding='utf-8')
        (output_dir / f"sar_data-{hostname}.json").write_text(json.dumps(sar_data, indent=2, default=json_serializer, ensure_ascii=False), encoding='utf-8')
        logging.info(Color.success(f"JSON 데이터 저장 완료: {output_dir}"))

    except Exception as e:
        logging.error(f"치명적인 오류 발생: {e}", exc_info=True)
        sys.exit(1)
    finally:
        if extract_path.exists(): shutil.rmtree(extract_path, ignore_errors=True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Smart sosreport Analyzer")
    parser.add_argument("tar_path", help="분석할 sosreport tar 아카이브 경로")
    parser.add_argument("--output", default="output", help="보고서 및 데이터 저장 디렉토리")
    parser.add_argument("--server-url", required=True, help="AI 분석을 위한 ABox_Server.py의 API 엔드포인트 URL (예: http://12.34.56.78/AIBox/api/sos/analyze_system)")
    parser.add_argument("--anonymize", action='store_true', help="서버 전송 전 민감 정보 익명화")
    main(parser.parse_args())