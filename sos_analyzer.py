#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ==============================================================================
# Smart sosreport Analyzer - The Truly Final & Stabilized Edition
# ------------------------------------------------------------------------------
# [개선]
# 1. 'AI 선정 긴급 보안 위협' 로직을 Red Hat 보안 API와 연동하여 완벽 복원.
# 2. SAR 데이터 파서의 안정성을 향상하여 CPU 그래프 미출력 문제를 해결.
# 3. 코드 전반의 안정성과 유지보수성을 위한 추가 개선 적용.
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
        return { 'hostname': self._read_file(['hostname']), 'os_release': self._read_file(['etc/redhat-release']), 'kernel': kernel_str, 'system_model': model_match.group(1).strip() if model_match else 'N/A', 'cpu': cpu_str, 'memory': f"{int(mem_total_match.group(1)) / 1024 / 1024:.1f} GiB" if mem_total_match else "N/A", 'uptime': uptime_str, 'last_boot': self._read_file(['sos_commands/boot/who_-b']).replace('system boot', '').strip() }

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

    def _parse_network_details(self) -> Dict[str, Any]:
        details = {'interfaces': [], 'routing_table': [], 'ethtool': {}, 'bonding': [], 'netdev': []}; all_ifaces = set()
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
        # [BUG FIX] CPU 그래프 미출력 문제 해결을 위해 파서 안정성 강화
        report_day_str = self.report_date.strftime('%d'); content = self._read_file([f'var/log/sa/sar{report_day_str}', f'sos_commands/sar/sar{report_day_str}', 'sos_commands/monitoring/sar_-A'])
        if content == 'N/A' or not content.strip(): return {}
        
        data: Dict[str, List[Dict]] = {}; header_map, current_section = {}, None
        
        # [개선] 각 섹션을 식별하기 위한 키워드 집합 정의
        section_keys = {
            'cpu': {'%user', '%usr', '%system', '%iowait', '%idle'},
            'memory': {'kbmemfree', 'kbmemused', '%memused'},
            'disk': {'tps', 'rtps', 'wtps', 'rkB/s', 'wkB/s'},
            'load': {'runq-sz', 'ldavg-1', 'ldavg-5'},
            'swap': {'kbswpfree', 'kbswpused', '%swpused'},
            'network': {'IFACE', 'rxpck/s', 'txpck/s'}
        }

        for line in content.strip().replace('\r\n', '\n').split('\n'):
            line = line.strip()
            if not line or line.startswith(('Average:', 'Linux')): header_map, current_section = {}, None; continue
            
            is_header = re.match(r'^\d{2}:\d{2}:\d{2}(?:\s+PM|AM)?', line) and any(k in line for k in ['CPU', '%', 'IFACE', 'kb', 'tps', 'ldavg', 'runq-sz'])
            
            if is_header:
                parts = re.split(r'\s+', line); metric_start_idx = 2 if len(parts) > 1 and parts[1] in ['AM', 'PM'] else 1
                header_cols_raw = parts[metric_start_idx:]
                header_cols = [p.replace('%', 'pct_').replace('/', '_s').replace('%usr', 'pct_user') for p in header_cols_raw]
                header_map = {col: i for i, col in enumerate(header_cols)}
                
                # [개선] 키워드 집합을 사용하여 현재 섹션을 더 정확하게 식별
                current_section = None
                for sec, keys in section_keys.items():
                    if any(key in header_cols_raw for key in keys):
                        current_section = sec
                        break
                
                if current_section:
                    logging.info(f"SAR 데이터 파싱: '{current_section}' 섹션 식별됨 (헤더: {header_cols_raw})")
                continue

            if current_section and header_map:
                parts = re.split(r'\s+', line); ts_end_idx = 2 if len(parts) > 1 and parts[1] in ['AM', 'PM'] else 1
                timestamp = " ".join(parts[:ts_end_idx]); values = parts[ts_end_idx:]; entry = {'timestamp': timestamp}
                for h, i in header_map.items():
                    if i < len(values): entry[h] = self._safe_float(values[i]) if h not in ['IFACE', 'DEV', 'CPU'] else values[i]
                
                if current_section == 'cpu' and entry.get('CPU') != 'all': continue
                if current_section == 'network' and entry.get('IFACE') == 'lo': continue
                data.setdefault(current_section, []).append(entry)
        
        logging.info(f"SAR 데이터 파싱 완료. 추출된 섹션: {list(data.keys())}")
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

    def get_structured_analysis(self, metadata: Dict, anonymize: bool) -> Dict:
        log_step("서버에 AI 분석 요청")
        data_to_send = metadata
        if anonymize:
            anonymizer = DataAnonymizer()
            hostnames = [metadata.get("system_info", {}).get("hostname", "")]
            data_to_send = anonymizer.anonymize_data(metadata, specific_hostnames=hostnames)
            logging.info("데이터 익명화 완료.")
        try:
            logging.info(f"AI 분석 서버로 요청 전송: {self.api_url}")
            response = self.session.post(self.api_url, json=data_to_send, timeout=300)
            response.raise_for_status()
            server_response = response.json()
            formatted_response = {
                "summary": server_response.get("analysis_summary", "요약 정보 없음."),
                "recommendations": [{"priority": "높음", "category": "미분류", "issue": issue.get("issue", "N/A"), "solution": issue.get("solution", "N/A"), "related_logs": [issue.get("cause", "N/A")]} for issue in server_response.get("key_issues", [])],
                "critical_issues": [], "warnings": []
            }
            logging.info(Color.success("서버로부터 AI 분석 결과 수신 완료."))
            return formatted_response
        except requests.exceptions.RequestException as e:
            logging.error(f"AI 분석 서버 통신 오류: {e}")
            error_details = str(e)
            if e.response is not None:
                try: error_details = e.response.json().get('details', e.response.text)
                except json.JSONDecodeError: error_details = e.response.text[:500]
            return {"summary": f"AI 분석 서버와 통신하는 데 실패했습니다. 보고서는 AI 분석 없이 생성됩니다.", "critical_issues": [f"서버 통신 오류: {error_details}"], "warnings": [], "recommendations": []}

    def fetch_security_news(self, metadata: Dict) -> List[Dict]:
        # [NEW] sos_analyzer_old.py의 보안 위협 분석 로직 복원 및 개선
        log_step("긴급 보안 위협 분석 시작 (Red Hat API)")
        
        HIGH_IMPACT_PACKAGES = ['kernel', 'glibc', 'openssl', 'httpd', 'nginx', 'java', 'python', 'bash', 'sudo', 'systemd', 'qemu-kvm', 'mariadb', 'postgresql', 'firefox', 'thunderbird', 'grub2']
        installed_packages = metadata.get("installed_packages", [])
        
        target_packages = set()
        for pkg_full in installed_packages:
            try:
                pkg_name = re.match(r'([a-zA-Z0-9_-]+)', pkg_full).group(1)
                for impact_pkg in HIGH_IMPACT_PACKAGES:
                    if impact_pkg in pkg_name:
                        target_packages.add(pkg_name)
                        break
            except (AttributeError, IndexError):
                continue
        
        if not target_packages:
            logging.info("분석 대상 주요 패키지가 설치되어 있지 않습니다.")
            return []

        logging.info(f"보안 분석 대상 패키지 ({len(target_packages)}개): {', '.join(sorted(list(target_packages)))}")
        
        start_date = (self.report_date - timedelta(days=180)).strftime('%Y-%m-%d')
        all_cves = {}

        def fetch_cves_for_package(pkg_name):
            try:
                url = f"https://access.redhat.com/hydra/rest/securitydata/cve.json?package={pkg_name}&after={start_date}"
                response = requests.get(url, timeout=20)
                if response.status_code == 200:
                    return response.json()
            except requests.RequestException as e:
                logging.warning(f"'{pkg_name}' 패키지 CVE 조회 실패: {e}")
            return []

        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(fetch_cves_for_package, target_packages)
            for cve_list in results:
                for cve in cve_list:
                    if cve.get('severity') in ['critical', 'important']:
                        all_cves[cve['CVE']] = cve
        
        if not all_cves:
            logging.info("최근 180일 내에 Critical/Important 등급의 CVE가 없습니다.")
            return []

        severity_map = {'critical': 0, 'important': 1}
        sorted_cves = sorted(all_cves.values(), key=lambda x: (severity_map.get(x.get('severity'), 2), x.get('public_date', '')), reverse=False)

        top_cves = sorted_cves[:10]
        logging.info(Color.success(f"총 {len(all_cves)}개의 CVE 발견, 상위 {len(top_cves)}개 선정 완료."))
        
        return [{
            "cve_id": cve.get('CVE'),
            "severity": cve.get('severity', 'N/A').capitalize(),
            "package": ', '.join(sorted(list(set(pkg.split(':')[0] for pkg in cve.get('affected_packages', []))))) or 'N/A',
            "description": cve.get('bugzilla_description', 'N/A').split('\n\nStatement:')[0]
        } for cve in top_cves]

class HTMLReportGenerator:
    def __init__(self, metadata: Dict, sar_data: Dict, ai_analysis: Dict, hostname: str):
        self.metadata, self.sar_data, self.ai_analysis, self.hostname = metadata, sar_data, ai_analysis, hostname
        self._setup_korean_font()

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
        graphs, sar = {}, self.sar_data
        graphs['cpu'] = self._create_plot(sar.get('cpu'), 'CPU Usage (%)', {'pct_user': 'User', 'pct_system': 'System', 'pct_iowait': 'I/O Wait'}, True)
        graphs['memory'] = self._create_plot(sar.get('memory'), 'Memory Usage (KB)', {'kbmemused': 'Used', 'kbcached': 'Cached'})
        graphs['load'] = self._create_plot(sar.get('load'), 'System Load Average', {'ldavg-1': '1-min', 'ldavg-5': '5-min', 'ldavg-15': '15-min'})
        disk_data = sar.get('disk')
        if disk_data and disk_data[0]:
            if 'bread_s' in disk_data[0]: graphs['disk'] = self._create_plot(disk_data, 'Disk I/O (blocks/s)', {'bread_s': 'Read', 'bwrtn_s': 'Write'})
            elif 'rkB_s' in disk_data[0]: graphs['disk'] = self._create_plot(disk_data, 'Disk I/O (kB/s)', {'rkB_s': 'Read', 'wkB_s': 'Write'})
        graphs['swap'] = self._create_plot(sar.get('swap'), 'Swap Usage (%)', {'pct_swpused': 'Used %'})
        if sar.get('network'):
            graphs['network'] = {}
            net_by_iface = {}; [net_by_iface.setdefault(d.get('IFACE'), []).append(d) for d in sar['network'] if d.get('IFACE')]
            up_interfaces = {iface['iface'] for iface in self.metadata.get('network', {}).get('interfaces', []) if iface.get('state') == 'up'}
            for iface, data in net_by_iface.items():
                if iface in up_interfaces and len(data) > 1 and sum(d.get('rxkB_s', 0) + d.get('txkB_s', 0) for d in data) > 0: 
                    graphs['network'][iface] = self._create_plot_dual_axis(data, f'Network Traffic: {iface}', {'rxpck_s': 'RX pck/s', 'txpck_s': 'TX pck/s'}, {'rxkB_s': 'RX kB/s', 'txkB_s': 'TX kB/s'})
        return graphs

    def _create_plot(self, data, title, labels, is_stack=False):
        if not data: return None
        fig, ax = plt.subplots(figsize=(12, 6)); timestamps = [d['timestamp'] for d in data]
        if is_stack: ax.stackplot(timestamps, [[self._safe_float(d.get(k, 0)) for d in data] for k in labels.keys()], labels=list(labels.values()))
        else:
            for key, label in labels.items(): ax.plot(timestamps, [self._safe_float(d.get(key, 0)) for d in data], label=label)
        ax.set_title(title, fontsize=14, weight='bold'); ax.legend(fontsize='small'); plt.tight_layout(); ax.grid(True, linestyle='--', alpha=0.6)
        ax.xaxis.set_major_locator(mticker.MaxNLocator(nbins=10, prune='both')); plt.xticks(rotation=30, ha='right')
        buf = io.BytesIO(); plt.savefig(buf, format='png'); plt.close(fig)
        return base64.b64encode(buf.getvalue()).decode('utf-8')

    def _create_plot_dual_axis(self, data, title, labels1, labels2):
        if not data: return None
        fig, ax1 = plt.subplots(figsize=(12,6)); ax2 = ax1.twinx(); timestamps = [d['timestamp'] for d in data]
        colors1 = ['tab:blue', 'tab:cyan']; colors2 = ['tab:red', 'tab:orange']
        for (key, label), color in zip(labels1.items(), colors1): ax1.plot(timestamps, [self._safe_float(d.get(key,0)) for d in data], label=label, color=color)
        for (key, label), color in zip(labels2.items(), colors2): ax2.plot(timestamps, [self._safe_float(d.get(key,0)) for d in data], label=label, linestyle='--', color=color)
        ax1.set_title(title, fontsize=14, weight='bold'); ax1.set_ylabel('Packets/s'); ax2.set_ylabel('kB/s')
        lines1, labels1 = ax1.get_legend_handles_labels(); lines2, labels2 = ax2.get_legend_handles_labels()
        ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left', fontsize='small'); plt.tight_layout(); ax1.grid(True, linestyle='--', alpha=0.6)
        ax1.xaxis.set_major_locator(mticker.MaxNLocator(nbins=10, prune='both')); plt.setp(ax1.get_xticklabels(), rotation=30, ha='right')
        buf = io.BytesIO(); plt.savefig(buf, format='png'); plt.close(fig)
        return base64.b64encode(buf.getvalue()).decode('utf-8')

    def _safe_float(self, value):
        try: return float(value)
        except (ValueError, TypeError): return 0.0

    def generate(self) -> str:
        graphs = self._generate_graphs()
        template_data = {
            "hostname": self.hostname, "ai_analysis": self.ai_analysis,
            "graphs": graphs, **self.metadata
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
        
        output_dir = Path(args.output); output_dir.mkdir(exist_ok=True)
        hostname = metadata.get('system_info', {}).get('hostname', 'unknown')
        (output_dir / f"metadata-{hostname}.json").write_text(json.dumps(metadata, indent=2, default=json_serializer, ensure_ascii=False), encoding='utf-8')
        (output_dir / f"sar_data-{hostname}.json").write_text(json.dumps(sar_data, indent=2, default=json_serializer, ensure_ascii=False), encoding='utf-8')
        
        # [개선] AIAnalyzer 초기화 시 report_date 전달
        ai_analyzer = AIAnalyzer(args.server_url, parser.report_date)
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_ai = executor.submit(ai_analyzer.get_structured_analysis, metadata, args.anonymize)
            future_sec = executor.submit(ai_analyzer.fetch_security_news, metadata)
            structured_analysis = future_ai.result()
            metadata['security_news'] = future_sec.result()
        
        reporter = HTMLReportGenerator(metadata, sar_data, structured_analysis, hostname)
        html_content = reporter.generate()
        
        report_path = output_dir / f"report-{hostname}.html"
        report_path.write_text(html_content, encoding='utf-8')
        logging.info(Color.success(f"분석 완료! 보고서 저장 경로: {report_path}"))

    except Exception as e:
        logging.error(f"치명적인 오류 발생: {e}", exc_info=True)
        sys.exit(1)
    finally:
        if extract_path.exists(): shutil.rmtree(extract_path, ignore_errors=True)
        
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Smart sosreport Analyzer")
    parser.add_argument("tar_path", help="분석할 sosreport tar 아카이브 경로")
    parser.add_argument("--output", default="output", help="보고서 및 데이터 저장 디렉토리")
    parser.add_argument("--server-url", required=True, help="AI 분석을 위한 ABox_Server.py의 API 엔드포인트 URL (예: http://127.0.0.1:5000/AIBox/api/sos/analyze_system)")
    parser.add_argument("--anonymize", action='store_true', help="서버 전송 전 민감 정보 익명화")
    main(parser.parse_args())

