# -*- coding: utf-8 -*-
# ==============================================================================
# HTML Template Module
# ------------------------------------------------------------------------------
# [BUG FIX] 네트워크 그래프 생성 시 발생하던 TypeError를 해결하기 위해 잘못된 중괄호 문법을 수정했습니다.
# [BUG FIX] 누락되었던 'Last Boot' 정보가 시스템 요약 테이블에 표시되도록 수정했습니다.
# ==============================================================================

import html
import re
from datetime import datetime

# [개선] 마크다운 라이브러리를 사용하여 AI 분석 요약을 더 정교하게 HTML로 변환합니다.
try:
    from markdown import markdown
    IS_MARKDOWN_AVAILABLE = True
except ImportError:
    IS_MARKDOWN_AVAILABLE = False

def get_html_template(data):
    def h(text):
        return html.escape(str(text)) if text is not None else ''

    svg_icons = {
        "info": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="icon"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"></path></svg>',
        "dashboard": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="icon"><path d="M13 2.05v3.03c3.39.49 6 3.39 6 6.92 0 .9-.18 1.75-.48 2.54l2.6 1.53c.56-1.24.88-2.62.88-4.07 0-5.18-3.95-9.45-9-9.95zM12 19c-3.87 0-7-3.13-7-7 0-3.53 2.61-6.43 6-6.92V2.05c-5.06.5-9 4.76-9 9.95 0 5.52 4.48 10 10 10 3.31 0 6.24-1.61 8.06-4.09l-2.6-1.53C16.17 17.98 14.21 19 12 19z"></path></svg>',
        "network": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="icon"><path d="M23.121 8.879l-1.414 1.414L23.121 11.707l-1.414 1.414 1.414 1.414-1.414 1.414-1.414-1.414-1.414 1.414 1.414 1.414-1.414 1.414-8.485-8.485 1.414-1.414 1.414 1.414 1.414-1.414-1.414-1.414 1.414-1.414 1.414 1.414zm-9.9-1.414l-1.414 1.414-1.414-1.414-1.414 1.414 1.414 1.414-1.414 1.414-8.485-8.485 1.414-1.414 1.414 1.414 1.414-1.414-1.414-1.414 1.414-1.414 1.414 1.414 1.414-1.414 1.414 1.414z"></path></svg>',
        "cpu": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="icon"><path d="M9 21h6v-2H9v2zm.5-4.59L11 15V9h-1.5v4.51l-1.79-1.8-1.42 1.42L9.5 16.41zm6.29-1.8L13 16.41V11.5L14.5 10v6l1.79-1.79 1.42 1.42L14.5 18.41zM20 2H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h4v-2H4V4h16v12h-4v2h4c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2z"></path></svg>',
        "disk": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="icon"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 14H9V8h2v8zm4 0h-2V8h2v8z"></path></svg>',
        "critical": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="icon"><path d="M12 2C6.47 2 2 6.47 2 12s4.47 10 10 10 10-4.47 10-10S17.53 2 12 2zm5 13.59L15.59 17 12 13.41 8.41 17 7 15.59 10.59 12 7 8.41 8.41 7 12 10.59 15.59 7 17 8.41 13.41 12 17 15.59z"></path></svg>',
        "cluster": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="icon"><path d="M18.5 13.5c-1.93 0-3.5 1.57-3.5 3.5s1.57 3.5 3.5 3.5 3.5-1.57 3.5-3.5-1.57-3.5-3.5-3.5zm-13 0C3.57 13.5 2 15.07 2 17s1.57 3.5 3.5 3.5 3.5-1.57 3.5-3.5-1.57-3.5-3.5-3.5zm0-10C3.57 3.5 2 5.07 2 7s1.57 3.5 3.5 3.5 3.5-1.57 3.5-3.5S7.43 3.5 5.5 3.5zm13 0c-1.93 0-3.5 1.57-3.5 3.5s1.57 3.5 3.5 3.5 3.5-1.57 3.5-3.5-1.57-3.5-3.5-3.5z"></path></svg>',
        "warning": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="icon"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"></path></svg>',
        "idea": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="icon"><path d="M9 21c0 .55.45 1 1 1h4c.55 0 1-.45 1-1v-1H9v1zM12 2C7.86 2 4.5 5.36 4.5 9.5c0 3.82 2.66 5.86 3.77 6.5h7.46c1.11-.64 3.77-2.68 3.77-6.5C19.5 5.36 16.14 2 12 2z"></path></svg>',
        "shield": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="icon"><path d="M12 2L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-3zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V13H5V6.3l7-3.11v10.8z"></path></svg>',
        "summary_ai": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="icon"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zM9.5 9.5c.83 0 1.5.67 1.5 1.5s-.67 1.5-1.5 1.5-1.5-.67-1.5-1.5.67-1.5 1.5-1.5zm3 5c.83 0 1.5.67 1.5 1.5s-.67 1.5-1.5 1.5-1.5-.67-1.5-1.5.67-1.5 1.5-1.5zm3.5-2.5c.83 0 1.5.67 1.5 1.5s-.67 1.5-1.5 1.5-1.5-.67-1.5-1.5.67-1.5 1.5-1.5z"></path></svg>'
    }

    def create_list_table(items, empty_message):
        if not items: return f"<tr><td colspan='1' style='text-align:center; padding: 1.5rem;'>{h(empty_message)}</td></tr>"
        return "".join(f"<tr><td>{h(str(item))}</td></tr>" for item in items)

    def create_storage_rows(storage_list):
        if not storage_list: return "<tr><td colspan='6' style='text-align:center;'>데이터 없음</td></tr>"
        rows = ""
        for item in storage_list:
            rows += f"<tr><td>{h(item.get('filesystem', 'N/A'))}</td><td>{h(item.get('size', 'N/A'))}</td><td>{h(item.get('used', 'N/A'))}</td><td>{h(item.get('avail', 'N/A'))}</td><td>{h(item.get('mounted_on', 'N/A'))}</td>"
            use_pct_str = item.get('use_pct', '0%').replace('%', '')
            try:
                use_pct = int(use_pct_str); color = "#2ecc71"
                if use_pct >= 90: color = "#e74c3c"
                elif use_pct >= 80: color = "#f39c12"
                rows += f'<td style="min-width: 120px;"><div style="display: flex; align-items: center; gap: 8px;"><span>{use_pct}%</span><div class="progress-bar-container"><div class="progress-bar" style="width: {use_pct}%; background-color: {color};"></div></div></div></td></tr>'
            except (ValueError, TypeError): rows += "<td>N/A</td></tr>"
        return rows

    def create_recommendation_rows(rec_list):
        if not rec_list: return "<tr><td colspan='4' style='text-align:center;'>데이터 없음</td></tr>"
        rows = ""
        # [사용자 요청] AI가 한글로 반환하는 우선순위를 CSS 클래스에 맞게 매핑합니다.
        priority_map = {"높음": "high", "중간": "medium", "낮음": "low", "High": "high", "Medium": "medium", "Low": "low"}
        for item in rec_list:
            priority_class = priority_map.get(item.get('priority', ''), "")
            issue_html = h(str(item.get('issue', 'N/A')))
            related_logs = item.get('related_logs')
            if related_logs and isinstance(related_logs, list):
                logs_html = h('\n'.join(related_logs))
                issue_html += f' <div class="tooltip"><span class="log-icon">💬</span><span class="tooltiptext">{logs_html}</span></div>'
            
            solution_html = h(str(item.get('solution', 'N/A')))
            rows += f"<tr><td><span class='priority-badge {priority_class}'>{h(item.get('priority', 'N/A'))}</span></td><td>{h(str(item.get('category', 'N/A')))}</td><td>{issue_html}</td><td>{solution_html}</td></tr>"
        return rows

    def create_security_audit_rows(audit_list):
        if not audit_list: return "<tr><td colspan='4' style='text-align:center;'>발견된 보안 설정 이슈 없음</td></tr>"
        rows = ""
        # [사용자 요청] 심각도를 한글로 표기하고 CSS 클래스에 맞게 매핑합니다.
        severity_map = {"High": ("높음", "high"), "Medium": ("중간", "medium"), "Low": ("낮음", "low")}
        for item in audit_list:
            severity_en = item.get('severity', 'N/A')
            severity_ko, severity_class = severity_map.get(severity_en, (severity_en, ""))
            rows += f"<tr><td><span class='priority-badge {severity_class}'>{h(severity_ko)}</span></td><td>{h(str(item.get('category', 'N/A')))}</td><td>{h(str(item.get('name', 'N/A')))}</td><td>{h(str(item.get('solution', 'N/A')))}</td></tr>"
        return rows

    def create_kb_finding_rows(finding_list):
        if not finding_list: return "<tr><td colspan='4' style='text-align:center;'>규칙 기반으로 발견된 이슈 없음</td></tr>"
        rows = ""
        # [사용자 요청] 심각도를 한글로 표기하고 CSS 클래스에 맞게 매핑합니다.
        severity_map = {"High": ("높음", "high"), "Medium": ("중간", "medium"), "Low": ("낮음", "low")}
        for item in finding_list:
            severity_en = item.get('severity', 'N/A')
            severity_ko, severity_class = severity_map.get(severity_en, (severity_en, ""))
            rows += f"<tr><td><span class='priority-badge {severity_class}'>{h(severity_ko)}</span></td><td>{h(str(item.get('category', 'N/A')))}</td><td>{h(str(item.get('name', 'N/A')))}</td><td>{h(str(item.get('solution', 'N/A')))}</td></tr>"
        return rows

    def render_graph(graph_key, title, graphs_data):
        # [사용자 요청] 하이브리드 그래프: (base64_png, interactive_html) 튜플을 받습니다.
        graph_tuple = graphs_data.get(graph_key)
        # [BUG FIX & 개선] disk_detail 데이터가 존재하고 비어있지 않을 때만 팝업을 활성화합니다.
        #                  'data.get('sar_data', {}).get('disk_detail')'은 리스트가 비어있어도 True로 평가될 수 있습니다.
        has_disk_detail = bool(data.get('sar_data', {}).get('disk_detail'))
        # [수정] 네트워크 그래프 팝업을 위한 조건 추가 (UP 상태인 인터페이스가 2개 이상일 때)
        up_interfaces = [iface for iface in data.get('network', {}).get('interfaces', []) if iface.get('state') == 'up']
        has_multiple_nics = len(up_interfaces) > 1

        if graph_tuple and isinstance(graph_tuple, tuple) and len(graph_tuple) == 2:
            base64_png, interactive_html = graph_tuple
            hostname = h(data.get('hostname', ''))
            popup_filename = f"popup_{graph_key}_{hostname}.html"

            if base64_png: # 정적 이미지가 있으면 이미지로 표시
                graph_html = f'<img src="data:image/png;base64,{base64_png}" alt="{title}" style="width:100%; cursor:pointer;" onclick="openGraphPopup(\'{popup_filename}\')">'
            else: # 정적 이미지가 없으면 (kaleido 미설치) 동적 그래프를 직접 표시
                graph_html = f'<div class="plotly-graph-container">{interactive_html}</div>'
            
            # "Details" 버튼 로직은 그대로 유지
            details_button_html = ""
            if graph_key == 'disk_detail' and has_disk_detail:
                details_button_html = '<div class="details-button-container"><button class="details-button" onclick="openDiskDetailPopup()">세부 정보 보기 (Details)</button></div>'
            if graph_key == 'network_representative' and has_multiple_nics:
                details_button_html = '<div class="details-button-container"><button class="details-button" onclick="openNicDetailPopup()">다른 인터페이스 보기 (Details)</button></div>'
            return f'<div class="graph-container"><h3>{title}</h3>{graph_html}{details_button_html}</div>'

        return f'<div class="graph-container"><h3 class="no-data-message">{title}</h3><p class="no-data-message">그래프 데이터 없음</p></div>'

    def create_ip4_details_rows(interfaces):
        if not interfaces: return "<tr><td colspan='4' style='text-align:center;'>데이터 없음</td></tr>"
        rows = []
        for item in interfaces:
            state_color = "#2ecc71" if item.get("state") == "up" else "#7f8c8d"
            row_html = f"""
                <tr>
                    <td>{h(item.get('iface'))}</td>
                    <td>{h(item.get('mac'))}</td>
                    <td>{h(item.get('ipv4'))}</td>
                    <td style="color:{state_color};">{h(item.get('state', 'unknown').upper())}</td>
                </tr>
            """
            rows.append(row_html)
        return "".join(rows)

    def create_routing_table_rows(routing_table):
        """[신규] 라우팅 테이블 정보를 HTML 행으로 생성합니다."""
        if not routing_table: return "<tr><td colspan='3' style='text-align:center;'>데이터 없음</td></tr>"
        rows = []
        for route in routing_table:
            row_html = f"""
                <tr>
                    <td>{h(route.get('destination', 'N/A'))}</td>
                    <td>{h(route.get('gateway', 'N/A'))}</td>
                    <td>{h(route.get('device', 'N/A'))}</td>
                </tr>"""
            rows.append(row_html)
        return "".join(rows)

    def create_drbd_rows(drbd_resources):
        """[신규] DRBD 리소스 정보를 HTML 행으로 생성합니다."""
        if not drbd_resources: return "<tr><td colspan='5' style='text-align:center;'>DRBD 리소스 없음</td></tr>"
        rows = []
        for res in drbd_resources:
            warning_style = 'style="background-color: #fffbe6;"' if 'warning' in res else ''
            row_html = f"""
                <tr {warning_style}>
                    <td>{h(res.get('id'))}</td>
                    <td>{h(res.get('connection'))}</td>
                    <td>{h(res.get('roles'))}</td>
                    <td>{h(res.get('disk_states'))}</td>
                    <td>{h(res.get('warning', '정상'))}</td>
                </tr>
            """
            rows.append(row_html)
        return "".join(rows)


    def create_ethtool_rows(ethtool_data):
        if not ethtool_data: return "<tr><td colspan='6' style='text-align:center;'>데이터 없음</td></tr>"
        return "".join(f"<tr><td>{h(iface)}</td><td>{h(d.get('driver'))}</td><td>{h(d.get('speed'))}</td><td>{h(d.get('duplex'))}</td><td>{'UP' if d.get('link') == 'yes' else 'DOWN'}</td><td>{h(d.get('rx_ring'))}</td></tr>" for iface, d in ethtool_data.items())

    def create_process_rows(proc_list, empty_msg, include_mem=False):
        if not proc_list: return f"<tr><td colspan='{7 if include_mem else 5}' style='text-align:center;'>{h(empty_msg)}</td></tr>"
        rows = ""
        for p in proc_list:
            cmd = h(p.get('command')); cmd_short = cmd[:80] + '...' if len(cmd) > 80 else cmd
            mem_cols = f"<td>{h(p.get('mem_pct'))}</td><td>{h(p.get('rss_kb'))}</td>" if include_mem else ""
            rows += f"<tr><td>{h(p.get('user'))}</td><td>{h(p.get('pid'))}</td><td>{h(p.get('cpu_pct'))}</td>{mem_cols}<td>{h(p.get('stat'))}</td><td class='tooltip'>{cmd_short}<span class='tooltiptext'>{cmd}</span></td></tr>"
        return rows

    def create_security_news_rows(news_list):
        if not news_list: return "<tr><td colspan='4' style='text-align:center;'>AI가 선정한 보안 위협 없음</td></tr>"
        rows = ""
        # [사용자 요청] AI가 한글 또는 영문으로 반환할 수 있는 심각도를 CSS 클래스에 맞게 매핑합니다.        
        severity_map = {"심각": "high", "critical": "high", "중요": "medium", "important": "medium"} 
        for item in news_list:
            severity_class = severity_map.get(item.get('severity', '').lower(), "low") # noqa: E501
            severity_badge = f"<span class='priority-badge {severity_class}'>{h(item.get('severity', 'N/A'))}</span>"
            
            # [사용자 요청] 설치된 버전 정보를 툴팁으로 표시
            package_name = h(item.get('package'))
            installed_version = item.get('installed_version')
            if installed_version:
                package_html = f'<div class="tooltip">{package_name}<span class="tooltiptext" style="width: 300px; margin-left: -150px;">Installed: {h(installed_version)}</span></div>'
            else:
                package_html = package_name
            
            # [사용자 요청] CVE ID 아래에 공개일과 CVSSv3 점수를 추가합니다.
            cve_id = h(item.get('cve_id'))
            # [BUG FIX] JSON 데이터의 필드 이름(release_date)을 정확히 참조하도록 수정합니다.
            public_date = h(item.get('release_date', item.get('public_date', '')).split('T')[0])
            
            # [BUG FIX] CVSS 점수 필드(cvss3.cvss3_base_score)를 정확히 참조하도록 수정합니다.
            cvss3_data = item.get('cvss3', {})
            cvss_score = 'N/A'
            if isinstance(cvss3_data, dict):
                cvss_score = h(cvss3_data.get('cvss3_base_score', 'N/A'))
            
            cve_cell_html = f"""
                <a href='https://access.redhat.com/security/cve/{cve_id}' target='_blank'>{cve_id}</a>
                <div style='font-size: 0.8em; color: #7f8c8d;'>
                    <span>{public_date}</span> &bull; <span>CVSS: {cvss_score}</span>
                </div>
            """
            
            rows += f"<tr><td>{cve_cell_html}</td><td>{severity_badge}</td><td>{package_html}</td><td>{h(item.get('description'))}</td></tr>"
        return rows

    def create_netdev_rows(netdev_list):
        if not netdev_list: return "<tr><td colspan='9' style='text-align:center;'>데이터 없음</td></tr>"
        return "".join(f"<tr><td>{h(item.get('iface'))}</td><td>{item.get('rx_bytes'):,}</td><td>{item.get('rx_packets'):,}</td><td style='color: #e74c3c;'>{item.get('rx_errs'):,}</td><td style='color: #e74c3c;'>{item.get('rx_drop'):,}</td><td>{item.get('tx_bytes'):,}</td><td>{item.get('tx_packets'):,}</td><td style='color: #e74c3c;'>{item.get('tx_errs'):,}</td><td style='color: #e74c3c;'>{item.get('tx_drop'):,}</td></tr>" for item in netdev_list)

    def create_bonding_rows(bonding_list):
        if not bonding_list: return "<tr><td colspan='4' style='text-align:center;'>데이터 없음</td></tr>"
        rows = ""
        for bond in bonding_list:
            status_color = 'color: #2ecc71;' if bond.get('mii_status') == 'up' else 'color: #e74c3c;'
            rows += f"<tr style='background-color: #f0f5f9; font-weight: bold;'><td>{h(bond.get('device'))}</td><td style='{status_color}'>{h(bond.get('mii_status', 'N/A').upper())}</td><td colspan='2'>{h(bond.get('mode', 'N/A'))}</td></tr>"
            for slave in bond.get('slaves_info', []):
                rows += f"<tr><td style='padding-left: 2rem;'>- {h(slave.get('name'))}</td><td>{h(slave.get('mii_status'))}</td><td>{h(slave.get('speed'))}</td><td></td></tr>"
        return rows

    def create_by_user_rows(user_list):
        if not user_list: return "<tr><td colspan='4' style='text-align:center;'>데이터 없음</td></tr>"
        return "".join(f"<tr><td>{h(item.get('user'))}</td><td>{item.get('cpu_pct'):.1f}%</td><td>{item.get('mem_pct'):.1f}%</td><td>{item.get('rss_kb')/1024:.1f} MB</td></tr>" for item in user_list)

    system_info = data.get('system_info', {})
    ai_analysis = data.get('ai_analysis', {})
    graphs = data.get('graphs', {})
    network_details = data.get('network', {})
    kb_findings = ai_analysis.get('kb_findings', [])
    ha_cluster_info = data.get('ha_cluster_info', {})
    drbd_info = data.get('drbd_info', {})
    security_audit_findings = ai_analysis.get('security_audit_findings', [])
    process_stats = data.get('processes', {})
    security_news = data.get('security_advisories', [])
    
    summary_raw = ai_analysis.get('summary', '분석 결과 없음')
    # [핵심 개선] markdown 라이브러리를 사용하여 AI 요약을 HTML로 변환합니다.
    if IS_MARKDOWN_AVAILABLE:
        # 'tables' 확장 기능을 활성화하여 마크다운 테이블도 지원합니다.
        summary_html = markdown(summary_raw, extensions=['tables', 'fenced_code'])
    else:
        # 라이브러리가 없을 경우, 기존의 간단한 정규식 기반 변환을 유지합니다.
        summary_html = h(summary_raw)
        summary_html = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', summary_html)
        summary_html = re.sub(r'((?:\* .*(?:\n|$))+)', r'<ul>\g<1></ul>', summary_html)
        summary_html = re.sub(r'\* (.*?)\n', r'<li>\1</li>\n', summary_html)
        summary_html = summary_html.replace('\n', '<br>')

    return f"""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <title>AI 시스템 분석 보고서: {h(data.get('hostname', ''))}</title>
        <style>
            :root {{ --primary-color: #3498db; --secondary-color: #2c3e50; --success-color: #2ecc71; --warning-color: #f39c12; --danger-color: #e74c3c; --light-gray: #ecf0f1; --card-bg: #ffffff; --body-bg: #f4f6f8; --border-color: #dfe4ea; --box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08); }}
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans KR", sans-serif; background-color: var(--body-bg); color: #34495e; margin: 0; padding: 2rem; }}
            .container {{ max-width: 1400px; margin: auto; }}
            header {{ background: linear-gradient(135deg, var(--secondary-color) 0%, #34495e 100%); color: white; padding: 2rem; text-align: center; border-radius: 12px; margin-bottom: 2rem; box-shadow: var(--box-shadow); }}
            h1, h2, h3 {{ margin:0; padding:0;}}
            h3 {{ font-size: 1.2em; color: var(--secondary-color); margin-top: 1.5rem; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid var(--light-gray);}}
            .report-card {{ background: var(--card-bg); border-radius: 10px; margin-bottom: 2rem; box-shadow: var(--box-shadow); overflow: hidden; }}
            .card-header {{ background-color: #f7f9fc; padding: 1rem 1.5rem; font-size: 1.5em; font-weight: 600; display: flex; align-items: center; border-bottom: 1px solid var(--border-color); }}
            .card-header .icon {{ width: 28px; height: 28px; margin-right: 1rem; color: var(--primary-color); }}
            .card-body {{ padding: 1.5rem; }}
            .data-table {{ width: 100%; border-collapse: collapse; }}
            .data-table th, .data-table td {{ padding: 0.9rem 1rem; text-align: left; border-bottom: 1px solid var(--border-color); word-break: break-all; }}
            .data-table thead th {{ background-color: #f7f9fc; font-weight: 600; }}
            .graph-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(450px, 1fr)); gap: 1.5rem; }}
            .graph-container {{ padding: 1rem; border: 1px solid var(--border-color); border-radius: 8px; margin-top: 1rem; }}
            .graph-container h3 {{ text-align: center; border: none; }}
            .plotly-graph-container {{ width: 100%; min-height: 450px; }}
            .no-data-message {{ text-align: center; color: #888; padding: 2rem; }}
            .details-button-container {{ text-align: center; margin-top: 1rem; }}
            .details-button {{
                background-color: #f0f2f5; color: #34495e; border: 1px solid #dfe4ea;
                padding: 8px 16px; border-radius: 6px; cursor: pointer;
                font-weight: 500; font-size: 0.9rem; transition: all 0.2s ease;
            }}
            .details-button:hover {{ background-color: #e9ecef; border-color: #ced4da; }}
            .progress-bar-container {{ height: 12px; width: 100%; background-color: var(--light-gray); border-radius: 6px; overflow:hidden;}}
            .progress-bar {{ height: 100%; border-radius: 6px; }}
            .priority-badge {{ padding: 0.25em 0.6em; border-radius: 5px; font-size: 0.85em; color: white; font-weight: 600; }}
            .priority-badge.high {{ background-color: var(--danger-color); }}
            .priority-badge.medium {{ background-color: var(--warning-color); }}
            .priority-badge.low {{ background-color: #7f8c8d; }}
            .tooltip {{ position: relative; display: inline-block; cursor: help; }}
            .tooltip .tooltiptext {{ visibility: hidden; width: 450px; background-color: var(--secondary-color); color: #fff; text-align: left; border-radius: 6px; padding: 10px; position: absolute; z-index: 10; bottom: 125%; left: 50%; margin-left: -225px; opacity: 0; transition: opacity 0.3s; white-space: pre-wrap;}}
            .log-icon {{ font-size: 0.8em; vertical-align: super; }}
            .solution-box {{ margin-bottom: 0.5rem; }}
            .validation-box {{ margin-top: 0.8rem; padding: 0.5rem 0.8rem; background-color: #f0f2f5; border-radius: 4px; font-size: 0.9em; }}
            .validation-box code {{ background-color: transparent; padding: 0; }}
            .tooltip:hover .tooltiptext {{ visibility: visible; opacity: 1; }}
            /* [사용자 요청] 푸터 텍스트를 중앙에 정렬하고 여백을 추가합니다. */
            footer {{
                text-align: center;
                padding: 2rem 0;
                color: #7f8c8d;
            }}
        </style>
        <script>
            function openGraphPopup(filename) {{
                window.open(filename, 'GraphPopup', 'width=1200,height=600,scrollbars=yes,resizable=yes');
            }}
        </script>
    </head>
    <body>
        <div class="container">
            <header><h1>AI 시스템 분석 보고서</h1><p>Hostname: {h(data.get('hostname', 'N/A'))} &bull; Report Date: {datetime.now().strftime('%Y-%m-%d')}</p></header>

            <div class="report-card">
                <div class="card-header">{svg_icons['info']} 시스템 요약</div>
                <div class="card-body"><table class="data-table">
                    <tr><th>OS Version</th><td>{h(system_info.get('os_release', 'N/A'))}</td></tr>
                    <tr><th>Kernel</th><td>{h(system_info.get('kernel', 'N/A'))}</td></tr>
                    <tr><th>System Model</th><td>{h(system_info.get('system_model', 'N/A'))}</td></tr>
                    <tr><th>CPU</th><td>{h(system_info.get('cpu', 'N/A'))}</td></tr>
                    <tr><th>Memory</th><td>{h(system_info.get('memory', 'N/A'))}</td></tr>
                    <tr><th>Uptime</th><td>{h(system_info.get('uptime', 'N/A'))}</td></tr>
                    <tr><th>Boot time</th><td>{h(system_info.get('boot_time', 'N/A'))}</td></tr>
                    <tr><th>Report creation date</th><td>{h(system_info.get('report_creation_date', 'N/A'))}</td></tr>
                </table></div>
            </div>

            <div class="report-card">
                <div class="card-header">{svg_icons['summary_ai']} AI 종합 분석</div>
                <div class="card-body" style="line-height: 1.8;">{summary_html}</div>
            </div>
            <div class="report-card" {'style="display:none;"' if not ai_analysis.get('critical_issues') else ''}>
                <div class="card-header">{svg_icons['critical']} AI 분석: 심각한 이슈</div>
                <div class="card-body"><table class="data-table"><tbody>{create_list_table(ai_analysis.get('critical_issues', []), "발견된 심각한 이슈가 없습니다.")}</tbody></table></div>
            </div>
            <div class="report-card">
                <div class="card-header">{svg_icons['warning']} AI 분석: 경고 사항</div>
                <div class="card-body"><table class="data-table"><tbody>{create_list_table(ai_analysis.get('warnings', []), "특별한 경고 사항이 없습니다.")}</tbody></table></div>
            </div>
            <div class="report-card">
                <div class="card-header">{svg_icons['idea']} AI 분석: 권장사항</div>
                <div class="card-body"><table class="data-table">
                    <thead><tr><th>우선순위</th><th>카테고리</th><th>문제점</th><th>해결 방안</th></tr></thead>
                    <tbody>{create_recommendation_rows(ai_analysis.get('recommendations', []))}</tbody>
                </table></div>
            </div>

            <div class="report-card" {'style="display:none;"' if not ha_cluster_info and not drbd_info else ''}>
                <div class="card-header">{svg_icons['cluster']} HA 클러스터 및 DRBD 정보</div>
                <div class="card-body">
                    {'<h3>Pacemaker/Corosync 정보</h3><pre><code>' + h(ha_cluster_info.get('crm_report', '데이터 없음')) + '</code></pre>' if ha_cluster_info else ''}
                    {f'''<h3>DRBD 상태</h3>
                    <table class="data-table">
                        <thead><tr><th>ID</th><th>Connection</th><th>Roles</th><th>Disk States</th><th>Warning</th></tr></thead>
                        <tbody>{create_drbd_rows(drbd_info.get('resources', []))}</tbody>
                    </table>
                    ''' if drbd_info else ''}
                    {'<h3>DRBD 설정 (/etc/drbd.conf)</h3><pre><code>' + h(drbd_info.get('drbd_config', '데이터 없음')) + '</code></pre>' if drbd_info.get('drbd_config') else ''}
                </div>
            </div>


            <div class="report-card" {'style="display:none;"' if not security_audit_findings else ''}>
                <div class="card-header">{svg_icons['shield']} 보안 감사 결과</div>
                <div class="card-body"><table class="data-table">
                    <thead><tr><th style="width: 10%; text-align: center;">심각도</th><th>카테고리</th><th>문제점</th><th>해결 방안</th></tr></thead>
                    <tbody>{create_security_audit_rows(security_audit_findings)}</tbody>
                </table></div>
            </div>

            <div class="report-card" {'style="display:none;"' if not kb_findings else ''}>
                <div class="card-header">{svg_icons['shield']} 규칙 기반 진단 결과 (Knowledge Base)</div>
                <div class="card-body"><table class="data-table">
                    <thead><tr><th style="width: 10%; text-align: center;">심각도</th><th>카테고리</th><th>문제점</th><th>해결 방안</th></tr></thead>
                    <tbody>{create_kb_finding_rows(kb_findings)}</tbody>
                </table></div>
            </div>


            <div class="report-card">
                <div class="card-header">{svg_icons['dashboard']} 자원 사용 현황</div>
                <div class="card-body graph-grid">
                    {render_graph('cpu', 'CPU Usage (%)', graphs)}
                    {render_graph('memory', 'Memory Usage (KB)', graphs)}
                    {render_graph('load', 'System Load Average', graphs)}
                    {render_graph('io_usage', 'I/O Usage (sar -b)', graphs)}
                    {render_graph('disk_detail', 'Block Device I/O (sar -d)', graphs)}
                    {render_graph('swap', 'Swap Usage (%)', graphs)}
                    {render_graph('file_handler', 'File and Inode Handlers', graphs)}
                    {render_graph('network_representative', 'Network Traffic', graphs)}
                </div>
            </div>

            <div class="report-card">
                <div class="card-header">{svg_icons['disk']} 스토리지 및 파일 시스템</div>
                <div class="card-body"><table class="data-table">
                    <thead><tr><th>Filesystem</th><th>Size</th><th>Used</th><th>Avail</th><th>Mounted on</th><th>Usage</th></tr></thead>
                    <tbody>{create_storage_rows(data.get('storage', []))}</tbody>
                </table></div>
            </div>

            <div class="report-card">
                <div class="card-header">{svg_icons['network']} 네트워크 정보</div>
                <div class="card-body">
                    <h3>IP4 상세 정보</h3>
                    <table class="data-table">
                        <thead><tr><th>Interface</th><th>MAC</th><th>IPv4</th><th>State</th></tr></thead>
                        <tbody>{create_ip4_details_rows(network_details.get('interfaces', []))}</tbody>
                    </table>
                    <h3>라우팅 정보</h3>
                    <table class="data-table">
                        <thead><tr><th>Destination</th><th>Gateway</th><th>Device</th></tr></thead>
                        <tbody>{create_routing_table_rows(network_details.get('routing_table', []))}</tbody>
                    </table>
                    <h3>ETHTOOL 상태</h3>
                    <table class="data-table">
                        <thead><tr><th>Interface</th><th>Driver</th><th>Speed</th><th>Duplex</th><th>Link</th><th>RX Ring</th></tr></thead>
                        <tbody>{create_ethtool_rows(network_details.get('ethtool', {}))}</tbody>
                    </table>
                    <h3>NETDEV 통계</h3>
                    <table class="data-table">
                        <thead><tr><th>Iface</th><th>RX Bytes</th><th>RX Pkts</th><th>RX Errs</th><th>RX Drop</th><th>TX Bytes</th><th>TX Pkts</th><th>TX Errs</th><th>TX Drop</th></tr></thead>
                        <tbody>{create_netdev_rows(network_details.get('netdev', []))}</tbody>
                    </table>
                    <h3>네트워크 본딩</h3>
                    <table class="data-table">
                        <thead><tr><th>Device / Slave</th><th>MII Status</th><th>Speed</th><th>Mode</th></tr></thead>
                        <tbody>{create_bonding_rows(network_details.get('bonding', []))}</tbody>
                    </table>
                </div>
            </div>

            <div class="report-card">
                <div class="card-header">{svg_icons['cpu']} 프로세스 및 리소스</div>
                <div class="card-body">
                     <h3>리소스 사용 현황 (상위 5개 사용자)</h3>
                     <table class="data-table">
                        <thead><tr><th>User</th><th>CPU%</th><th>MEM%</th><th>RSS</th></tr></thead>
                        <tbody>{create_by_user_rows(process_stats.get('by_user',[]))}</tbody>
                    </table>
                    <h3>Top 5 CPU 사용 프로세스</h3>
                    <table class="data-table">
                        <thead><tr><th>User</th><th>PID</th><th>CPU%</th><th>STAT</th><th>Command</th></tr></thead>
                        <tbody>{create_process_rows(process_stats.get('top_cpu', []), "CPU 사용량 높은 프로세스 없음")}</tbody>
                    </table>
                    <h3>Top 5 메모리 사용 프로세스</h3>
                    <table class="data-table">
                        <thead><tr><th>User</th><th>PID</th><th>CPU%</th><th>MEM%</th><th>RSS(KB)</th><th>STAT</th><th>Command</th></tr></thead>
                        <tbody>{create_process_rows(process_stats.get('top_mem', []), "메모리 사용량 높은 프로세스 없음", include_mem=True)}</tbody>
                    </table>
                     <h3>Uninterruptible/Zombie Processes</h3>
                    <table class="data-table">
                        <thead><tr><th>User</th><th>PID</th><th>CPU%</th><th>MEM%</th><th>RSS(KB)</th><th>STAT</th><th>Command</th></tr></thead>
                        <tbody>
                            {create_process_rows(process_stats.get('uninterruptible', []), "Uninterruptible 프로세스 없음", include_mem=True)}
                            {create_process_rows(process_stats.get('zombie', []), "Zombie 프로세스 없음", include_mem=True)}
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="report-card">
                <div class="card-header">{svg_icons['shield']} AI 선정 보안 위협</div>
                 <div class="card-body">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th style="width: 15%;">CVE</th>
                                <th style="width: 10%; text-align: center;">Severity</th>
                                <th style="width: 15%;">영향받는 패키지</th>
                                <th>취약점 요약</th>
                            </tr>
                        </thead>
                        <tbody>{create_security_news_rows(security_news)}</tbody>
                    </table>
                </div>
            </div>

        </div>
        <footer>AI System Analyzer &bull; Generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer>
        <script>
            function openDiskDetailPopup() {{
                const hostname = "{h(data.get('hostname', ''))}"; // eslint-disable-line
                window.open(`sar_gui_disk-${{hostname}}.html`, 'DiskIODetail', 'width=1200,height=800,scrollbars=yes,resizable=yes');
            }}
            function openNicDetailPopup() {{
                const hostname = "{h(data.get('hostname', ''))}"; // eslint-disable-line
                window.open(`sar_nic_detail-${{hostname}}.html`, 'NicDetail', 'width=1200,height=800,scrollbars=yes,resizable=yes');
            }}
        </script>
    </body>
    </html>
    """