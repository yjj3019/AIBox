# -*- coding: utf-8 -*-
# ==============================================================================
# HTML Template Module
# ------------------------------------------------------------------------------
# [BUG FIX] 네트워크 그래프 생성 시 발생하던 TypeError를 해결하기 위해
#           잘못된 중괄호 문법을 수정했습니다.
# [BUG FIX] 누락되었던 'Last Boot' 정보가 시스템 요약 테이블에 표시되도록 수정.
# ==============================================================================

import html
from datetime import datetime

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
        priority_map = {"높음": "high", "중간": "medium", "낮음": "low"}
        for item in rec_list:
            priority_class = priority_map.get(item.get('priority', ''), "")
            issue_html = h(str(item.get('issue', 'N/A')))
            related_logs = item.get('related_logs')
            if related_logs and isinstance(related_logs, list):
                logs_html = h('\n'.join(related_logs))
                issue_html += f' <div class="tooltip"><span class="log-icon">💬</span><span class="tooltiptext">{logs_html}</span></div>'
            rows += f"<tr><td><span class='priority-badge {priority_class}'>{h(item.get('priority', 'N/A'))}</span></td><td>{h(str(item.get('category', 'N/A')))}</td><td>{issue_html}</td><td>{h(str(item.get('solution', 'N/A')))}</td></tr>"
        return rows

    def render_graph(graph_key, title, graphs_data):
        graph_data = graphs_data.get(graph_key)
        # [요청 반영] disk_detail 데이터가 있을 때만 팝업을 활성화합니다.
        has_disk_detail = data.get('sar_data', {}).get('disk_detail')
        if isinstance(graph_data, str) and graph_data:
            # [요청 반영] Disk I/O 그래프에 팝업을 여는 onclick 이벤트 추가
            if graph_key == 'disk' and has_disk_detail:
                return f'<div class="graph-container interactive" onclick="openDiskDetailPopup()"><h3>{title}</h3><img src="data:image/png;base64,{graph_data}" alt="{title} Graph"><div class="graph-overlay">상세 정보 보기</div></div>'
            return f'<div class="graph-container"><h3>{title}</h3><img src="data:image/png;base64,{graph_data}" alt="{title} Graph"></div>'
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
        if not news_list: return "<tr><td colspan='4' style='text-align:center;'>관련 보안 뉴스 없음</td></tr>"
        rows = ""
        for item in news_list:
            severity = item.get('severity', '').lower()
            severity_badge = f"<span class='priority-badge {'high' if severity == 'critical' else 'medium' if severity == 'important' else 'low'}'>{h(item.get('severity'))}</span>"
            rows += f"<tr><td><a href='https://access.redhat.com/security/cve/{h(item.get('cve_id'))}' target='_blank'>{h(item.get('cve_id'))}</a></td><td>{severity_badge}</td><td>{h(item.get('package'))}</td><td>{h(item.get('description'))}</td></tr>"
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
    process_stats = data.get('processes', {})
    security_news = data.get('security_advisories', [])
    
    summary_raw = ai_analysis.get('summary', '분석 결과 없음')
    summary_html = h(summary_raw).replace('\n', '<br>')

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
            .data-table th, .data-table td {{ padding: 0.9rem 1rem; text-align: left; border-bottom: 1px solid var(--border-color); word-break: break-word; }}
            .data-table thead th {{ background-color: #f7f9fc; font-weight: 600; }}
            .graph-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(450px, 1fr)); gap: 1.5rem; }}
            .graph-container {{ padding: 1rem; border: 1px solid var(--border-color); border-radius: 8px; margin-top: 1rem; }}
            .graph-container h3 {{ text-align: center; border: none; }}
            .graph-container img {{ width: 100%; display: block; }}
            .no-data-message {{ text-align: center; color: #888; padding: 2rem; }}
            .graph-container.interactive {{ cursor: pointer; position: relative; }}
            .graph-container.interactive:hover .graph-overlay {{ opacity: 1; }}
            .graph-overlay {{ position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); color: white; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; font-weight: bold; opacity: 0; transition: opacity 0.3s; }}
            .progress-bar-container {{ height: 12px; width: 100%; background-color: var(--light-gray); border-radius: 6px; overflow:hidden;}}
            .progress-bar {{ height: 100%; border-radius: 6px; }}
            .priority-badge {{ padding: 0.25em 0.6em; border-radius: 5px; font-size: 0.85em; color: white; font-weight: 600; }}
            .priority-badge.high {{ background-color: var(--danger-color); }}
            .priority-badge.medium {{ background-color: var(--warning-color); }}
            .priority-badge.low {{ background-color: #7f8c8d; }}
            .tooltip {{ position: relative; display: inline-block; cursor: help; }}
            .tooltip .tooltiptext {{ visibility: hidden; width: 450px; background-color: var(--secondary-color); color: #fff; text-align: left; border-radius: 6px; padding: 10px; position: absolute; z-index: 10; bottom: 125%; left: 50%; margin-left: -225px; opacity: 0; transition: opacity 0.3s; white-space: pre-wrap;}}
            .tooltip:hover .tooltiptext {{ visibility: visible; opacity: 1; }}
            footer {{ text-align: center; padding-top: 2rem; color: #777; }}
        </style>
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
                    <tr><th>Last Boot</th><td>{h(system_info.get('last_boot', 'N/A'))}</td></tr>
                </table></div>
            </div>

            <div class="report-card">
                <div class="card-header">{svg_icons['summary_ai']} AI 종합 분석</div>
                <div class="card-body"><p>{summary_html}</p></div>
            </div>
            <div class="report-card">
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

            <div class="report-card">
                <div class="card-header">{svg_icons['dashboard']} 자원 사용 현황</div>
                <div class="card-body graph-grid">
                    {render_graph('cpu', 'CPU Usage (%)', graphs)}
                    {render_graph('memory', 'Memory Usage (KB)', graphs)}
                    {render_graph('load', 'System Load Average', graphs)}
                    {render_graph('disk', 'Disk I/O', graphs)}
                    {render_graph('swap', 'Swap Usage (%)', graphs)}
                    {''.join(render_graph(iface, f"Network Traffic ({iface})", {iface: graph_data}) for iface, graph_data in graphs.get('network', {}).items())}
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
                <div class="card-header">{svg_icons['shield']} AI 선정 긴급 보안 위협</div>
                 <div class="card-body">
                    <table class="data-table">
                        <thead><tr><th>CVE</th><th>Severity</th><th>Package</th><th>Description</th></tr></thead>
                        <tbody>{create_security_news_rows(security_news)}</tbody>
                    </table>
                </div>
            </div>

        </div>
        <footer>AI System Analyzer &bull; Generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer>
        <script>
            function openDiskDetailPopup() {{
                const hostname = "{h(data.get('hostname', ''))}";
                window.open(`sar_gui_disk-${{hostname}}.html`, 'DiskIODetail', 'width=1200,height=800,scrollbars=yes,resizable=yes');
            }}
        </script>
    </body>
    </html>
    """