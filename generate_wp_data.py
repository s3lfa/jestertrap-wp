#!/usr/bin/env python3
"""
JesterTrap WP - Generador de datos para el dashboard
Lee logs del honeypot WordPress y genera wp-data.json con stats, ataques, y eventos detallados.
Procesa: page visits, login attempts, XML-RPC, REST API, wp-admin, comments, trackbacks,
plugin enumeration, AJAX, setup-config, sitemap, pingbacks.
"""

import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime
import urllib.request

LOG_FILE = '/var/www/wp-honeypot/logs/wp-honeypot.json'
OUTPUT_FILE = '/var/www/honeypot/wp-data.json'
GEOIP_CACHE = {}

def read_logs():
    events = []
    if not os.path.exists(LOG_FILE):
        return events
    with open(LOG_FILE, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events

def batch_geoip(ips):
    """Usa ip-api.com batch endpoint para geoip"""
    results = {}
    unique_ips = list(set(ips))
    unique_ips = [ip for ip in unique_ips if ip and not ip.startswith('127.') and ip != '::1']
    if not unique_ips:
        return results
    for i in range(0, len(unique_ips), 100):
        batch = unique_ips[i:i+100]
        try:
            data = json.dumps([{"query": ip, "fields": "query,country,countryCode,region,city,lat,lon,timezone,isp,org,as"} for ip in batch]).encode()
            req = urllib.request.Request(
                'http://ip-api.com/batch',
                data=data,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                for item in data:
                    ip = item.get('query', '')
                    if ip:
                        results[ip] = {
                            'country': item.get('countryCode', ''),
                            'country_name': item.get('country', ''),
                            'city': item.get('city', ''),
                            'lat': item.get('lat'),
                            'lon': item.get('lon'),
                            'org': item.get('org', item.get('isp', '')),
                            'as': item.get('as', ''),
                        }
        except Exception as e:
            sys.stderr.write(f"GeoIP error: {e}\n")
    return results

ATTACK_LABELS = {
    'sqli': 'SQL Injection',
    'xss': 'Cross-Site Scripting (XSS)',
    'lfi_rfi': 'LFI/RFI',
    'cmd_injection': 'Command Injection',
    'php_injection': 'PHP Code Injection',
    'ssti': 'Server-Side Template Injection',
    'xpath': 'XPath Injection',
    'crlf': 'CRLF Injection',
    'open_redirect': 'Open Redirect',
    'ssrf': 'SSRF',
    'suspicious_scanner': 'Scanner Sospechoso',
}

# Map eventid -> category for stats
EVENT_CATEGORIES = {
    'wp-honeypot.page.visit': 'page_visits',
    'wp-honeypot.wp-login.visit': 'login_visits',
    'wp-honeypot.wp-login.attempt': 'login_attempts',
    'wp-honeypot.xmlrpc.request': 'xmlrpc_requests',
    'wp-honeypot.xmlrpc.method': 'xmlrpc_requests',
    'wp-honeypot.xmlrpc.credentials': 'xmlrpc_credentials',
    'wp-honeypot.xmlrpc.pingback': 'xmlrpc_pingbacks',
    'wp-honeypot.xmlrpc.multicall': 'xmlrpc_multicalls',
    'wp-honeypot.rest-api.request': 'rest_api_requests',
    'wp-honeypot.wp-admin.visit': 'wp_admin_visits',
    'wp-honeypot.wp-admin.ajax': 'wp_admin_ajax',
    'wp-honeypot.wp-admin.setup-config': 'wp_setup_config',
    'wp-honeypot.feed.visit': 'feed_visits',
    'wp-honeypot.wp-comments.visit': 'comment_visits',
    'wp-honeypot.wp-comments.spam': 'comment_spam',
    'wp-honeypot.wp-trackback.visit': 'trackback_visits',
    'wp-honeypot.wp-trackback.attempt': 'trackback_attempts',
    'wp-honeypot.wp-plugins.enum': 'plugin_enum',
    'wp-honeypot.wp-plugins.search': 'plugin_search',
    'wp-honeypot.wp-plugins.access': 'plugin_access',
    'wp-honeypot.sitemap.request': 'sitemap_requests',
}

def process_events(events):
    # Stats base
    stats = {
        'total_events': len(events),
        'unique_ips': len(set(e.get('src_ip', '') for e in events)),
    }
    
    # Contar por categoría
    category_counts = Counter()
    for e in events:
        eid = e.get('eventid', '')
        cat = EVENT_CATEGORIES.get(eid, 'other')
        category_counts[cat] += 1
    
    stats.update(dict(category_counts))
    
    # Contar ataques detectados
    attack_types = Counter()
    attack_severities = Counter()
    attacks_detected = 0
    for e in events:
        atks = e.get('attacks', [])
        if atks:
            attacks_detected += len(atks)
            for a in atks:
                attack_types[a.get('type', 'unknown')] += 1
                attack_severities[a.get('severity', 'low')] += 1
    
    stats['attacks_detected'] = attacks_detected
    stats['unique_attack_types'] = len(attack_types)
    
    # GeoIP
    all_ips = list(set(e.get('src_ip', '') for e in events if e.get('src_ip')))
    geoip = batch_geoip(all_ips)
    
    # Ataques por IP
    ip_counts = Counter(e.get('src_ip', '') for e in events)
    ip_event_types = defaultdict(Counter)
    for e in events:
        ip = e.get('src_ip', '')
        if ip:
            ip_event_types[ip][e.get('eventid', 'unknown')] += 1
    
    attacks = []
    for ip, count in ip_counts.most_common(100):
        if not ip or ip in ('127.0.0.1', '::1'):
            continue
        geo = geoip.get(ip, {})
        # Top event type for this IP
        top_event = ip_event_types[ip].most_common(1)[0][0] if ip_event_types[ip] else ''
        attacks.append({
            'ip': ip,
            'count': count,
            'last_seen': next((e.get('timestamp', '') for e in reversed(events) if e.get('src_ip') == ip), ''),
            'country': geo.get('country', ''),
            'country_name': geo.get('country_name', ''),
            'city': geo.get('city', ''),
            'lat': geo.get('lat'),
            'lon': geo.get('lon'),
            'org': geo.get('org', ''),
            'as': geo.get('as', ''),
            'top_event': top_event,
            'event_breakdown': dict(ip_event_types[ip]),
        })
    
    # Top credenciales (wp-login)
    cred_counter = Counter()
    for e in events:
        if e.get('eventid') == 'wp-honeypot.wp-login.attempt':
            u = e.get('username', e.get('post_data', {}).get('log', ''))
            p = e.get('password', e.get('post_data', {}).get('pwd', ''))
            if u or p:
                cred_counter[f"{u}:{p}"] += 1
    # XML-RPC credentials
    xmlrpc_cred_counter = Counter()
    for e in events:
        if e.get('eventid') == 'wp-honeypot.xmlrpc.credentials':
            method = e.get('method_name', '')
            params = [e.get('param1', ''), e.get('param2', '')]
            xmlrpc_cred_counter[f"{method}:{params[0]}:{params[1]}"] += 1
    
    top_creds = [{'cred': c, 'count': n, 'source': 'wp-login'} for c, n in cred_counter.most_common(50)]
    top_creds += [{'cred': c, 'count': n, 'source': 'xmlrpc'} for c, n in xmlrpc_cred_counter.most_common(20)]
    
    # Logins recientes
    recent_logins = []
    for e in reversed(events):
        if e.get('eventid') == 'wp-honeypot.wp-login.attempt':
            recent_logins.append({
                'ip': e.get('src_ip', ''),
                'username': e.get('username', e.get('post_data', {}).get('log', '')),
                'password': e.get('password', e.get('post_data', {}).get('pwd', '')),
                'time': e.get('timestamp', ''),
                'attacks': e.get('attacks', []),
            })
    recent_logins = recent_logins[:50]
    
    # XML-RPC recientes
    recent_xmlrpc = []
    for e in reversed(events):
        if e.get('eventid') in ('wp-honeypot.xmlrpc.request', 'wp-honeypot.xmlrpc.method', 'wp-honeypot.xmlrpc.credentials', 'wp-honeypot.xmlrpc.pingback', 'wp-honeypot.xmlrpc.multicall'):
            recent_xmlrpc.append({
                'ip': e.get('src_ip', ''),
                'method_name': e.get('method_name', ''),
                'event_type': e.get('eventid', '').replace('wp-honeypot.xmlrpc.', ''),
                'time': e.get('timestamp', ''),
                'body' : e.get('body', '')[:500] if e.get('body') else '',
                'attacks': e.get('attacks', []),
            })
    recent_xmlrpc = recent_xmlrpc[:50]
    
    # REST API recientes
    recent_rest = []
    for e in reversed(events):
        if e.get('eventid') == 'wp-honeypot.rest-api.request':
            recent_rest.append({
                'ip': e.get('src_ip', ''),
                'method': e.get('method', 'GET'),
                'uri': e.get('uri', ''),
                'time': e.get('timestamp', ''),
                'attacks': e.get('attacks', []),
            })
    recent_rest = recent_rest[:30]
    
    # wp-admin visitas
    recent_admin = []
    for e in reversed(events):
        if e.get('eventid') in ('wp-honeypot.wp-admin.visit', 'wp-honeypot.wp-admin.ajax', 'wp-honeypot.wp-admin.setup-config'):
            recent_admin.append({
                'ip': e.get('src_ip', ''),
                'uri': e.get('uri', ''),
                'event_type': e.get('eventid', '').replace('wp-honeypot.', ''),
                'time': e.get('timestamp', ''),
                'attacks': e.get('attacks', []),
                'action' : e.get('action', ''),
            })
    recent_admin = recent_admin[:50]
    
    # Visitas a páginas
    recent_pages = []
    for e in reversed(events):
        if e.get('eventid') == 'wp-honeypot.page.visit':
            recent_pages.append({
                'ip': e.get('src_ip', ''),
                'uri': e.get('uri', ''),
                'method': e.get('method', 'GET'),
                'time': e.get('timestamp', ''),
                'attacks': e.get('attacks', []),
                'max_severity': e.get('max_severity', ''),
            })
    recent_pages = recent_pages[:50]
    
    # POST Bodies capturados
    recent_post_bodies = []
    for e in reversed(events):
        post_body = e.get('post_body', '') or e.get('post_data_raw', '')
        if post_body and e.get('method', '') in ('POST', 'PUT', 'PATCH'):
            recent_post_bodies.append({
                'ip': e.get('src_ip', ''),
                'uri': e.get('uri', ''),
                'method': e.get('method', 'POST'),
                'time': e.get('timestamp', ''),
                'post_body': post_body[:1000],
                'event_type': e.get('eventid', '').replace('wp-honeypot.', ''),
            })
    recent_post_bodies = recent_post_bodies[:50]
    
    # Comentarios spam
    recent_comments = []
    for e in reversed(events):
        if e.get('eventid') == 'wp-honeypot.wp-comments.spam':
            recent_comments.append({
                'ip': e.get('src_ip', ''),
                'author': e.get('author', ''),
                'email': e.get('email', ''),
                'url': e.get('url', ''),
                'comment': (e.get('comment', '') or '')[:300],
                'post_id': e.get('post_id', ''),
                'time': e.get('timestamp', ''),
                'attacks': e.get('attacks', []),
            })
    recent_comments = recent_comments[:50]
    
    # Trackbacks
    recent_trackbacks = []
    for e in reversed(events):
        if e.get('eventid') == 'wp-honeypot.wp-trackback.attempt':
            recent_trackbacks.append({
                'ip': e.get('src_ip', ''),
                'title': e.get('title', ''),
                'blog_name': e.get('blog_name', ''),
                'url': e.get('url', ''),
                'time': e.get('timestamp', ''),
                'attacks': e.get('attacks', []),
            })
    recent_trackbacks = recent_trackbacks[:30]
    
    # Plugin enumeration
    recent_plugins = []
    for e in reversed(events):
        if e.get('eventid') in ('wp-honeypot.wp-plugins.search', 'wp-honeypot.wp-plugins.access', 'wp-honeypot.wp-plugins.enum'):
            recent_plugins.append({
                'ip': e.get('src_ip', ''),
                'plugin': e.get('plugin_name', e.get('plugin', '')),
                'uri': e.get('uri', ''),
                'time': e.get('timestamp', ''),
                'event_type': e.get('eventid', '').replace('wp-honeypot.wp-plugins.', ''),
            })
    recent_plugins = recent_plugins[:50]
    
    # Pingbacks
    recent_pingbacks = []
    for e in reversed(events):
        if e.get('eventid') == 'wp-honeypot.xmlrpc.pingback':
            recent_pingbacks.append({
                'ip': e.get('src_ip', ''),
                'source_url': e.get('source_url', ''),
                'target_url': e.get('target_url', ''),
                'time': e.get('timestamp', ''),
            })
    recent_pingbacks = recent_pingbacks[:30]
    
    # === Ataques detectados ===
    recent_attacks = []
    for e in reversed(events):
        atks = e.get('attacks', [])
        if atks:
            recent_attacks.append({
                'ip': e.get('src_ip', ''),
                'time': e.get('timestamp', ''),
                'uri': e.get('uri', ''),
                'method': e.get('method', 'GET'),
                'types': e.get('attack_types', []),
                'severity': e.get('max_severity', 'info'),
                'details': atks,
                'user_agent': e.get('user_agent', ''),
                'event_type': e.get('eventid', '').replace('wp-honeypot.', ''),
            })
    recent_attacks = recent_attacks[:50]
    
    # Top tipos de ataque
    attack_type_stats = [{'type': t, 'count': c, 'label': ATTACK_LABELS.get(t, t)} for t, c in attack_types.most_common(20)]
    
    # Top User-Agents
    ua_counter = Counter(e.get('user_agent', '') for e in events if e.get('user_agent'))
    top_user_agents = [{'ua': ua, 'count': c} for ua, c in ua_counter.most_common(15) if ua]
    
    # Top URIs visitadas
    uri_counter = Counter(e.get('uri', '') for e in events if e.get('uri'))
    top_uris = [{'uri': u, 'count': c} for u, c in uri_counter.most_common(20) if u]
    
    # Top plugins buscados
    plugin_counter = Counter()
    for e in events:
        if e.get('eventid') in ('wp-honeypot.wp-plugins.search', 'wp-honeypot.wp-plugins.access'):
            p = e.get('plugin_name', e.get('plugin', ''))
            if p:
                plugin_counter[p] += 1
    top_plugins = [{'plugin': p, 'count': c} for p, c in plugin_counter.most_common(20)]
    
    return {
        'stats': stats,
        'attacks': attacks,
        'attack_types': attack_type_stats,
        'attack_severities': dict(attack_severities),
        'top_credentials': top_creds,
        'recent_logins': recent_logins,
        'recent_xmlrpc': recent_xmlrpc,
        'recent_rest_api': recent_rest,
        'recent_admin_visits': recent_admin,
        'recent_page_visits': recent_pages,
        'recent_comments': recent_comments,
        'recent_trackbacks': recent_trackbacks,
        'recent_plugins': recent_plugins,
        'recent_pingbacks': recent_pingbacks,
        'recent_attacks': recent_attacks,
        'top_user_agents': top_user_agents,
        'top_uris': top_uris,
        'top_plugins': top_plugins,
        'recent_post_bodies': recent_post_bodies,
    }

def main():
    events = read_logs()
    data = process_events(events)
    
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(data, f)
    
    s = data['stats']
    print(f"wp-data.json generado: {s.get('total_events', 0)} eventos, {s.get('unique_ips', 0)} IPs, "
          f"{s.get('login_attempts', 0)} logins, {s.get('xmlrpc_requests', 0)} xmlrpc, "
          f"{s.get('rest_api_requests', 0)} rest-api, {s.get('wp_admin_visits', 0)} wp-admin, "
          f"{s.get('comment_spam', 0)} comments, {s.get('trackback_attempts', 0)} trackbacks, "
          f"{s.get('plugin_search', 0)} plugin searches, "
          f"{s.get('attacks_detected', 0)} ataques detectados")

if __name__ == '__main__':
    main()