#!/usr/bin/env python3
# webrecon_v4.py
# WebRecon v4 - Comprehensive web reverse-engineering + vuln detection + bug-bounty report templates (Arabic UI).
# WARNING: Active checks are potentially intrusive. Use --active ONLY on targets you are AUTHORIZED to test.

import argparse, re, json, os, sys, time, shutil, base64, traceback
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlencode, urlunparse, parse_qsl
import hashlib

# Optional libraries (soft dependencies)
try:
    import requests
except Exception:
    requests = None

try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

try:
    import jsbeautifier
except Exception:
    jsbeautifier = None

# ----------------- Utilities -----------------
def ensure_requests():
    if requests is None:
        raise RuntimeError('مكتبة requests غير مثبتة. شغّل: pip install requests')

def ensure_bs4():
    if BeautifulSoup is None:
        raise RuntimeError('مكتبة beautifulsoup4 غير مثبتة. شغّل: pip install beautifulsoup4')

def safe_mkdir(p): Path(p).mkdir(parents=True, exist_ok=True)

def sha256_bytes(b: bytes) -> str:
    import hashlib
    h = hashlib.sha256(); h.update(b); return h.hexdigest()

# ----------------- Network helpers -----------------
def fetch_url(url, timeout=12, headers=None, allow_redirects=True):
    ensure_requests()
    headers = headers or {'User-Agent': 'WebReconV4/1.0'}
    try:
        r = requests.get(url, timeout=timeout, headers=headers, allow_redirects=allow_redirects)
        return {'ok': True, 'status_code': r.status_code, 'content': r.content, 'text': r.text, 'url': r.url, 'headers': dict(r.headers), 'cookies': r.cookies.get_dict()}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def head_request(url, timeout=8):
    ensure_requests()
    try:
        r = requests.head(url, timeout=timeout, allow_redirects=True)
        return {'ok': True, 'headers': dict(r.headers), 'status': r.status_code}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

# ----------------- Passive vulnerability checks -----------------
SECURITY_HEADERS = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy']

def check_security_headers(headers):
    issues = []
    if not headers:
        return issues
    if headers.get('Strict-Transport-Security') is None:
        issues.append({'id':'missing_hsts','severity':'medium','desc':'Missing Strict-Transport-Security header (HSTS)'})
    csp = headers.get('Content-Security-Policy') or headers.get('X-Content-Security-Policy')
    if not csp:
        issues.append({'id':'missing_csp','severity':'medium','desc':'Missing Content-Security-Policy header'})
    else:
        if 'unsafe-inline' in csp or 'unsafe-eval' in csp:
            issues.append({'id':'weak_csp','severity':'medium','desc':'CSP allows unsafe-inline or unsafe-eval'})
    if headers.get('X-Frame-Options') is None and 'frame-ancestors' not in (csp or ''):
        issues.append({'id':'clickjacking','severity':'medium','desc':'Missing X-Frame-Options and no frame-ancestors in CSP (possible clickjacking)'})
    if headers.get('X-Content-Type-Options') is None:
        issues.append({'id':'missing_xcto','severity':'low','desc':'Missing X-Content-Type-Options header'})
    cookies = headers.get('Set-Cookie')
    if cookies and 'secure' not in cookies.lower():
        issues.append({'id':'cookie_not_secure','severity':'low','desc':'Set-Cookie lacks Secure attribute (may be sent over HTTP)'})
    return issues

COMMON_SENSITIVE_PATHS = [
    '/.env','.env','/config.php','.git/HEAD','/.git','/phpinfo.php','/server-status','/backup.zip','/wp-config.php','/admin/login.php','/composer.json','.DS_Store'
]

def check_sensitive_paths(base_url):
    ensure_requests()
    findings = []
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    for p in COMMON_SENSITIVE_PATHS:
        url = urljoin(base, p)
        try:
            r = requests.get(url, timeout=6, allow_redirects=True, headers={'User-Agent':'WebReconV4/1.0'})
            if r.status_code == 200 and len(r.content) > 50:
                findings.append({'path': p, 'url': url, 'status': r.status_code, 'note':'Found content (possible sensitive file)'})
        except Exception:
            pass
    return findings

def check_cors(headers):
    findings = []
    acao = headers.get('Access-Control-Allow-Origin') if headers else None
    if acao == '*' :
        findings.append({'id':'cors_wildcard','severity':'high','desc':'Access-Control-Allow-Origin: * (wildcard) - potential data exfiltration via cross-origin requests'})
    return findings

def detect_open_redirects_links(html_text, base_url):
    suspects = []
    for m in re.findall(r'href=[\"\\\']([^\"\\\']+)[\"\\\']', html_text, re.I):
        if any(p in m.lower() for p in ['redirect=','url=','next=','return=']):
            suspects.append(urljoin(base_url, m))
    return suspects

# ----------------- JS static analysis helpers -----------------
def extract_scripts_from_html(html_text, base_url=None):
    ensure_bs4()
    soup = BeautifulSoup(html_text, 'html.parser')
    scripts = []
    for tag in soup.find_all('script'):
        src = tag.get('src')
        text = tag.string or ''
        if src:
            full = urljoin(base_url or '', src)
            scripts.append({'type': 'external', 'src': src, 'url': full, 'content': None})
        else:
            scripts.append({'type': 'inline', 'src': None, 'url': None, 'content': text})
    return scripts

JS_PATTERNS = [r'\beval\s*\(', r'\bFunction\s*\(', r'atob\s*\(', r'unescape\s*\(', r'\\x[0-9A-Fa-f]{2}', r'_0x[0-9a-fA-F]+']

def js_static_checks(code_text):
    findings = []
    for p in JS_PATTERNS:
        matches = re.findall(p, code_text)
        if matches:
            findings.append({'pattern': p, 'count': len(matches)})
    b64s = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', code_text)
    if b64s:
        findings.append({'pattern': 'long_base64_blob', 'count': len(b64s)})
    return findings

def try_base64_decode(s):
    s2 = re.sub(r'[^A-Za-z0-9+/=]', '', s)
    try:
        b = base64.b64decode(s2)
        try: txt = b.decode('utf-8')
        except: txt = b.decode('latin-1', errors='ignore')
        return {'ok': True, 'text': txt, 'bytes': b}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def unescape_js_string(s):
    s1 = re.sub(r'\\x([0-9A-Fa-f]{2})', lambda m: chr(int(m.group(1),16)), s)
    s2 = re.sub(r'\\u([0-9A-Fa-f]{4})', lambda m: chr(int(m.group(1),16)), s1)
    try: return bytes(s2, 'utf-8').decode('unicode_escape')
    except: return s2

# ----------------- Heuristic _0x deobfuscation -----------------
def try_deobf_0x(code_text):
    arr_match = re.search(r"var\s+(_0x[0-9a-fA-F]+)\s*=\s*(\[[^\]]+\])", code_text)
    if not arr_match: return None
    name = arr_match.group(1)
    arr_literal = arr_match.group(2)
    try:
        import ast
        cleaned = arr_literal.replace('\n','').replace('\r','')
        pylist = ast.literal_eval(cleaned)
        def repl(m):
            idx = int(m.group(1), 16) if m.group(1).startswith('0x') else int(m.group(1))
            try: return repr(pylist[idx])
            except Exception: return m.group(0)
        pattern = re.compile(re.escape(name) + r"\[\s*(0x[0-9A-Fa-f]+|\d+)\s*\]")
        newcode = pattern.sub(repl, code_text)
        return {'ok': True, 'deobf_code': newcode[:20000], 'replacements': True}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

# ----------------- Active lightweight checks (ONLY with --active) -----------------
def active_reflected_xss_test(url):
    ensure_requests()
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    token = 'XR_TEST_499'  # short safe token
    if qs:
        first = next(iter(qs))
        qs[first] = token
    else:
        qs['q'] = token
    new_q = urlencode(qs)
    new_parsed = parsed._replace(query=new_q)
    test_url = urlunparse(new_parsed)
    res = fetch_url(test_url)
    if not res.get('ok'): return {'ok': False, 'error': res.get('error')}
    if token in res.get('text',''):
        return {'ok': True, 'vuln': 'reflected_xss', 'evidence': 'payload reflected in response', 'test_url': test_url}
    return {'ok': True, 'vuln': None}

def active_open_redirect_test(url):
    ensure_requests()
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    redirectable = False
    test_target = 'https://example.com/redirect_test'
    if qs:
        # try common redirect params
        for param in list(qs.keys())[:3]:
            qs[param] = test_target
            new_q = urlencode(qs)
            test_url = parsed._replace(query=new_q)
            test_url_s = urlunparse(test_url)
            res = fetch_url(test_url_s)
            if res.get('ok') and 'example.com/redirect_test' in res.get('text','') or res.get('url','').startswith('https://example.com'):
                redirectable = True
                return {'ok': True, 'vuln': 'open_redirect', 'test_url': test_url_s}
    return {'ok': True, 'vuln': None}

def active_sql_injection_test(url):
    ensure_requests()
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if not qs:
        return {'ok': True, 'vuln': None}
    payloads = ["' OR '1'='1", "\" OR \"1\"=\"1", "'; -- ", "' OR 1=1 -- "]
    for p in payloads:
        for param in list(qs.keys())[:3]:
            qs[param] = p
            new_q = urlencode(qs)
            test_url = urlunparse(parsed._replace(query=new_q))
            res = fetch_url(test_url)
            if not res.get('ok'): continue
            text = res.get('text','').lower()
            # heuristic: SQL error strings
            if any(err in text for err in ['sql syntax', 'mysql', 'sqlstate', 'syntax error', 'unterminated string constant']):
                return {'ok': True, 'vuln': 'sql_error_disclosure', 'test_url': test_url, 'evidence_snippet': text[:400]}
    return {'ok': True, 'vuln': None}

# ----------------- CSRF detection (passive) -----------------
def detect_csrf_on_forms(html_text, base_url):
    ensure_bs4()
    soup = BeautifulSoup(html_text, 'html.parser')
    forms = []
    for form in soup.find_all('form'):
        method = (form.get('method') or 'GET').upper()
        has_csrf = False
        for inp in form.find_all('input', {'type':'hidden'}):
            name = (inp.get('name') or '').lower()
            if 'csrf' in name or 'token' in name or 'nonce' in name:
                has_csrf = True
                break
        forms.append({'action': urljoin(base_url or '', form.get('action') or ''), 'method': method, 'has_csrf': has_csrf})
    # return forms lacking csrf token (POST forms)
    risky = [f for f in forms if f['method']=='POST' and not f['has_csrf']]
    return risky

# ----------------- Aggregate vulnerability detection for a page -----------------
def analyze_page_vulns(page_item, active=False):
    vulns = []
    headers = page_item.get('headers') or {}
    vulns.extend(check_security_headers(headers))
    vulns.extend(check_cors(headers))
    html = page_item.get('raw_html') or page_item.get('text') or ''
    redirects = detect_open_redirects_links(html, page_item.get('url'))
    if redirects:
        vulns.append({'id':'potential_open_redirects','severity':'medium','desc':'Found links with redirect-like parameters', 'examples': redirects[:5]})
    base = page_item.get('base') or page_item.get('url') or ''
    sensitive = check_sensitive_paths(base) if base else []
    if sensitive:
        vulns.append({'id':'sensitive_files','severity':'high','desc':'Found potentially sensitive files', 'examples': sensitive})
    csrf_risky = detect_csrf_on_forms(html, page_item.get('url'))
    if csrf_risky:
        vulns.append({'id':'csrf_missing','severity':'medium','desc':'Found POST forms without CSRF token', 'examples': csrf_risky[:5]})
    if active:
        try:
            x = active_reflected_xss_test(page_item.get('url'))
            if x.get('ok') and x.get('vuln'):
                vulns.append({'id':'reflected_xss','severity':'high','desc':'Reflected XSS detected', 'evidence': x.get('evidence'), 'test_url': x.get('test_url')})
        except Exception:
            pass
        try:
            r = active_open_redirect_test(page_item.get('url'))
            if r.get('ok') and r.get('vuln'):
                vulns.append({'id':'open_redirect','severity':'high','desc':'Open redirect detected', 'test_url': r.get('test_url')})
        except Exception:
            pass
        try:
            s = active_sql_injection_test(page_item.get('url'))
            if s.get('ok') and s.get('vuln'):
                vulns.append({'id':'sql_injection','severity':'high','desc':'SQL error disclosure or potential injection', 'evidence': s.get('evidence_snippet'), 'test_url': s.get('test_url')})
        except Exception:
            pass
    return vulns

# ----------------- Report generation (JSON, HTML, Bounty Markdown) -----------------
def generate_html_report_with_vulns(report, out_dir):
    safe_mkdir(out_dir)
    html = ['<html><head><meta charset="utf-8"><title>WebRecon v4 Report</title></head><body>']
    html.append(f"<h1>WebRecon v4 Report for {report.get('start_url')}</h1>")
    html.append(f"<p>Generated: {report.get('scanned_at')}</p>")
    for p in report.get('pages', []):
        html.append(f"<h2>Page: {p.get('url')}</h2>")
        if p.get('error'):
            html.append(f"<p><b>Error:</b> {p.get('error')}</p>"); continue
        html.append(f"<p>Status: {p.get('status')}</p>")
        html.append(f"<p>Scripts: {len(p.get('scripts',[]))}</p>")
        v = p.get('vulns', [])
        if v:
            html.append('<h3 style="color:red">Vulnerabilities found:</h3>')
            for vv in v:
                html.append(f"<div><b>{vv.get('id')}</b> - {vv.get('desc')} (severity: {vv.get('severity')})</div>")
                if vv.get('examples'): html.append(f"<pre>{json.dumps(vv.get('examples'), ensure_ascii=False, indent=2)}</pre>")
                if vv.get('evidence'): html.append(f"<pre>{vv.get('evidence')}</pre>")
                if vv.get('test_url'): html.append(f"<p>Test URL: {vv.get('test_url')}</p>")
        else:
            html.append('<p style="color:green">No immediate issues detected (passive checks).</p>')
        html.append('<hr/>')
    html.append('</body></html>')
    out = Path(out_dir) / 'webrecon_v4_report.html'
    out.write_text('\n'.join(html), encoding='utf-8')
    return str(out)

def generate_bounty_markdown(report, out_dir):
    safe_mkdir(out_dir)
    parts = []
    parts.append(f"# Bug Bounty Report for {report.get('start_url')}\n")
    parts.append(f"Generated: {report.get('scanned_at')}\n")
    for p in report.get('pages', []):
        v = p.get('vulns', [])
        if not v: continue
        parts.append(f"## Affected page: {p.get('url')}\n")
        for vv in v:
            parts.append(f"### {vv.get('id')} - Severity: {vv.get('severity')}\n")
            parts.append(f"{vv.get('desc')}\n")
            if vv.get('test_url'): parts.append(f"- Test URL: `{vv.get('test_url')}`\n")
            if vv.get('evidence'): parts.append(f"- Evidence: ```{vv.get('evidence')}```\n")
            if vv.get('examples'): parts.append(f"- Examples: ```{json.dumps(vv.get('examples'), ensure_ascii=False, indent=2)}```\n")
            parts.append("**Steps to reproduce**:\n1. ...\n\n**Impact**:\n- Describe how this can be abused.\n\n**Suggested fix**:\n- Provide remediation steps.\n\n---\n")
    out = Path(out_dir) / 'webrecon_v4_bounty_report.md'
    out.write_text('\n'.join(parts), encoding='utf-8')
    return str(out)

# ----------------- Main scan (combines everything) -----------------
def full_scan_all(start_url, out_dir, depth=1, active=False, brute_force=False):
    ensure_requests(); ensure_bs4()
    safe_mkdir(out_dir)
    parsed = urlparse(start_url); base = f"{parsed.scheme}://{parsed.netloc}"
    report = {'start_url': start_url, 'scanned_at': time.strftime('%Y-%m-%dT%H:%M:%SZ'), 'pages': []}
    visited = set(); to_visit = [(start_url,0)]
    # passive checks: robots and sitemap (simple)
    try:
        r_robot = fetch_url(urljoin(base, '/robots.txt'))
        if r_robot.get('ok'): Path(out_dir).joinpath('robots.txt').write_bytes(r_robot.get('content'))
    except Exception:
        pass
    while to_visit:
        url, d = to_visit.pop(0)
        if url in visited or d>depth: continue
        visited.add(url)
        print(f"Fetching: {url} (depth {d})")
        res = fetch_url(url)
        page = {'url': url, 'status': res.get('status_code') if res.get('ok') else None, 'error': res.get('error') if not res.get('ok') else None, 'scripts':[], 'links':[], 'headers': res.get('headers') if res.get('ok') else {}, 'text': res.get('text') if res.get('ok') else ''}
        if not res.get('ok'):
            report['pages'].append(page); continue
        try:
            soup = BeautifulSoup(res.get('text',''), 'html.parser')
        except Exception:
            soup = None
        if soup:
            for tag in soup.find_all('script'):
                src = tag.get('src'); code = tag.string or ''
                if src:
                    full = urljoin(url, src)
                    item = {'type':'external','url':full}
                    try:
                        r2 = fetch_url(full)
                        item['len'] = len(r2.get('content') or b'') if r2.get('ok') else 0
                        item['sha256'] = sha256_bytes(r2.get('content') or b'') if r2.get('ok') else None
                        txt = r2.get('text') or ''
                        item['findings'] = js_static_checks(txt)
                        b64s = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', txt)
                        if b64s: item['base64_example'] = try_base64_decode(b64s[0])
                        deob = try_deobf_0x(txt)
                        if deob and deob.get('ok'): item['deobf_0x'] = True; item['deobf_sample'] = deob.get('deobf_code')[:2000]
                    except Exception:
                        item['error'] = 'fetch_error'
                else:
                    item = {'type':'inline','code': code, 'findings': js_static_checks(code)}
                    b64s = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', code)
                    if b64s: item['base64_example'] = try_base64_decode(b64s[0])
                    deob = try_deobf_0x(code)
                    if deob and deob.get('ok'): item['deobf_0x'] = True; item['deobf_sample'] = deob.get('deobf_code')[:2000]
                page['scripts'].append(item)
            for a in soup.find_all('a', href=True):
                href = urljoin(url, a['href'])
                page['links'].append(href)
                if urlparse(href).netloc == parsed.netloc and href not in visited and d<depth:
                    to_visit.append((href, d+1))
        page['base'] = base
        # run vulnerability analysis for this page
        page['vulns'] = analyze_page_vulns({'url': url, 'headers': page.get('headers'), 'text': page.get('text'), 'base': base}, active=active)
        report['pages'].append(page)
    # reports
    out_json = Path(out_dir) / 'webrecon_v4_report.json'; out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    out_html = generate_html_report_with_vulns(report, out_dir)
    out_md = generate_bounty_markdown(report, out_dir)
    return {'json': str(out_json), 'html': out_html, 'bounty_md': out_md}

# ----------------- CLI / Interactive -----------------
def interactive_menu():
    print('WebRecon v4 - شاملة (Passive + Active + Bounty report templates)')
    print('تحذير قانوني: الفحوصات النشطة قد تكون اختراقية. لا تستخدم دون إذن صريح.')
    print('1. فحص سلبي كامل (موزع وبالحد الأدنى من الطلبات)')
    print('2. فحص نشط محدود (يتضمن اختبارات XSS/SQLi/Open-Redirect) - مطلوب إذن')
    print('3. توليد تقرير باونتي (بناءً على نتائج الفحص)')
    print('4. خروج')
    choice = input('ادخل رقم: ').strip()
    if choice == '1':
        url = input('ادخل رابط: ').strip(); out = input('مجلد الإخراج (default webrecon_v4_out): ').strip() or 'webrecon_v4_out'; depth = input('عمق المسح (default 1): ').strip() or '1'
        try: depth = int(depth)
        except: depth=1
        res = full_scan_all(url, out, depth=depth, active=False)
        print('Finished. Reports:', res); return
    elif choice == '2':
        print('تنبيه: سيجري اختبارات نشطة محدودة — تأكد من أنك تمتلك الإذن الصريح. اكتب YES للمتابعة.')
        confirm = input('اكتب YES لمتابعة: ').strip()
        if confirm != 'YES':
            print('ملغى'); return
        url = input('ادخل رابط: ').strip(); out = input('مجلد الإخراج (default webrecon_v4_out): ').strip() or 'webrecon_v4_out'; depth = input('عمق المسح (default 1): ').strip() or '1'
        try: depth = int(depth)
        except: depth=1
        res = full_scan_all(url, out, depth=depth, active=True)
        print('Finished. Reports:', res); return
    elif choice == '3':
        print('هذه العملية تعتمد على وجود نتائج سابقة في مجلد التقرير. اختر ملف JSON التقرير لتوليد تقرير باونتي مفصل.')
        p = input('ادخل مسار ملف webrecon_v4_report.json: ').strip()
        if not Path(p).exists(): print('الملف غير موجود'); return
        report = json.loads(Path(p).read_text(encoding='utf-8'))
        out = Path(p).parent
        md = generate_bounty_markdown(report, out)
        print('تم توليد تقرير باونتي:', md); return
    else:
        print('خروج'); return

def main():
    parser = argparse.ArgumentParser(description='WebRecon v4 - Comprehensive web reverse-engineering + vuln detection (Arabic)')
    sub = parser.add_subparsers(dest='cmd')
    p_scan = sub.add_parser('scan', help='Full scan (use --active only with permission)')
    p_scan.add_argument('url'); p_scan.add_argument('-o','--out', default='webrecon_v4_out'); p_scan.add_argument('--depth', type=int, default=1); p_scan.add_argument('--active', action='store_true', help='Perform lightweight active probes (use only with permission)')
    args = parser.parse_args() if len(sys.argv)>1 else None
    if args is None:
        interactive_menu(); return
    if args.cmd == 'scan':
        if args.active:
            print('تحذير قانوني: ستجري الأداة اختبارات نشطة محدودة — تأكد أنك مرخّص للاختبار.')
            confirm = input('اكتب YES للمتابعة: ').strip()
            if confirm != 'YES':
                print('ملغي'); return
        res = full_scan_all(args.url, args.out, depth=args.depth, active=args.active)
        print('Finished. Reports:', res)

if __name__ == '__main__':
    main()
