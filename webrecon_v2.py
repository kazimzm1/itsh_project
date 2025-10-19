#!/usr/bin/env python3
# webrecon_v2.py
# أداة شاملة مُحسّنة لهندسة عكسية لمواقع الويب — static + lightweight dynamic analysis.
# Features: robots/sitemap, security headers, JS extraction, deobfuscation heuristics, selenium optional, HTML report.

import argparse, re, json, os, sys, time, shutil, base64, traceback
from pathlib import Path
from urllib.parse import urljoin, urlparse
import hashlib
import ssl
import socket

# optional libs
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

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
except Exception:
    webdriver = None
    ChromeOptions = None

# ---------------- utility ----------------
def ensure_requests():
    if requests is None:
        raise RuntimeError('مكتبة requests غير مثبتة. شغّل: pip install requests')

def ensure_bs4():
    if BeautifulSoup is None:
        raise RuntimeError('مكتبة beautifulsoup4 غير مثبتة. شغّل: pip install beautifulsoup4')

def sha256_bytes(b: bytes) -> str:
    import hashlib
    h = hashlib.sha256(); h.update(b); return h.hexdigest()

def safe_mkdir(p): Path(p).mkdir(parents=True, exist_ok=True)

# ---------------- network helpers ----------------
def fetch_url(url, timeout=15, headers=None, allow_redirects=True):
    ensure_requests()
    headers = headers or {'User-Agent': 'WebReconV2/1.0'}
    try:
        r = requests.get(url, timeout=timeout, headers=headers, allow_redirects=allow_redirects)
        return {'ok': True, 'status_code': r.status_code, 'content': r.content, 'text': r.text, 'url': r.url, 'headers': dict(r.headers), 'cookies': r.cookies.get_dict()}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def head_request(url, timeout=10):
    ensure_requests()
    try:
        r = requests.head(url, timeout=timeout, allow_redirects=True)
        return {'ok': True, 'headers': dict(r.headers), 'status': r.status_code}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

# ---------------- security header checks ----------------
SECURITY_HEADERS = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy']

def analyze_security_headers(headers: dict):
    found = {}
    for h in SECURITY_HEADERS:
        if h in headers:
            found[h] = headers[h]
    return found

# ---------------- robots + sitemap ----------------
def fetch_robots(base_url, out_dir):
    parsed = urlparse(base_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    r = fetch_url(robots_url)
    if r.get('ok'):
        p = Path(out_dir) / 'robots.txt'; p.write_bytes(r['content'])
        return {'ok': True, 'path': str(p), 'content_sample': r['text'][:1000]}
    return {'ok': False, 'error': r.get('error')}

def fetch_sitemap(base_url, out_dir):
    parsed = urlparse(base_url)
    candidates = [f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"]
    results = []
    for url in candidates:
        r = fetch_url(url)
        if r.get('ok') and b'urlset' in r['content'][:2000].lower():
            p = Path(out_dir) / 'sitemap.xml'; p.write_bytes(r['content'])
            results.append({'url': url, 'path': str(p)})
    return results

# ---------------- extract scripts ----------------
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

# ---------------- JS heuristics ----------------
JS_PATTERNS = [r'\beval\s*\(', r'\bFunction\s*\(', r'atob\s*\(', r'unescape\s*\(', r'\\x[0-9A-Fa-f]{2}', r'_0x[0-9a-fA-F]+']

def js_static_checks(code_text):
    findings = []
    for p in JS_PATTERNS:
        matches = re.findall(p, code_text)
        if matches:
            findings.append({'pattern': p, 'count': len(matches)})
    # long base64
    b64s = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', code_text)
    if b64s: findings.append({'pattern': 'long_base64_blob', 'count': len(b64s)})
    return findings

# ---------------- API endpoints extraction ----------------
API_REGEX = re.compile(r'["\']((?:https?:)?//[^"\']*(?:api|ajax|graphql|wp-json|/v\d+/)[^"\']*)["\']', re.I)
def extract_api_endpoints(text, base_url=None):
    found = set()
    for m in API_REGEX.findall(text):
        try:
            url = urljoin(base_url or '', m)
            found.add(url)
        except Exception:
            pass
    for m in re.findall(r'["\'](\/[^"\']*(?:api|ajax|graphql|wp-json)[^"\']*)["\']', text, re.I):
        try:
            url = urljoin(base_url or '', m)
            found.add(url)
        except Exception:
            pass
    return sorted(found)

# ---------------- simple _0x array deobfuscator (heuristic) ----------------
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

# ---------------- decode helpers ----------------
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

# ---------------- selenium dynamic render ----------------
def selenium_render(url, out_dir, headless=True, wait=2):
    if webdriver is None:
        return {'ok': False, 'error': 'selenium غير مثبت أو WebDriver غير متاح'}
    opts = ChromeOptions()
    if headless: opts.add_argument('--headless=new')
    opts.add_argument('--no-sandbox'); opts.add_argument('--disable-dev-shm-usage')
    try:
        driver = webdriver.Chrome(options=opts)
        driver.set_page_load_timeout(30)
        driver.get(url)
        time.sleep(wait)
        html = driver.page_source
        screenshot_path = Path(out_dir) / 'screenshot.png'
        driver.save_screenshot(str(screenshot_path))
        driver.quit()
        return {'ok': True, 'html': html, 'screenshot': str(screenshot_path)}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

# ---------------- sourcemap fetch ----------------
def find_sourcemap_url(js_text, js_url):
    m = re.search(r'[#@]\s*sourceMappingURL\s*=\s*(?P<url>[^\s]+)', js_text)
    if m:
        return urljoin(js_url, m.group('url').strip())
    return None

def fetch_sourcemap(smap_url, out_dir):
    r = fetch_url(smap_url)
    if r.get('ok'):
        p = Path(out_dir) / ('sourcemap_%s.map' % hashlib.sha1(smap_url.encode()).hexdigest())
        p.write_bytes(r['content'])
        return {'ok': True, 'path': str(p)}
    return {'ok': False, 'error': r.get('error')}

# ---------------- HTML report generation ----------------
def generate_html_report(report, out_dir):
    safe_mkdir(out_dir)
    html = ['<html><head><meta charset="utf-8"><title>WebRecon Report</title></head><body>']
    html.append(f"<h1>WebRecon Report for {report.get('start_url')}</h1>")
    html.append(f"<p>Generated: {report.get('scanned_at')}</p>")
    for p in report.get('pages', []):
        html.append(f"<h2>Page: {p.get('url')}</h2>")
        if p.get('error'): html.append(f"<p><b>Error:</b> {p.get('error')}</p>"); continue
        html.append(f"<p>Status: {p.get('status')}</p>")
        html.append(f"<p>Scripts: {len(p.get('scripts',[]))}</p>")
        for s in p.get('scripts', []):
            html.append(f"<h3>Script ({s.get('type')})</h3>")
            if s.get('url'): html.append(f"<p>URL: <a href='{s.get('url')}'>{s.get('url')}</a></p>")
            if s.get('findings'): html.append(f"<p>Findings: {s.get('findings')}</p>")
            if s.get('base64_example'): html.append(f"<pre>Base64 decoded example: {s.get('base64_example')}</pre>")
            if s.get('unescaped_sample'): html.append(f"<pre>{s.get('unescaped_sample')[:1000]}</pre>")
    html.append('</body></html>')
    out = Path(out_dir) / 'webrecon_report.html'
    out.write_text('\n'.join(html), encoding='utf-8')
    return str(out)

# ---------------- main crawl/analyze ----------------
def full_scan(start_url, out_dir, depth=1, use_selenium=False):
    ensure_requests(); ensure_bs4()
    safe_mkdir(out_dir)
    parsed = urlparse(start_url); base = f"{parsed.scheme}://{parsed.netloc}"
    report = {'start_url': start_url, 'scanned_at': time.strftime('%Y-%m-%dT%H:%M:%SZ'), 'pages': []}
    visited = set(); to_visit = [(start_url,0)]
    report['robots'] = fetch_robots(start_url, out_dir)
    report['sitemap'] = fetch_sitemap(start_url, out_dir)
    while to_visit:
        url, d = to_visit.pop(0)
        if url in visited or d>depth: continue
        visited.add(url)
        print(f"Fetching: {url} (depth {d})")
        if use_selenium:
            dyn = selenium_render(url, out_dir)
            if dyn.get('ok'): text = dyn.get('html'); res = {'ok': True, 'status_code': 200, 'headers': {}}
            else:
                res = fetch_url(url); text = res.get('text','') if res.get('ok') else ''
        else:
            res = fetch_url(url); text = res.get('text','') if res.get('ok') else ''
        page = {'url': url, 'status': res.get('status_code') if res.get('ok') else None, 'error': res.get('error') if not res.get('ok') else None, 'scripts':[], 'links':[]}
        if not res.get('ok'): report['pages'].append(page); continue
        scripts = extract_scripts_from_html(text, base_url=url)
        soup = BeautifulSoup(text, 'html.parser')
        for a in soup.find_all('a', href=True):
            href = urljoin(url, a['href'])
            if urlparse(href).netloc == parsed.netloc and href not in visited and d<depth:
                to_visit.append((href, d+1))
            page['links'].append(href)
        for s in scripts:
            if s['type']=='inline':
                code = s.get('content','') or ''
                item = {'type':'inline','summary':code[:200],'findings': js_static_checks(code)}
                b64s = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', code)
                if b64s: item['base64_example'] = try_base64_decode(b64s[0])
                deob = try_deobf_0x(code)
                if deob and deob.get('ok'): item['deobf_0x'] = True; item['deobf_sample'] = deob.get('deobf_code')[:2000]
                item['unescaped'] = unescape_js_string(code)[:1000]
                if jsbeautifier:
                    try: item['beautified'] = jsbeautifier.beautify(code)[:2000]
                    except: pass
                page['scripts'].append(item)
            else:
                su = s.get('url')
                item = {'type':'external','url':su}
                r2 = fetch_url(su)
                if r2.get('ok'):
                    b = r2['content']; txt = r2['text']
                    item['sha256'] = sha256_bytes(b); item['len']=len(b); item['findings']=js_static_checks(txt)
                    smurl = find_sourcemap_url(txt, su)
                    if smurl: item['sourcemap'] = fetch_sourcemap(smurl, out_dir)
                    b64s = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', txt)
                    if b64s: item['base64_example']= try_base64_decode(b64s[0])
                    deob = try_deobf_0x(txt)
                    if deob and deob.get('ok'): item['deobf_0x']=True; item['deobf_sample']=deob.get('deobf_code')[:2000]
                    item['unescaped']= unescape_js_string(txt)[:1000]
                    if jsbeautifier:
                        try: item['beautified'] = jsbeautifier.beautify(txt)[:2000]
                        except: pass
                else:
                    item['error'] = r2.get('error')
                page['scripts'].append(item)
        page['headers'] = res.get('headers') if res.get('ok') else {}
        page['security_headers'] = analyze_security_headers(page.get('headers',{}))
        page['api_endpoints'] = extract_api_endpoints(text, base_url=base)
        report['pages'].append(page)
    out_json = Path(out_dir) / 'webrecon_v2_report.json'; out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    out_html = generate_html_report(report, out_dir)
    return {'json': str(out_json), 'html': out_html}

# ---------------- CLI interactive ----------------
def interactive_menu():
    menu = [
        {'num':1, 'name':'فحص كامل للموقع (static + optional dynamic Selenium)', 'func':'fullscan'},
        {'num':2, 'name':'فحص ملف جافاسكربت محلي', 'func':'check_js'},
        {'num':3, 'name':'حالة المكتبات والاعتمادات', 'func':'status'},
        {'num':4, 'name':'خروج', 'func':'exit'},
    ]
    def print_menu():
        print('\nWebRecon v2 - اختَر رقم الوظيفة:')
        for m in menu: print(f"  {m['num']}. {m['name']}")
    while True:
        print_menu()
        try:
            choice = input('\nأدخل الرقم: ').strip()
        except (EOFError,KeyboardInterrupt):
            print('خروج.'); return
        if not choice.isdigit(): print('أدخل رقم صحيح'); continue
        choice=int(choice); sel = next((x for x in menu if x['num']==choice), None)
        if not sel: print('اختيار غير موجود'); continue
        if sel['func']=='exit': print('خروج'); return
        if sel['func']=='status':
            print('Requests:', 'متوفر' if requests else 'غير مثبت')
            print('bs4:', 'متوفر' if BeautifulSoup else 'غير مثبت')
            print('jsbeautifier:', 'متوفر' if jsbeautifier else 'غير مثبت')
            print('selenium:', 'متوفر' if webdriver else 'غير مثبت')
            continue
        if sel['func']=='fullscan':
            url = input('ادخل رابط الموقع (مثال https://example.com): ').strip()
            out = input('مجلد الخرج (default webrecon_v2_out): ').strip() or 'webrecon_v2_out'
            depth = input('عمق المسح (default 1): ').strip() or '1'
            use_selenium = input('تشغيل Selenium لتنفيذ JS؟ (y/N): ').strip().lower()=='y'
            try: depth=int(depth)
            except: depth=1
            print('بدء الفحص...')
            res = full_scan(url, out, depth=depth, use_selenium=use_selenium)
            print('انتهى. تقارير محفوظة في:', res); continue
        if sel['func']=='check_js':
            p = input('ادخل مسار ملف JS: ').strip()
            if not Path(p).exists(): print('الملف غير موجود'); continue
            txt = Path(p).read_text(encoding='utf-8', errors='ignore')
            print('Findings:', js_static_checks(txt))
            b64s = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', txt)
            if b64s: print('Base64 example:', b64s[0][:80]); print('Decoded:', try_base64_decode(b64s[0]))
            deob = try_deobf_0x(txt)
            if deob and deob.get('ok'): print('Found _0x-array, deobf sample (truncated):'); print(deob.get('deobf_code')[:1000])
            continue

def main():
    parser = argparse.ArgumentParser(description='WebRecon v2 - أداة هندسة عكس مواقع الويب (عربية)')
    sub = parser.add_subparsers(dest='cmd')
    p_scan = sub.add_parser('scan', help='فحص موقع كامل')
    p_scan.add_argument('url'); p_scan.add_argument('-o','--out', default='webrecon_v2_out'); p_scan.add_argument('--depth', type=int, default=1); p_scan.add_argument('--selenium', action='store_true')
    p_check = sub.add_parser('check_js', help='فحص ملف JS'); p_check.add_argument('path')
    if len(sys.argv)==1: interactive_menu(); return
    args = parser.parse_args()
    if args.cmd=='scan':
        res = full_scan(args.url, args.out, depth=args.depth, use_selenium=args.selenium)
        print('Finished. Reports:', res)
    elif args.cmd=='check_js':
        p = args.path
        if not Path(p).exists(): print('ملف غير موجود'); return
        txt = Path(p).read_text(encoding='utf-8', errors='ignore')
        print('Findings:', js_static_checks(txt))
    else:
        parser.print_help()

if __name__=='__main__': main()
