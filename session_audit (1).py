#!/usr/bin/env python3
# session_audit.py (interactive)
# Session & Cookie Auditor (safe, non-exploitative)
# Extended to extract: cookies, headers, response body (JSON/text/HTML),
# and form parameters (input names) if HTML (uses BeautifulSoup if available).
#
# If run without the URL argument, the tool will prompt interactively for the target URL,
# optional login info, and output path.
#
# Requirements: pip install requests beautifulsoup4 (bs4 optional but recommended)

import argparse, json, sys, re, ssl, socket
from urllib.parse import urlparse, urljoin, parse_qs
from datetime import datetime
import requests

# Optional BeautifulSoup for form parsing
try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

MAX_BODY_PREVIEW = 20000  # limit to avoid huge outputs

def parse_set_cookie_header(sc_value):
    parts = [p.strip() for p in sc_value.split(';')]
    name_val = parts[0]
    if '=' in name_val:
        name, val = name_val.split('=',1)
    else:
        name, val = name_val, ''
    attrs = {'name': name, 'value': val, 'raw': sc_value, 'flags': {}}
    for attr in parts[1:]:
        if '=' in attr:
            k, v = attr.split('=',1)
            attrs['flags'][k.lower()] = v
        else:
            attrs['flags'][attr.lower()] = True
    return attrs

def analyze_cookies(set_cookie_headers, session_cookies):
    cookies = []
    for sc in set_cookie_headers:
        cookies.append(parse_set_cookie_header(sc))
    # also include session cookies from requests' session.cookies
    sess_list = []
    for c in session_cookies:
        sess_list.append({'name': c.name, 'value': c.value, 'domain': c.domain, 'path': c.path, 'secure': c.secure, 'httponly': getattr(c, 'rest', {}).get('HttpOnly', False)})
    findings = []
    for c in cookies:
        name = c['name']
        flags = c['flags']
        issues = []
        if 'httponly' not in flags:
            issues.append('missing_HttpOnly')
        if 'secure' not in flags:
            issues.append('missing_Secure')
        samesite = flags.get('samesite')
        if not samesite:
            issues.append('missing_SameSite')
        else:
            if isinstance(samesite, str) and samesite.lower() not in ['lax','strict','none']:
                issues.append('weird_SameSite_value')
        if 'expires' in flags:
            try:
                exp = flags.get('expires')
                exp_dt = datetime.strptime(exp, "%a, %d %b %Y %H:%M:%S %Z")
                days_left = (exp_dt - datetime.utcnow()).days
                if days_left > 365:
                    issues.append('very_long_lived_cookie')
            except Exception:
                pass
        cookies_summary = {'name': name, 'issues': issues, 'flags': flags}
        findings.append(cookies_summary)
    return cookies, sess_list, findings

def extract_response_body_info(resp):
    info = {'content_type': None, 'body_preview': None, 'is_json': False, 'json': None, 'forms': []}
    headers = resp.headers or {}
    ct = headers.get('Content-Type','').lower()
    info['content_type'] = ct
    text = ''
    try:
        # read small preview safely
        text = resp.text or ''
        if len(text) > MAX_BODY_PREVIEW:
            info['body_preview'] = text[:MAX_BODY_PREVIEW] + '\n...[truncated]'
        else:
            info['body_preview'] = text
    except Exception:
        info['body_preview'] = None
    # try parse JSON
    if 'application/json' in ct or (text.strip().startswith('{') or text.strip().startswith('[')):
        try:
            info['json'] = resp.json()
            info['is_json'] = True
        except Exception:
            info['is_json'] = False
    # parse HTML forms if BS4 available or naive regex fallback
    if 'html' in ct or '<form' in (text.lower() if text else ''):
        forms = []
        if BeautifulSoup is not None and text:
            try:
                soup = BeautifulSoup(text, 'html.parser')
                for form in soup.find_all('form'):
                    action = form.get('action')
                    method = (form.get('method') or 'GET').upper()
                    inputs = []
                    for inp in form.find_all(['input','textarea','select']):
                        name = inp.get('name')
                        typ = inp.get('type') or inp.name
                        if name:
                            inputs.append({'name': name, 'type': typ})
                    forms.append({'action': action, 'method': method, 'inputs': inputs})
            except Exception:
                forms = []
        else:
            # naive regex fallback: find input names
            try:
                for m in re.finditer(r'<form[^>]*>(.*?)</form>', text or '', re.S|re.I):
                    fhtml = m.group(1)
                    inputs = []
                    for mi in re.finditer(r'<(input|textarea|select)[^>]*name=[\'"]?([^\s\'">]+)', fhtml or '', re.I):
                        inputs.append({'name': mi.group(2), 'type': mi.group(1)})
                    forms.append({'action': None, 'method': None, 'inputs': inputs})
            except Exception:
                forms = []
        info['forms'] = forms
    return info

def fetch_and_analyze(url, session=None, follow_redirects=True, headers=None):
    headers = headers or {'User-Agent': 'SessionAudit/1.0'}
    sess = session or requests.Session()
    try:
        r = sess.get(url, headers=headers, allow_redirects=follow_redirects, timeout=15)
    except Exception as e:
        return {'ok': False, 'error': str(e)}
    # collect Set-Cookie headers robustly
    raw = []
    try:
        raw_hdrs = r.raw.headers
        if hasattr(raw_hdrs, 'get_all'):
            raw = raw_hdrs.get_all('Set-Cookie') or []
        else:
            sc = r.headers.get('Set-Cookie')
            if sc:
                raw = [sc]
    except Exception:
        sc = r.headers.get('Set-Cookie')
        if sc:
            raw = [sc]
    # fallback: use session cookies if no Set-Cookie found
    if not raw and sess.cookies:
        for c in sess.cookies:
            raw.append(f"{c.name}={c.value}")
    cookies_parsed, session_cookie_list, cookie_findings = analyze_cookies(raw if raw else [], sess.cookies)
    # response headers
    resp_headers = dict(r.headers)
    # request info
    req_info = {'method': r.request.method, 'url': r.request.url, 'headers': dict(r.request.headers)}
    # include request body if present (could be bytes)
    body = None
    try:
        if getattr(r.request, 'body', None):
            rb = r.request.body
            if isinstance(rb, bytes):
                try:
                    body = rb.decode('utf-8', errors='ignore')
                except Exception:
                    body = str(rb)
            else:
                body = str(rb)
            if len(body) > MAX_BODY_PREVIEW:
                body = body[:MAX_BODY_PREVIEW] + '\n...[truncated]'
            req_info['body'] = body
    except Exception:
        pass
    # response body info (JSON/HTML/forms/text preview)
    body_info = extract_response_body_info(r)
    # query params from URL
    qp = {}
    try:
        parsed = urlparse(r.url)
        qp = {k: v for k, v in parse_qs(parsed.query).items()}
    except Exception:
        qp = {}
    result = {
        'ok': True,
        'url': r.url,
        'status_code': r.status_code,
        'response_headers': resp_headers,
        'request': req_info,
        'response_body': body_info.get('body_preview'),
        'response_json': body_info.get('json'),
        'response_forms': body_info.get('forms'),
        'cookies_parsed': cookies_parsed,
        'session_cookies_list': session_cookie_list,
        'cookie_findings': cookie_findings,
        'redirects': [str(h.url) for h in r.history] if r.history else [],
        'query_params': qp
    }
    return result

def tls_certificate_info(host, port=443):
    info = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                info['protocol'] = ssock.version()
                info['cipher'] = ssock.cipher()
                try:
                    info['cert_subject'] = dict(x[0] for x in cert.get('subject', ()))
                except Exception:
                    info['cert_subject'] = cert.get('subject')
                try:
                    info['cert_issuer'] = dict(x[0] for x in cert.get('issuer', ()))
                except Exception:
                    info['cert_issuer'] = cert.get('issuer')
                info['notBefore'] = cert.get('notBefore')
                info['notAfter'] = cert.get('notAfter')
                try:
                    dt = datetime.strptime(cert.get('notAfter'), "%b %d %H:%M:%S %Y %Z")
                    info['days_left'] = (dt - datetime.utcnow()).days
                except Exception:
                    info['days_left'] = None
                return {'ok': True, 'cert': info}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def attempt_login_and_get_cookies(login_url, user_field, pass_field, username, password, extra_fields=None, headers=None):
    sess = requests.Session()
    headers = headers or {'User-Agent': 'SessionAudit/1.0'}
    payload = {user_field: username, pass_field: password}
    if extra_fields:
        payload.update(extra_fields)
    try:
        r = sess.post(login_url, data=payload, headers=headers, allow_redirects=True, timeout=15)
    except Exception as e:
        return {'ok': False, 'error': str(e)}
    raw = []
    try:
        raw_hdrs = r.raw.headers
        if hasattr(raw_hdrs, 'get_all'):
            raw = raw_hdrs.get_all('Set-Cookie') or []
        else:
            sc = r.headers.get('Set-Cookie')
            if sc:
                raw = [sc]
    except Exception:
        sc = r.headers.get('Set-Cookie')
        if sc:
            raw = [sc]
    if not raw and sess.cookies:
        for c in sess.cookies:
            raw.append(f"{c.name}={c.value}")
    cookies_parsed, session_cookie_list, cookie_findings = analyze_cookies(raw)
    # also extract forms/response and request payload info
    body_info = extract_response_body_info(r)
    req_info = {'method': r.request.method, 'url': r.request.url, 'headers': dict(r.request.headers)}
    try:
        if getattr(r.request, 'body', None):
            rb = r.request.body
            if isinstance(rb, bytes):
                try:
                    rb = rb.decode('utf-8', errors='ignore')
                except Exception:
                    rb = str(rb)
            req_info['body'] = rb if len(str(rb)) <= MAX_BODY_PREVIEW else str(rb)[:MAX_BODY_PREVIEW] + '\n...[truncated]'
    except Exception:
        pass
    return {'ok': True, 'status_code': r.status_code, 'url': r.url, 'cookies_parsed': cookies_parsed, 'cookie_findings': cookie_findings, 'headers': dict(r.headers), 'response_body_preview': body_info.get('body_preview'), 'response_json': body_info.get('json'), 'response_forms': body_info.get('forms'), 'request': req_info}

def generate_report(target_url, login_info=None):
    report = {'target': target_url, 'scanned_at': datetime.utcnow().isoformat()+'Z', 'notes': 'Session & TLS audit (extended)', 'results': {}}
    session = requests.Session()
    if login_info:
        login_res = attempt_login_and_get_cookies(login_info['login_url'], login_info['user_field'], login_info['pass_field'], login_info['username'], login_info['password'], extra_fields=login_info.get('extra'))
        report['results']['login_attempt'] = login_res
    fetch_res = fetch_and_analyze(target_url, session=session)
    report['results']['fetch'] = fetch_res
    parsed = urlparse(target_url)
    if parsed.scheme == 'https':
        host = parsed.hostname
        port = parsed.port or 443
        tls = tls_certificate_info(host, port=port)
        report['results']['tls'] = tls
    recs = []
    if fetch_res.get('cookie_findings'):
        for cf in fetch_res['cookie_findings']:
            if 'missing_HttpOnly' in cf['issues']:
                recs.append(f"Cookie '{cf['name']}' is missing HttpOnly flag - recommend setting HttpOnly to mitigate XSS cookie theft.")
            if 'missing_Secure' in cf['issues']:
                recs.append(f"Cookie '{cf['name']}' is missing Secure flag - set Secure to ensure cookie sent only over HTTPS.")
            if 'missing_SameSite' in cf['issues']:
                recs.append(f"Cookie '{cf['name']}' is missing SameSite attribute - consider SameSite=Lax or Strict for session cookies.")
            if 'very_long_lived_cookie' in cf['issues']:
                recs.append(f"Cookie '{cf['name']}' seems very long-lived - consider reducing lifetime for session cookies.")
    if report.get('results',{}).get('tls',{}).get('ok'):
        tls_info = report['results']['tls']['cert']
        if tls_info.get('days_left') is not None and tls_info['days_left'] < 30:
            recs.append("TLS certificate expires in less than 30 days - renew certificate.")
    report['recommendations'] = recs
    return report

def interactive_prompt():
    print("Session & TLS Auditor - interactive mode")
    url = input("Enter target URL (e.g. https://example.com): ").strip()
    if not url:
        print("No URL provided. Exiting."); sys.exit(1)
    use_login = input("Do you want to attempt a login? (y/N): ").strip().lower() == 'y'
    login_info = None
    if use_login:
        login_url = input("Login URL (e.g. https://example.com/login): ").strip()
        user_field = input("Username field name (default 'username'): ").strip() or 'username'
        pass_field = input("Password field name (default 'password'): ").strip() or 'password'
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        login_info = {'login_url': login_url, 'user_field': user_field, 'pass_field': pass_field, 'username': username, 'password': password}
    out = input("Output JSON path (default 'session_audit_report.json'): ").strip() or 'session_audit_report.json'
    return url, login_info, out

def main():
    parser = argparse.ArgumentParser(description='Session & TLS Auditor (safe checks only) - extended & interactive')
    parser.add_argument('url', nargs='?', help='Target URL to audit (e.g. https://example.com)')
    parser.add_argument('--login-url', help='Optional login URL to POST credentials to')
    parser.add_argument('--user-field', default='username', help='Form field name for username/email')
    parser.add_argument('--pass-field', default='password', help='Form field name for password')
    parser.add_argument('--username', help='Username for optional login')
    parser.add_argument('--password', help='Password for optional login')
    parser.add_argument('-o','--out', default='session_audit_report.json', help='Output JSON report path')
    args = parser.parse_args()
    if not args.url:
        target_url, login_info, outpath = interactive_prompt()
    else:
        target_url = args.url
        login_info = None
        if args.login_url and args.username and args.password:
            login_info = {'login_url': args.login_url, 'user_field': args.user_field, 'pass_field': args.pass_field, 'username': args.username, 'password': args.password}
        outpath = args.out
    report = generate_report(target_url, login_info=login_info)
    with open(outpath, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print("Report written to:", outpath)
    print("Summary:")
    if report['results'].get('fetch',{}).get('cookie_findings'):
        for cf in report['results']['fetch']['cookie_findings']:
            print(f" Cookie: {cf['name']} - issues: {', '.join(cf['issues']) if cf['issues'] else 'none'}")
    fetch = report['results'].get('fetch', {})
    if fetch.get('response_headers'):
        print("\nResponse headers:")
        for k,v in fetch['response_headers'].items():
            print(f" {k}: {v}")
    if fetch.get('cookies_parsed'):
        print("\nSet-Cookie headers parsed:")
        for c in fetch['cookies_parsed']:
            print(f" {c.get('raw')}")
    if fetch.get('session_cookies_list'):
        print("\nSession cookies (requests.Session):")
        for c in fetch['session_cookies_list']:
            print(f" {c.get('name')} = {c.get('value')} (domain={c.get('domain')})")
    if fetch.get('response_forms'):
        print("\nForms found in response:")
        for f in fetch['response_forms']:
            print(f" Action: {f.get('action')}; Method: {f.get('method')}")
            for inp in f.get('inputs', []):
                print(f"   - {inp.get('name')} ({inp.get('type')})")
    if fetch.get('response_body'):
        print("\nResponse body (preview):\n")
        print(fetch.get('response_body')[:1000])
    if report.get('recommendations'):
        print("\nRecommendations:")
        for r in report['recommendations']:
            print(" -", r)

if __name__ == '__main__':
    main()
