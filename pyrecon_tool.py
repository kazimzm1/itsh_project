#!/usr/bin/env python3
"""
pyrecon_tool.py
أداة سطر أوامر موحّدة لأتمتة مهام الهندسة العكسية لبايثون.

الميزات:
- مسح مجلد/ملف بحثًا عن ملفات .py و .pyc وملفات PyInstaller (.exe)
- استخراج محتوى PyInstaller باستخدام pyinstxtractor إذا كان متوفراً
- محاولة فك .pyc باستخدام decompyle3/uncompyle6/pycdc (إذا كانت متاحة)
- تفكيك (disassemble) للدوال باستخدام وحدة `dis`
- قراءة رؤوس .pyc ومحاولة marshal.load لاستخراج code object
- فحوصات ثابتة: البحث عن exec/eval/marshal/compile/دلائل التعتيم
- استخراج السلاسل النصية وحساب الانتروبيا لاكتشاف الحزم/التشفير
- توليد تقارير JSON و Markdown
- إمكانية إعطاء تلميحات للتشغيل الزمني عبر Frida إن كان مثبتًا

ملاحظة قانونية وأخلاقية: استخدم الأداة فقط على ملفات تملكها أو لديك إذن صريح لتحليلها.

هذه النسخة تحتوي على قائمة تفاعلية مرقّمة بالعربية بحيث تدخل رقم الوظيفة لتشغيلها.

لتشغيل غير تفاعلي:
  python3 pyrecon_tool.py scan target_folder -o report_dir

أو شغّل دون معاملات لواجهة تفاعلية بالعربية:
  python3 pyrecon_tool.py

المؤلف: تمّ توليدها بمساعدة مساعد ذكي في إطار وضع الخبير
"""

import argparse
import subprocess
import sys
import os
import json
import shutil
import hashlib
import struct
import marshal
import dis
import tempfile
import time
from pathlib import Path
from datetime import datetime
import re
import base64


# ------------------------ دوال مساعدة ------------------------

def which(cmd):
    """إرجاع مسار الأداة أو None إذا غير موجودة."""
    return shutil.which(cmd)

def run(cmd, capture_output=True, check=False):
    try:
        if capture_output:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)
            return res.stdout.decode('utf-8', errors='replace'), res.stderr.decode('utf-8', errors='replace'), res.returncode
        else:
            res = subprocess.run(cmd, check=check)
            return None, None, res.returncode
    except Exception as e:
        return '', str(e), 255


# ------------------------ فحص الملفات ------------------------
def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def extract_strings(path, min_len=4):
    results = set()
    with open(path, 'rb') as f:
        data = f.read()
    for s in re.findall(rb"[ -~]{%d,}" % min_len, data):
        try:
            results.add(s.decode('utf-8', errors='ignore'))
        except Exception:
            pass
    return sorted(results, key=lambda x: len(x), reverse=True)

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    from math import log2
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    l = len(data)
    for v in freq.values():
        p = v / l
        ent -= p * log2(p)
    return ent


# ------------------------ تحليل .pyc ------------------------
def read_pyc_header(path):
    with open(path, 'rb') as f:
        magic = f.read(4)
        rest = f.read(16)
    return {'magic': magic.hex(), 'raw_header': rest.hex()}

def try_load_codeobj(path):
    try:
        with open(path, 'rb') as f:
            magic = f.read(4)
            header = f.read(12)
            data = f.read()
        code = marshal.loads(data)
        return {'ok': True, 'type': type(code).__name__, 'co_name': getattr(code, 'co_name', None), 'co_consts_len': len(getattr(code, 'co_consts', []))}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


# ------------------------ تشغيل محاولات فكّ ------------------------
def decompile_pyc(path, out_dir):
    attempts = {}
    os.makedirs(out_dir, exist_ok=True)
    base = Path(path).stem

    if which('decompyle3'):
        out = Path(out_dir) / (base + '.decompyle3.py')
        cmd = ['decompyle3', path]
        stdout, stderr, rc = run(cmd)
        attempts['decompyle3'] = {'rc': rc, 'stderr': stderr}
        if rc == 0 and stdout.strip():
            out.write_text(stdout, encoding='utf-8')
            attempts['decompyle3']['out'] = str(out)
    else:
        attempts['decompyle3'] = {'rc': None, 'error': 'غير مثبت'}

    if which('uncompyle6'):
        out = Path(out_dir) / (base + '.uncompyle6.py')
        cmd = ['uncompyle6', path]
        stdout, stderr, rc = run(cmd)
        attempts['uncompyle6'] = {'rc': rc, 'stderr': stderr}
        if rc == 0 and stdout.strip():
            out.write_text(stdout, encoding='utf-8')
            attempts['uncompyle6']['out'] = str(out)
    else:
        attempts['uncompyle6'] = {'rc': None, 'error': 'غير مثبت'}

    if which('pycdc'):
        out = Path(out_dir) / (base + '.pycdc.py')
        cmd = ['pycdc', path]
        stdout, stderr, rc = run(cmd)
        attempts['pycdc'] = {'rc': rc, 'stderr': stderr}
        if rc == 0 and stdout.strip():
            out.write_text(stdout, encoding='utf-8')
            attempts['pycdc']['out'] = str(out)
    else:
        attempts['pycdc'] = {'rc': None, 'error': 'غير مثبت'}

    return attempts


# ------------------------ استخراج PyInstaller ------------------------
def extract_pyinstaller(exe_path, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    script = which('pyinstxtractor.py') or which('pyinstxtractor')
    attempts = {}
    if which('python') and (Path('pyinstxtractor.py').exists() or script):
        extractor = script if script else str(Path('pyinstxtractor.py'))
        cmd = ['python3', extractor, exe_path]
        stdout, stderr, rc = run(cmd)
        attempts['pyinstxtractor'] = {'rc': rc, 'stderr': stderr}
        base = Path(exe_path).stem
        for p in Path('.').glob(base + '*extracted*'):
            attempts.setdefault('extracted_dirs', []).append(str(p.resolve()))
    else:
        attempts['pyinstxtractor'] = {'error': 'pyinstxtractor.py غير موجود أو Python غير متوفرة'}
    return attempts


# ------------------------ فحوصات ثابتة لملفات .py ------------------------
def static_checks_on_py(path):
    txt = Path(path).read_text(encoding='utf-8', errors='ignore')
    findings = []
    suspects = ['exec(', 'eval(', 'compile(', 'marshal.', 'importlib', 'PyArmor', 'pyarmor', 'obfuscate']
    for s in suspects:
        if s in txt:
            findings.append({'pattern': s, 'count': txt.count(s)})
    b64s = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", txt)
    if b64s:
        findings.append({'pattern': 'long_base64_blob', 'count': len(b64s)})
    return findings


# ------------------------ Frida (تلميحات تشغيليّة) ------------------------
def frida_available():
    return which('frida') is not None or which('frida-trace') is not None

def frida_repl_demo(pid_or_cmd):
    if not frida_available():
        return {'ok': False, 'error': 'frida غير متوفرة في PATH'}
    return {'ok': True, 'note': 'frida متوفرة — شغّل يدوياً: frida -f <binary> -l <script.js> --no-pause'}


# ------------------------ تدفقات العمل الأساسية ------------------------
def scan_command(target, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    report = {'scanned_at': datetime.utcnow().isoformat() + 'Z', 'target': str(target), 'files': []}
    for p in Path(target).rglob('*'):
        if p.is_file():
            suffix = p.suffix.lower()
            if suffix in ('.py', '.pyc', '.pyo', '.exe', '.bin'):
                info = {'path': str(p.resolve()), 'size': p.stat().st_size, 'sha256': sha256(str(p)), 'suffix': suffix}
                info['strings_sample'] = extract_strings(str(p))[:20]
                if suffix == '.pyc':
                    info['pyc_header'] = read_pyc_header(str(p))
                    info['pyc_try_load'] = try_load_codeobj(str(p))
                if suffix == '.py':
                    info['static_checks'] = static_checks_on_py(str(p))
                report['files'].append(info)
    report_path = out_dir / 'scan_report.json'
    report_path.write_text(json.dumps(report, indent=2), encoding='utf-8')
    return {'ok': True, 'report': str(report_path)}

def analyze_command(target, out_dir, use_frida=False):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    final_report = {'analyzed_at': datetime.utcnow().isoformat() + 'Z', 'items': []}
    targets = [Path(target)] if Path(target).is_file() else list(Path(target).rglob('*'))
    for p in targets:
        if not p.is_file():
            continue
        item = {'path': str(p.resolve()), 'size': p.stat().st_size, 'sha256': sha256(str(p))}
        suffix = p.suffix.lower()
        item['strings_top'] = extract_strings(str(p))[:30]
        item['entropy'] = entropy(Path(p).read_bytes())
        if suffix == '.pyc':
            diro = out_dir / (p.stem + '_decomp')
            diro.mkdir(parents=True, exist_ok=True)
            item['decompile_attempts'] = decompile_pyc(str(p), str(diro))
            item['pyc_header'] = read_pyc_header(str(p))
            item['pyc_try_load'] = try_load_codeobj(str(p))
        if suffix == '.exe':
            item['pyinst_extract'] = extract_pyinstaller(str(p), str(out_dir))
        if suffix == '.py':
            item['static_checks'] = static_checks_on_py(str(p))
            try:
                txt = Path(p).read_text(encoding='utf-8', errors='ignore')
                codeobj = compile(txt, str(p), 'exec')
                dis_s = []
                for const in getattr(codeobj, 'co_consts', []):
                    if hasattr(const, 'co_code'):
                        fname = getattr(const, 'co_name', '<anon>')
                        s = f"Function: {fname}\n"
                        try:
                            from io import StringIO
                            sio = StringIO()
                            dis.dis(const, file=sio)
                            s += sio.getvalue()
                        except Exception as e:
                            s += f"dis error: {e}"
                        dis_s.append(s)
                item['disassembly_snippets'] = dis_s[:5]
            except Exception as e:
                item['dis_error'] = str(e)
        final_report['items'].append(item)
    if use_frida:
        final_report['frida'] = frida_repl_demo(target)
    jpath = Path(out_dir) / 'analyze_report.json'
    mpath = Path(out_dir) / 'analyze_report.md'
    jpath.write_text(json.dumps(final_report, indent=2), encoding='utf-8')
    with open(mpath, 'w', encoding='utf-8') as f:
        f.write('# تقرير التحليل\n\n')
        f.write('توقيت التوليد: %s\n\n' % final_report['analyzed_at'])
        for it in final_report['items']:
            f.write('## %s\n' % it['path'])
            f.write('* sha256: `%s`\n' % it.get('sha256'))
            f.write('* الحجم: %d بايت\n' % it.get('size', 0))
            f.write('* الانتروبيا: %.3f\n' % it.get('entropy', 0.0))
            if 'decompile_attempts' in it:
                f.write('* محاولات فكّ: %s\n' % ','.join([k for k,v in it['decompile_attempts'].items() if v and 'out' in v]))
            if 'pyinst_extract' in it:
                f.write('* استخراج PyInstaller: %s\n' % json.dumps(it['pyinst_extract']))
            f.write('\n')
    return {'ok': True, 'json': str(jpath), 'md': str(mpath)}


# ------------------------ القائمة التفاعلية (بالعربية) ------------------------
def interactive_menu():
    menu = [
        {'num': 1, 'name': 'مسح الهدف (بحث عن ملفات بايثون)', 'func': 'scan'},
        {'num': 2, 'name': 'استخراج PyInstaller (EXE)', 'func': 'extract'},
        {'num': 3, 'name': 'فكّ ملف .pyc', 'func': 'decompile'},
        {'num': 4, 'name': 'تحليل كامل (مسح + فكّ + فحوصات ثابتة)', 'func': 'analyze'},
        {'num': 5, 'name': 'عرض حالة الأدوات الخارجية المثبتة', 'func': 'status'},
        {'num': 6, 'name': 'خروج', 'func': 'exit'},
    ]

    def print_menu():
        print('\nقائمة PyRecon التفاعلية - اختَر رقم الوظيفة للتشغيل:')
        for item in menu:
            print('  {num}. {name}'.format(num=item['num'], name=item['name']))

    while True:
        print_menu()
        try:
            choice = input('\nأدخل الرقم: ').strip()
        except (EOFError, KeyboardInterrupt):
            print('\nخروج.')
            return
        if not choice.isdigit():
            print('الرجاء إدخال رقم صحيح.')
            continue
        choice = int(choice)
        sel = next((m for m in menu if m['num'] == choice), None)
        if not sel:
            print('الاختيار غير موجود. جرّب مرة أخرى.')
            continue
        if sel['func'] == 'exit':
            print('جارٍ الخروج...')
            return
        if sel['func'] == 'status':
            tools = {
                'decompyle3': which('decompyle3'),
                'uncompyle6': which('uncompyle6'),
                'pycdc': which('pycdc'),
                'pyinstxtractor.py (ملف محلي)': str(Path('pyinstxtractor.py').exists()),
                'frida': which('frida') or which('frida-trace'),
            }
            print('\nحالة الأدوات الخارجية:')
            for k, v in tools.items():
                print('  - %s: %s' % (k, v if v else 'غير موجود'))
            continue

        if sel['func'] == 'scan':
            target = input('أدخل مسار المجلد أو الملف للمسح: ').strip()
            out = input('أدخل مجلد الإخراج (افتراضي: pyrecon_out): ').strip() or 'pyrecon_out'
            print('بدء المسح...')
            r = scan_command(target, out)
            print('انتهى المسح. التقرير في:', r)
        elif sel['func'] == 'extract':
            exe = input('أدخل مسار ملف EXE لاستخراج محتواه: ').strip()
            out = input('أدخل مجلد الإخراج (افتراضي: pyrecon_out): ').strip() or 'pyrecon_out'
            print('جاري الاستخراج...')
            r = extract_pyinstaller(exe, out)
            print('انتهى. النتيجة:', json.dumps(r, indent=2, ensure_ascii=False))
        elif sel['func'] == 'decompile':
            pyc = input('أدخل مسار ملف .pyc الذي تريد فكّه: ').strip()
            out = input('أدخل مجلد الإخراج (افتراضي: pyrecon_out): ').strip() or 'pyrecon_out'
            print('محاولة فكّ الملف...')
            r = decompile_pyc(pyc, out)
            print('انتهت المحاولات. النتائج:', json.dumps(r, indent=2, ensure_ascii=False))
        elif sel['func'] == 'analyze':
            target = input('أدخل مسار المجلد أو الملف للتحليل: ').strip()
            out = input('أدخل مجلد الإخراج (افتراضي: pyrecon_out): ').strip() or 'pyrecon_out'
            use_frida = input('هل تريد تلميحات Frida أثناء التحليل؟ (y/N): ').strip().lower() == 'y'
            print('بدء التحليل (قد يستغرق وقتاً)...')
            r = analyze_command(target, out, use_frida)
            print('انتهى التحليل. التقارير محفوظة في:', r)
        else:
            print('وظيفة غير معروفة.')


# ------------------------ واجهة سطر الأوامر ------------------------
def main():
    parser = argparse.ArgumentParser(description='PyRecon - أداة هندسة عكسية لبايثون (عربية)')
    sub = parser.add_subparsers(dest='cmd')

    p_scan = sub.add_parser('scan', help='مسح مجلد/ملف للبحث عن آثار بايثون')
    p_scan.add_argument('target')
    p_scan.add_argument('-o', '--out', default='pyrecon_out')

    p_extract = sub.add_parser('extract', help='استخراج PyInstaller من EXE')
    p_extract.add_argument('exe')
    p_extract.add_argument('-o', '--out', default='pyrecon_out')

    p_decomp = sub.add_parser('decompile', help='فكّ ملف .pyc')
    p_decomp.add_argument('pyc')
    p_decomp.add_argument('-o', '--out', default='pyrecon_out')

    p_analyze = sub.add_parser('analyze', help='تحليل كامل (مسح + فكّ + فحوصات ثابتة)')
    p_analyze.add_argument('target')
    p_analyze.add_argument('-o', '--out', default='pyrecon_out')
    p_analyze.add_argument('--frida', action='store_true', help='تضمين تلميحات Frida إن توفرت')

    if len(sys.argv) == 1:
        interactive_menu()
        return

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        sys.exit(1)

    print('PyRecon - بدء التنفيذ:', args.cmd)
    print('تنبيه قانوني/أخلاقي: استخدم على عينات تمتلكها أو لديك إذن بتحليلها.')

    if args.cmd == 'scan':
        r = scan_command(args.target, args.out)
        print('انتهى المسح:', r)
    elif args.cmd == 'extract':
        r = extract_pyinstaller(args.exe, args.out)
        print('انتهى الاستخراج:', r)
    elif args.cmd == 'decompile':
        r = decompile_pyc(args.pyc, args.out)
        print('تم تسجيل محاولات الفكّ في مجلد الإخراج:', args.out)
        print(json.dumps(r, indent=2, ensure_ascii=False))
    elif args.cmd == 'analyze':
        r = analyze_command(args.target, args.out, use_frida=args.frida)
        print('انتهى التحليل. التقارير:', r)
    else:
        print('أمر غير معروف')

if __name__ == '__main__':
    main()
