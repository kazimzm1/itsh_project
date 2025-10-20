#!/usr/bin/env python3
# exe_analyzer.py
# Safe static analysis helper for Windows PE (EXE/DLL) files.
# Requires: pip install pefile lief
# Usage: python exe_analyzer.py /path/to/file.exe -o outdir

import argparse, os, sys, json, hashlib, math, re
from pathlib import Path
from datetime import datetime

try:
    import pefile
except Exception:
    pefile = None

try:
    import lief
except Exception:
    lief = None

PRINTABLE_RE = re.compile(rb'[\x20-\x7E]{4,}')

def ensure_pefile():
    if pefile is None:
        raise RuntimeError("pefile library not installed. Run: pip install pefile")

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0]*256
    for b in data:
        freq[b] += 1
    ent = 0.0
    length = len(data)
    for f in freq:
        if f == 0:
            continue
        p = f/length
        ent -= p * math.log2(p)
    return ent

def extract_strings(data: bytes, min_len=4):
    return [m.decode(errors='replace') for m in PRINTABLE_RE.findall(data)]

def analyze_pe(path):
    ensure_pefile()
    p = pefile.PE(path, fast_load=True)
    p.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                                         pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                                         pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
    report = {}
    report['file'] = str(Path(path).resolve())
    report['sha256'] = sha256_file(path)
    report['size'] = os.path.getsize(path)
    # Timestamp
    try:
        ts = p.FILE_HEADER.TimeDateStamp
        report['timestamp'] = ts
        report['timestamp_utc'] = datetime.utcfromtimestamp(ts).isoformat()+'Z'
    except Exception:
        report['timestamp'] = None
    # Headers summary
    try:
        report['machine'] = hex(p.FILE_HEADER.Machine)
        report['number_of_sections'] = p.FILE_HEADER.NumberOfSections
        report['characteristics'] = hex(p.FILE_HEADER.Characteristics)
        report['entry_point_rva'] = hex(p.OPTIONAL_HEADER.AddressOfEntryPoint)
        report['image_base'] = hex(p.OPTIONAL_HEADER.ImageBase)
        report['subsystem'] = getattr(p.OPTIONAL_HEADER, 'Subsystem', None)
    except Exception:
        pass
    # Sections
    sections = []
    for s in p.sections:
        name = s.Name.rstrip(b'\x00').decode(errors='ignore')
        data = s.get_data()
        sec_ent = entropy(data)
        sections.append({'name': name, 'virtual_address': hex(s.VirtualAddress), 'virtual_size': s.Misc_VirtualSize, 'raw_size': s.SizeOfRawData, 'entropy': sec_ent})
    report['sections'] = sections
    # Imports
    imports = []
    try:
        if hasattr(p, 'DIRECTORY_ENTRY_IMPORT') and p.DIRECTORY_ENTRY_IMPORT:
            for entry in p.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors='ignore') if isinstance(entry.dll, bytes) else str(entry.dll)
                funcs = []
                for imp in entry.imports:
                    funcs.append({'name': imp.name.decode(errors='ignore') if imp.name else None, 'address': hex(imp.address) if imp.address else None})
                imports.append({'dll': dll, 'functions': funcs})
    except Exception:
        pass
    report['imports'] = imports
    # Exports
    exports = []
    try:
        if hasattr(p, 'DIRECTORY_ENTRY_EXPORT') and p.DIRECTORY_ENTRY_EXPORT:
            for exp in p.DIRECTORY_ENTRY_EXPORT.symbols:
                exports.append({'name': exp.name.decode(errors='ignore') if exp.name else None, 'address': hex(p.OPTIONAL_HEADER.ImageBase + exp.address)})
    except Exception:
        pass
    report['exports'] = exports
    # Resources summary (types and counts)
    resources = {}
    try:
        if hasattr(p, 'DIRECTORY_ENTRY_RESOURCE') and p.DIRECTORY_ENTRY_RESOURCE:
            def walk_res(entries, prefix=''):
                for e in entries:
                    name = getattr(e, 'name', None) or getattr(e, 'id', None)
                    key = f"{prefix}/{name}"
                    resources.setdefault(key,0)
                    resources[key]+=1
                    if hasattr(e, 'directory') and e.directory:
                        walk_res(e.directory.entries, key)
            walk_res(p.DIRECTORY_ENTRY_RESOURCE.entries)
    except Exception:
        pass
    report['resources'] = resources
    # Strings and sensitive indicators
    with open(path, 'rb') as fh:
        data = fh.read()
    report['strings_count'] = len(PRINTABLE_RE.findall(data))
    report['strings_sample'] = extract_strings(data)[:200]
    report['sensitive_matches'] = []
    # simple heuristics for keys/tokens
    suspicious_patterns = [rb'AKIA[0-9A-Z]{16}', rb'AIza[0-9A-Za-z-_]{35}', rb'password', rb'passwd', rb'secret', rb'token', rb'BEGIN RSA PRIVATE KEY']
    for pat in suspicious_patterns:
        for m in re.findall(pat, data, re.I):
            try:
                report['sensitive_matches'].append(m.decode(errors='ignore'))
            except Exception:
                report['sensitive_matches'].append(str(m))
    # entropy heuristics: very high entropy in a section or entire file may indicate packing or embedded compressed/encrypted blob
    report['file_entropy'] = entropy(data)
    report['likely_packed'] = any(s['entropy'] > 7.5 for s in sections) or report['file_entropy'] > 7.8
    # Packer hints from section names and imports
    packer_hints = []
    for s in sections:
        if any(x in s['name'].lower() for x in ['upx','aspack','pack','petite','mpress','themida','epic']):
            packer_hints.append(s['name'])
    report['packer_hints'] = packer_hints
    # Try lief for richer info if available (optional)
    if lief is not None:
        try:
            l = lief.parse(path)
            report['lief'] = {
                'has_signature': bool(getattr(l, 'has_signature', False)),
                'is_packed': getattr(l, 'is_packed', None),
                'metadata': {'entrypoint': hex(l.entrypoint) if hasattr(l, 'entrypoint') else None}
            }
        except Exception:
            pass
    return report

def main():
    parser = argparse.ArgumentParser(description='EXE static analyzer (safe)')
    parser.add_argument('path', help='Path to EXE or DLL file')
    parser.add_argument('-o','--out', default='exe_report', help='Output directory for report (json + samples)')
    args = parser.parse_args()
    path = args.path
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    if not Path(path).exists():
        print('File not found:', path); sys.exit(2)
    try:
        report = analyze_pe(path)
    except Exception as e:
        print('Error analyzing file:', e); raise
    out_json = out / (Path(path).name + '.report.json')
    out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    print('Report written to:', out_json)
    # brief summary
    print('Summary:')
    print('  file:', report.get('file'))
    print('  sha256:', report.get('sha256'))
    print('  size:', report.get('size'))
    print('  entry:', report.get('entry_point_rva'))
    print('  sections:', len(report.get('sections',[])))
    print('  file_entropy:', round(report.get('file_entropy',0),3))
    if report.get('likely_packed'):
        print('  POSSIBLE PACKED FILE (high entropy or section names suggest packing):', report.get('packer_hints'))

if __name__ == '__main__':
    main()
