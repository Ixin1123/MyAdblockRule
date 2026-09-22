"""Conservative, explicitly typed ABP/Hosts conversion. Python 3.12 stdlib."""
from __future__ import annotations
import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VERSION = 3
LIMIT = 20 * 1024 * 1024

def domain(s):
    s = s.lower().rstrip('.')
    try:
        s = s.encode('idna').decode('ascii')
        ipaddress.ip_address(s)
        return None
    except UnicodeError:
        return None
    except ValueError:
        pass
    if len(s) > 253 or '.' not in s or s.endswith(('.localhost', '.local')):
        return None
    if all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p) for p in s.split('.')):
        return s
    return None

def covered(d, roots):
    parts = d.split('.')
    return any('.'.join(parts[i:]) in roots for i in range(len(parts)))

def key(line):
    base, sep, opts = line.partition('$')
    options = set(opts.split(',')) if sep else set()
    options.discard('badfilter')
    return base + ('$' + ','.join(sorted(options)) if options else '')

def parse(text, kind):
    if kind not in ('abp', 'hosts', 'domains'):
        raise ValueError('Unknown source format')
    if not text.strip() or re.search(r'<(?:!doctype\s+html|html|body)\b', text, re.I):
        raise ValueError('Empty or HTML response')
    counts = Counter()
    active = []
    depth = 0
    for raw in text.splitlines():
        counts['lines'] += 1
        s = raw.strip().lstrip('\ufeff')
        if s.startswith('!#if'):
            depth += 1
            counts['conditional_skipped'] += 1
            continue
        if s.startswith('!#endif'):
            depth -= 1
            if depth < 0:
                raise ValueError('Unbalanced conditional directive')
            counts['conditional_skipped'] += 1
            continue
        if depth:
            counts['conditional_skipped'] += 1
            continue
        if not s or s.startswith(('!', '#', '[')):
            counts['comments_blank_headers'] += 1
            continue
        active.append(s)
    if depth:
        raise ValueError('Unclosed conditional directive')
    disabled = {key(s) for s in active if '$' in s and 'badfilter' in s.split('$',1)[1].split(',')} if kind == 'abp' else set()
    blocks, allows = set(), set()
    for s in active:
        if kind == 'abp':
            if '$' in s and 'badfilter' in s.split('$',1)[1].split(','):
                counts['badfilter_directives'] += 1
            elif key(s) in disabled:
                counts['disabled_rules'] += 1
            elif '#' in s:
                counts['cosmetic_skipped'] += 1
            elif s.startswith('@@'):
                # Availability-first: identifiable exception targets are excluded
                # entirely because Hosts cannot preserve path/request conditions.
                m = re.match(r'^@@(?:\|\||\|?https?://)([\w.-]+)(?=[\^/:$]|$)', s)
                d = domain(m[1]) if m else None
                if d:
                    allows.add(d)
                    counts['conservative_exceptions'] += 1
                else:
                    counts['unresolved_exceptions'] += 1
            else:
                m = re.fullmatch(r'\|\|([\w.-]+)\^(?:\$(important))?', s)
                d = domain(m[1]) if m else None
                if d:
                    blocks.add(d)
                    counts['block_rules'] += 1
                else:
                    counts['unsupported_skipped'] += 1
        else:
            fields = s.split('#',1)[0].split()
            valid = []
            if kind == 'domains' and len(fields) == 1:
                valid = fields
            elif kind == 'hosts' and len(fields) >= 2:
                try:
                    ip = ipaddress.ip_address(fields[0])
                    if ip.is_loopback or ip.is_unspecified:
                        valid = fields[1:]
                except ValueError:
                    pass
            ds = {domain(x) for x in valid} - {None}
            if ds:
                blocks.update(ds)
                counts['block_rules'] += 1
            else:
                counts['unsupported_skipped'] += 1
    if not blocks:
        raise ValueError('No valid blocking domains in source')
    return blocks, allows, dict(sorted(counts.items()))

def download(url):
    if not url.startswith('https://'):
        raise ValueError('Only HTTPS sources are allowed')
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={'User-Agent':'MyAdBlockRules/3'})
            with urllib.request.urlopen(req, timeout=30) as response:
                if not response.url.startswith('https://'):
                    raise ValueError('Insecure redirect')
                data = response.read(LIMIT+1)
            if len(data) > LIMIT:
                raise ValueError('Source exceeds 20 MiB')
            return data.decode('utf-8-sig')
        except (OSError, UnicodeError):
            if attempt == 2:
                raise
            time.sleep(attempt+1)

def local(path):
    exact, suffix = set(), set()
    if not path.exists():
        return exact, suffix
    for raw in path.read_text(encoding='utf-8-sig').splitlines():
        s = raw.split('#',1)[0].strip()
        if not s:
            continue
        sub = s.startswith('*.')
        d = domain(s[2:] if sub else s)
        if not d:
            raise ValueError(f'Invalid local domain: {s}')
        (suffix if sub else exact).add(d)
    return exact, suffix

def guard(new, old, label, accept):
    if new <= 0:
        raise ValueError(f'{label}: empty result')
    if old and not accept and not old * 0.75 <= new <= old * 1.5:
        raise ValueError(f'{label}: suspicious count change {old} -> {new}; review before accepting')

def build(root=ROOT, fetch=download, accept=False):
    previous_path = root/'rules/stats.json'
    previous = json.loads(previous_path.read_text()) if previous_path.exists() else {}
    same_version = previous.get('schema_version') == VERSION
    history = {s['url']:s for s in previous.get('sources',[])} if same_version else {}
    blocks, allows = set(), set()
    sources = []
    seen = set()
    for raw in (root/'sources.txt').read_text(encoding='utf-8-sig').splitlines():
        s = raw.strip()
        if not s or s.startswith('#'):
            continue
        kind, minimum, url = s.split(None,2)
        if url in seen or int(minimum) < 1:
            raise ValueError('Duplicate source URL or invalid minimum')
        seen.add(url)
        text = fetch(url)
        b,a,stats = parse(text,kind)
        if len(b) < int(minimum):
            raise ValueError(f'{url}: below minimum {minimum}')
        guard(len(b),history.get(url,{}).get('unique_blocked',0),url,accept)
        blocks.update(b)
        allows.update(a)
        sources.append({'url':url,'format':kind,'sha256':hashlib.sha256(text.encode()).hexdigest(),
                        'unique_blocked':len(b),'unique_allowed':len(a),'counts':stats})
        print(f'{kind}: {len(b)} candidate domains, {len(a)} exception domains')
    if not sources:
        raise ValueError('No sources configured')
    before = len(blocks)
    blocks = {d for d in blocks if not covered(d,allows)}
    removed = before-len(blocks)
    extra,wild = local(root/'blocklist.txt')
    if wild:
        raise ValueError('Hosts blocklist does not support wildcards')
    blocks.update(extra)
    exact,suffix = local(root/'allowlist.txt')
    blocks = {d for d in blocks if d not in exact and not covered(d,suffix)}
    guard(len(blocks), previous.get('output_domains',0) if same_version else 0,'final output',accept)
    report = {'schema_version':VERSION,'policy':'availability-first; no hosts suffix compression',
              'sources':sources,'removed_by_upstream_exceptions':removed,'output_domains':len(blocks)}
    from datetime import datetime, timezone, timedelta
    beijing_time = datetime.now(
        timezone(timedelta(hours=8))
    ).strftime("%Y-%m-%d %H:%M:%S")

    header = [
        "# 名称：MyAdblockRule 去广告合并规则",
        "# 维护者：Ixin1123",
        "# 上游来源：damengzhu/abpmerge、AWAvenue-Ads-Rule",
        "# 仓库：https://github.com/Ixin1123/MyAdblockRule",
        "# 订阅：https://gcore.jsdelivr.net/gh/Ixin1123/MyAdblockRule@main/rules/adblockhosts.txt",
        "# 原始链接：https://raw.githubusercontent.com/Ixin1123/MyAdblockRule/main/rules/adblockhosts.txt",
        f"# 生成时间：{beijing_time}（北京时间 UTC+8）",
        "# 更新频率：每8小时自动检查并生成",
        f"# 域名数量：{len(blocks)}",
        "# 格式：Hosts；保留父子域名，仅删除完全重复项",
        "",
    ]
    hosts = "\n".join(header)
    hosts += "".join(
        f"0.0.0.0 {d}\n" for d in sorted(blocks)
    )
    hosts += ''.join('0.0.0.0 '+d+'\n' for d in sorted(blocks))
    # All validations precede publication. GitHub commits both outputs together.
    directory = root/'rules'
    directory.mkdir(exist_ok=True)
    payloads = {'adblockhosts.txt':hosts,'stats.json':json.dumps(report,ensure_ascii=False,indent=2)+'\n'}
    for name,content in payloads.items():
        (directory/(name+'.tmp')).write_text(content,encoding='utf-8',newline='\n')
    for name in payloads:
        os.replace(directory/(name+'.tmp'),directory/name)
    print(f'Final: {len(blocks)} exact domains')
    return report

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--accept-large-change',action='store_true',help='After review only; minimum checks still apply')
    args = parser.parse_args()
    try:
        build(accept=args.accept_large_change)
    except Exception as exc:
        print(f'BUILD FAILED; do not publish: {exc}',file=sys.stderr)
        sys.exit(1)
