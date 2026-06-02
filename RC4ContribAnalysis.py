#!/usr/bin/env python3
"""
RC4ContribAnalysis.py
Build the three contribution results:
  1) RC4 rate per port (RC4 / all TLS handshakes)
  2) RC4 by TLS version (modern TLS vs legacy)
  3) RC4 neglect indicators vs baseline TLS hosts

Usage:
  python3 RC4ContribAnalysis.py \
    --records results/IE-20260317-171424/records.fresh \
    --analysis rc4/rc4_analysis.json \
    --crossref rc4/rc4_crossref.json \
    --outdir rc4/contrib
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

try:
    from dateutil import parser as dparser
except Exception:
    dparser = None

PORTS = ['p25', 'p110', 'p143', 'p443', 'p587', 'p993']
PORT_LABELS = {
    'p25': 'SMTP (25)',
    'p110': 'POP3 (110)',
    'p143': 'IMAP (143)',
    'p443': 'HTTPS (443)',
    'p587': 'Submission (587)',
    'p993': 'IMAPS (993)',
}
TLS_VERSION_MAP = {
    0x0300: 'SSLv3',
    0x0301: 'TLSv1.0',
    0x0302: 'TLSv1.1',
    0x0303: 'TLSv1.2',
    0x0304: 'TLSv1.3',
}
LEGACY_VERSIONS = {'SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0', 'TLSv1.1'}

plt.rcParams.update({
    'figure.facecolor': 'white', 'axes.facecolor': '#FAFAFA',
    'axes.edgecolor': '#CCCCCC', 'axes.labelcolor': '#333333',
    'text.color': '#333333', 'xtick.color': '#555555', 'ytick.color': '#555555',
    'grid.color': '#E0E0E0', 'grid.alpha': 0.5,
    'font.family': 'serif', 'font.size': 11,
    'savefig.dpi': 300, 'savefig.bbox': 'tight', 'savefig.pad_inches': 0.4,
})

BLUE = '#2171B5'
RED = '#CB181D'
ORANGE = '#D94701'
GREEN = '#238B45'
PURPLE = '#6A51A3'


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def safe_get(blob, *keys):
    cur = blob
    for key in keys:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def parse_scandate(path, override=None):
    if override:
        return parse_time(override)
    match = re.search(r'(\d{8})-(\d{6})', path)
    if match:
        try:
            return datetime.strptime(match.group(1) + match.group(2), '%Y%m%d%H%M%S')
        except ValueError:
            pass
    log('Could not infer scan date from path; using current UTC time')
    return datetime.utcnow()


def parse_time(value):
    if not value:
        return None
    if dparser is not None:
        try:
            return normalize_dt(dparser.parse(value))
        except Exception:
            pass
    for fmt in ('%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S'):
        try:
            return normalize_dt(datetime.strptime(value, fmt))
        except Exception:
            continue
    return None


def normalize_dt(dt):
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def normalize_version(ver):
    if ver is None:
        return None
    if isinstance(ver, dict):
        ver = ver.get('name') or ver.get('value') or ver.get('id')
    if isinstance(ver, int):
        return TLS_VERSION_MAP.get(ver, str(ver))
    if isinstance(ver, str):
        v = ver.strip()
        low = v.lower()
        if low.startswith('0x'):
            try:
                return TLS_VERSION_MAP.get(int(low, 16), v)
            except ValueError:
                return v
        if low in {'tlsv1', 'tls1', 'tls1.0', 'tlsv1.0', 'tls 1.0', 'tls1_0'}:
            return 'TLSv1.0'
        if low in {'tlsv1.1', 'tls1.1', 'tls 1.1', 'tls1_1'}:
            return 'TLSv1.1'
        if low in {'tlsv1.2', 'tls1.2', 'tls 1.2', 'tls1_2'}:
            return 'TLSv1.2'
        if low in {'tlsv1.3', 'tls1.3', 'tls 1.3', 'tls1_3'}:
            return 'TLSv1.3'
        if low in {'sslv3', 'sslv3.0', 'ssl 3.0'}:
            return 'SSLv3'
        if low in {'sslv2', 'ssl 2.0', 'ssl2'}:
            return 'SSLv2'
        return v
    return str(ver)


def extract_tls_blob(rec, port):
    portrec = rec.get(port, {}) or {}
    data = portrec.get('data') or {}
    tls = data.get('tls')
    if isinstance(tls, dict):
        return tls
    if port == 'p443':
        tls = safe_get(data, 'http', 'response', 'request', 'tls_handshake')
        if isinstance(tls, dict):
            return tls
    for candidate in [
        safe_get(portrec, 'smtp', 'starttls', 'tls'),
        safe_get(portrec, 'imap', 'starttls', 'tls'),
        safe_get(portrec, 'pop3', 'starttls', 'tls'),
        safe_get(portrec, 'imaps', 'tls', 'tls'),
        safe_get(portrec, 'https', 'tls'),
    ]:
        if isinstance(candidate, dict):
            return candidate
    return None


def extract_server_hello(tls):
    if not isinstance(tls, dict):
        return None
    sh = safe_get(tls, 'handshake_log', 'server_hello')
    if isinstance(sh, dict):
        return sh
    sh = tls.get('server_hello')
    if isinstance(sh, dict):
        return sh
    return None


def extract_tls_version(tls):
    sh = extract_server_hello(tls)
    ver = None
    if isinstance(sh, dict):
        ver = sh.get('version')
    if ver is None and isinstance(tls, dict):
        ver = tls.get('version')
    return normalize_version(ver)


def extract_cert_fields(tls):
    cert = safe_get(tls, 'server_certificates', 'certificate', 'parsed')
    if cert is None:
        cert = safe_get(tls, 'certificate', 'parsed')
    return cert or {}


def cert_is_self_signed(cert):
    return bool(safe_get(cert, 'signature', 'self_signed'))


def cert_expired(cert, scandate):
    validity = cert.get('validity') or {}
    end = validity.get('end') or validity.get('not_after') or validity.get('notAfter')
    if not end:
        return None
    end_dt = parse_time(end)
    if not end_dt:
        return None
    return end_dt < scandate


def bar_chart(path, title, labels, values, color, ylabel):
    fig, ax = plt.subplots(figsize=(10, 4.8))
    bars = ax.bar(range(len(values)), values, color=color, edgecolor='white', linewidth=0.6)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=30, ha='right')
    ax.set_ylabel(ylabel)
    ax.set_title(title, fontweight='bold', fontsize=11)
    ax.grid(True, axis='y', alpha=0.3)
    if values:
        vmax = max(values)
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + vmax * 0.01,
                    str(val), ha='center', fontsize=9)
    plt.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def grouped_bar(path, title, labels, series, series_labels, colors, ylabel):
    fig, ax = plt.subplots(figsize=(10, 4.8))
    x = list(range(len(labels)))
    width = 0.35
    for i, values in enumerate(series):
        offset = (i - (len(series) - 1) / 2) * width
        ax.bar([v + offset for v in x], values, width, label=series_labels[i],
               color=colors[i], edgecolor='white', linewidth=0.6)
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel(ylabel)
    ax.set_title(title, fontweight='bold', fontsize=11)
    ax.grid(True, axis='y', alpha=0.3)
    ax.legend()
    plt.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description='Build RC4 contributions and plots')
    parser.add_argument('--records', default='records.fresh', help='records.fresh path')
    parser.add_argument('--analysis', default='rc4/rc4_analysis.json', help='rc4_analysis.json path')
    parser.add_argument('--crossref', default='rc4/rc4_crossref.json', help='rc4_crossref.json path')
    parser.add_argument('--outdir', default='rc4/contrib', help='output directory')
    parser.add_argument('--scandate', default=None, help='scan date override (ISO format)')
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    with open(args.analysis, 'r') as f:
        analysis = json.load(f)
    with open(args.crossref, 'r') as f:
        crossref = json.load(f)

    scandate = normalize_dt(parse_scandate(args.records, args.scandate))

    total_tls_by_port = Counter()
    host_flags = {}

    with open(args.records, 'r') as f:
        for line in f:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = rec.get('ip')
            if not ip:
                continue
            flags = host_flags.setdefault(ip, {
                'has_tls': False,
                'expired': False,
                'self_signed': False,
                'legacy_tls': False,
            })
            for port in PORTS:
                tls = extract_tls_blob(rec, port)
                if not tls:
                    continue
                total_tls_by_port[port] += 1
                flags['has_tls'] = True
                version = extract_tls_version(tls)
                if version in LEGACY_VERSIONS:
                    flags['legacy_tls'] = True
                cert = extract_cert_fields(tls)
                if cert:
                    if cert_is_self_signed(cert):
                        flags['self_signed'] = True
                    expired = cert_expired(cert, scandate)
                    if expired is True:
                        flags['expired'] = True

    tls_hosts = [f for f in host_flags.values() if f['has_tls']]
    total_tls_hosts = len(tls_hosts)
    base_expired = sum(1 for f in tls_hosts if f['expired'])
    base_self_signed = sum(1 for f in tls_hosts if f['self_signed'])
    base_legacy = sum(1 for f in tls_hosts if f['legacy_tls'])

    rc4_hosts = crossref.get('summary', {}).get('total_rc4_servers_analysed', 0)
    rc4_expired = crossref.get('summary', {}).get('neglect_indicators', {}).get('expired_cert', 0)
    rc4_self_signed = crossref.get('summary', {}).get('neglect_indicators', {}).get('self_signed', 0)
    rc4_legacy = crossref.get('summary', {}).get('neglect_indicators', {}).get('legacy_tls', 0)

    def pct(num, denom):
        return round((num / denom * 100.0), 2) if denom else 0.0

    summary = {
        'total_ips_scanned': analysis.get('total_ips_scanned', 0),
        'rc4_servers': analysis.get('rc4_servers', 0),
        'rc4_rate_percent': pct(analysis.get('rc4_servers', 0), analysis.get('total_ips_scanned', 0)),
        'total_tls_hosts': total_tls_hosts,
        'baseline': {
            'expired_cert': base_expired,
            'self_signed': base_self_signed,
            'legacy_tls': base_legacy,
        },
        'rc4': {
            'expired_cert': rc4_expired,
            'self_signed': rc4_self_signed,
            'legacy_tls': rc4_legacy,
        },
    }

    with open(os.path.join(args.outdir, 'rc4_contrib_summary.json'), 'w') as f:
        json.dump(summary, f, indent=2)

    # Contribution 1: RC4 rate per port
    with open(os.path.join(args.outdir, 'rc4_rate_per_port.csv'), 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['port', 'rc4_count', 'total_tls', 'rc4_rate_percent'])
        for port in PORTS:
            rc4_count = analysis.get('by_port', {}).get(port, {}).get('rc4_count', 0)
            total_tls = total_tls_by_port.get(port, 0)
            rate = pct(rc4_count, total_tls)
            writer.writerow([port, rc4_count, total_tls, rate])

    port_labels = []
    port_rates = []
    for port in PORTS:
        rc4_count = analysis.get('by_port', {}).get(port, {}).get('rc4_count', 0)
        total_tls = total_tls_by_port.get(port, 0)
        port_labels.append(PORT_LABELS.get(port, port))
        port_rates.append(pct(rc4_count, total_tls))
    bar_chart(
        os.path.join(args.outdir, 'rc4_rate_per_port.png'),
        'RC4 rate per port (RC4 / all TLS handshakes)',
        port_labels,
        port_rates,
        BLUE,
        'RC4 rate (%)'
    )

    # Contribution 2: RC4 by TLS version
    version_counts = Counter()
    for entry in analysis.get('rc4_ip_list', []):
        for info in entry.get('rc4_ports', []):
            v = info.get('tls_version') or 'Unknown'
            version_counts[v] += 1
    if version_counts:
        labels = list(version_counts.keys())
        values = [version_counts[k] for k in labels]
        bar_chart(
            os.path.join(args.outdir, 'rc4_by_tls_version.png'),
            'RC4 handshakes by TLS version',
            labels,
            values,
            ORANGE,
            'RC4 handshakes'
        )

    # Contribution 3: RC4 neglect vs baseline
    rc4_rates = [pct(rc4_expired, rc4_hosts), pct(rc4_self_signed, rc4_hosts), pct(rc4_legacy, rc4_hosts)]
    base_rates = [pct(base_expired, total_tls_hosts), pct(base_self_signed, total_tls_hosts), pct(base_legacy, total_tls_hosts)]
    grouped_bar(
        os.path.join(args.outdir, 'rc4_neglect_vs_baseline.png'),
        'Neglect indicators: RC4 vs baseline TLS hosts',
        ['Expired cert', 'Self-signed', 'Legacy TLS'],
        [rc4_rates, base_rates],
        ['RC4 hosts', 'All TLS hosts'],
        [RED, GREEN],
        'Rate (%)'
    )

    log(f"Outputs written to: {args.outdir}")


if __name__ == '__main__':
    main()
