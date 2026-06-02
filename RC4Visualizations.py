#!/usr/bin/env python3
"""
RC4Visualizations.py
Generate plots from rc4/ outputs (rc4_analysis.json, rc4_crossref.json, rc4_providers.txt).

Usage:
    python3 RC4Visualizations.py -o rc4/figures
"""

import argparse
import csv
import json
import os
import sys
from collections import Counter

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

DEFAULT_ANALYSIS = 'rc4/rc4_analysis.json'
DEFAULT_CROSSREF = 'rc4/rc4_crossref.json'
DEFAULT_PROVIDERS = 'rc4/rc4_providers.txt'

PORT_ORDER = ['p25', 'p110', 'p143', 'p587', 'p993', 'p443']
PORT_LABELS = {
    'p25': 'SMTP (25)',
    'p110': 'POP3 (110)',
    'p143': 'IMAP (143)',
    'p587': 'Submission (587)',
    'p993': 'IMAPS (993)',
    'p443': 'HTTPS (443)',
}

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
TEAL = '#006D75'


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def load_json(path):
    if not path or not os.path.exists(path):
        return None
    with open(path, 'r') as f:
        return json.load(f)


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


def histogram(path, title, labels, values, color, ylabel):
    fig, ax = plt.subplots(figsize=(8.5, 4.6))
    bars = ax.bar(range(len(values)), values, color=color, edgecolor='white', linewidth=0.6)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels)
    ax.set_ylabel(ylabel)
    ax.set_title(title, fontweight='bold', fontsize=11)
    ax.grid(True, axis='y', alpha=0.3)
    if values:
        vmax = max(values)
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + vmax * 0.02,
                    str(val), ha='center', fontsize=9)
    plt.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def load_provider_counts(path):
    if not path or not os.path.exists(path):
        return Counter()
    counts = Counter()
    with open(path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            provider = (row.get('Provider') or row.get('provider') or '').strip()
            if not provider:
                provider = 'Unknown'
            counts[provider] += 1
    return counts


def main():
    parser = argparse.ArgumentParser(description='Generate RC4 plots from rc4/ outputs')
    parser.add_argument('-a', '--analysis', default=DEFAULT_ANALYSIS,
                        help='path to rc4_analysis.json')
    parser.add_argument('-x', '--crossref', default=DEFAULT_CROSSREF,
                        help='path to rc4_crossref.json')
    parser.add_argument('-p', '--providers', default=DEFAULT_PROVIDERS,
                        help='path to rc4_providers.txt')
    parser.add_argument('-o', '--outdir', default='rc4/figures',
                        help='output directory for plots')
    parser.add_argument('--topn', type=int, default=15,
                        help='top N providers to plot')
    args = parser.parse_args()

    analysis = load_json(args.analysis)
    crossref = load_json(args.crossref)

    os.makedirs(args.outdir, exist_ok=True)

    if not analysis:
        log(f"Missing analysis file: {args.analysis}")
        sys.exit(1)

    total_ips = analysis.get('total_ips_scanned', 0)
    rc4_servers = analysis.get('rc4_servers', 0)
    rc4_rate = (rc4_servers / total_ips * 100.0) if total_ips else 0.0

    # Plot 1: RC4 by port
    port_counts = []
    port_labels = []
    for port in PORT_ORDER:
        pdata = analysis.get('by_port', {}).get(port)
        if not pdata:
            continue
        port_counts.append(pdata.get('rc4_count', 0))
        port_labels.append(PORT_LABELS.get(port, port))
    bar_chart(
        os.path.join(args.outdir, 'rc4_by_port.png'),
        f"RC4 servers by port (n={rc4_servers}, {rc4_rate:.2f}% of IPs)",
        port_labels,
        port_counts,
        BLUE,
        'RC4 servers'
    )

    # Plot 2: RC4 by cipher suite
    cipher_counts = analysis.get('by_cipher', {})
    if cipher_counts:
        labels = list(cipher_counts.keys())
        values = [cipher_counts[k] for k in labels]
        bar_chart(
            os.path.join(args.outdir, 'rc4_by_cipher.png'),
            'RC4 cipher suite distribution',
            labels,
            values,
            RED,
            'RC4 handshakes'
        )

    # Plot 3: RC4 TLS version distribution
    version_counts = Counter()
    for entry in analysis.get('rc4_ip_list', []):
        for portinfo in entry.get('rc4_ports', []):
            v = portinfo.get('tls_version') or 'Unknown'
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

    # Plot 4: RC4 ports per host
    port_dist = Counter()
    for entry in analysis.get('rc4_ip_list', []):
        port_dist[entry.get('num_rc4_ports', 0)] += 1
    if port_dist:
        labels = [str(k) for k in sorted(port_dist.keys())]
        values = [port_dist[int(k)] for k in labels]
        histogram(
            os.path.join(args.outdir, 'rc4_ports_per_host.png'),
            'Number of RC4-enabled ports per host',
            labels,
            values,
            TEAL,
            'Hosts'
        )

    # Plot 5: Provider concentration (from crossref or providers list)
    provider_counts = Counter()
    if crossref and crossref.get('summary', {}).get('top_providers'):
        provider_counts = Counter(crossref['summary']['top_providers'])
    else:
        provider_counts = load_provider_counts(args.providers)

    if provider_counts:
        top = provider_counts.most_common(args.topn)
        labels = [p[0] if len(p[0]) <= 28 else p[0][:27] + '...' for p in top]
        values = [p[1] for p in top]
        bar_chart(
            os.path.join(args.outdir, 'rc4_top_providers.png'),
            f'Top {len(top)} providers running RC4',
            labels,
            values,
            PURPLE,
            'RC4 servers'
        )

    # Plot 6: Neglect indicators and scores
    if crossref and crossref.get('summary'):
        indicators = crossref['summary'].get('neglect_indicators', {})
        if indicators:
            labels = list(indicators.keys())
            values = [indicators[k] for k in labels]
            bar_chart(
                os.path.join(args.outdir, 'rc4_neglect_indicators.png'),
                'Neglect indicators among RC4 servers',
                labels,
                values,
                GREEN,
                'Servers'
            )

        scores = crossref['summary'].get('neglect_score_distribution', {})
        if scores:
            labels = [str(k) for k in sorted(scores.keys(), key=lambda x: int(x))]
            values = [scores[k] for k in labels]
            histogram(
                os.path.join(args.outdir, 'rc4_neglect_scores.png'),
                'Neglect score distribution',
                labels,
                values,
                BLUE,
                'Servers'
            )

        days_expired = crossref['summary'].get('days_expired_distribution', {})
        if days_expired:
            labels = list(days_expired.keys())
            values = [days_expired[k] for k in labels]
            bar_chart(
                os.path.join(args.outdir, 'rc4_days_expired.png'),
                'Certificate expiry among RC4 servers',
                labels,
                values,
                ORANGE,
                'Servers'
            )

    log(f"RC4 plots written to: {args.outdir}")


if __name__ == '__main__':
    main()
