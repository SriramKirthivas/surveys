#!/usr/bin/env python3
"""
AnalyticalFigures.py
Generates research-question-driven figures from collisions.json.
Each figure answers a specific question for the dissertation results chapter.

Usage:
    python3 AnalyticalFigures.py -f results/IE-20260317-171424/collisions.json -o figures/
"""

import argparse, json, re, os, sys, time, math
from collections import Counter, defaultdict
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.ticker as ticker
import numpy as np
import networkx as nx

def log(msg):
    print(msg, file=sys.stderr, flush=True)

# =============================================================================
# Style
# =============================================================================
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
GREEN = '#238B45'
ORANGE = '#D94701'
PURPLE = '#6A51A3'
TEAL = '#006D75'
PALETTE = ['#2171B5', '#CB181D', '#238B45', '#D94701', '#6A51A3',
           '#006D75', '#CE1256', '#525252', '#8C6D31', '#49006A',
           '#0570B0', '#E6550D', '#31A354', '#756BB1', '#636363']

PORT_LABELS = {'p22': 'SSH\n(22)', 'p25': 'SMTP\n(25)', 'p110': 'POP3\n(110)',
               'p143': 'IMAP\n(143)', 'p443': 'HTTPS\n(443)',
               'p587': 'Subm.\n(587)', 'p993': 'IMAPS\n(993)'}
PORT_SHORT = {'p22': 'SSH', 'p25': 'SMTP', 'p110': 'POP3',
              'p143': 'IMAP', 'p443': 'HTTPS', 'p587': 'Subm.', 'p993': 'IMAPS'}


# =============================================================================
# Data prep
# =============================================================================
def load(path):
    log(f"Loading {path}...")
    t0 = time.time()
    with open(path) as f:
        data = json.load(f)
    log(f"  {len(data)} entries in {time.time()-t0:.1f}s")
    return data


def prep(data):
    """Pre-compute all derived data structures."""
    log("Pre-computing...")

    # Per-cluster info
    clusters = defaultdict(lambda: {'ips': set(), 'asns': set(), 'size': 0,
                                     'fprint_ports': set(), 'coll_types': Counter()})
    # Per-ASN info
    asn_info = defaultdict(lambda: {'ips': set(), 'clusters': set(), 'max_cluster': 0})

    # Port-pair matrix
    ports = ['p22', 'p25', 'p110', 'p143', 'p443', 'p587', 'p993']
    pp_matrix = np.zeros((7, 7), dtype=int)
    pidx = {p: i for i, p in enumerate(ports)}

    # Reuse classification
    same_port = 0; cross_port = 0; cross_proto = 0
    mail_ports = {'p25', 'p587', 'p110', 'p143', 'p993'}

    for e in data:
        cn = e.get('clusternum', -1)
        ip = e.get('ip', '')
        asn = e.get('asn', '?')
        csize = e.get('csize', 0)

        clusters[cn]['ips'].add(ip)
        clusters[cn]['asns'].add(asn)
        clusters[cn]['size'] = csize
        for p in e.get('fprints', {}):
            clusters[cn]['fprint_ports'].add(p)

        asn_info[asn]['ips'].add(ip)
        asn_info[asn]['clusters'].add(cn)
        asn_info[asn]['max_cluster'] = max(asn_info[asn]['max_cluster'], csize)

        for _, rc in e.get('rcs', {}).items():
            pairs = re.findall(r'(p\d+)==(p\d+)', rc.get('str_colls', ''))
            for p1, p2 in pairs:
                clusters[cn]['coll_types'][f'{p1}-{p2}'] += 1
                if p1 in pidx and p2 in pidx:
                    pp_matrix[pidx[p1], pidx[p2]] += 1
                if p1 == p2:
                    same_port += 1
                else:
                    s1 = 'mail' if p1 in mail_ports else ('web' if p1 == 'p443' else 'ssh')
                    s2 = 'mail' if p2 in mail_ports else ('web' if p2 == 'p443' else 'ssh')
                    if s1 != s2:
                        cross_proto += 1
                    else:
                        cross_port += 1

    log(f"  {len(clusters)} clusters, {len(asn_info)} ASNs")
    return {
        'clusters': dict(clusters), 'asn_info': dict(asn_info),
        'pp_matrix': pp_matrix, 'ports': ports,
        'reuse_class': {'same': same_port, 'cross_port': cross_port, 'cross_proto': cross_proto},
    }


# =============================================================================
# Figure 1: Cluster Size Distribution (CDF + Histogram)
# RQ: What is the shape of key reuse — many small clusters or few large ones?
# =============================================================================
def fig1_cluster_size_dist(p, outdir):
    log("  Fig 1: Cluster size distribution...")
    sizes = sorted([c['size'] for c in p['clusters'].values()])
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.5))

    # Histogram
    bins = np.logspace(np.log10(min(sizes)), np.log10(max(sizes)), 30)
    ax1.hist(sizes, bins=bins, color=BLUE, alpha=0.8, edgecolor='white', linewidth=0.5)
    ax1.set_xscale('log')
    ax1.set_xlabel('Cluster Size')
    ax1.set_ylabel('Number of Clusters')
    ax1.set_title('(a) Cluster Size Histogram (log-scale)', fontweight='bold', fontsize=11)
    ax1.grid(True, alpha=0.3)

    # CDF with percentiles
    cdf = np.arange(1, len(sizes) + 1) / len(sizes)
    ax2.plot(sizes, cdf, color=BLUE, linewidth=2)
    ax2.fill_between(sizes, cdf, alpha=0.05, color=BLUE)
    for pct in [0.50, 0.75, 0.90, 0.95, 0.99]:
        idx = min(int(pct * len(sizes)), len(sizes) - 1)
        ax2.axhline(y=pct, color='#CCCCCC', linewidth=0.5, linestyle=':')
        ax2.plot(sizes[idx], pct, 'o', color=RED, markersize=7, zorder=5)
        ax2.annotate(f'P{int(pct*100)}={sizes[idx]}', (sizes[idx], pct),
                     xytext=(8, -3), textcoords='offset points',
                     fontsize=8, color=RED)
    ax2.set_xscale('log')
    ax2.set_xlabel('Cluster Size')
    ax2.set_ylabel('Cumulative Probability')
    ax2.set_title('(b) Cumulative Distribution Function', fontweight='bold', fontsize=11)
    ax2.grid(True, alpha=0.3)

    fig.suptitle('Figure 1: Distribution of Key Reuse Cluster Sizes (n=%d clusters)' % len(sizes),
                 fontsize=12, fontweight='bold', y=1.02)
    plt.tight_layout()
    fig.savefig(os.path.join(outdir, 'fig1_cluster_size_distribution.png'))
    plt.close(fig)


# =============================================================================
# Figure 2: Port-Pair Reuse Heatmap
# RQ: Which protocol combinations most commonly share cryptographic keys?
# =============================================================================
def fig2_port_heatmap(p, outdir):
    log("  Fig 2: Port-pair heatmap...")
    matrix = p['pp_matrix'].copy()
    ports = p['ports']
    labels = [PORT_SHORT.get(pt, pt) for pt in ports]

    # Log scale for visibility (huge range: 70K to 9.7M)
    log_matrix = np.log10(matrix + 1)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

    # Raw counts
    im1 = ax1.imshow(matrix, cmap='YlOrRd', aspect='auto')
    ax1.set_xticks(range(7)); ax1.set_yticks(range(7))
    ax1.set_xticklabels(labels, fontsize=9); ax1.set_yticklabels(labels, fontsize=9)
    for i in range(7):
        for j in range(7):
            v = matrix[i, j]
            if v > 0:
                txt = f'{v/1e6:.1f}M' if v >= 1e6 else (f'{v/1e3:.0f}K' if v >= 1e3 else str(v))
                c = 'white' if v > matrix.max() * 0.3 else '#333333'
                ax1.text(j, i, txt, ha='center', va='center', fontsize=7, fontweight='bold', color=c)
    ax1.set_title('(a) Raw Reuse Counts', fontweight='bold', fontsize=11)
    plt.colorbar(im1, ax=ax1, shrink=0.8, label='Count')

    # Log scale
    im2 = ax2.imshow(log_matrix, cmap='YlOrRd', aspect='auto')
    ax2.set_xticks(range(7)); ax2.set_yticks(range(7))
    ax2.set_xticklabels(labels, fontsize=9); ax2.set_yticklabels(labels, fontsize=9)
    for i in range(7):
        for j in range(7):
            v = matrix[i, j]
            if v > 0:
                ax2.text(j, i, f'{np.log10(v):.1f}', ha='center', va='center',
                         fontsize=8, color='white' if log_matrix[i,j] > 3 else '#333333')
    ax2.set_title('(b) Log₁₀ Scale', fontweight='bold', fontsize=11)
    cbar = plt.colorbar(im2, ax=ax2, shrink=0.8, label='log₁₀(count)')

    fig.suptitle('Figure 2: Cross-Protocol Key Reuse Matrix', fontsize=12, fontweight='bold', y=1.02)
    plt.tight_layout()
    fig.savefig(os.path.join(outdir, 'fig2_port_pair_heatmap.png'))
    plt.close(fig)


# =============================================================================
# Figure 3: Reuse Type Classification
# RQ: How much key reuse crosses protocol boundaries?
# =============================================================================
def fig3_reuse_classification(p, outdir):
    log("  Fig 3: Reuse classification...")
    rc = p['reuse_class']
    total = rc['same'] + rc['cross_port'] + rc['cross_proto']

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.5))

    # Donut
    vals = [rc['same'], rc['cross_port'], rc['cross_proto']]
    labels = ['Same Port\nSame Protocol', 'Different Port\nSame Protocol', 'Cross\nProtocol']
    colors = [BLUE, ORANGE, RED]
    wedges, texts, autotexts = ax1.pie(
        vals, labels=labels, colors=colors, autopct='%1.1f%%',
        startangle=90, pctdistance=0.75,
        wedgeprops=dict(width=0.4, edgecolor='white', linewidth=2))
    for t in texts: t.set_fontsize(9)
    for t in autotexts: t.set_fontsize(9); t.set_fontweight('bold')
    ax1.set_title('(a) Reuse Type Proportions', fontweight='bold', fontsize=11)

    # Bar with actual numbers
    cats = ['Same Port', 'Cross Port\n(Same Proto)', 'Cross\nProtocol']
    bars = ax2.bar(cats, vals, color=colors, edgecolor='white', linewidth=0.5)
    ax2.set_ylabel('Number of Reuse Instances')
    ax2.set_title('(b) Reuse Counts by Category', fontweight='bold', fontsize=11)
    for bar, val in zip(bars, vals):
        txt = f'{val/1e6:.1f}M' if val >= 1e6 else (f'{val/1e3:.0f}K' if val >= 1e3 else str(val))
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + total*0.01,
                 txt, ha='center', fontsize=10, fontweight='bold')
    ax2.grid(True, axis='y', alpha=0.3)

    fig.suptitle('Figure 3: Classification of Key Reuse — Same Protocol vs Cross-Protocol',
                 fontsize=12, fontweight='bold', y=1.02)
    plt.tight_layout()
    fig.savefig(os.path.join(outdir, 'fig3_reuse_classification.png'))
    plt.close(fig)


# =============================================================================
# Figure 4: ASN Landscape
# RQ: Which organizations are most affected by key reuse?
# =============================================================================
def fig4_asn_landscape(p, outdir):
    log("  Fig 4: ASN landscape...")
    asn = p['asn_info']
    top = sorted(asn.items(), key=lambda x: len(x[1]['ips']), reverse=True)[:25]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5))

    # Horizontal bar: IPs per ASN
    names = [a[0] for a in reversed(top[:15])]
    counts = [len(a[1]['ips']) for a in reversed(top[:15])]
    colors_bar = [PALETTE[i % len(PALETTE)] for i in range(len(names))]
    bars = ax1.barh(names, counts, color=colors_bar, edgecolor='white', linewidth=0.5)
    for bar, val in zip(bars, counts):
        ax1.text(bar.get_width() + max(counts)*0.01, bar.get_y() + bar.get_height()/2,
                 str(val), va='center', fontsize=8, fontweight='bold')
    ax1.set_xlabel('IPs with Reused Keys')
    ax1.set_title('(a) Top 15 ASNs by Affected IPs', fontweight='bold', fontsize=11)
    ax1.grid(True, axis='x', alpha=0.3)

    # Bubble: clusters vs IPs vs max cluster size
    for i, (name, st) in enumerate(top[:20]):
        x = len(st['clusters'])
        y = len(st['ips'])
        s = max(40, min(1000, st['max_cluster'] * 3))
        ax2.scatter(x, y, s=s, color=PALETTE[i % len(PALETTE)],
                    alpha=0.6, edgecolors='white', linewidth=1.5, zorder=3)
        ax2.annotate(name, (x, y), fontsize=6, ha='center', va='bottom',
                     xytext=(0, 8), textcoords='offset points',
                     color=PALETTE[i % len(PALETTE)], fontweight='bold')
    ax2.set_xlabel('Number of Clusters Involved')
    ax2.set_ylabel('Total IPs with Reused Keys')
    ax2.set_title('(b) ASN Exposure (bubble size = largest cluster)', fontweight='bold', fontsize=11)
    ax2.grid(True, alpha=0.3)

    fig.suptitle('Figure 4: Organizational Analysis of Key Reuse by ASN',
                 fontsize=12, fontweight='bold', y=1.02)
    plt.tight_layout()
    fig.savefig(os.path.join(outdir, 'fig4_asn_landscape.png'))
    plt.close(fig)


# =============================================================================
# Figure 5: ASN Diversity within Clusters
# RQ: Do clusters typically stay within one organization or span multiple?
# =============================================================================
def fig5_asn_diversity(p, outdir):
    log("  Fig 5: ASN diversity per cluster...")
    clusters = p['clusters']

    # Number of ASNs per cluster
    asn_counts = [len(c['asns']) for c in clusters.values()]
    sizes = [c['size'] for c in clusters.values()]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.5))

    # Histogram of ASN count per cluster
    max_asn = min(max(asn_counts), 20)
    bins = range(1, max_asn + 2)
    ax1.hist(asn_counts, bins=bins, color=PURPLE, alpha=0.8, edgecolor='white',
             linewidth=0.5, align='left')
    ax1.set_xlabel('Number of ASNs in Cluster')
    ax1.set_ylabel('Number of Clusters')
    ax1.set_title('(a) ASN Diversity Distribution', fontweight='bold', fontsize=11)
    ax1.grid(True, axis='y', alpha=0.3)
    single = sum(1 for a in asn_counts if a == 1)
    multi = sum(1 for a in asn_counts if a > 1)
    ax1.annotate(f'Single ASN: {single} ({single/len(asn_counts)*100:.0f}%)\n'
                 f'Multi ASN: {multi} ({multi/len(asn_counts)*100:.0f}%)',
                 xy=(0.95, 0.95), xycoords='axes fraction', ha='right', va='top',
                 fontsize=9, bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

    # Scatter: cluster size vs ASN count
    ax2.scatter(sizes, asn_counts, alpha=0.4, s=30, color=PURPLE, edgecolors='white', linewidth=0.5)
    ax2.set_xlabel('Cluster Size (hosts)')
    ax2.set_ylabel('Number of ASNs')
    ax2.set_xscale('log')
    ax2.set_title('(b) Cluster Size vs ASN Diversity', fontweight='bold', fontsize=11)
    ax2.grid(True, alpha=0.3)

    # Correlation annotation
    log_sizes = np.log10([max(s, 1) for s in sizes])
    corr = np.corrcoef(log_sizes, asn_counts)[0, 1]
    ax2.annotate(f'r = {corr:.3f} (log-linear)',
                 xy=(0.05, 0.95), xycoords='axes fraction', ha='left', va='top',
                 fontsize=9, bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

    fig.suptitle('Figure 5: Cross-Organizational Key Reuse — ASN Diversity per Cluster',
                 fontsize=12, fontweight='bold', y=1.02)
    plt.tight_layout()
    fig.savefig(os.path.join(outdir, 'fig5_asn_diversity.png'))
    plt.close(fig)


# =============================================================================
# Figure 6: Port Fingerprint Prevalence
# RQ: Which services are most commonly involved in key reuse?
# =============================================================================
def fig6_port_prevalence(p, outdir):
    log("  Fig 6: Port prevalence...")
    clusters = p['clusters']
    ports = p['ports']

    # Count how many clusters have each port in their fingerprints
    port_cluster_count = Counter()
    port_ip_count = Counter()
    for c in clusters.values():
        for pt in c['fprint_ports']:
            port_cluster_count[pt] += 1
            port_ip_count[pt] += len(c['ips'])

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.5))

    # Clusters per port
    labels = [PORT_SHORT.get(pt, pt) for pt in ports]
    vals1 = [port_cluster_count.get(pt, 0) for pt in ports]
    colors_bar = [PALETTE[i] for i in range(len(ports))]
    bars1 = ax1.bar(labels, vals1, color=colors_bar, edgecolor='white', linewidth=0.5)
    for b, v in zip(bars1, vals1):
        if v > 0:
            ax1.text(b.get_x() + b.get_width()/2, v + max(vals1)*0.02,
                     str(v), ha='center', fontsize=9, fontweight='bold')
    ax1.set_ylabel('Number of Clusters')
    ax1.set_title('(a) Clusters Involving Each Port', fontweight='bold', fontsize=11)
    ax1.grid(True, axis='y', alpha=0.3)

    # IPs per port
    vals2 = [port_ip_count.get(pt, 0) for pt in ports]
    bars2 = ax2.bar(labels, vals2, color=colors_bar, edgecolor='white', linewidth=0.5)
    for b, v in zip(bars2, vals2):
        if v > 0:
            ax2.text(b.get_x() + b.get_width()/2, v + max(vals2)*0.02,
                     str(v), ha='center', fontsize=9, fontweight='bold')
    ax2.set_ylabel('Number of IPs')
    ax2.set_title('(b) IPs with Reused Keys per Port', fontweight='bold', fontsize=11)
    ax2.grid(True, axis='y', alpha=0.3)

    fig.suptitle('Figure 6: Service-Level Key Reuse Prevalence',
                 fontsize=12, fontweight='bold', y=1.02)
    plt.tight_layout()
    fig.savefig(os.path.join(outdir, 'fig6_port_prevalence.png'))
    plt.close(fig)


# =============================================================================
# Figure 7: Cluster Composition Analysis
# RQ: What types of port reuse dominate within clusters?
# =============================================================================
def fig7_cluster_composition(p, outdir):
    log("  Fig 7: Cluster composition...")
    clusters = p['clusters']

    # For each cluster, determine dominant reuse type
    web_only = 0; mail_only = 0; ssh_only = 0; mixed = 0
    mail_ports_set = {'p25', 'p587', 'p110', 'p143', 'p993'}

    categories = []
    sizes_by_cat = defaultdict(list)

    for cn, c in clusters.items():
        involved = c['fprint_ports']
        has_web = 'p443' in involved
        has_mail = bool(involved & mail_ports_set)
        has_ssh = 'p22' in involved

        count = sum([has_web, has_mail, has_ssh])
        if count > 1:
            cat = 'Mixed'
        elif has_web:
            cat = 'Web Only\n(HTTPS)'
        elif has_mail:
            cat = 'Mail Only\n(SMTP/IMAP/POP3)'
        elif has_ssh:
            cat = 'SSH Only'
        else:
            cat = 'Other'
        categories.append(cat)
        sizes_by_cat[cat].append(c['size'])

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.5))

    # Pie of cluster types
    cat_counts = Counter(categories)
    labels = list(cat_counts.keys())
    vals = list(cat_counts.values())
    colors_pie = [BLUE, RED, GREEN, ORANGE, PURPLE][:len(labels)]
    wedges, texts, autotexts = ax1.pie(
        vals, labels=labels, colors=colors_pie, autopct='%1.1f%%',
        startangle=90, pctdistance=0.8,
        wedgeprops=dict(edgecolor='white', linewidth=2))
    for t in texts: t.set_fontsize(9)
    for t in autotexts: t.set_fontsize(8); t.set_fontweight('bold')
    ax1.set_title('(a) Cluster Type Distribution', fontweight='bold', fontsize=11)

    # Box plot of sizes by category
    cat_labels = sorted(sizes_by_cat.keys(), key=lambda x: -len(sizes_by_cat[x]))
    box_data = [sizes_by_cat[c] for c in cat_labels]
    bp = ax2.boxplot(box_data, labels=[c.replace('\n', ' ') for c in cat_labels],
                     patch_artist=True, showfliers=True,
                     flierprops=dict(marker='.', markersize=3, alpha=0.4))
    for i, patch in enumerate(bp['boxes']):
        patch.set_facecolor(colors_pie[i % len(colors_pie)])
        patch.set_alpha(0.6)
    ax2.set_ylabel('Cluster Size')
    ax2.set_yscale('log')
    ax2.set_title('(b) Size Distribution by Type', fontweight='bold', fontsize=11)
    ax2.grid(True, axis='y', alpha=0.3)
    ax2.tick_params(axis='x', labelsize=8)

    fig.suptitle('Figure 7: Cluster Composition — Protocol Dominance',
                 fontsize=12, fontweight='bold', y=1.02)
    plt.tight_layout()
    fig.savefig(os.path.join(outdir, 'fig7_cluster_composition.png'))
    plt.close(fig)


# =============================================================================
# Figure 8: Cloud vs ISP Key Reuse
# RQ: Are cloud providers more prone to key reuse than traditional ISPs?
# =============================================================================
def fig8_cloud_vs_isp(p, outdir):
    log("  Fig 8: Cloud vs ISP analysis...")
    asn = p['asn_info']

    # Classify ASNs (heuristic based on common names)
    cloud_keywords = ['amazon', 'aws', 'microsoft', 'azure', 'google', 'gcp',
                      'digitalocean', 'hetzner', 'ovh', 'cloudflare', 'leaseweb',
                      'linode', 'vultr', 'oracle']
    isp_keywords = ['eir', 'virgin', 'vodafone', 'three', 'sky', 'bt ',
                    'magnet', 'imagine', 'digiweb']

    cloud_ips = 0; isp_ips = 0; other_ips = 0
    cloud_clusters = set(); isp_clusters = set(); other_clusters = set()
    cloud_names = []; isp_names = []; other_names = []

    for name, st in asn.items():
        lower = name.lower()
        n_ips = len(st['ips'])
        if any(kw in lower for kw in cloud_keywords):
            cloud_ips += n_ips
            cloud_clusters.update(st['clusters'])
            cloud_names.append((name, n_ips))
        elif any(kw in lower for kw in isp_keywords):
            isp_ips += n_ips
            isp_clusters.update(st['clusters'])
            isp_names.append((name, n_ips))
        else:
            other_ips += n_ips
            other_clusters.update(st['clusters'])
            other_names.append((name, n_ips))

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.5))

    # Stacked comparison
    categories = ['IPs with\nReused Keys', 'Clusters\nInvolved']
    cloud_vals = [cloud_ips, len(cloud_clusters)]
    isp_vals = [isp_ips, len(isp_clusters)]
    other_vals = [other_ips, len(other_clusters)]

    x = np.arange(len(categories))
    w = 0.25
    ax1.bar(x - w, cloud_vals, w, label=f'Cloud ({len(cloud_names)} ASNs)', color=BLUE, edgecolor='white')
    ax1.bar(x, isp_vals, w, label=f'ISP ({len(isp_names)} ASNs)', color=GREEN, edgecolor='white')
    ax1.bar(x + w, other_vals, w, label=f'Other ({len(other_names)} ASNs)', color=ORANGE, edgecolor='white')
    ax1.set_xticks(x); ax1.set_xticklabels(categories)
    ax1.set_ylabel('Count')
    ax1.set_title('(a) Cloud vs ISP vs Other', fontweight='bold', fontsize=11)
    ax1.legend(fontsize=8)
    ax1.grid(True, axis='y', alpha=0.3)

    # Top ASNs breakdown
    all_sorted = sorted(cloud_names + isp_names + other_names, key=lambda x: -x[1])[:15]
    names_list = [a[0] for a in reversed(all_sorted)]
    vals_list = [a[1] for a in reversed(all_sorted)]
    colors_list = []
    for name, _ in reversed(all_sorted):
        lower = name.lower()
        if any(kw in lower for kw in cloud_keywords):
            colors_list.append(BLUE)
        elif any(kw in lower for kw in isp_keywords):
            colors_list.append(GREEN)
        else:
            colors_list.append(ORANGE)

    ax2.barh(names_list, vals_list, color=colors_list, edgecolor='white', linewidth=0.5)
    ax2.set_xlabel('IPs with Reused Keys')
    ax2.set_title('(b) Top 15 ASNs Colored by Type', fontweight='bold', fontsize=11)
    ax2.grid(True, axis='x', alpha=0.3)

    # Legend
    ax2.legend(handles=[
        mpatches.Patch(color=BLUE, label='Cloud'),
        mpatches.Patch(color=GREEN, label='ISP'),
        mpatches.Patch(color=ORANGE, label='Other'),
    ], fontsize=8, loc='lower right')

    fig.suptitle('Figure 8: Cloud Provider vs ISP Key Reuse Comparison',
                 fontsize=12, fontweight='bold', y=1.02)
    plt.tight_layout()
    fig.savefig(os.path.join(outdir, 'fig8_cloud_vs_isp.png'))
    plt.close(fig)


# =============================================================================
# Main
# =============================================================================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', required=True, help='Path to collisions.json')
    parser.add_argument('-o', '--outdir', default='figures', help='Output directory')
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    data = load(args.file)
    p = prep(data)

    log(f"\nGenerating figures → {args.outdir}/\n")

    fig1_cluster_size_dist(p, args.outdir)
    fig2_port_heatmap(p, args.outdir)
    fig3_reuse_classification(p, args.outdir)
    fig4_asn_landscape(p, args.outdir)
    fig5_asn_diversity(p, args.outdir)
    fig6_port_prevalence(p, args.outdir)
    fig7_cluster_composition(p, args.outdir)
    fig8_cloud_vs_isp(p, args.outdir)

    log(f"\n{'='*50}")
    log(f"✅ All figures saved to {args.outdir}/")
    log(f"{'='*50}")
    for f in sorted(os.listdir(args.outdir)):
        sz = os.path.getsize(os.path.join(args.outdir, f))
        log(f"  {f:45s} {sz/1024:.0f} KB")


if __name__ == '__main__':
    main()