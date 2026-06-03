#!/usr/bin/python3

# RC4 Analysis Visualization Script
# Generates publication-ready graphs for RC4 findings
# Uses data from rc4_analysis.json, rc4_crossref.json, software_fingerprint.json, rc4_providers.txt
#
# Requires: pip3 install matplotlib numpy
# Usage: python3 rc4_graphs.py --rc4 rc4_analysis.json --crossref rc4_crossref.json --software software_fingerprint.json --providers rc4_providers.txt --outdir rc4_charts

import json
import argparse
import os
import collections

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

parser = argparse.ArgumentParser(description='Generate RC4 analysis charts')
parser.add_argument('--rc4', default='rc4_analysis.json')
parser.add_argument('--crossref', default='rc4_crossref.json')
parser.add_argument('--software', default='software_fingerprint.json')
parser.add_argument('--providers', default='rc4_providers.txt')
parser.add_argument('--outdir', default='rc4_charts')
args = parser.parse_args()

os.makedirs(args.outdir, exist_ok=True)

# Load data
print("Loading data...")
with open(args.rc4) as f:
    rc4 = json.load(f)

crossref = None
try:
    with open(args.crossref) as f:
        crossref = json.load(f)
    print("  Loaded crossref data")
except FileNotFoundError:
    print("  No crossref data found, skipping neglect charts")

software = None
try:
    with open(args.software) as f:
        software = json.load(f)
    print("  Loaded software data")
except FileNotFoundError:
    print("  No software data found, skipping software charts")

# Load provider data
provider_counts = collections.Counter()
try:
    with open(args.providers) as f:
        for line in f:
            line = line.strip()
            if ',' in line and not line.startswith('IP'):
                parts = line.split(',', 1)
                if len(parts) == 2:
                    provider = parts[1].strip()
                    if provider and provider != 'Unknown':
                        provider_counts[provider] += 1
    print(f"  Loaded provider data: {sum(provider_counts.values())} IPs")
except FileNotFoundError:
    print("  No provider data found, skipping provider charts")

chart_num = 0

def save(fig, name):
    global chart_num
    chart_num += 1
    path = os.path.join(args.outdir, f'{chart_num:02d}_{name}.png')
    fig.savefig(path, dpi=200, bbox_inches='tight')
    plt.close(fig)
    print(f"  [{chart_num:02d}] {name}.png")

print("\nGenerating RC4 charts...")

# ══════════════════════════════════════════════════════════════════════════════
# 1. RC4 Prevalence - Context Bar
# ══════════════════════════════════════════════════════════════════════════════
fig, ax = plt.subplots(figsize=(8, 5))
total = rc4['total_ips_scanned']
rc4_count = rc4['rc4_servers']
non_rc4 = total - rc4_count

ax.barh(['Non-RC4', 'RC4'], [non_rc4, rc4_count],
        color=['#2ecc71', '#e74c3c'], edgecolor='white', height=0.5)
ax.text(non_rc4 + 100, 0, f'{non_rc4:,} ({non_rc4/total*100:.1f}%)',
        va='center', fontsize=11)
ax.text(rc4_count + 100, 1, f'{rc4_count} ({rc4["rc4_rate"]}%)',
        va='center', fontsize=11, fontweight='bold', color='#c0392b')
ax.set_xlabel('Number of Mail Servers')
ax.set_title(f'RC4 Cipher Usage Among Irish Mail Servers (n={total:,})\n'
             f'RFC 7465 deprecated RC4 in February 2015 — 11 years ago')
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
save(fig, 'rc4_prevalence')

# ══════════════════════════════════════════════════════════════════════════════
# 2. RC4 by Port
# ══════════════════════════════════════════════════════════════════════════════
fig, ax = plt.subplots(figsize=(8, 5))
port_labels = []
port_counts = []
port_map = {'p25': 'P25 SMTP', 'p587': 'P587 Submission',
            'p110': 'P110 POP3', 'p143': 'P143 IMAP', 'p993': 'P993 IMAPS'}

for port in ['p25', 'p587', 'p110', 'p143', 'p993']:
    count = rc4['by_port'][port]['rc4_count']
    if count > 0:
        port_labels.append(port_map[port])
        port_counts.append(count)

bars = ax.bar(port_labels, port_counts, color='#e74c3c', edgecolor='white', width=0.5)
for bar, count in zip(bars, port_counts):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
            str(count), ha='center', fontsize=11, fontweight='bold')
ax.set_ylabel('Number of Servers')
ax.set_title('RC4 Servers by Port')
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
save(fig, 'rc4_by_port')

# ══════════════════════════════════════════════════════════════════════════════
# 3. RC4 Cipher Suites Found
# ══════════════════════════════════════════════════════════════════════════════
fig, ax = plt.subplots(figsize=(10, 4))
ciphers = list(rc4['by_cipher'].keys())
cipher_counts = list(rc4['by_cipher'].values())
cipher_short = [c.replace('TLS_', '') for c in ciphers]

bars = ax.barh(cipher_short[::-1], cipher_counts[::-1],
               color='#e74c3c', edgecolor='white', height=0.4)
for bar, count in zip(bars, cipher_counts[::-1]):
    ax.text(bar.get_width() + 5, bar.get_y() + bar.get_height()/2,
            str(count), va='center', fontsize=11, fontweight='bold')
ax.set_xlabel('Occurrences Across All Ports')
ax.set_title('RC4 Cipher Suites Found\n(Both deprecated by RFC 7465, Feb 2015)')
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
save(fig, 'rc4_cipher_suites')

# ══════════════════════════════════════════════════════════════════════════════
# 4. RC4 Multi-Port vs Single-Port
# ══════════════════════════════════════════════════════════════════════════════
fig, ax = plt.subplots(figsize=(7, 5))
multi = rc4['summary']['multi_port_rc4_servers']
single = rc4['rc4_servers'] - multi

bars = ax.bar(['RC4 on ALL 5 ports', 'RC4 on some ports'],
              [multi, single],
              color=['#c0392b', '#e74c3c'], edgecolor='white', width=0.4)
for bar, count in zip(bars, [multi, single]):
    pct = count / rc4['rc4_servers'] * 100
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
            f'{count} ({pct:.0f}%)', ha='center', fontsize=11, fontweight='bold')
ax.set_ylabel('Number of Servers')
ax.set_title(f'RC4 Port Coverage (n={rc4["rc4_servers"]})\n'
             f'{multi} servers use RC4 on every single mail port')
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
save(fig, 'rc4_multi_port')

# ══════════════════════════════════════════════════════════════════════════════
# 5. RC4 by Provider (from whois)
# ══════════════════════════════════════════════════════════════════════════════
if provider_counts:
    fig, ax = plt.subplots(figsize=(10, 6))
    # Group small providers
    top_providers = provider_counts.most_common(10)
    other_count = sum(provider_counts.values()) - sum(c for _, c in top_providers)
    
    names = [p[:30] for p, _ in top_providers]
    counts = [c for _, c in top_providers]
    if other_count > 0:
        names.append('Other')
        counts.append(other_count)
    
    bars = ax.barh(names[::-1], counts[::-1], color='#e74c3c', edgecolor='white')
    for bar, count in zip(bars, counts[::-1]):
        ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height()/2,
                str(count), va='center', fontsize=10)
    ax.set_xlabel('Number of RC4 Servers')
    ax.set_title('RC4 Servers by Hosting Provider / ASN\n(from whois lookup)')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    save(fig, 'rc4_by_provider')

# ══════════════════════════════════════════════════════════════════════════════
# 6. RC4 by Software Type
# ══════════════════════════════════════════════════════════════════════════════
if software:
    fig, ax = plt.subplots(figsize=(9, 5))
    hc = software['health_comparison']
    sw_rc4 = []
    for sw_name, data in sorted(hc.items(), key=lambda x: x[1]['total'], reverse=True):
        if data['total'] >= 10 and data['rc4_pct'] > 0:
            sw_rc4.append((sw_name, data['rc4_pct'], data['total']))
    
    if sw_rc4:
        sw_rc4.sort(key=lambda x: x[1], reverse=True)
        names = [s[0] for s in sw_rc4]
        pcts = [s[1] for s in sw_rc4]
        totals = [s[2] for s in sw_rc4]
        
        colors = ['#c0392b' if p > 10 else '#e74c3c' if p > 2 else '#e67e22' for p in pcts]
        bars = ax.bar(names, pcts, color=colors, edgecolor='white', width=0.5)
        for bar, pct, total in zip(bars, pcts, totals):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
                    f'{pct}%\n(n={total})', ha='center', fontsize=9)
        ax.set_ylabel('RC4 Usage Rate (%)')
        ax.set_title('RC4 Usage by Mail Server Software\nSendmail stands out at 15.3%')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        plt.xticks(rotation=15, ha='right')
        save(fig, 'rc4_by_software')

# ══════════════════════════════════════════════════════════════════════════════
# 7. Neglect Score Distribution
# ══════════════════════════════════════════════════════════════════════════════
if crossref:
    fig, ax = plt.subplots(figsize=(9, 5))
    ni = crossref['summary']['neglect_indicators']
    score_dist = crossref['summary']['neglect_score_distribution']
    
    scores = sorted(score_dist.keys(), key=lambda x: int(x))
    counts = [score_dist[s] for s in scores]
    labels_map = {
        '0': 'Score 0\nRC4 only\n(maintained)',
        '1': 'Score 1\nOne other\nissue',
        '2': 'Score 2\nTwo other\nissues',
        '3': 'Score 3\nFully\nneglected'
    }
    labels = [labels_map.get(s, f'Score {s}') for s in scores]
    colors = ['#f39c12', '#e67e22', '#e74c3c', '#c0392b']
    
    bars = ax.bar(labels, counts, color=colors[:len(scores)], edgecolor='white', width=0.5)
    for bar, count in zip(bars, counts):
        pct = count / sum(counts) * 100
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
                f'{count}\n({pct:.0f}%)', ha='center', fontsize=10, fontweight='bold')
    ax.set_ylabel('Number of RC4 Servers')
    ax.set_title('RC4 Server Neglect Score Distribution (n=179)\n'
                 'Score 0 = valid cert + modern TLS (but still RC4)\n'
                 'Score 3 = expired cert + legacy TLS + self-signed')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    save(fig, 'rc4_neglect_scores')

# ══════════════════════════════════════════════════════════════════════════════
# 8. Neglect Indicators Breakdown
# ══════════════════════════════════════════════════════════════════════════════
if crossref:
    fig, ax = plt.subplots(figsize=(9, 5))
    ni = crossref['summary']['neglect_indicators']
    total_rc4 = crossref['summary']['total_rc4_servers_analysed']
    
    indicators = ['Expired\nCert', 'Self-\nSigned', 'Legacy\nTLS', 'Expired +\nLegacy TLS',
                  'Triple\nNeglect', 'Otherwise\nHealthy']
    counts = [ni['expired_cert'], ni['self_signed'], ni['legacy_tls'],
              ni['expired_and_legacy'], ni['triple_neglect'], ni['all_fine_except_rc4']]
    colors = ['#e74c3c', '#f39c12', '#e67e22', '#c0392b', '#922b21', '#27ae60']
    
    bars = ax.bar(indicators, counts, color=colors, edgecolor='white', width=0.55)
    for bar, count in zip(bars, counts):
        pct = count / total_rc4 * 100
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
                f'{count}\n({pct:.0f}%)', ha='center', fontsize=9, fontweight='bold')
    ax.set_ylabel('Number of RC4 Servers')
    ax.set_title(f'What Else is Wrong with RC4 Servers? (n={total_rc4})\n'
                 f'68% also have expired certificates — indicating abandoned infrastructure')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    save(fig, 'rc4_neglect_indicators')

# ══════════════════════════════════════════════════════════════════════════════
# 9. Expiry Age of RC4 Server Certificates
# ══════════════════════════════════════════════════════════════════════════════
if crossref:
    fig, ax = plt.subplots(figsize=(8, 5))
    ea = crossref['summary'].get('days_expired_distribution', {})
    if ea:
        ea_labels = list(ea.keys())
        ea_counts = list(ea.values())
        colors = ['#f1c40f', '#e67e22', '#e74c3c', '#922b21']
        
        bars = ax.bar(ea_labels, ea_counts, color=colors[:len(ea_labels)],
                      edgecolor='white', width=0.5)
        for bar, count in zip(bars, ea_counts):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                    str(count), ha='center', fontsize=11, fontweight='bold')
        ax.set_ylabel('Number of RC4 Servers')
        ax.set_title('How Long Have RC4 Server Certificates Been Expired?\n'
                     '101 servers have certs expired for over 2 years')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        save(fig, 'rc4_expiry_age')

# ══════════════════════════════════════════════════════════════════════════════
# 10. RC4 Two Populations Comparison
# ══════════════════════════════════════════════════════════════════════════════
if crossref:
    fig, ax = plt.subplots(figsize=(9, 6))
    ni = crossref['summary']['neglect_indicators']
    total_rc4 = crossref['summary']['total_rc4_servers_analysed']
    
    neglected = total_rc4 - ni['all_fine_except_rc4']
    maintained = ni['all_fine_except_rc4']
    
    categories = ['Neglected Infrastructure\n(expired certs, legacy TLS)',
                  'Maintained but Misconfigured\n(valid certs, modern TLS)']
    counts = [neglected, maintained]
    colors = ['#e74c3c', '#3498db']
    
    bars = ax.bar(categories, counts, color=colors, edgecolor='white', width=0.45)
    for bar, count in zip(bars, counts):
        pct = count / total_rc4 * 100
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
                f'{count} servers\n({pct:.0f}%)', ha='center', fontsize=12, fontweight='bold')
    
    ax.set_ylabel('Number of Servers')
    ax.set_title('Why Are 179 Irish Mail Servers Still Using RC4?\nTwo Distinct Failure Modes Identified')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    # Add explanation text
    ax.text(0, -0.15, 'These servers have not been touched in years.\n'
            'Nobody is maintaining them.',
            transform=ax.transAxes, fontsize=9, color='#e74c3c', ha='left', va='top')
    ax.text(1, -0.15, 'These servers are actively maintained but\n'
            'RC4 was never removed from the config.',
            transform=ax.transAxes, fontsize=9, color='#3498db', ha='right', va='top')
    
    plt.subplots_adjust(bottom=0.22)
    save(fig, 'rc4_two_populations')

# ══════════════════════════════════════════════════════════════════════════════
# 11. RC4 Port Heatmap
# ══════════════════════════════════════════════════════════════════════════════
fig, ax = plt.subplots(figsize=(8, 4))
ports = ['p25', 'p110', 'p143', 'p587', 'p993']
port_names = ['P25\nSMTP', 'P110\nPOP3', 'P143\nIMAP', 'P587\nSubmission', 'P993\nIMAPS']

# Build cipher x port matrix
cipher_names = list(rc4['by_cipher'].keys())
cipher_short = [c.replace('TLS_', '').replace('_WITH_', '\n') for c in cipher_names]
data_matrix = []

for cipher in cipher_names:
    row = []
    for port in ports:
        port_ciphers = rc4['by_port'][port].get('rc4_ciphers', {})
        row.append(port_ciphers.get(cipher, 0))
    data_matrix.append(row)

data_matrix = np.array(data_matrix)
im = ax.imshow(data_matrix, cmap='Reds', aspect='auto')

ax.set_xticks(range(len(ports)))
ax.set_xticklabels(port_names, fontsize=9)
ax.set_yticks(range(len(cipher_names)))
ax.set_yticklabels(cipher_short, fontsize=9)

# Add count text in each cell
for i in range(len(cipher_names)):
    for j in range(len(ports)):
        val = data_matrix[i, j]
        color = 'white' if val > 50 else 'black'
        ax.text(j, i, str(int(val)), ha='center', va='center',
                fontsize=11, fontweight='bold', color=color)

ax.set_title('RC4 Cipher Suite Usage by Port (Heatmap)')
fig.colorbar(im, ax=ax, label='Server Count', shrink=0.8)
save(fig, 'rc4_port_heatmap')

# ══════════════════════════════════════════════════════════════════════════════
# 12. Timeline: RC4 Deprecation Context
# ══════════════════════════════════════════════════════════════════════════════
fig, ax = plt.subplots(figsize=(12, 4))

events = [
    (2013, 'RC4 attacks\npublished', '#e67e22'),
    (2015, 'RFC 7465\nRC4 banned', '#e74c3c'),
    (2018, 'Farrell survey\n(no RC4 analysis)', '#3498db'),
    (2020, 'TLS 1.0/1.1\ndeprecated', '#f39c12'),
    (2026, f'This study:\n179 RC4 servers\nstill active', '#c0392b'),
]

years = [e[0] for e in events]
labels = [e[1] for e in events]
colors = [e[2] for e in events]

ax.plot([2012, 2027], [0, 0], color='#bdc3c7', linewidth=2, zorder=1)

for year, label, color in events:
    ax.scatter(year, 0, s=150, color=color, zorder=3, edgecolor='white', linewidth=2)
    offset = 0.4 if events.index((year, label, color)) % 2 == 0 else -0.5
    ax.annotate(label, (year, 0), xytext=(0, 40 if offset > 0 else -55),
                textcoords='offset points', ha='center', fontsize=9,
                fontweight='bold', color=color,
                arrowprops=dict(arrowstyle='->', color=color, lw=1.5))

ax.set_xlim(2012, 2027.5)
ax.set_ylim(-1.2, 1.2)
ax.set_xlabel('Year')
ax.set_title('RC4 Deprecation Timeline: 11 Years and Still Counting')
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.spines['left'].set_visible(False)
ax.yaxis.set_visible(False)
save(fig, 'rc4_timeline')

# ══════════════════════════════════════════════════════════════════════════════
# 13. RC4 vs Non-RC4 Certificate Health Comparison
# ══════════════════════════════════════════════════════════════════════════════
if crossref:
    fig, ax = plt.subplots(figsize=(9, 5))
    ni = crossref['summary']['neglect_indicators']
    total_rc4 = crossref['summary']['total_rc4_servers_analysed']
    
    # RC4 server stats
    rc4_expired_pct = ni['expired_cert'] / total_rc4 * 100
    rc4_ss_pct = ni['self_signed'] / total_rc4 * 100
    rc4_legacy_pct = ni['legacy_tls'] / total_rc4 * 100
    
    # Overall stats (from total scan: 19720 IPs, 5217 expired, 7491 self-signed, 188 legacy)
    total_all = 19720
    all_expired_pct = 5217 / total_all * 100
    all_ss_pct = 7491 / total_all * 100
    all_legacy_pct = 188 / total_all * 100
    
    categories = ['Expired\nCertificate', 'Self-Signed\nCertificate', 'Legacy TLS\n(1.0/1.1)']
    rc4_pcts = [rc4_expired_pct, rc4_ss_pct, rc4_legacy_pct]
    all_pcts = [all_expired_pct, all_ss_pct, all_legacy_pct]
    
    x = np.arange(len(categories))
    w = 0.3
    
    bars1 = ax.bar(x - w/2, all_pcts, w, label='All Servers (n=19,720)',
                   color='#3498db', edgecolor='white')
    bars2 = ax.bar(x + w/2, rc4_pcts, w, label='RC4 Servers (n=179)',
                   color='#e74c3c', edgecolor='white')
    
    for bar, pct in zip(bars1, all_pcts):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                f'{pct:.1f}%', ha='center', fontsize=9)
    for bar, pct in zip(bars2, rc4_pcts):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                f'{pct:.1f}%', ha='center', fontsize=9, fontweight='bold', color='#c0392b')
    
    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    ax.set_ylabel('Percentage of Servers')
    ax.set_title('RC4 Servers vs All Servers: Certificate Health Comparison\n'
                 'RC4 servers have significantly worse certificate hygiene')
    ax.legend()
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    save(fig, 'rc4_vs_all_health')

print(f"\nDone! {chart_num} charts saved to {args.outdir}/")
print(f"\nCharts generated:")
print(f"  01 - RC4 prevalence (179 of 19,720)")
print(f"  02 - RC4 by port")
print(f"  03 - RC4 cipher suites found")
print(f"  04 - RC4 multi-port vs single-port")
print(f"  05 - RC4 by hosting provider (whois)")
print(f"  06 - RC4 by mail server software")
print(f"  07 - Neglect score distribution")
print(f"  08 - Neglect indicators breakdown")
print(f"  09 - Expiry age of RC4 server certs")
print(f"  10 - Two populations: neglected vs maintained")
print(f"  11 - RC4 cipher x port heatmap")
print(f"  12 - RC4 deprecation timeline")
print(f"  13 - RC4 vs all servers health comparison")