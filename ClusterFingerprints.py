#!/usr/bin/env python3
"""
ClusterFingerprints.py
Novel visualization: encodes each cluster's properties into a compact
radial glyph ("fingerprint"). All 712 clusters rendered on a single page
for pattern discovery and comparison.

Each fingerprint encodes 7 dimensions:
  - Spoke 1: Cluster size (normalized)
  - Spoke 2: Graph density
  - Spoke 3: ASN diversity (number of unique ASNs)
  - Spoke 4: Cross-ASN reuse percentage
  - Spoke 5: Port diversity (how many different ports involved)
  - Spoke 6: Dominant protocol ratio (web vs mail vs ssh)
  - Spoke 7: Hub dominance (max degree / avg degree)

The shape of each glyph reveals the cluster's character at a glance.
Similar-looking fingerprints = similar reuse patterns.

Outputs:
  - fingerprint_landscape.png  — ALL clusters on one page, grouped by similarity
  - fingerprint_detail_{N}.png — Larger detailed fingerprints for selected clusters
  - fingerprint_legend.png     — Explains how to read the glyphs

Usage:
    python3 ClusterFingerprints.py -f collisions.json -o fingerprints/
    python3 ClusterFingerprints.py -f collisions.json -o fingerprints/ --detail 19 70 477 716
"""

import argparse, json, re, os, sys, time, math
from collections import Counter, defaultdict
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch
import numpy as np

def log(msg):
    print(msg, file=sys.stderr, flush=True)

# =============================================================================
# Style
# =============================================================================
plt.rcParams.update({
    'figure.facecolor': 'white', 'axes.facecolor': 'white',
    'font.family': 'serif', 'font.size': 10,
    'savefig.dpi': 300, 'savefig.bbox': 'tight', 'savefig.pad_inches': 0.3,
})

SPOKE_COLORS = ['#2171B5', '#CB181D', '#238B45', '#D94701', '#6A51A3', '#006D75', '#CE1256']
SPOKE_LABELS = ['Size', 'Density', 'ASN\nDiversity', 'Cross-ASN\n%', 'Port\nDiversity',
                'Protocol\nMix', 'Hub\nDominance']

CATEGORY_COLORS = {
    'web_single': '#2171B5',
    'web_multi': '#6BAED6',
    'mail_single': '#CB181D',
    'mail_multi': '#FB6A4A',
    'mixed_single': '#238B45',
    'mixed_multi': '#74C476',
    'ssh': '#D94701',
    'other': '#969696',
}

CATEGORY_LABELS = {
    'web_single': 'Web-only, Single ASN',
    'web_multi': 'Web-only, Multi ASN',
    'mail_single': 'Mail-only, Single ASN',
    'mail_multi': 'Mail-only, Multi ASN',
    'mixed_single': 'Mixed Protocol, Single ASN',
    'mixed_multi': 'Mixed Protocol, Multi ASN',
    'ssh': 'SSH-involved',
    'other': 'Other',
}


# =============================================================================
# Data loading + feature extraction
# =============================================================================
def load_and_extract(path):
    log(f"Loading {path}...")
    t0 = time.time()
    with open(path) as f:
        data = json.load(f)
    log(f"  {len(data)} entries in {time.time()-t0:.1f}s")

    log("  Extracting cluster features...")
    clusters = defaultdict(lambda: {
        'ips': set(), 'asns': set(), 'size': 0,
        'fprint_ports': set(), 'edges': 0, 'edge_pairs': Counter(),
        'degrees': Counter(),
    })

    mail_ports = {'p25', 'p587', 'p110', 'p143', 'p993'}

    for e in data:
        cn = e.get('clusternum', -1)
        ip = e.get('ip', '')
        asn = e.get('asn', '?')
        clusters[cn]['ips'].add(ip)
        clusters[cn]['asns'].add(asn)
        clusters[cn]['size'] = e.get('csize', 0)
        for p in e.get('fprints', {}):
            clusters[cn]['fprint_ports'].add(p)

        rcs = e.get('rcs', {})
        clusters[cn]['degrees'][ip] += len(rcs)
        for _, rc in rcs.items():
            pairs = re.findall(r'(p\d+)==(p\d+)', rc.get('str_colls', ''))
            for p1, p2 in pairs:
                clusters[cn]['edge_pairs'][f'{p1}-{p2}'] += 1
            clusters[cn]['edges'] += len(pairs)

    # Compute 7 features per cluster (all normalized 0-1)
    features = {}
    all_sizes = [c['size'] for c in clusters.values()]
    max_size = max(all_sizes) if all_sizes else 1
    log_max_size = math.log10(max(max_size, 2))

    for cn, c in clusters.items():
        n = c['size']
        if n < 2:
            continue

        n_asns = len(c['asns'])
        n_ports = len(c['fprint_ports'])
        edge_count = c['edges']

        # Density: for undirected graph, density = 2E / (N*(N-1))
        max_edges = n * (n - 1) / 2
        density = min(edge_count / max(max_edges, 1), 1.0)

        # Cross-ASN percentage (estimated from ASN diversity)
        cross_asn_pct = min((n_asns - 1) / max(n - 1, 1), 1.0) if n_asns > 1 else 0.0

        # Port diversity (out of 7 possible ports)
        port_div = n_ports / 7.0

        # Protocol mix: ratio of non-dominant protocol
        has_web = 'p443' in c['fprint_ports']
        has_mail = bool(c['fprint_ports'] & mail_ports)
        has_ssh = 'p22' in c['fprint_ports']
        proto_count = sum([has_web, has_mail, has_ssh])
        proto_mix = min(proto_count / 3.0, 1.0)

        # Hub dominance: max_degree / avg_degree
        degs = list(c['degrees'].values())
        if degs and len(degs) > 1:
            avg_deg = sum(degs) / len(degs)
            max_deg = max(degs)
            hub_dom = min((max_deg / max(avg_deg, 1)) / 5.0, 1.0)  # normalized, cap at 5x
        else:
            hub_dom = 0.0

        # Categorize
        if has_ssh:
            cat = 'ssh'
        elif has_web and has_mail:
            cat = 'mixed_multi' if n_asns > 1 else 'mixed_single'
        elif has_web:
            cat = 'web_multi' if n_asns > 1 else 'web_single'
        elif has_mail:
            cat = 'mail_multi' if n_asns > 1 else 'mail_single'
        else:
            cat = 'other'

        features[cn] = {
            'values': [
                math.log10(max(n, 2)) / log_max_size,  # size (log normalized)
                density,
                min(n_asns / 10.0, 1.0),  # ASN diversity (cap at 10)
                cross_asn_pct,
                port_div,
                proto_mix,
                hub_dom,
            ],
            'size': n,
            'category': cat,
            'label': f'C{cn}',
            'n_asns': n_asns,
            'n_ports': n_ports,
        }

    log(f"  {len(features)} clusters with features extracted")
    return features


# =============================================================================
# Draw a single fingerprint glyph
# =============================================================================
def draw_fingerprint(ax, values, color, label='', size_text='', alpha=0.7, show_spokes=False):
    """
    Draw a radial fingerprint glyph on the given axes.
    values: list of 7 floats in [0, 1]
    """
    n_spokes = len(values)
    angles = np.linspace(0, 2 * np.pi, n_spokes, endpoint=False).tolist()
    angles.append(angles[0])  # close the polygon
    vals = values + [values[0]]

    # Background circle
    theta = np.linspace(0, 2 * np.pi, 100)
    ax.plot(np.cos(theta), np.sin(theta), color='#E0E0E0', linewidth=0.5, alpha=0.5)
    ax.plot(0.5 * np.cos(theta), 0.5 * np.sin(theta), color='#E0E0E0', linewidth=0.3, alpha=0.3)

    # Spoke lines
    if show_spokes:
        for i, angle in enumerate(angles[:-1]):
            ax.plot([0, np.cos(angle)], [0, np.sin(angle)],
                    color='#CCCCCC', linewidth=0.5, alpha=0.5)

    # Filled polygon
    xs = [v * np.cos(a) for v, a in zip(vals, angles)]
    ys = [v * np.sin(a) for v, a in zip(vals, angles)]
    ax.fill(xs, ys, color=color, alpha=alpha * 0.4)
    ax.plot(xs, ys, color=color, linewidth=1.5, alpha=alpha)

    # Dots at vertices
    for i in range(n_spokes):
        x = vals[i] * np.cos(angles[i])
        y = vals[i] * np.sin(angles[i])
        ax.plot(x, y, 'o', color=color, markersize=3, alpha=alpha)

    # Labels
    if label:
        ax.text(0, -1.35, label, ha='center', va='center', fontsize=6,
                fontweight='bold', color='#333333', family='monospace')
    if size_text:
        ax.text(0, -1.55, size_text, ha='center', va='center', fontsize=5,
                color='#777777', family='monospace')

    ax.set_xlim(-1.7, 1.7)
    ax.set_ylim(-1.7, 1.7)
    ax.set_aspect('equal')
    ax.axis('off')


# =============================================================================
# Figure 1: Individual fingerprint PNGs — one per cluster
# =============================================================================
def generate_landscape(features, outdir):
    log("  Generating individual fingerprint PNGs...")

    # Create subfolder
    indiv_dir = os.path.join(outdir, 'individual')
    os.makedirs(indiv_dir, exist_ok=True)

    total = len(features)
    for i, (cn, feat) in enumerate(sorted(features.items(), key=lambda x: -x[1]['size'])):
        cat_label = CATEGORY_LABELS.get(feat['category'], feat['category'])
        cat_color = CATEGORY_COLORS.get(feat['category'], '#969696')

        fig, ax = plt.subplots(figsize=(5, 5.5))
        draw_fingerprint(ax, feat['values'], cat_color, show_spokes=True, alpha=0.9)

        # Spoke labels with values
        n_spokes = 7
        angles = np.linspace(0, 2 * np.pi, n_spokes, endpoint=False)
        for j, angle in enumerate(angles):
            x = 1.45 * np.cos(angle)
            y = 1.45 * np.sin(angle)
            ax.text(x, y, f'{SPOKE_LABELS[j]}\n{feat["values"][j]:.2f}',
                    ha='center', va='center', fontsize=7,
                    color=SPOKE_COLORS[j], fontweight='bold')

        ax.set_title(f'Cluster {cn} — {feat["size"]} hosts, {feat["n_asns"]} ASNs\n{cat_label}',
                     fontsize=11, fontweight='bold', color=cat_color, pad=20)

        plt.tight_layout()
        path = os.path.join(indiv_dir, f'fingerprint_C{cn}.png')
        fig.savefig(path)
        plt.close(fig)

        if (i + 1) % 100 == 0:
            log(f"    {i+1}/{total} done...")

    log(f"    ✓ {total} individual fingerprints → {indiv_dir}/")

    # Also generate the category overview (average fingerprint per category)
    log("    Generating category overview...")
    by_cat = defaultdict(list)
    for cn, feat in features.items():
        by_cat[feat['category']].append((cn, feat))

    cats_used = sorted(by_cat.keys(), key=lambda c: -len(by_cat[c]))
    n_cats = len(cats_used)
    fig, axes = plt.subplots(1, n_cats, figsize=(3.5 * n_cats, 4.5))
    if n_cats == 1:
        axes = [axes]

    for i, cat in enumerate(cats_used):
        members = by_cat[cat]
        cat_label = CATEGORY_LABELS.get(cat, cat)
        cat_color = CATEGORY_COLORS.get(cat, '#969696')

        avg_vals = [0.0] * 7
        for _, feat in members:
            for j in range(7):
                avg_vals[j] += feat['values'][j]
        avg_vals = [v / len(members) for v in avg_vals]

        draw_fingerprint(axes[i], avg_vals, cat_color, show_spokes=True, alpha=0.9)
        axes[i].set_title(f'{cat_label}\n({len(members)} clusters)',
                          fontsize=9, fontweight='bold', color=cat_color, pad=15)

        # Spoke labels on first glyph
        if i == 0:
            n_spokes = 7
            angles = np.linspace(0, 2 * np.pi, n_spokes, endpoint=False)
            for j, angle in enumerate(angles):
                x = 1.45 * np.cos(angle)
                y = 1.45 * np.sin(angle)
                axes[i].text(x, y, SPOKE_LABELS[j], ha='center', va='center',
                             fontsize=5, color=SPOKE_COLORS[j], fontweight='bold')

    fig.suptitle('Average Fingerprint by Category — Key Reuse Cluster Archetypes',
                 fontsize=13, fontweight='bold', y=1.05)
    plt.tight_layout()
    path = os.path.join(outdir, 'landscape_overview.png')
    fig.savefig(path)
    plt.close(fig)
    log(f"    ✓ {path}")


# =============================================================================
# Figure 2: Legend / How to read the fingerprints
# =============================================================================
def generate_legend(outdir):
    log("  Generating legend...")

    fig, axes = plt.subplots(1, 4, figsize=(16, 4.5))

    # Example 1: Large, dense, single-ASN, web-only
    vals1 = [0.9, 0.8, 0.1, 0.0, 0.15, 0.33, 0.3]
    draw_fingerprint(axes[0], vals1, '#2171B5', show_spokes=True)
    axes[0].set_title('Large, Dense\nSingle-ASN, Web-only', fontsize=9, fontweight='bold', pad=15)
    # Add spoke labels
    n_spokes = 7
    angles = np.linspace(0, 2 * np.pi, n_spokes, endpoint=False)
    for i, angle in enumerate(angles):
        x = 1.3 * np.cos(angle)
        y = 1.3 * np.sin(angle)
        axes[0].text(x, y, SPOKE_LABELS[i], ha='center', va='center',
                     fontsize=5, color=SPOKE_COLORS[i], fontweight='bold')

    # Example 2: Small, sparse, multi-ASN, mixed
    vals2 = [0.2, 0.2, 0.7, 0.8, 0.7, 0.9, 0.1]
    draw_fingerprint(axes[1], vals2, '#238B45', show_spokes=True)
    axes[1].set_title('Small, Sparse\nMulti-ASN, Mixed', fontsize=9, fontweight='bold', pad=15)

    # Example 3: Medium, hub-dominated
    vals3 = [0.5, 0.3, 0.3, 0.2, 0.3, 0.33, 0.95]
    draw_fingerprint(axes[2], vals3, '#D94701', show_spokes=True)
    axes[2].set_title('Medium, Hub-Dominated\nStar Topology', fontsize=9, fontweight='bold', pad=15)

    # Example 4: Uniform — all spokes equal
    vals4 = [0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5]
    draw_fingerprint(axes[3], vals4, '#6A51A3', show_spokes=True)
    axes[3].set_title('Uniform Profile\n(Balanced Cluster)', fontsize=9, fontweight='bold', pad=15)

    fig.suptitle('How to Read Cluster Fingerprints — 7 Dimensions Encoded as Radial Glyphs',
                 fontsize=13, fontweight='bold', y=1.05)

    # Spoke explanation text
    fig.text(0.5, -0.08,
             'Each spoke represents a normalized metric (0 = center, 1 = edge):\n'
             'Size (log) · Density · ASN Diversity · Cross-ASN % · Port Diversity · Protocol Mix · Hub Dominance',
             ha='center', fontsize=9, color='#555555', family='serif', style='italic')

    plt.tight_layout()
    path = os.path.join(outdir, 'fingerprint_legend.png')
    fig.savefig(path)
    plt.close(fig)
    log(f"    ✓ {path}")


# =============================================================================
# Figure 3: Detailed fingerprints for selected clusters
# =============================================================================
def generate_detail(features, cluster_nums, outdir):
    log(f"  Generating detail fingerprints for {cluster_nums}...")

    n = len(cluster_nums)
    ncols = min(n, 4)
    nrows = math.ceil(n / ncols)

    fig, axes = plt.subplots(nrows, ncols, figsize=(4.5 * ncols, 5 * nrows))
    if n == 1:
        axes = np.array([axes])
    axes_flat = np.array(axes).flatten()

    for idx, cn in enumerate(cluster_nums):
        ax = axes_flat[idx]
        if cn not in features:
            ax.text(0.5, 0.5, f'Cluster {cn}\nnot found', ha='center', va='center',
                    transform=ax.transAxes, fontsize=10, color='#999999')
            ax.axis('off')
            continue

        feat = features[cn]
        color = CATEGORY_COLORS.get(feat['category'], '#969696')
        draw_fingerprint(ax, feat['values'], color, show_spokes=True, alpha=0.9)

        # Spoke labels with values
        n_spokes = 7
        angles = np.linspace(0, 2 * np.pi, n_spokes, endpoint=False)
        for i, angle in enumerate(angles):
            x = 1.45 * np.cos(angle)
            y = 1.45 * np.sin(angle)
            val_text = f'{feat["values"][i]:.2f}'
            ax.text(x, y, f'{SPOKE_LABELS[i]}\n{val_text}', ha='center', va='center',
                    fontsize=6, color=SPOKE_COLORS[i], fontweight='bold')

        cat_label = CATEGORY_LABELS.get(feat['category'], feat['category'])
        ax.set_title(f'Cluster {cn} — {feat["size"]} hosts, {feat["n_asns"]} ASNs\n{cat_label}',
                     fontsize=10, fontweight='bold', pad=20)

    for idx in range(len(cluster_nums), len(axes_flat)):
        axes_flat[idx].axis('off')

    fig.suptitle('Cluster Fingerprint Detail View',
                 fontsize=14, fontweight='bold', y=1.02)
    plt.tight_layout()
    path = os.path.join(outdir, 'fingerprint_detail.png')
    fig.savefig(path)
    plt.close(fig)
    log(f"    ✓ {path}")


# =============================================================================
# Figure 4: Fingerprint similarity matrix — which clusters look alike?
# =============================================================================
def generate_similarity(features, outdir):
    log("  Generating similarity analysis...")

    # Get feature vectors
    cnums = sorted(features.keys())
    vectors = np.array([features[cn]['values'] for cn in cnums])
    cats = [features[cn]['category'] for cn in cnums]

    # Compute pairwise euclidean distance
    from scipy.spatial.distance import pdist, squareform
    try:
        dists = squareform(pdist(vectors, 'euclidean'))
    except ImportError:
        log("    scipy not installed, skipping similarity matrix")
        return

    # Sort by category for block structure
    sorted_idx = sorted(range(len(cnums)), key=lambda i: (cats[i], -features[cnums[i]]['size']))
    dists_sorted = dists[np.ix_(sorted_idx, sorted_idx)]
    sorted_cats = [cats[i] for i in sorted_idx]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # Distance matrix
    im = ax1.imshow(dists_sorted, cmap='viridis_r', aspect='auto')
    ax1.set_title('(a) Cluster Similarity Matrix\n(sorted by category)',
                  fontweight='bold', fontsize=11)
    ax1.set_xlabel('Cluster index (sorted)')
    ax1.set_ylabel('Cluster index (sorted)')
    plt.colorbar(im, ax=ax1, shrink=0.8, label='Euclidean distance (lower = more similar)')

    # Draw category boundaries
    prev_cat = sorted_cats[0]
    for i, cat in enumerate(sorted_cats):
        if cat != prev_cat:
            ax1.axhline(y=i - 0.5, color='white', linewidth=0.5)
            ax1.axvline(x=i - 0.5, color='white', linewidth=0.5)
            prev_cat = cat

    # Category size bar chart
    cat_counts = Counter(cats)
    cat_names = [CATEGORY_LABELS.get(k, k) for k in cat_counts.keys()]
    cat_vals = list(cat_counts.values())
    cat_colors = [CATEGORY_COLORS.get(k, '#969696') for k in cat_counts.keys()]

    bars = ax2.barh(cat_names, cat_vals, color=cat_colors, edgecolor='white', linewidth=0.5)
    for bar, val in zip(bars, cat_vals):
        ax2.text(bar.get_width() + max(cat_vals) * 0.02,
                 bar.get_y() + bar.get_height() / 2,
                 f'{val} ({val/len(cnums)*100:.0f}%)',
                 va='center', fontsize=9, fontweight='bold')
    ax2.set_xlabel('Number of Clusters')
    ax2.set_title('(b) Cluster Category Distribution', fontweight='bold', fontsize=11)
    ax2.grid(True, axis='x', alpha=0.3)

    fig.suptitle('Figure: Cluster Fingerprint Similarity Analysis',
                 fontsize=13, fontweight='bold', y=1.02)
    plt.tight_layout()
    path = os.path.join(outdir, 'fingerprint_similarity.png')
    fig.savefig(path)
    plt.close(fig)
    log(f"    ✓ {path}")


# =============================================================================
# Main
# =============================================================================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', required=True, help='Path to collisions.json')
    parser.add_argument('-o', '--outdir', default='fingerprints', help='Output directory')
    parser.add_argument('--detail', nargs='+', type=int, default=None,
                        help='Cluster numbers for detailed fingerprints')
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    features = load_and_extract(args.file)

    log(f"\nGenerating fingerprint visualizations → {args.outdir}/\n")

    generate_legend(args.outdir)
    generate_landscape(features, args.outdir)

    # Detail view
    if args.detail:
        generate_detail(features, args.detail, args.outdir)
    else:
        # Auto-pick interesting clusters: largest, smallest, most diverse
        by_size = sorted(features.items(), key=lambda x: -x[1]['size'])
        auto = [by_size[0][0]]  # largest
        auto.append(by_size[-1][0])  # smallest
        # Most ASN-diverse
        by_asn = sorted(features.items(), key=lambda x: -x[1]['n_asns'])
        auto.append(by_asn[0][0])
        # Most port-diverse
        by_port = sorted(features.items(), key=lambda x: -x[1]['n_ports'])
        if by_port[0][0] not in auto:
            auto.append(by_port[0][0])
        else:
            auto.append(by_size[len(by_size)//2][0])  # median
        generate_detail(features, auto[:4], args.outdir)

    generate_similarity(features, args.outdir)

    log(f"\n{'='*50}")
    log(f"✅ All fingerprints saved to {args.outdir}/")
    log(f"{'='*50}")
    for f in sorted(os.listdir(args.outdir)):
        sz = os.path.getsize(os.path.join(args.outdir, f))
        log(f"  {f:45s} {sz/1024:.0f} KB")


if __name__ == '__main__':
    main()