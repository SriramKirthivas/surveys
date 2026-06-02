#!/usr/bin/env python3
"""
RC4ProviderImpact.py
Compute provider concentration and "what-if" impact tables from rc4_providers.txt.

Usage:
  python3 RC4ProviderImpact.py \
    --providers rc4/rc4_providers.txt \
    --outdir rc4/provider_impact
"""

import argparse
import csv
import json
import os
from collections import Counter

DEFAULT_TOPN = [1, 3, 5, 10]


def load_provider_counts(path, include_unknown=False):
    counts = Counter()
    with open(path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            provider = (row.get('Provider') or row.get('provider') or '').strip()
            if not provider:
                provider = 'Unknown'
            if provider == 'Unknown' and not include_unknown:
                continue
            counts[provider] += 1
    return counts


def gini(values):
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    total = sum(sorted_vals)
    if total == 0:
        return 0.0
    cum = 0
    for i, v in enumerate(sorted_vals, start=1):
        cum += i * v
    return (2 * cum) / (n * total) - (n + 1) / n


def hhi(shares):
    return sum(s * s for s in shares)


def write_provider_table(out_path, counts, total):
    with open(out_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['provider', 'rc4_count', 'share', 'cum_share'])
        cum = 0.0
        for provider, count in counts:
            share = count / total if total else 0.0
            cum += share
            writer.writerow([provider, count, round(share, 6), round(cum, 6)])


def write_what_if(out_path, counts, total, topn_list):
    with open(out_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['top_n', 'removed_count', 'removed_percent', 'remaining_count', 'remaining_percent'])
        for n in topn_list:
            subset = counts[:min(n, len(counts))]
            removed = sum(c for _, c in subset)
            remaining = max(total - removed, 0)
            removed_pct = (removed / total * 100.0) if total else 0.0
            remaining_pct = 100.0 - removed_pct if total else 0.0
            writer.writerow([n, removed, round(removed_pct, 2), remaining, round(remaining_pct, 2)])


def main():
    parser = argparse.ArgumentParser(description='RC4 provider concentration and impact analysis')
    parser.add_argument('--providers', default='rc4/rc4_providers.txt', help='rc4_providers.txt path')
    parser.add_argument('--outdir', default='rc4/provider_impact', help='output directory')
    parser.add_argument('--include-unknown', action='store_true', help='include Unknown providers')
    parser.add_argument('--topn', default=None, help='comma-separated list of top-N values (e.g., 1,3,5,10)')
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    counts = load_provider_counts(args.providers, include_unknown=args.include_unknown)
    sorted_counts = counts.most_common()
    total = sum(counts.values())

    if args.topn:
        topn_list = [int(x.strip()) for x in args.topn.split(',') if x.strip().isdigit()]
    else:
        topn_list = DEFAULT_TOPN

    shares = [(c / total) if total else 0.0 for _, c in sorted_counts]

    summary = {
        'total_rc4_hosts': total,
        'provider_count': len(sorted_counts),
        'top_provider': sorted_counts[0][0] if sorted_counts else None,
        'top_provider_share': round(shares[0], 6) if shares else 0.0,
        'hhi': round(hhi(shares), 6),
        'gini': round(gini([c for _, c in sorted_counts]), 6),
        'top3_share': round(sum(shares[:3]), 6),
        'top5_share': round(sum(shares[:5]), 6),
        'top10_share': round(sum(shares[:10]), 6),
    }

    with open(os.path.join(args.outdir, 'rc4_provider_concentration.json'), 'w') as f:
        json.dump(summary, f, indent=2)

    write_provider_table(
        os.path.join(args.outdir, 'rc4_provider_concentration.csv'),
        sorted_counts,
        total
    )

    write_what_if(
        os.path.join(args.outdir, 'rc4_provider_what_if.csv'),
        sorted_counts,
        total,
        topn_list
    )

    print('Wrote outputs to', args.outdir)


if __name__ == '__main__':
    main()
