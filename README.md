# CIDR Pull — Residential ISP Whitelist Generator

A fully-featured CLI tool for fetching CIDR ranges from residential ISP ASNs worldwide, with rich terminal output and multiple export formats targeting firewalls and Cloudflare.

The strategy this tool supports is **whitelisting residential ISPs and blocking everything else at layer 2** — a far more tractable approach than trying to blocklist the entire threat landscape. Rather than chasing down every VPN, datacenter, bot network, and proxy range, you define the universe of legitimate residential traffic and drop the rest by default.

---

## Features

- **250+ pre-loaded residential ISP ASNs** across 7 regions and 50+ countries
- **Live concurrent fetching** with configurable thread count and per-ASN progress display
- **Mobile carrier tagging** — flag or exclude mobile ASNs per-region per your policy
- **Rich terminal UI** — color-coded by region, progress bars, summary trees, results tables, stat panels
- **Interactive export menu** or fully non-interactive via CLI flags for use in cron/automation
- **7 export formats** covering every common firewall and Cloudflare workflow
- **Filters** by region, country, ASN list, mobile status, and IP version

---

## Requirements

Python 3.10+ and two dependencies:

```bash
pip install rich requests
```

---

## Usage

### Interactive mode

Running bare launches interactive mode — shows the ASN fetch plan, prompts for confirmation, fetches with a live progress bar, displays results, then walks you through export options.

```bash
python3 cidr_pull.py
```

### CLI flags

```bash
# Exclude all mobile carriers globally
python3 cidr_pull.py --no-mobile

# Filter to specific regions
python3 cidr_pull.py --region NA EU OC

# Filter to specific countries
python3 cidr_pull.py --country US CA GB DE AU

# Fetch specific ASNs only (bypasses the DB entirely)
python3 cidr_pull.py --asn 7018 7922 20115 701

# Non-interactive, export all formats at once
python3 cidr_pull.py --no-mobile --format all

# Cloudflare expression only, IPv4 only
python3 cidr_pull.py --format cf_expr --no-v6

# Higher thread count for faster fetches
python3 cidr_pull.py --threads 20

# Custom output directory
python3 cidr_pull.py --format all --output /etc/fw/whitelist/

# Preview the fetch plan without hitting the API
python3 cidr_pull.py --summary-only --no-mobile --region NA EU

# List every ASN in the database and exit
python3 cidr_pull.py --list-asns
```

### All flags

| Flag | Description |
|---|---|
| `--no-mobile` | Exclude ASNs tagged as mobile carriers |
| `--region` | One or more region codes: `NA SA EU AS OC ME AF` |
| `--country` | One or more ISO country codes: `US GB DE JP AU` etc. |
| `--asn` | Fetch specific ASNs only (space-separated) |
| `--threads` | Concurrent fetch threads (default: 10) |
| `--format` | Export format — skips interactive menu (see below) |
| `--output` | Output directory path (default: auto-timestamped) |
| `--no-v6` | Exclude IPv6 prefixes from all output |
| `--list-asns` | Print all ASNs in the database and exit |
| `--summary-only` | Show fetch plan and exit without fetching |

---

## Export Formats

| Format | Flag value | Description |
|---|---|---|
| JSON | `json` | Full structured output with metadata per ASN — names, countries, regions, mobile flag, v4/v6 split |
| Flat IPv4 | `flat_v4` | Plain text, one CIDR per line, IPv4 only |
| Flat IPv6 | `flat_v6` | Plain text, one CIDR per line, IPv6 only |
| Flat both | `flat_both` | Plain text, one CIDR per line, all prefixes |
| Cloudflare Expression | `cf_expr` | Ready-to-paste Cloudflare WAF rule using `ip.geoip.asnum in {...}` |
| Cloudflare IP List | `cf_ip_list` | CIDR list with ASN comments, importable into a Cloudflare IP List |
| ipset script | `ipset` | Shell script that builds `whitelist_v4` / `whitelist_v6` ipsets and applies iptables DROP rules |
| nftables config | `nftables` | Complete nftables table with whitelist sets and a default-drop input chain |
| All formats | `all` | Writes every format above in a single run |

Output files are written to a timestamped directory (`cidr_output_YYYYMMDD_HHMMSS/`) unless `--output` is specified.

---

## ASN Coverage

The built-in database covers residential fixed-line ISPs across:

| Region | Code | Countries included |
|---|---|---|
| North America | `NA` | US, CA, MX |
| South America | `SA` | BR, AR, CL, CO, PE, VE |
| Europe | `EU` | GB, DE, FR, IT, ES, NL, BE, CH, AT, SE, NO, FI, DK, PL, CZ, HU, RO, BG, UA, RS, HR, SK, PT, GR, TR, RU |
| Asia | `AS` | JP, KR, TW, HK, IN, PH, ID, VN, TH, MY, SG |
| Oceania | `OC` | AU, NZ |
| Middle East | `ME` | IL, SA, AE |
| Africa | `AF` | ZA, EG, MA |

### Mobile carrier policy

ASNs are individually tagged `mobile: true/false`. Some large carriers run both fixed and mobile infrastructure under the same ASN — these are tagged based on their primary residential footprint but noted for review. Use `--no-mobile` to exclude all tagged mobile ASNs, or review the list with `--list-asns` to make per-ASN decisions.

ASNs in the database that are tagged as mobile carriers:

| ASN | Carrier | Country | Note |
|---|---|---|---|
| 21928 | T-Mobile US | US | Home Internet product exists but core is mobile |
| 26615 | TIM Brasil | BR | Mobile-primary |
| 55836 | Reliance Jio | IN | Mobile-primary |
| 9299 | PLDT | PH | Mixed fixed/mobile |
| 8359 | MTS Russia | RU | Mobile carrier — remove if excluding RU mobile |

---

## Data Source

Prefix data is fetched from the [RIPE Stat announced-prefixes API](https://stat.ripe.net/data/announced-prefixes/data.json), which reflects currently announced BGP prefixes per ASN. This is the same data underlying most IP-to-ASN lookups.

The API is free and unauthenticated. The tool rate-limits itself via thread count — 10 threads (the default) is well within polite usage. Increase with `--threads` if you need faster pulls.

---

## Refreshing Data

ISPs acquire and release prefixes continuously. The CIDR ranges fetched today will drift over time. For firewall rules that need to stay accurate:

- **Monthly refresh** is sufficient for most residential ISP blocks — these change slowly
- **Weekly** if you're in a high-stakes environment or covering fast-growing ISPs (Starlink AS14593 in particular expands frequently)

A cron job to refresh and reload:

```bash
# /etc/cron.monthly/refresh-whitelist
#!/bin/bash
cd /opt/cidr-pull
python3 cidr_pull.py --no-mobile --format ipset --output /etc/fw/
bash /etc/fw/whitelist_ipset_*.sh
```

---

## Example: Cloudflare Workflow

**Option A — ASN-based (recommended, no CIDR list needed):**

```bash
python3 cidr_pull.py --format cf_expr --no-mobile
```

Paste the output directly into a Cloudflare WAF Custom Rule. Cloudflare resolves ASN → IPs on their end in real time, so no CIDR list maintenance is needed.

**Option B — Cloudflare IP Lists:**

```bash
python3 cidr_pull.py --format cf_ip_list --no-mobile --no-v6
```

Import the output into a Cloudflare IP List (Dashboard → Manage Account → Lists), then reference it in a WAF rule with `ip.src in $your_list_name`.

---

## Example: Linux Firewall Workflow

**ipset + iptables:**

```bash
python3 cidr_pull.py --no-mobile --format ipset
chmod +x cidr_output_*/whitelist_ipset_*.sh
sudo bash cidr_output_*/whitelist_ipset_*.sh
```

**nftables:**

```bash
python3 cidr_pull.py --no-mobile --format nftables
sudo cp cidr_output_*/whitelist_nftables_*.conf /etc/nftables.conf
sudo nft -f /etc/nftables.conf
```

---

## Adding ASNs

The ASN database lives in the `ASN_DB` dict near the top of `cidr_pull.py`. Each entry follows this structure:

```python
12345: {
    "name":    "My ISP",   # Human-readable carrier name
    "country": "US",       # ISO 3166-1 alpha-2 country code
    "region":  "NA",       # NA SA EU AS OC ME AF
    "mobile":  False,      # True if primarily a mobile carrier
},
```

Look up ASNs via [bgp.tools](https://bgp.tools), [RIPE Stat](https://stat.ripe.net), or [Hurricane Electric BGP Toolkit](https://bgp.he.net).

---

## License

MIT
