# Ivanti VPN Detection Scanner

This tool probes target IPs to detect the presence of Ivanti (formerly Pulse Secure) VPN login portals. It captures responses, uses regex matching for known Ivanti indicators, and optionally runs Nuclei templates to confirm the findings.

## Requirements

- Python 3.7+
- `requests` module
- [`nuclei`](https://github.com/projectdiscovery/nuclei) (installed and in your PATH)

Install Python deps:
```bash
pip install requests
```

## Usage

```bash
python3 ivanti-scan.py --targets <path-to-ip-list> --output <output-file.csv>
```

### Example:
```bash
python3 ivanti-scan.py --targets targets.txt --output ivanti-results.csv
```

## Output

After running, the tool generates:

- `ivanti_scan_results/`
  - `report.md`: Human-readable report with detection summary and Nuclei results
  - `ivanti_candidates.txt`: Hosts matching Ivanti indicators
  - `httpx_output.json`: Captured metadata from detected portals
  - `raw_html/`: HTML responses saved per host
  - `ivanti-templates/`: Nuclei detection template for confirmation scanning

## What It Detects

The scanner flags hosts with pages containing:

- Ivanti/Pulse branding
- `/dana-na/auth/` path structure
- Common login form patterns
- Favicon or HTML titles like "SSL gateway"

## Future Ideas

- HTML export of results
- Slack/Discord alerts
- Scan threading for faster bulk testing