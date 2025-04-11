# Ivanti VPN Detection Scanner

This script scans IP addresses for signs of exposed **Ivanti Secure Access VPN** (formerly Pulse Secure) appliances by:

1. Performing TLS JA3 fingerprinting with `zgrab2`
2. Matching against known Ivanti JA3 hashes
3. Probing likely endpoints with `nuclei`
4. Capturing screenshots and metadata using `httpx`
5. Generating a Markdown report

---

## Dependencies

The script will check for and attempt to install the following tools:

- [zgrab2](https://github.com/zmap/zgrab2) – TLS scanner with JA3 support (built from source)
- [jq](https://stedolan.github.io/jq/) – JSON parser
- [nuclei](https://github.com/projectdiscovery/nuclei) – Fast web vulnerability scanner
- [httpx](https://github.com/projectdiscovery/httpx) – Web service probe + screenshot tool
- `go` and `git` – required to build `zgrab2` from source

The script supports both **Linux (apt)** and **macOS** environments.

---

## Usage

```bash
./ivanti-scan.sh --targets targets.txt [--output results.csv] [--force-rebuild]
```

### Arguments:
- `--targets` (required): Path to a text file with IPs or hostnames (one per line)
- `--output` (optional): Output path for the final results file (default: `./ivanti_scan_results/final_results.csv`)
- `--force-rebuild` (optional): Rebuilds `zgrab2` from scratch (cleans up old install)

---

## Output

After running, you will find:
- `ivanti_candidates.txt` – IPs matching Ivanti JA3 fingerprint
- `final_results.csv` – Matched targets from `nuclei`
- `.httpx/screenshots/` – Screenshot previews
- `httpx_output.json` – Service metadata
- `report.md` – Human-readable Markdown summary

---

## Example

```bash
chmod +x ivanti-scan.sh
./ivanti-scan.sh --targets mytargets.txt --output ivanti-results.csv --force-rebuild
```

---

## 🔐 Legal Disclaimer

Only scan systems you own or are explicitly authorized to test. Unauthorized scanning may violate laws or terms of service.
