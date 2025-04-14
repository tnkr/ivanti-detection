import argparse
import os
import subprocess
import datetime
import re
from pathlib import Path
import requests
from requests.exceptions import RequestException

OUTPUT_DIR = Path("ivanti_scan_results")
HTTPX_DIR = OUTPUT_DIR / ".httpx/screenshots"
RAW_HTML_DIR = OUTPUT_DIR / "raw_html"
IVANTI_CANDIDATES = OUTPUT_DIR / "ivanti_candidates.txt"
IVANTI_URLS = OUTPUT_DIR / "ivanti_probe_urls.txt"
HTTPX_OUTPUT = OUTPUT_DIR / "httpx_output.json"
TEMPLATE_DIR = Path("ivanti-templates")
TEMPLATE_FILE = TEMPLATE_DIR / "ivanti-welcome-detect.yaml"

IVANTI_PATTERNS = re.compile(r"Ivanti|Pulse Secure|SSL gateway|Ivanti_favicon|dana-na|form.*login", re.IGNORECASE)

def check_dependencies():
    for tool in ["nuclei"]:
        if not shutil.which(tool):
            print(f"[!] Missing dependency: {tool}. Please install it.")
            exit(1)

def probe_targets(target_file):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    RAW_HTML_DIR.mkdir(parents=True, exist_ok=True)
    matches = []

    with open(target_file) as tf:
        for line in tf:
            host = line.strip()
            if not host:
                continue
            url = f"https://{host}/dana-na/auth/url_11/welcome.cgi"
            try:
                response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15, verify=False)
                html = response.text
                (RAW_HTML_DIR / f"{host}.txt").write_text(html)
                if IVANTI_PATTERNS.search(html):
                    matches.append(host)
                    print(f"[+] Ivanti detected: {host}")
            except RequestException as e:
                print(f"[-] Failed to probe {url}: {e}")

    with open(IVANTI_CANDIDATES, 'w') as f:
        f.write('\n'.join(matches) + '\n')
    return matches

def run_nuclei(output_file):
    subprocess.run([
        "nuclei", "-l", str(IVANTI_CANDIDATES), "-t", str(TEMPLATE_DIR), "-o", output_file
    ], check=True)

def run_httpx_metadata():
    HTTPX_DIR.mkdir(parents=True, exist_ok=True)
    os.environ["HTTPX_SCREENSHOT_DIR"] = str(HTTPX_DIR)
    subprocess.run([
        "httpx", "-l", str(IVANTI_CANDIDATES), "-p", "443", "-screenshot",
        "-title", "-web-server", "-tech-detect", "-json",
        "-o", str(HTTPX_OUTPUT)
    ], check=True)

def write_template():
    TEMPLATE_DIR.mkdir(exist_ok=True)
    TEMPLATE_FILE.write_text('''id: ivanti-welcome-detect
info:
  name: Ivanti VPN Web UI Detection
  author: zachlawson
  severity: info
  tags: ivanti,vpn,pulse,web

requests:
  - method: GET
    path:
      - "{{BaseURL}}/dana-na/auth/url_*/welcome.cgi"

    matchers-condition: or
    matchers:
      - type: word
        words:
          - "Pulse Secure"
          - "Ivanti Secure Access"
        part: body

      - type: status
        status:
          - 200
''')

def generate_report(output_file, target_file):
    with open(OUTPUT_DIR / "report.md", 'w') as report:
        report.write("# Ivanti Detection Report\n\n")
        report.write("**Scan Date**: {}\n".format(datetime.datetime.now()))
        report.write("**Targets Scanned**: {}\n".format(sum(1 for _ in open(target_file))))
        report.write("**Ivanti Matches**: {}\n\n".format(sum(1 for _ in open(IVANTI_CANDIDATES))))

        report.write("## Nuclei Findings\n```\n")
        with open(output_file) as res:
            report.write(res.read())
        report.write("\n```\n\n")

        report.write("## Screenshots\n")
        report.write("Saved under: `{}`\n\n".format(HTTPX_DIR))

        report.write("## Metadata Output\n")
        report.write("See `{}` for details.\n\n".format(HTTPX_OUTPUT))

        report.write("## Raw Responses\n")
        report.write("See `{}`\n".format(RAW_HTML_DIR))

def main():
    parser = argparse.ArgumentParser(description="Ivanti Scanner")
    parser.add_argument('--targets', required=True, help='Target IP list file')
    parser.add_argument('--output', required=False, default=str(OUTPUT_DIR / "final_results.csv"))
    args = parser.parse_args()

    import urllib3
    urllib3.disable_warnings()

    check_dependencies()
    matches = probe_targets(args.targets)
    if not matches:
        print("[!] No Ivanti-like web paths detected.")
        return

    write_template()
    run_nuclei(args.output)
    run_httpx_metadata()
    generate_report(args.output, args.targets)
    print("[*] Report saved to:", OUTPUT_DIR / "report.md")

if __name__ == "__main__":
    import shutil
    main()
