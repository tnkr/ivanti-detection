#!/bin/bash

set -e

# === Ivanti VPN JA3 Hash (update as needed)
IVANTI_JA3_HASH="e7d705a3286e19ea42f587b344ee6865"

# === Output Directories
OUTPUT_DIR="./ivanti_scan_results"
HTTPX_DIR=".httpx/screenshots"
mkdir -p "$OUTPUT_DIR"

# === Dependencies
REQUIRED_TOOLS=("zgrab2" "jq" "nuclei" "httpx")

# === Function: Check Dependencies
check_dependencies() {
  for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      echo "[!] Missing dependency: $tool"
      read -p "Do you want to try installing $tool? (y/n): " choice
      if [[ "$choice" == "y" ]]; then
        install_tool "$tool"
      else
        echo "[!] Please install $tool manually and rerun the script."
        exit 1
      fi
    fi
  done
}

# === Function: Install Tool
install_tool() {
  tool="$1"
  if [[ "$OSTYPE" == "linux-gnu"* ]] && command -v apt-get >/dev/null 2>&1; then
    echo "[*] Installing $tool with apt..."
    case "$tool" in
      zgrab2)
        if [[ "$FORCE_REBUILD" == true ]]; then
          echo "[*] Force rebuild enabled: cleaning up old zgrab2 binary..."
          sudo rm -rf /usr/local/bin/zgrab2 /tmp/zgrab2
        fi
        sudo apt-get install -y golang git
        sudo rm -rf /usr/local/bin/zgrab2 /tmp/zgrab2
        git clone https://github.com/zmap/zgrab2.git /tmp/zgrab2
        cd /tmp/zgrab2/cmd/zgrab2
        go build
        sudo mv zgrab2 /usr/local/bin/
        cd -
        ;;
      jq|nuclei|httpx)
        sudo apt-get install -y "$tool"
        ;;
    esac
  elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "[*] Detected macOS. Installing $tool manually via source."
    case "$tool" in
      zgrab2)
        if [[ "$FORCE_REBUILD" == true ]]; then
          echo "[*] Force rebuild enabled: cleaning up old zgrab2 binary..."
          sudo rm -rf /usr/local/bin/zgrab2 /tmp/zgrab2
        fi
        command -v go >/dev/null 2>&1 || { echo "[!] Go compiler not found. Please install Golang."; exit 1; }
        git clone https://github.com/zmap/zgrab2.git /tmp/zgrab2
        cd /tmp/zgrab2/cmd/zgrab2
        go build
        sudo mv zgrab2 /usr/local/bin/
        cd -
        ;;
      *)
        echo "[!] Please install $tool manually (Homebrew or binary download)."
        exit 1
        ;;
    esac
    exit 1
  fi
}

# === Function: Show Usage
usage() {
  echo "Usage: $0 --targets targets.txt [--output results.csv]"
  exit 1
}

# === Parse Arguments
FORCE_REBUILD=false
while [[ $# -gt 0 ]]; do
  case $1 in
    --targets)
      TARGET_FILE="$2"
      shift 2
      ;;
    --output)
      OUTPUT_FILE="$2"
      shift 2
      ;;
    --force-rebuild)
      FORCE_REBUILD=true
      shift
      ;;
    *)
      usage
      ;;
  esac
done

# === Validate Input
if [[ -z "$TARGET_FILE" ]]; then
  usage
fi

# === Default Output File
OUTPUT_FILE="${OUTPUT_FILE:-$OUTPUT_DIR/final_results.csv}"

# === Start
check_dependencies

# === Zgrab2 JA3 Fingerprinting
echo "[*] Running zgrab2 for TLS JA3..."
zgrab2 tls -p 443 --timeout 15 -o "$OUTPUT_DIR/ja3_results.json" -f "$TARGET_FILE"

# === Filter for Ivanti
echo "[*] Filtering for Ivanti JA3 hash..."
jq -r "select(.data.tls.result.handshake_log.server_ja3s==\"$IVANTI_JA3_HASH\") | .ip" "$OUTPUT_DIR/ja3_results.json" > "$OUTPUT_DIR/ivanti_candidates.txt"

if [[ ! -s "$OUTPUT_DIR/ivanti_candidates.txt" ]]; then
  echo "[!] No Ivanti VPN services detected."
  exit 0
fi

# === Nuclei Scanning
echo "[*] Running Nuclei on filtered Ivanti targets..."
nuclei -l "$OUTPUT_DIR/ivanti_candidates.txt" -t ./ivanti-templates/ -o "$OUTPUT_FILE"

# === Httpx Screenshot Capture
echo "[*] Capturing screenshots and metadata with httpx..."
httpx -l "$OUTPUT_DIR/ivanti_candidates.txt" \
  -p 443 \
  -screenshot \
  -title -web-server -tech-detect \
  -json -o "$OUTPUT_DIR/httpx_output.json"

# === Report Summary
echo "\n========================"
echo "[+] Scan Summary"
echo "Nuclei Results : $OUTPUT_FILE"
echo "Screenshots     : $HTTPX_DIR"
echo "Httpx JSON      : $OUTPUT_DIR/httpx_output.json"
echo "========================"

# === Optional: Convert JSON to Markdown (Bonus)
cat <<EOF > "$OUTPUT_DIR/report.md"
# Ivanti Detection Report

**Scan Date**: $(date)
**Targets Scanned**: $(wc -l < "$TARGET_FILE")
**Ivanti Matches**: $(wc -l < "$OUTPUT_DIR/ivanti_candidates.txt")

## Nuclei Findings
\`\`\`
$(cat "$OUTPUT_FILE")
\`\`\`

## Screenshots
Saved under: \`$HTTPX_DIR\`

## Metadata Output
See \`httpx_output.json\` for detailed info.
EOF

echo "[*] Markdown report saved to: $OUTPUT_DIR/report.md"

# === Create Nuclei Template Directory with Ivanti Template
mkdir -p ./ivanti-templates
cat <<'EOT' > ./ivanti-templates/ivanti-welcome-detect.yaml
id: ivanti-welcome-detect
info:
  name: Ivanti VPN Web UI Detection
  author: zachlawson
  severity: info
  tags: ivanti,vpn,pulse,web

requests:
  - method: GET
    path:
      - "{{BaseURL}}/dana-na/auth/url_default/welcome.cgi"
      - "{{BaseURL}}/dana-cached/sc/"

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
EOT
