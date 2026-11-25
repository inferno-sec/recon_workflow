#!/bin/bash
#
# recon.sh — full subdomain recon pipeline for a single target domain
#
# Usage:
#   ./recon.sh cascadiamotion.com
#   ./recon.sh cascadiamotion.com /path/to/resolvers.txt
#   ./recon.sh cascadiamotion.com /path/to/resolvers.txt /path/to/output/dir
#   ./recon.sh cascadiamotion.com "" /path/to/output/dir     # skip resolvers arg, still set output dir
#
# If no resolvers.txt path is given, it will download a fresh one into the
# target's own folder.
#
# If no output directory is given, results are written under
# ./<domain>/ in the current working directory, same as before.

set -euo pipefail

# ---- Input handling -------------------------------------------------------

if [ -z "${1:-}" ]; then
  echo "Usage: $0 <domain> [path/to/resolvers.txt] [path/to/output/dir]"
  exit 1
fi

DOMAIN="$1"
RESOLVERS_INPUT="${2:-}"
OUTPUT_BASE="${3:-.}"
WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

echo "[*] Target domain: $DOMAIN"
echo "[*] Output base directory: $OUTPUT_BASE"

# ---- Workspace setup --------------------------------------------------------

mkdir -p "$OUTPUT_BASE/$DOMAIN"
cd "$OUTPUT_BASE/$DOMAIN"
echo "[*] Writing results to: $(pwd)"

# ---- Resolvers --------------------------------------------------------------

if [ -n "$RESOLVERS_INPUT" ] && [ -f "$RESOLVERS_INPUT" ]; then
  echo "[*] Using existing resolvers file: $RESOLVERS_INPUT"
  cp "$RESOLVERS_INPUT" resolvers.txt
else
  echo "[*] Downloading fresh resolvers list"
  curl -s https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -o resolvers.txt
fi
wc -l resolvers.txt

# ---- Passive enumeration -----------------------------------------------------

echo "[*] Running passive enumeration (subfinder, assetfinder, findomain, amass)"
subfinder -d "$DOMAIN" -all -recursive -silent -o subfinder.txt || true
assetfinder --subs-only "$DOMAIN" > assetfinder.txt || true
findomain -t "$DOMAIN" -q -u findomain.txt || true
amass enum -passive -d "$DOMAIN" -o amass.txt || true

# ---- Active bruteforce -------------------------------------------------------

echo "[*] Running active bruteforce with puredns"
puredns bruteforce "$WORDLIST" "$DOMAIN" -r resolvers.txt -w puredns_brute.txt || true

# ---- Merge + dedupe -----------------------------------------------------------

echo "[*] Merging and deduping all sources"
cat subfinder.txt assetfinder.txt findomain.txt amass.txt puredns_brute.txt 2>/dev/null \
  | sort -u > all_subs.txt

# Strip any markdown-link-wrapped entries just in case (e.g. [host](url))
sed -E 's/\[([^]]+)\]\([^)]+\)/\1/' all_subs.txt | sort -u > all_subs_clean.txt

echo "[+] Total unique subdomains found: $(wc -l < all_subs_clean.txt)"

# ---- DNS resolution validation -----------------------------------------------

echo "[*] Validating DNS resolution"
cat all_subs_clean.txt | dnsx -silent -o resolved.txt
echo "[+] Hosts that actually resolve: $(wc -l < resolved.txt)"

# ---- Live HTTP triage (common web ports) ----------------------------------------

# Common web/admin/management ports worth checking beyond plain 80/443
WEB_PORTS="80,443,8080,8443,8000,8008,8081,8088,8090,8888,8181,9000,9090,9443,10000,7001,4443,3000,5000"

echo "[*] Running httpx for live HTTP/HTTPS triage across common web ports"
httpx -l resolved.txt -ports "$WEB_PORTS" -title -status-code -tech-detect -follow-redirects -json -o httpx_full.json

# ---- Additional port discovery with naabu (catches anything outside the list above) --

echo "[*] Running naabu for broader port discovery (top 1000 ports)"
naabu -l resolved.txt -top-ports 1000 -o naabu_results.txt || true

echo "[*] Running httpx against naabu-discovered open ports"
httpx -l naabu_results.txt -title -status-code -tech-detect -follow-redirects -json -o httpx_naabu.json || true

# ---- Merge httpx results (web-port scan + naabu-discovered ports) ----------------

echo "[*] Merging httpx results from both passes"
cat httpx_full.json httpx_naabu.json 2>/dev/null | jq -s 'unique_by(.url)' > httpx_merged.json
# Flatten back into JSON-lines for the jq filters below
jq -c '.[]' httpx_merged.json > httpx_combined.json

# ---- Cloudflare / direct-origin split -------------------------------------------

echo "[*] Splitting into Cloudflare-fronted vs. direct-origin hosts"
cat httpx_combined.json | jq -r 'select(.tech[]? | test("Cloudflare"; "i")) | .url' > cf_hosts.txt
cat httpx_combined.json | jq -r 'select([.tech[]? | test("Cloudflare"; "i")] | length == 0) | .url' > direct_hosts.txt

echo "[+] Cloudflare-fronted hosts: $(wc -l < cf_hosts.txt)"
echo "[+] Direct-origin hosts:      $(wc -l < direct_hosts.txt)"

# ---- Cleanup intermediate files --------------------------------------------------

echo "[*] Cleaning up intermediate per-tool files"
rm -f subfinder.txt assetfinder.txt findomain.txt amass.txt puredns_brute.txt all_subs.txt

echo ""
echo "============================================================"
echo " Recon complete for $DOMAIN"
echo " Results directory: $(pwd)"
echo " Kept files:"
echo "   - resolvers.txt       (resolver list, reusable for next target)"
echo "   - all_subs_clean.txt  (deduped subdomain list)"
echo "   - resolved.txt        (DNS-validated hosts)"
echo "   - httpx_full.json     (full tech/status data)"
echo "   - cf_hosts.txt        (Cloudflare-fronted hosts)"
echo "   - direct_hosts.txt    (direct-origin hosts — nuclei these)"
echo "============================================================"
echo ""
echo "[*] Suggested next steps:"
echo "    gowitness scan file -f cf_hosts.txt --screenshot-path ../screenshots"
echo "    nuclei -l direct_hosts.txt -tags cve,exposure,misconfig,takeover,default-login,rce,lfi,ssrf -severity low,medium,high,critical -rate-limit 20 -c 10 -o nuclei_direct_results.txt"
