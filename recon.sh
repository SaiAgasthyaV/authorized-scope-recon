#!/usr/bin/env bash
#
# recon.sh -- passive asset inventory, with optional scoped public-resource review
#
# The default run ends after httpx and workbook generation exactly as the original
# lightweight workflow did. --crawl enables only ordinary in-scope HTML-link
# traversal; --analyze-js performs redacted, unverified static analysis afterwards.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_OUT="recon_output_$(date +%Y%m%d_%H%M%S)"
OUT_DIR=""
SCOPE_FILES=()
CRAWL=0
ANALYZE_JS=0
SOURCE_MAPS=0
BOUNTY_ONLY=0
MAX_DEPTH=2
MAX_PAGES=25
MAX_JS=50
MAX_RESPONSE_SIZE=2000000
TIMEOUT=10
RATE_LIMIT=1
CONCURRENCY=2

usage() {
    cat <<'EOF'
Usage:
  ./recon.sh scope.csv [output_dir] [options]
  ./recon.sh --scope scope-a.csv --scope scope-b.csv --output output_dir [options]

Default behavior is passive enumeration + httpx liveness inventory only.

Optional controlled crawl/analysis flags:
  --crawl                         Discover normal in-scope HTML links/resources
  --analyze-js                    Crawl and inspect discovered JS (implies --crawl)
  --source-maps                   Inspect explicitly referenced in-scope maps (implies --analyze-js)
  --max-depth N                   Link depth per seed (default: 2)
  --max-pages N                   Maximum pages per host (default: 25)
  --max-js N                      Maximum JS URLs per host (default: 50)
  --max-response-size BYTES       Maximum downloaded response size (default: 2000000)
  --timeout SECONDS               Per-request timeout (default: 10)
  --rate-limit REQUESTS_PER_SEC   Global GET rate (default: 1)
  --concurrency N                 Crawler workers (default: 2)
  --bounty-only                   Require explicit bounty/submission eligibility
  --platform LABEL                Apply a provenance label to all imported CSVs
  --output DIR                    Output directory (same as legacy second positional argument)
  --scope FILE                    Add another scope CSV (repeatable)
  -h, --help                      Show this help
EOF
}

PLATFORM=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --scope)
            [[ $# -ge 2 ]] || { echo "[!] --scope needs a CSV path"; exit 1; }
            SCOPE_FILES+=("$2"); shift 2 ;;
        --output)
            [[ $# -ge 2 ]] || { echo "[!] --output needs a directory"; exit 1; }
            OUT_DIR="$2"; shift 2 ;;
        --platform)
            [[ $# -ge 2 ]] || { echo "[!] --platform needs a label"; exit 1; }
            PLATFORM="$2"; shift 2 ;;
        --crawl) CRAWL=1; shift ;;
        --analyze-js) CRAWL=1; ANALYZE_JS=1; shift ;;
        --source-maps) CRAWL=1; ANALYZE_JS=1; SOURCE_MAPS=1; shift ;;
        --bounty-only) BOUNTY_ONLY=1; shift ;;
        --max-depth|--max-pages|--max-js|--max-response-size|--timeout|--rate-limit|--concurrency)
            [[ $# -ge 2 ]] || { echo "[!] $1 needs a value"; exit 1; }
            case "$1" in
                --max-depth) MAX_DEPTH="$2" ;;
                --max-pages) MAX_PAGES="$2" ;;
                --max-js) MAX_JS="$2" ;;
                --max-response-size) MAX_RESPONSE_SIZE="$2" ;;
                --timeout) TIMEOUT="$2" ;;
                --rate-limit) RATE_LIMIT="$2" ;;
                --concurrency) CONCURRENCY="$2" ;;
            esac
            shift 2 ;;
        -h|--help) usage; exit 0 ;;
        -* ) echo "[!] Unknown option: $1"; usage; exit 1 ;;
        * )
            if [[ ${#SCOPE_FILES[@]} -eq 0 ]]; then
                SCOPE_FILES+=("$1")
            elif [[ -z "$OUT_DIR" ]]; then
                # Legacy: second positional argument is the output directory.
                OUT_DIR="$1"
            else
                echo "[!] Extra positional argument '$1'. Use --scope for another CSV."
                exit 1
            fi
            shift ;;
    esac
done

[[ ${#SCOPE_FILES[@]} -gt 0 ]] || { usage; exit 1; }
OUT_DIR="${OUT_DIR:-$DEFAULT_OUT}"

# Resolve files before changing into the output directory (fixes relative CSV input).
ABS_SCOPE_FILES=()
for scope_file in "${SCOPE_FILES[@]}"; do
    if [[ ! -f "$scope_file" ]]; then
        echo "[!] Scope CSV not found: $scope_file"
        exit 1
    fi
    ABS_SCOPE_FILES+=("$(cd "$(dirname "$scope_file")" && pwd)/$(basename "$scope_file")")
done

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
cd "$OUT_DIR" || exit 1

echo "=================================================="
echo " Passive Asset Inventory Pipeline"
echo " Scope CSV(s): ${#ABS_SCOPE_FILES[@]}"
echo " Output:       $OUT_DIR"
echo " Crawl:        $CRAWL | JS analysis: $ANALYZE_JS | Source maps: $SOURCE_MAPS"
echo "=================================================="

echo -e "\n[1/7] Normalizing authorized scope..."
SCOPE_ARGS=("${ABS_SCOPE_FILES[@]}" -o domains.txt --wildcards-output wildcard_domains.txt --excluded-output excluded_rows.txt --normalized-output normalized_scope.json)
[[ $BOUNTY_ONLY -eq 1 ]] && SCOPE_ARGS+=(--bounty-only)
[[ -n "$PLATFORM" ]] && SCOPE_ARGS+=(--platform "$PLATFORM")
python3 "$SCRIPT_DIR/parse_scope.py" "${SCOPE_ARGS[@]}"
if [[ ! -s domains.txt ]]; then
    echo "[!] No confidently mapped in-scope web domains found. Review excluded_rows.txt. Exiting."
    exit 1
fi
echo "[+] $(wc -l < domains.txt) root domain(s) to enumerate"

echo -e "\n[2/7] Running passive subdomain enumeration..."
> all_subs_raw.txt
command -v subfinder >/dev/null 2>&1 && HAVE_SUBFINDER=1 || HAVE_SUBFINDER=0
command -v assetfinder >/dev/null 2>&1 && HAVE_ASSETFINDER=1 || HAVE_ASSETFINDER=0
command -v findomain >/dev/null 2>&1 && HAVE_FINDOMAIN=1 || HAVE_FINDOMAIN=0
command -v amass >/dev/null 2>&1 && HAVE_AMASS=1 || HAVE_AMASS=0

if [[ $HAVE_SUBFINDER -eq 0 && $HAVE_ASSETFINDER -eq 0 && $HAVE_FINDOMAIN -eq 0 && $HAVE_AMASS -eq 0 ]]; then
    echo "[!] None of subfinder/assetfinder/findomain/amass found in PATH."
    echo "    Install at least one passive enumeration tool and re-run."
    exit 1
fi

while IFS= read -r domain; do
    [[ -z "$domain" ]] && continue
    echo "  -> $domain"
    [[ $HAVE_SUBFINDER -eq 1 ]] && subfinder -d "$domain" -silent -all >> all_subs_raw.txt 2>/dev/null
    [[ $HAVE_ASSETFINDER -eq 1 ]] && assetfinder --subs-only "$domain" >> all_subs_raw.txt 2>/dev/null
    [[ $HAVE_FINDOMAIN -eq 1 ]] && findomain -t "$domain" -q >> all_subs_raw.txt 2>/dev/null
    [[ $HAVE_AMASS -eq 1 ]] && amass enum -passive -d "$domain" -silent >> all_subs_raw.txt 2>/dev/null
done < domains.txt
cat domains.txt >> all_subs_raw.txt

echo -e "\n[3/7] Merging and deduping results..."
grep -Eo '^[a-zA-Z0-9](-?[a-zA-Z0-9])*(\.[a-zA-Z0-9](-?[a-zA-Z0-9])*)+$' all_subs_raw.txt \
    | tr '[:upper:]' '[:lower:]' | sort -u > all_subdomains.txt
echo "[+] $(wc -l < all_subdomains.txt) unique subdomain(s) after merge/dedupe"

echo -e "\n[4/7] Probing for live web applications (httpx, no scanning/fuzzing)..."
if command -v httpx >/dev/null 2>&1; then
    httpx -l all_subdomains.txt -silent -status-code -title -tech-detect -location -content-length \
        -follow-redirects -json -o httpx_output.json 2>/dev/null
    echo "[+] httpx probing complete -> httpx_output.json"
else
    echo "[!] httpx not found in PATH -- skipping web application identification."
    : > httpx_output.json
fi

if [[ $CRAWL -eq 1 ]]; then
    echo -e "\n[5/7] Controlled in-scope crawl (ordinary links/resources only)..."
    python3 "$SCRIPT_DIR/crawler.py" --scope normalized_scope.json --live-urls httpx_output.json --output-dir . \
        --max-depth "$MAX_DEPTH" --max-pages "$MAX_PAGES" --max-js "$MAX_JS" \
        --max-response-size "$MAX_RESPONSE_SIZE" --timeout "$TIMEOUT" --rate-limit "$RATE_LIMIT" --concurrency "$CONCURRENCY"
else
    echo -e "\n[5/7] Crawl disabled (use --crawl to enable)."
fi

if [[ $ANALYZE_JS -eq 1 ]]; then
    echo -e "\n[6/7] Analyzing in-scope JavaScript (redacted, unverified findings only)..."
    ANALYSIS_ARGS=(--scope normalized_scope.json --resources crawl_resources.jsonl --output-dir . --max-response-size "$MAX_RESPONSE_SIZE" --timeout "$TIMEOUT" --rate-limit "$RATE_LIMIT")
    [[ $SOURCE_MAPS -eq 1 ]] && ANALYSIS_ARGS+=(--source-maps)
    python3 "$SCRIPT_DIR/resource_analyzer.py" "${ANALYSIS_ARGS[@]}"
else
    echo -e "\n[6/7] JavaScript analysis disabled (use --analyze-js to enable)."
fi

echo -e "\n[7/7] Building Excel asset inventory..."
python3 "$SCRIPT_DIR/build_excel.py" --domains domains.txt --wildcards wildcard_domains.txt \
    --subdomains all_subdomains.txt --httpx-json httpx_output.json --scope-normalized normalized_scope.json \
    --js-assets javascript_assets.jsonl --secret-findings secret_findings.jsonl \
    --crawl-stats crawl_statistics.json --analysis-stats analysis_statistics.json --output asset_inventory.xlsx

echo -e "\n=================================================="
echo " Done. Output directory: $OUT_DIR"
echo " Workbook: $OUT_DIR/asset_inventory.xlsx"
echo "=================================================="
