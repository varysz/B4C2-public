import requests
import sys
import time
import os
import re
from dotenv import load_dotenv
from datetime import datetime

# ---------------------------------------------------------------------------
# jsrepo_rnd_hunt.py
#
# Focused hunter for the /jsrepo?rnd= C2 pattern.
#
# This tool hunts a single high-confidence indicator: any URL of the form
#   <C2_domain>/jsrepo?rnd=...
# injected into a page's DOM. This pattern is never used by legitimate
# developers and is a reliable fingerprint of this threat actor's campaign,
# regardless of whether base64 arrays are used or not.
#
# Usage:
#   python3 jsrepo_rnd_hunt.py <domains_file>
#
# Output (per run, in output_<timestamp>/ directory):
#   - results_jsrepo_hunt.txt   — full findings per domain
#   - c2_domains.txt            — deduplicated list of extracted C2 domains
#   - victim_<domain>.txt       — full DOM snapshot for each infected domain
# ---------------------------------------------------------------------------

load_dotenv()
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")

if not URLSCAN_API_KEY:
    print("❌ No API key found! Create a .env file with URLSCAN_API_KEY=yourkey")
    sys.exit(1)

HEADERS = {
    "api-key": URLSCAN_API_KEY,
    "Content-Type": "application/json"
}

# Each run gets its own timestamped directory — keeps runs clean and separated
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_DIR = f"output_{TIMESTAMP}"
os.makedirs(OUTPUT_DIR, exist_ok=True)

OUTPUT_FILE = os.path.join(OUTPUT_DIR, "results_jsrepo_hunt.txt")
C2_FILE     = os.path.join(OUTPUT_DIR, "c2_domains.txt")

# Collect C2 domains across all scanned domains for final deduped summary
c2s_global = set()

# The single pattern we hunt — matches any URL ending with /jsrepo?rnd=
# Captures the full C2 URL including domain so we can extract it
JSREPO_PATTERN = re.compile(r'(https?://[^\s"\'\\]+/jsrepo\?rnd=)', re.IGNORECASE)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def write_result(line):
    """Write a line to both console and output file."""
    print(line)
    with open(OUTPUT_FILE, "a") as f:
        f.write(line + "\n")


def load_file(filepath):
    """Load non-empty, non-comment lines from a text file."""
    try:
        with open(filepath, "r") as f:
            lines = [line.strip() for line in f
                     if line.strip() and not line.strip().startswith("#")]
        return lines
    except FileNotFoundError:
        print(f"❌ File not found: {filepath}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# urlscan.io helpers — reused from base64array_hunting_v2
# ---------------------------------------------------------------------------

def quick_check(url):
    """
    Check if a recent scan already exists for this URL.
    Reuse window reduced to 120 hours (vs 240 in v2) — jsrepo injections
    can appear and disappear quickly, fresher scans give better signal.
    """
    domain = url.replace("https://", "").replace("http://", "").rstrip("/")
    print(f"🔎 Checking existing scans for: {domain}")

    response = requests.get(
        f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5",
        headers=HEADERS
    )

    if response.status_code != 200:
        print(f"⚠️  Could not search existing scans, will submit new scan.")
        return None

    data = response.json()
    results = data.get("results", [])

    if not results:
        print(f"ℹ️  No existing scans found.")
        return None

    latest = results[0]
    scan_time_str = latest.get("task", {}).get("time", "")

    if scan_time_str:
        scan_time = datetime.strptime(scan_time_str[:19], "%Y-%m-%dT%H:%M:%S")
        age_hours = (datetime.utcnow() - scan_time).total_seconds() / 3600

        if age_hours < 120:
            scan_id = latest.get("_id") or latest.get("task", {}).get("uuid")
            print(f"✅ Found recent scan from {age_hours:.1f} hours ago — reusing it!")
            return scan_id
        else:
            print(f"ℹ️  Most recent scan is {age_hours:.1f} hours old — submitting fresh scan.")
            return None

    return None


def submit_scan(url):
    """Submit a new scan to urlscan.io."""
    print(f"🔍 Submitting to urlscan.io: {url}")
    response = requests.post(
        "https://urlscan.io/api/v1/scan",
        headers=HEADERS,
        json={
            "url": url,
            "visibility": "public",
            "country": "nl",
            "customagent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
    )
    data = response.json()

    if "uuid" not in data:
        print(f"❌ Failed to submit: {data}")
        return None

    scan_id = data["uuid"]
    print(f"✅ Submitted! ID: {scan_id}")
    return scan_id


def wait_for_scan(scan_id):
    """Poll until scan is complete."""
    print("⏳ Waiting for scan", end="", flush=True)
    time.sleep(10)

    for _ in range(24):
        response = requests.get(
            f"https://urlscan.io/api/v1/result/{scan_id}/",
            headers=HEADERS
        )
        if response.status_code == 200:
            print(" ✅ Done!")
            return response.json()
        elif response.status_code == 404:
            print(".", end="", flush=True)
            time.sleep(5)
        else:
            print(f"\n❌ Unexpected status: {response.status_code}")
            return None

    print("\n❌ Scan timed out.")
    return None


def fetch_dom(scan_id):
    """Fetch the DOM snapshot for a scan."""
    response = requests.get(
        f"https://urlscan.io/dom/{scan_id}/",
        headers=HEADERS
    )
    if response.status_code == 200:
        return response.text
    else:
        print(f"❌ Could not fetch DOM: {response.status_code}")
        return None


def save_victim_dom(domain_label, dom):
    """Save full DOM snapshot for a victim domain."""
    safe_name = domain_label.replace(".", "_").replace("/", "_").replace(":", "_")
    filepath = os.path.join(OUTPUT_DIR, f"victim_{safe_name}.txt")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(dom)
    print(f"💾 DOM saved to: {filepath}")


# ---------------------------------------------------------------------------
# Core detection — single focused function
# ---------------------------------------------------------------------------

def hunt_jsrepo_pattern(dom, domain_label):
    """
    Hunt for the /jsrepo?rnd= C2 pattern in the DOM.

    This is a single high-confidence indicator — no legitimate code uses this
    endpoint path. The regex captures the full injected URL so we can extract
    the C2 domain directly from the match without any base64 decoding needed.

    The actor injects URLs of the form:
        <C2_domain>/jsrepo?rnd=<random_value>

    We extract the full URL and the C2 domain separately so both can be
    reported and tracked.

    Returns list of (line_number, full_url, c2_domain) tuples.
    """
    findings = []
    seen_urls = set()
    lines = dom.splitlines()

    for line_number, line in enumerate(lines, start=1):
        for match in JSREPO_PATTERN.finditer(line):
            full_url = match.group(1)

            if full_url in seen_urls:
                continue
            seen_urls.add(full_url)

            # Extract just the C2 domain from the full URL
            # e.g. https://getalib.org/jsrepo?rnd= → getalib.org
            c2_domain = re.sub(r'^https?://', '', full_url).split('/')[0]

            # Skip if the C2 domain matches the scanned domain itself
            # (would be a false positive — site loading its own resources)
            if domain_label.lower() in c2_domain.lower():
                continue

            findings.append((line_number, full_url, c2_domain))

    return findings


# ---------------------------------------------------------------------------
# Scan pipeline
# ---------------------------------------------------------------------------

def get_scan_result(url, domain_label):
    """Obtain a scan result — reuse recent one or submit fresh."""
    scan_id = quick_check(url)

    if not scan_id:
        scan_id = submit_scan(url)
        if not scan_id:
            print(f"❌ Could not obtain scan ID for {domain_label} — skipping.")
            return None
        scan_result = wait_for_scan(scan_id)
        if not scan_result:
            print(f"❌ Scan did not complete for {domain_label} — skipping.")
            return None
        return scan_id

    response = requests.get(
        f"https://urlscan.io/api/v1/result/{scan_id}/",
        headers=HEADERS
    )
    if response.status_code != 200:
        scan_id = submit_scan(url)
        if not scan_id:
            return None
        scan_result = wait_for_scan(scan_id)
        if not scan_result:
            return None

    return scan_id


def scan_domain(url):
    """Full scan pipeline for a single domain."""
    global c2s_global

    if not url.startswith("http"):
        url = "https://" + url

    domain_label = url.replace("https://", "").replace("http://", "").rstrip("/")

    scan_id = get_scan_result(url, domain_label)
    if not scan_id:
        return

    dom = fetch_dom(scan_id)
    if not dom:
        print(f"❌ DOM not available for {domain_label} — skipping.")
        return

    findings = hunt_jsrepo_pattern(dom, domain_label)

    if findings:
        write_result(f"\n{'='*60}")
        write_result(f"🚨 INFECTED: {domain_label}")
        write_result(f"{'='*60}")
        write_result(f"  /jsrepo?rnd= pattern found ({len(findings)} instance(s)):\n")

        for line_number, full_url, c2_domain in findings:
            write_result(f"  🔴 line {line_number}: {full_url}")
            write_result(f"     C2 domain: {c2_domain}")
            c2s_global.add(c2_domain)

        save_victim_dom(domain_label, dom)
    else:
        print(f"  ✅ {domain_label} — no /jsrepo?rnd= pattern found.")

    time.sleep(3)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("\nUsage: python3 jsrepo_rnd_hunt.py <domains_file>")
        print("Example: python3 jsrepo_rnd_hunt.py domains.txt\n")
        sys.exit(1)

    domains_file = sys.argv[1]
    domains = load_file(domains_file)

    print(f"🎯 jsrepo_rnd_hunt — focused /jsrepo?rnd= C2 hunter")
    print(f"📋 {len(domains)} domains to scan")
    print(f"📁 Output directory: {OUTPUT_DIR}")
    print(f"🚀 Starting...\n")

    for domain in domains:
        scan_domain(domain)

    # --- Summary ---
    infected = 0
    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "r") as f:
            infected = f.read().count("🚨 INFECTED:")

    write_result("\n" + "=" * 60)
    write_result(f"📊 Summary: {infected} infected domain(s) out of {len(domains)} scanned")
    write_result(f"🚨 Unique C2 domains found: {len(c2s_global)}")
    write_result("=" * 60)

    # Write deduplicated C2 domains file
    if c2s_global:
        with open(C2_FILE, "w") as f:
            for c2 in sorted(c2s_global):
                f.write(c2 + "\n")
        write_result(f"\n📄 C2 domains saved to: {C2_FILE}")
        write_result("\nC2 domains identified:")
        for c2 in sorted(c2s_global):
            write_result(f"  🔴 {c2}")
