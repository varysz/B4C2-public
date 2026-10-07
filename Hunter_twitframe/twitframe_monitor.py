"""
twitframe_monitor.py - Monitor twitframe[.]com redirect destination.

twitframe[.]com is a hijacked domain used as a persistent redirect relay
by a threat actor. The actor rotates the destination domain whenever the
current bad domain gets reported/taken down. This script tracks where
twitframe[.]com is currently pointing, detects changes, and logs a full
history with timestamps.

Usage:
    python twitframe_monitor.py

    Run manually or as a daily cronjob:
        0 9 * * * /usr/bin/python3 /path/to/twitframe_monitor.py

Output:
    twitframe_history.txt   - persistent log of all observed destinations
    twitframe_latest.txt    - current destination only (easy to grep/check)

ThreatFox:
    When a new destination is detected, a ready-to-copy ThreatFox
    submission block is printed to the console.
"""

import os
import sys
import requests
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TARGET_URL        = "https://twitframe.com/"
HISTORY_FILE      = "twitframe_history.txt"
LATEST_FILE       = "twitframe_latest.txt"
REQUEST_TIMEOUT   = 15   # seconds
USER_AGENT        = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


# ---------------------------------------------------------------------------
# Redirect follower
# ---------------------------------------------------------------------------

def follow_redirects(url):
    """
    Follow the full redirect chain from a URL.

    Args:
        url: Starting URL to follow.

    Returns:
        dict with:
            final_url    (str)        : final destination URL
            final_domain (str)        : domain of final destination
            chain        (list[str])  : full list of URLs in redirect chain
            status_codes (list[int])  : HTTP status at each hop
            error        (str|None)   : error message if request failed
    """
    try:
        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT})

        response = session.get(
            url,
            allow_redirects=True,
            timeout=REQUEST_TIMEOUT
        )

        # Build full chain from response history + final response
        chain        = [r.url for r in response.history] + [response.url]
        status_codes = [r.status_code for r in response.history] + [response.status_code]
        final_url    = response.url
        final_domain = extract_domain(final_url)

        return {
            "final_url":    final_url,
            "final_domain": final_domain,
            "chain":        chain,
            "status_codes": status_codes,
            "error":        None
        }

    except requests.exceptions.ConnectionError as e:
        return {"final_url": None, "final_domain": None,
                "chain": [], "status_codes": [], "error": f"ConnectionError: {e}"}
    except requests.exceptions.Timeout:
        return {"final_url": None, "final_domain": None,
                "chain": [], "status_codes": [], "error": "Timeout"}
    except requests.exceptions.RequestException as e:
        return {"final_url": None, "final_domain": None,
                "chain": [], "status_codes": [], "error": str(e)}


def extract_domain(url):
    """Extract bare domain from a full URL."""
    if not url:
        return None
    domain = url.replace("https://", "").replace("http://", "").lstrip("www.")
    return domain.split("/")[0].strip()


# ---------------------------------------------------------------------------
# History management
# ---------------------------------------------------------------------------

def load_last_known():
    """
    Read the last known destination from twitframe_latest.txt.

    Returns:
        Last known domain string, or None if file doesn't exist.
    """
    if not os.path.exists(LATEST_FILE):
        return None
    with open(LATEST_FILE, "r") as f:
        content = f.read().strip()
    return content if content else None


def save_latest(domain):
    """Overwrite twitframe_latest.txt with the current destination."""
    with open(LATEST_FILE, "w") as f:
        f.write(domain + "\n")


def append_history(entry):
    """
    Append a single line to the persistent history log.

    Format:
        2026-04-14 21:01:28 UTC | twitframe.com | → xoilaczzqipxt.tv | NEW | chain: twitframe.com → xoilaczzqipxt.tv
    """
    with open(HISTORY_FILE, "a") as f:
        f.write(entry + "\n")


def load_history():
    """Return full history file contents, or empty string if not found."""
    if not os.path.exists(HISTORY_FILE):
        return ""
    with open(HISTORY_FILE, "r") as f:
        return f.read()


# ---------------------------------------------------------------------------
# ThreatFox helper
# ---------------------------------------------------------------------------

def print_threatfox_block(domain, final_url):
    """Print a ready-to-copy ThreatFox submission block."""
    print("\n" + "=" * 60)
    print("  📋 THREATFOX SUBMISSION — copy & paste")
    print("=" * 60)
    print(f"  IOC type   : domain")
    print(f"  IOC        : {domain}")
    print(f"  Malware    : Unknown malware")
    print(f"  Confidence : 75%")
    print(f"  Tags       : twitframe, redirect-relay, hijacked-domain")
    print(f"  Reference  : https://twitframe.com/")
    print(f"  Comment    : twitframe[.]com (hijacked domain) 301-redirects")
    print(f"               to {domain} as of {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"  Full URL   : {final_url}")
    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{now_str}] twitframe monitor starting...")
    print(f"[CHECK] Following redirects from {TARGET_URL}")

    result = follow_redirects(TARGET_URL)

    # Handle request failure
    if result["error"]:
        msg = f"{now_str} | ERROR | {result['error']}"
        print(f"[ERROR] {result['error']}")
        append_history(msg)
        sys.exit(1)

    final_domain = result["final_domain"]
    final_url    = result["final_url"]

    # Build chain summary string
    chain_str = " → ".join(extract_domain(u) or u for u in result["chain"])
    codes_str = " → ".join(str(c) for c in result["status_codes"])

    print(f"[OK]    Final destination : {final_url}")
    print(f"[OK]    Redirect chain    : {chain_str}")
    print(f"[OK]    Status codes      : {codes_str}")

    # Compare to last known destination
    last_known = load_last_known()

    if last_known is None:
        status = "FIRST_RUN"
        print(f"\n[INFO] First run — recording initial destination: {final_domain}")
    elif final_domain != last_known:
        status = "CHANGED"
        print(f"\n[🚨 ALERT] Destination CHANGED!")
        print(f"  Previous : {last_known}")
        print(f"  Current  : {final_domain}")
        print_threatfox_block(final_domain, final_url)
    else:
        status = "SAME"
        print(f"\n[OK] Destination unchanged: {final_domain}")

    # Log to history
    history_line = (
        f"{now_str} | {TARGET_URL} | → {final_domain} "
        f"| {status} | chain: {chain_str} | codes: {codes_str}"
    )
    append_history(history_line)
    save_latest(final_domain)

    # Always show last 5 history entries for context
    print("\n--- Recent history (last 5 entries) ---")
    history = load_history().strip().splitlines()
    for line in history[-5:]:
        print(f"  {line}")
    print("---------------------------------------")
    print(f"\n[DONE] History saved to {HISTORY_FILE}")


if __name__ == "__main__":
    main()
