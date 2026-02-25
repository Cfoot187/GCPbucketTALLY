#!/usr/bin/env python3
"""
gcp_bucket_scanner.py
Unauthenticated scan of public GCS buckets.
Reads target buckets from buckets.txt, paginates the full object listing,
and writes a summary report to a timestamped file.

Usage:
    python3 gcp_bucket_scanner.py
    python3 gcp_bucket_scanner.py --buckets buckets.txt --output my_report.txt
"""

import argparse
import os
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GCS_BASE        = "https://storage.googleapis.com"
PAGE_SIZE       = 1000
REQUEST_TIMEOUT = 30  # seconds


# ---------------------------------------------------------------------------
# ANSI color helpers (auto-disabled when not writing to a real terminal)
# ---------------------------------------------------------------------------

def _c(code: str, text: str) -> str:
    if not sys.stdout.isatty() if hasattr(sys.stdout, "isatty") else True:
        return text
    return f"\033[{code}m{text}\033[0m"

def cyan(t):   return _c("96", t)
def yellow(t): return _c("93", t)
def green(t):  return _c("92", t)
def red(t):    return _c("91", t)
def dim(t):    return _c("2",  t)
def bold(t):   return _c("1",  t)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = r"""
  ██████╗███████╗ ██████╗  ██████╗ ████████╗   ██╗ █████╗  ███████╗
 ██╔════╝██╔════╝██╔═══██╗██╔═══██╗╚══██╔══╝  ███║██╔══██╗ ╚════██║
 ██║     █████╗  ██║   ██║██║   ██║   ██║      ██║╚█████╔╝     ██╔╝ 
 ██║     ██╔══╝  ██║   ██║██║   ██║   ██║      ██║██╔══██╗    ██╔╝  
 ╚██████╗██║     ╚██████╔╝╚██████╔╝   ██║      ██║╚█████╔╝   ██║   
  ╚═════╝╚═╝      ╚═════╝  ╚═════╝    ╚═╝      ╚═╝ ╚════╝    ╚═╝   
"""

TAGLINE  = "  GCP Public Bucket Scanner  //  Unauthenticated  //  v2.0"
DIVIDER  = "  " + "─" * 66


def print_banner():
    print(cyan(BANNER))
    print(yellow(TAGLINE))
    print(dim(DIVIDER))
    print()


# ---------------------------------------------------------------------------
# HTTP session with retry logic
# ---------------------------------------------------------------------------

def build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=4,
        backoff_factor=1.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


SESSION = build_session()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} PB"


def file_ext(key: str) -> str:
    filename = key.split("/")[-1]
    if "." in filename:
        return "." + filename.rsplit(".", 1)[-1].lower()
    return "<no extension>"


def ns_helpers(root: ET.Element):
    """Return (find, findall) closures that handle the XML namespace transparently."""
    ns = root.tag.split("}")[0].lstrip("{") if root.tag.startswith("{") else ""

    def find(elem, tag):
        return elem.find(f"{{{ns}}}{tag}" if ns else tag)

    def findall(elem, tag):
        return elem.findall(f"{{{ns}}}{tag}" if ns else tag)

    return find, findall


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

class BucketScanError(Exception):
    pass


def iter_objects(bucket: str):
    """
    Yield (key, size_bytes) for every object in the bucket.
    Raises BucketScanError on unrecoverable HTTP errors.
    """
    token = None
    page  = 0

    while True:
        url = f"{GCS_BASE}/{quote(bucket, safe='')}?list-type=2&max-keys={PAGE_SIZE}"
        if token:
            url += f"&continuation-token={quote(token)}"

        try:
            resp = SESSION.get(url, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            raise BucketScanError(f"Network error: {exc}") from exc

        if resp.status_code == 403:
            raise BucketScanError("Access denied (403) — bucket is private or listing is disabled.")
        if resp.status_code == 404:
            raise BucketScanError("Bucket not found (404) — check the name or public access settings.")
        if resp.status_code != 200:
            raise BucketScanError(f"Unexpected HTTP {resp.status_code}: {resp.text[:300]}")

        try:
            root = ET.fromstring(resp.content)
        except ET.ParseError as exc:
            raise BucketScanError(f"Malformed XML in response: {exc}") from exc

        find, findall = ns_helpers(root)
        page += 1

        for item in findall(root, "Contents"):
            key_el  = find(item, "Key")
            size_el = find(item, "Size")
            key  = key_el.text  if key_el  is not None else ""
            size = int(size_el.text) if size_el is not None else 0
            yield key, size

        truncated = find(root, "IsTruncated")
        if truncated is not None and truncated.text.strip().lower() == "true":
            next_token = find(root, "NextContinuationToken")
            if next_token is not None and next_token.text:
                token = next_token.text
                print(dim(f"    page {page} fetched, continuing..."), flush=True)
            else:
                print(yellow("  [WARN] IsTruncated=true but no continuation token returned. Stopping early."))
                break
        else:
            print(dim(f"    page {page} fetched (done)."), flush=True)
            break


def scan_bucket(bucket: str) -> dict | None:
    print(f"\n  {bold(cyan('►'))} {bold(bucket)}")
    print(dim("  " + "─" * 60))

    total_size  = 0
    total_count = 0
    by_ext      = defaultdict(lambda: {"count": 0, "size": 0})

    try:
        for key, size in iter_objects(bucket):
            ext = file_ext(key)
            total_size           += size
            total_count          += 1
            by_ext[ext]["count"] += 1
            by_ext[ext]["size"]  += size
    except BucketScanError as exc:
        print(f"  {red('[SKIP]')} {exc}")
        return None

    if total_count == 0:
        print(yellow("  No objects returned — bucket may be empty."))
        return None

    print(f"\n  {green('gs://' + bucket)}")
    print(f"  Objects : {bold(f'{total_count:,}')}")
    print(f"  Size    : {bold(fmt_size(total_size))} {dim(f'({total_size:,} bytes)')}")
    print(f"\n  {dim('Extension'):<33} {dim('Files'):>10} {dim('Size'):>14}")
    print(dim("  " + "-" * 50))
    for ext, data in sorted(by_ext.items(), key=lambda x: x[1]["count"], reverse=True):
        print(f"  {ext:<24} {data['count']:>10,} {fmt_size(data['size']):>14}")
    print(dim("  " + "-" * 50))
    print(f"  {'TOTAL':<24} {bold(f'{total_count:>10,}')} {bold(fmt_size(total_size)):>14}")

    return {
        "bucket":      bucket,
        "total_count": total_count,
        "total_size":  total_size,
        "by_ext":      dict(by_ext),
    }


# ---------------------------------------------------------------------------
# Output — mirrors terminal writes to a plain-text log file (no ANSI codes)
# ---------------------------------------------------------------------------

class Tee:
    """
    Mirrors all writes to both stdout and a file.
    Strips ANSI escape codes from the file copy so the report is clean text.
    """
    import re
    _ANSI = re.compile(r"\033\[[0-9;]*m")

    def __init__(self, path: str):
        self._terminal = sys.stdout
        self._file     = open(path, "w", encoding="utf-8")
        self._file.write("GCP Bucket Scan\n")
        self._file.write(f"Run at : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self._file.write("=" * 62 + "\n\n")

    def write(self, data: str):
        self._terminal.write(data)
        self._file.write(self._ANSI.sub("", data))

    def flush(self):
        self._terminal.flush()
        self._file.flush()

    def isatty(self):
        return self._terminal.isatty()

    def close(self, footer: str = ""):
        if footer:
            self._file.write(self._ANSI.sub("", footer))
        self._file.close()
        sys.stdout = self._terminal


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Unauthenticated GCS bucket scanner.")
    parser.add_argument("--buckets", default="buckets.txt", help="Path to bucket list (default: buckets.txt)")
    parser.add_argument("--output",  default=None,          help="Output file path (default: auto-timestamped)")
    return parser.parse_args()


def load_buckets(path: str) -> list[str]:
    if not os.path.exists(path):
        sys.exit(red(f"[ERROR] Bucket file not found: {path}"))
    with open(path) as f:
        buckets = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if not buckets:
        sys.exit(red(f"[ERROR] No bucket names found in {path}"))
    return buckets


def main():
    print_banner()

    args    = parse_args()
    buckets = load_buckets(args.buckets)

    output_path = args.output or f"gcp_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    tee = Tee(output_path)
    sys.stdout = tee

    print(f"  {dim('Targets     :')} {', '.join(buckets)}")
    print(f"  {dim('Output file :')} {output_path}")

    results = [r for b in buckets if (r := scan_bucket(b)) is not None]

    if len(results) > 1:
        grand_count = sum(r["total_count"] for r in results)
        grand_size  = sum(r["total_size"]  for r in results)
        combined    = defaultdict(lambda: {"count": 0, "size": 0})
        for r in results:
            for ext, data in r["by_ext"].items():
                combined[ext]["count"] += data["count"]
                combined[ext]["size"]  += data["size"]

        print(f"\n\n{'='*62}")
        print(bold(f"  GRAND TOTAL — {len(results)} buckets"))
        print(f"{'='*62}")
        print(f"  Objects : {bold(f'{grand_count:,}')}")
        print(f"  Size    : {bold(fmt_size(grand_size))} {dim(f'({grand_size:,} bytes)')}")
        print(f"\n  {dim('Extension'):<33} {dim('Files'):>10} {dim('Size'):>14}")
        print(dim("  " + "-" * 50))
        for ext, data in sorted(combined.items(), key=lambda x: x[1]["count"], reverse=True):
            print(f"  {ext:<24} {data['count']:>10,} {fmt_size(data['size']):>14}")
        print(dim("  " + "-" * 50))
        print(f"  {'TOTAL':<24} {bold(f'{grand_count:>10,}')} {bold(fmt_size(grand_size)):>14}")

    footer = f"\n\nCompleted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    tee.close(footer)
    print(f"\n  {green('[+]')} Report written to: {bold(os.path.abspath(output_path))}\n")


if __name__ == "__main__":
    main()