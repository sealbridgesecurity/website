#!/usr/bin/env python3
"""Tell IndexNow search engines (Bing, Yandex and others) which pages changed.

Usage:
  indexnow.py all                 submit every URL in sitemap.xml
  indexnow.py changed BASE HEAD   submit only pages changed between two commits

The key is public by design: IndexNow checks it by fetching /<key>.txt from the site.
"""
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

HOST = "sealbridgesecurity.com"
SITE = "https://" + HOST
KEY = "968998e606478ee267515a024f2dc778"
KEY_LOCATION = f"{SITE}/{KEY}.txt"
ENDPOINT = "https://api.indexnow.org/indexnow"
NS = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}


def sitemap_urls():
    root = ET.parse("sitemap.xml").getroot()
    return [loc.text.strip() for loc in root.findall("sm:url/sm:loc", NS)]


def url_for(path):
    """Map a repo file to its live address (the host serves pages without .html)."""
    if path == "index.html":
        return SITE + "/"
    if path.endswith(".html") and "/" not in path:
        return f"{SITE}/{path[:-5]}"
    return None


def changed_urls(base, head, known):
    out = subprocess.run(
        ["git", "diff", "--name-only", base, head],
        check=True, capture_output=True, text=True,
    ).stdout.split()
    if "sitemap.xml" in out:
        return known
    urls = {url_for(p) for p in out}
    return [u for u in known if u in urls]


def wait_for_key(timeout=600):
    """Wait until the live site serves the key file, so IndexNow can verify it."""
    deadline = time.time() + timeout
    while True:
        try:
            req = urllib.request.Request(KEY_LOCATION, headers={"User-Agent": "sealbridge-indexnow"})
            with urllib.request.urlopen(req, timeout=20) as r:
                if r.read().decode().strip() == KEY:
                    return
        except urllib.error.URLError:
            pass
        if time.time() > deadline:
            sys.exit(f"Key file not live at {KEY_LOCATION}; not submitting.")
        time.sleep(15)


def submit(urls):
    body = json.dumps({
        "host": HOST, "key": KEY, "keyLocation": KEY_LOCATION, "urlList": urls,
    }).encode()
    req = urllib.request.Request(
        ENDPOINT, data=body, method="POST",
        headers={"Content-Type": "application/json; charset=utf-8"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            status = r.status
    except urllib.error.HTTPError as e:
        status = e.code
    print(f"IndexNow answered {status} for {len(urls)} URL(s):")
    for u in urls:
        print("  " + u)
    # 200 = accepted, 202 = accepted while the key is still being checked.
    if status not in (200, 202):
        sys.exit(f"IndexNow rejected the submission (HTTP {status}).")


def main():
    known = sitemap_urls()
    if sys.argv[1:2] == ["changed"] and len(sys.argv) == 4:
        urls = changed_urls(sys.argv[2], sys.argv[3], known)
    elif sys.argv[1:2] == ["all"]:
        urls = known
    else:
        sys.exit(__doc__)
    if not urls:
        print("No pages in the sitemap changed; nothing to submit.")
        return
    wait_for_key()
    submit(urls)


if __name__ == "__main__":
    main()
