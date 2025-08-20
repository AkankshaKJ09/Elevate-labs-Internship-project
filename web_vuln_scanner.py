"""
Web Vulnerability Scanner (Flask + Python)
- Background scanning (non-blocking)
- Improved payloads and detection
- Bootstrap UI using templates/
- Deployable on Render (gunicorn)
IMPORTANT: Only scan apps you own or have permission to test.
"""

import os
import re
import time
import json
import uuid
import threading
import logging
from queue import Queue
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, abort

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# --- Configuration ---
REQUESTS_TIMEOUT = 8          # seconds per request
MAX_PAGES_DEFAULT = 50
POLITENESS_DELAY = 0.3       # seconds between requests
USER_AGENT = "WebVulnScanner/1.0 (+https://example.com)"
HEADERS = {"User-Agent": USER_AGENT}

# Payloads (stronger but non-destructive)
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"'><svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<svg><script>alert(1)</script></svg>"
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1 -- ",
    "'\";--"
]

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"mysql_fetch",
    r"ORA-\d+",
    r"PG::SyntaxError",
    r"SQL syntax.*MySQL",
]

# Simple in-memory store for scans
scans = {}

# --- Helpers ---


def same_domain(a, b):
    try:
        return urlparse(a).netloc == urlparse(b).netloc
    except Exception:
        return False


def normalize_url(base, link):
    if not link:
        return base
    return urljoin(base, link.split("#")[0])


def safe_get(session, url, **kwargs):
    try:
        resp = session.get(url, timeout=REQUESTS_TIMEOUT, allow_redirects=True, **kwargs)
        return resp
    except Exception as e:
        app.logger.debug(f"GET error for {url}: {e}")
        return None


def find_links(base, soup):
    links = set()
    for a in soup.find_all("a", href=True):
        href = a.get("href").strip()
        if href.startswith("javascript:") or href.startswith("mailto:"):
            continue
        links.add(normalize_url(base, href))
    return links


def extract_forms(soup):
    forms = []
    for form in soup.find_all("form"):
        f = {
            "action": form.get("action") or "",
            "method": (form.get("method") or "get").lower(),
            "inputs": []
        }
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            f["inputs"].append({"name": name, "type": inp.get("type", "text")})
        forms.append(f)
    return forms


def has_csrf_token(form):
    for inp in form.get("inputs", []):
        if re.search(r"csrf|token|auth", inp["name"], re.I):
            return True
    return False


def detect_sql_error(text):
    if not text:
        return False
    for pat in SQL_ERROR_PATTERNS:
        if re.search(pat, text, re.I):
            return pat
    return False


# --- Scanner Implementation ---


class Scanner:
    def __init__(self, start_url, max_pages=MAX_PAGES_DEFAULT):
        self.start_url = start_url.rstrip("/")
        self.max_pages = max_pages
        self.visited = set()
        self.to_visit = Queue()
        self.to_visit.put(self.start_url)
        self.results = []
        self.session = requests.Session()
        self.session.headers.update(HEADERS)

    def crawl_and_test(self):
        while not self.to_visit.empty() and len(self.visited) < self.max_pages:
            url = self.to_visit.get()
            if url in self.visited:
                continue
            app.logger.info(f"Scanning: {url}")
            resp = safe_get(self.session, url)
            time.sleep(POLITENESS_DELAY)
            if not resp or resp.status_code >= 400:
                self.visited.add(url)
                continue

            text = resp.text or ""
            soup = BeautifulSoup(text, "html.parser")

            # discover links (same domain only)
            for link in find_links(url, soup):
                if same_domain(self.start_url, link) and link not in self.visited:
                    self.to_visit.put(link)

            # forms: CSRF, XSS, SQLi
            forms = extract_forms(soup)
            for form in forms:
                action = normalize_url(url, form["action"]) if form["action"] else url
                if not has_csrf_token(form):
                    self.results.append({
                        "url": action,
                        "type": "csrf_missing",
                        "evidence": f"Form at {action} appears to not include CSRF token.",
                        "severity": "medium"
                    })

                # Build payload dict
                if not form["inputs"]:
                    continue
                for payload in XSS_PAYLOADS:
                    data = {inp["name"]: payload for inp in form["inputs"]}
                    try:
                        if form["method"] == "post":
                            r2 = self.session.post(action, data=data, timeout=REQUESTS_TIMEOUT)
                        else:
                            r2 = self.session.get(action, params=data, timeout=REQUESTS_TIMEOUT)
                    except Exception:
                        continue
                    time.sleep(POLITENESS_DELAY)
                    if r2 and payload in (r2.text or ""):
                        self.results.append({
                            "url": action,
                            "type": "xss_reflected",
                            "evidence": payload,
                            "severity": "high"
                        })
                        break  # found XSS for this form

                # SQLi via form
                for payload in SQLI_PAYLOADS:
                    data = {inp["name"]: payload for inp in form["inputs"]}
                    try:
                        if form["method"] == "post":
                            r3 = self.session.post(action, data=data, timeout=REQUESTS_TIMEOUT)
                        else:
                            r3 = self.session.get(action, params=data, timeout=REQUESTS_TIMEOUT)
                    except Exception:
                        continue
                    time.sleep(POLITENESS_DELAY)
                    pattern = detect_sql_error(r3.text if r3 else "")
                    if pattern:
                        self.results.append({
                            "url": action,
                            "type": "sqli_error",
                            "evidence": f"Detected SQL error pattern: {pattern}",
                            "severity": "high"
                        })
                        break

            # test URL params
            parsed = urlparse(url)
            if parsed.query:
                # parse simple query and replace values with payloads
                params_raw = parsed.query.split("&")
                keys = [p.split("=")[0] for p in params_raw if p]
                if keys:
                    for payload in XSS_PAYLOADS:
                        q = {k: payload for k in keys}
                        try:
                            base = parsed._replace(query=None).geturl()
                            r4 = self.session.get(base, params=q, timeout=REQUESTS_TIMEOUT)
                        except Exception:
                            continue
                        time.sleep(POLITENESS_DELAY)
                        if r4 and payload in (r4.text or ""):
                            self.results.append({
                                "url": url,
                                "type": "xss_param_reflected",
                                "evidence": payload,
                                "severity": "high"
                            })
                            break
                    for payload in SQLI_PAYLOADS:
                        q = {k: payload for k in keys}
                        try:
                            base = parsed._replace(query=None).geturl()
                            r5 = self.session.get(base, params=q, timeout=REQUESTS_TIMEOUT)
                        except Exception:
                            continue
                        time.sleep(POLITENESS_DELAY)
                        pattern = detect_sql_error(r5.text if r5 else "")
                        if pattern:
                            self.results.append({
                                "url": url,
                                "type": "sqli_error",
                                "evidence": f"Detected SQL error pattern: {pattern}",
                                "severity": "high"
                            })
                            break

            self.visited.add(url)

    def run(self):
        try:
            self.crawl_and_test()
        except Exception as e:
            app.logger.exception(f"Scanner crashed: {e}")


# --- Background management ---


def start_scan_background(sid, start_url, max_pages):
    app.logger.info(f"Starting background scan {sid} -> {start_url} (max {max_pages})")
    scanner = Scanner(start_url, max_pages=max_pages)
    scanner.run()
    scans[sid]["results"] = scanner.results
    scans[sid]["status"] = "done"
    scans[sid]["finished_at"] = time.time()
    app.logger.info(f"Scan {sid} finished with {len(scanner.results)} findings")


# --- Flask routes ---


@app.route("/")
def index():
    return render_template("index.html", scans=scans)


@app.route("/start", methods=["POST"])
def start_scan():
    start_url = request.form.get("start_url", "").strip()
    if not start_url:
        return redirect(url_for("index"))
    max_pages = int(request.form.get("max_pages") or MAX_PAGES_DEFAULT)
    # basic URL validation
    if not (start_url.startswith("http://") or start_url.startswith("https://")):
        start_url = "http://" + start_url
    sid = uuid.uuid4().hex[:8]
    scans[sid] = {
        "start_url": start_url,
        "status": "running",
        "results": [],
        "started_at": time.time()
    }
    thread = threading.Thread(target=start_scan_background, args=(sid, start_url, max_pages), daemon=True)
    thread.start()
    return redirect(url_for("view_scan", sid=sid))


@app.route("/scan/<sid>")
def view_scan(sid):
    info = scans.get(sid)
    if not info:
        abort(404)
    return render_template("scan.html", sid=sid, info=info)


@app.route("/download/<sid>")
def download_report(sid):
    info = scans.get(sid)
    if not info or info.get("status") != "done":
        abort(404)
    fname = f"/tmp/webscan_{sid}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"start_url": info["start_url"], "results": info["results"]}, f, indent=2)
    return send_file(fname, as_attachment=True, download_name=f"webscan_{sid}.json")


@app.route("/api/scan/<sid>")
def api_scan_status(sid):
    info = scans.get(sid)
    if not info:
        return jsonify({"error": "not found"}), 404
    return jsonify(info)


# --- Run (for local debugging) ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
