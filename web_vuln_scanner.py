from flask import Flask, render_template, request, redirect, url_for, send_file
import requests, re, uuid, json
from bs4 import BeautifulSoup
from urllib.parse import urljoin

app = Flask(__name__)

scans = {}

def crawl_and_scan(start_url, max_pages=50):
    visited, to_visit = set(), [start_url]
    results = []
    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited: continue
        visited.add(url)
        try:
            r = requests.get(url, timeout=5)
            soup = BeautifulSoup(r.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action')
                target = urljoin(url, action) if action else url
                data = {i.get('name', 'input'): "<script>alert(1)</script>" for i in form.find_all('input')}
                try:
                    res = requests.post(target, data=data, timeout=5)
                    if "<script>alert(1)</script>" in res.text:
                        results.append({"type": "XSS", "url": target, "evidence": "Payload reflected", "severity": "high"})
                except: pass
            if re.search(r"error.*sql|syntax.*mysql", r.text, re.I):
                results.append({"type": "SQLi", "url": url, "evidence": "SQL error detected", "severity": "high"})
            for a in soup.find_all('a', href=True):
                link = urljoin(url, a['href'])
                if link.startswith(start_url) and link not in visited:
                    to_visit.append(link)
        except: pass
    return results

@app.route("/")
def index():
    return render_template("index.html", scans=scans)

@app.route("/start", methods=["POST"])
def start_scan():
    start_url = request.form['start_url']
    max_pages = int(request.form.get('max_pages', 50))
    sid = str(uuid.uuid4())[:8]
    scans[sid] = {"start_url": start_url, "status": "running", "results": []}
    results = crawl_and_scan(start_url, max_pages)
    scans[sid]["results"] = results
    scans[sid]["status"] = "done"
    return redirect(url_for("scan_report", sid=sid))

@app.route("/scan/<sid>")
def scan_report(sid):
    return render_template("scan.html", sid=sid, info=scans[sid])

@app.route("/download/<sid>")
def download_report(sid):
    path = f"/tmp/report_{sid}.json"
    with open(path, "w") as f:
        json.dump(scans[sid], f, indent=2)
    return send_file(path, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
