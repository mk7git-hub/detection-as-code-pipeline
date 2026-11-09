"""Create or update each converted rule as a Splunk saved search over the REST API.

Needs SPLUNK_URL (https://host:8089) and SPLUNK_TOKEN. Skips cleanly when they are not set,
so forks and pull requests never touch Splunk.
"""
import os
import pathlib
import sys
import urllib.parse
import urllib.request
import ssl

url, token = os.environ.get("SPLUNK_URL"), os.environ.get("SPLUNK_TOKEN")
if not url or not token:
    print("SPLUNK_URL or SPLUNK_TOKEN not set; skipping deploy")
    sys.exit(0)

ctx = ssl.create_default_context()
if os.environ.get("SPLUNK_INSECURE") == "1":  # lab Splunk with a self-signed cert only
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE

def post(path, data):
    req = urllib.request.Request(url.rstrip("/") + path, data=urllib.parse.urlencode(data).encode(),
                                 headers={"Authorization": f"Bearer {token}"})
    return urllib.request.urlopen(req, context=ctx, timeout=30)

base = "/servicesNS/nobody/search/saved/searches"
for spl in sorted(pathlib.Path("build/splunk").glob("*.spl")):
    name = f"DaC - {spl.stem}"
    body = {"search": "index=aws sourcetype=aws:cloudtrail " + spl.read_text().strip(),
            "cron_schedule": "*/15 * * * *", "is_scheduled": "1",
            "dispatch.earliest_time": "-20m", "dispatch.latest_time": "now",
            "alert_type": "number of events", "alert_comparator": "greater than", "alert_threshold": "0"}
    try:
        post(f"{base}/{urllib.parse.quote(name)}", body)
        print(f"updated {name}")
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
        post(base, {"name": name, **body})
        print(f"created {name}")
