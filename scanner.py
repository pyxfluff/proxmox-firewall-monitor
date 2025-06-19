# pyxfluff 2025

import re
import httpx
import orjson

from time import sleep
from pathlib import Path
from datetime import datetime

# Configuration
PORT_TO_MONITOR = "27017"
REFRESHDUR = 60


def detected(log_text, url, node):
    try:
        known_responses = orjson.loads(Path("data/known_requests.json").read_text("utf8"))
    except FileNotFoundError:
        known_responses = {}

    search = re.compile(
        r"(?P<date>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})[^ ]*.*?SRC=(?P<ip>[0-9.]+).*?DPT=(?P<port>\d+)"
    ).search(log_text)

    date, ip, port = None, None, None

    try:
        date, ip, port = search.group("date"), search.group("ip"), search.group("port")
    except AttributeError as e:
        if log_text == "no content":
            return

        print(f"Failed to unpack: {e}\nOriginal text: {log_text}")

        return

    if port != PORT_TO_MONITOR:
        return

    if ip.startswith("192.") or ip.startswith("10.") or ip.startswith("172."):
        print("Ignoring local IP")

        return

    ip_info = httpx.get(
        f"http://www.ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,org,as,reverse,mobile,proxy,hosting,query"
    ).json()

    known_responses[log_text] = ip_info

    Path("data/known_requests.json").write_text(
        orjson.dumps(known_responses).decode("utf-8")
    )

    httpx.post(
        url,
        json={
            "content": "",
            "embeds": [
                {
                    "title": f"Proxmox firewall tripped on {node}:{PORT_TO_MONITOR}!",
                    "description": f"What a fool of **{ip}**.\n\n**IP Info:**\n```json\n{"\n".join(f"{k.title()}: {v}" for k, v in ip_info.items())}\n```",
                    "color": 14177041,
                    "fields": [
                        {"name": "Date", "value": date, "inline": True},
                        {"name": "Source IP", "value": ip, "inline": True}
                    ],
                    "timestamp": datetime.strptime(
                        date, "%d/%b/%Y:%H:%M:%S"
                    ).isoformat()
                }
            ]
        }
    )

    sleep(1.25)


def request(url, token, secret):
    return httpx.get(
        url, headers={"Authorization": f"PVEAPIToken={token}={secret}"}, verify=False
    )

try:
    nodes = orjson.loads(Path("data/nodes.json").read_text("utf8"))
except Exception:
    print("data/nodes.json was not found, you need it before continuing.")
    exit(1)

def scan():
    for url, auth in nodes.items():
        response = request(url, auth["id"], auth["secret"])

        try:
            response = response.json()
        except Exception as e:
            print(e)

        try:        
            known_responses = orjson.loads(Path("data/known_requests.json").read_text("utf8"))
        except FileNotFoundError:
            known_responses = {}

        for log in response["data"]:
            log = log["t"]

            try:
                _ = known_responses[log]

                if known_responses[log] is None:
                    detected(log, auth["report_url"], auth["name"])
            except KeyError:
                detected(log, auth["report_url"], auth["name"])


while True:
    scan()

    print("Scan complete")

    sleep(REFRESHDUR)
