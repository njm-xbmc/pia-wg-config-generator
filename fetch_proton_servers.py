#!/usr/bin/env python3
import requests
import json
import sys
import urllib3
urllib3.disable_warnings()

API_URL = "https://api.protonvpn.ch/vpn/logicals"
HEADERS = {
    "x-pm-appversion": "Other",
    "x-pm-apiversion": "3",
    "Accept": "application/vnd.protonmail.v1+json"
}

def fetch_servers():
    try:
        r = requests.get(API_URL, headers=HEADERS, timeout=30, verify=False)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        print(f"Failed to fetch ProtonVPN servers: {e}", file=sys.stderr)
        with open("/app/proton_servers.json", "w") as f:
            json.dump({"servers": [], "error": str(e)}, f)
        sys.exit(0)

    servers = []
    for server in data.get("LogicalServers", []):
        if server.get("Status", 0) != 1 or server.get("Tier", 0) != 0:
            continue
        for physical in server.get("Servers", []):
            entry_ip = physical.get("EntryIP")
            if not entry_ip:
                continue
            servers.append({
                "name": server["Name"],
                "country": server["Country"],
                "city": server.get("City", ""),
                "tier": server.get("Tier", 0),
                "entry_ip": entry_ip,
                "load": server.get("Load", 0)
            })

    servers.sort(key=lambda x: (x["country"], x["name"]))

    with open("/app/proton_servers.json", "w") as f:
        json.dump({"servers": servers}, f)

    print(f"Saved {len(servers)} ProtonVPN servers")

if __name__ == "__main__":
    fetch_servers()
