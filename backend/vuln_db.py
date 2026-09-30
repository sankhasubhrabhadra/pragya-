import json
import os

def load_vulnerabilities(path: str = "data/vulnerabilities.json"):
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return json.load(f)

def check_host_vulnerabilities(host: str):
    """Returns a list of vulnerabilities mapped to a specific host."""
    vulns = load_vulnerabilities()
    # In a real system, we'd look up the host's software inventory.
    # Here, we just match by host string if the JSON defines it, or return some based on hardcoded rules.
    mapped = []
    for v in vulns:
        if host in v.get("known_hosts", []):
            # Strip known_hosts before returning
            v_out = {k: v[k] for k in v if k != "known_hosts"}
            mapped.append(v_out)
    return mapped
