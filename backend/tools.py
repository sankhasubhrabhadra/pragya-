from typing import List, Dict, Any, Optional
from loader import Event
import main  # We can import main to access global `all_events` and `incidents` and `profiles`.
import vuln_db

# Helper to format events
def format_events(events: List[Event]) -> Dict[str, Any]:
    return {
        "event_ids": [e.event_id for e in events],
        "events": [e.dict() for e in events]
    }

def search_auth_logs(user: Optional[str] = None, ip: Optional[str] = None, result: Optional[str] = None) -> Dict[str, Any]:
    """Search authentication logs for specific user, IP, or result."""
    matched = []
    for e in main.all_events:
        if e.source != "auth":
            continue
        if user and e.user != user:
            continue
        if ip and e.source_ip != ip:
            continue
        if result and e.event_type != result:
            continue
        matched.append(e)
    return format_events(matched)

def correlate_ip(ip: str) -> Dict[str, Any]:
    """Find every event across all log types involving this IP address."""
    matched = [e for e in main.all_events if e.source_ip == ip or e.dest_ip == ip]
    return format_events(matched)

def analyze_user_behavior(user: str) -> Dict[str, Any]:
    """Compare baseline profile vs incident behavior for a user."""
    profile = main.profiles.get(user)
    if not profile:
        return {"error": "No baseline profile found for this user."}
        
    # Get all anomalous events for this user
    anomalous = [e for e in main.all_events if e.user == user and getattr(e, 'anomaly_score', 0) > 0.6]
    
    return {
        "baseline_profile": profile,
        "anomalous_events_count": len(anomalous),
        "anomalies": format_events(anomalous)
    }

def map_attack_path(incident_id: str) -> Dict[str, Any]:
    """Extract hosts and accounts the attacker moved through from the graph."""
    inc = next((i for i in main.incidents if i.id == incident_id), None)
    if not inc:
        return {"error": "Incident not found."}
        
    users = set()
    hosts = set()
    ips = set()
    for e in inc.events:
        evt = e.event
        if evt.user: users.add(evt.user)
        if evt.host: hosts.add(evt.host)
        if evt.source_ip: ips.add(evt.source_ip)
        if evt.dest_ip: ips.add(evt.dest_ip)
        
    return {
        "users_involved": list(users),
        "hosts_compromised": list(hosts),
        "ips_involved": list(ips),
        "event_ids": [e.event.event_id for e in inc.events]
    }

def check_vulnerabilities(host: str) -> Dict[str, Any]:
    """Check for known vulnerabilities on a specific host asset."""
    vulns = vuln_db.check_host_vulnerabilities(host)
    return {"host": host, "vulnerabilities": vulns, "event_ids": []}

def identify_affected_assets(incident_id: str) -> Dict[str, Any]:
    """Identify accounts, hosts, and data at risk with criticality."""
    inc = next((i for i in main.incidents if i.id == incident_id), None)
    if not inc:
        return {"error": "Incident not found."}
        
    assets = []
    for e in inc.events:
        if e.event.host and e.event.host not in [a["name"] for a in assets]:
            criticality = "high" if "DB" in e.event.host or "FILE" in e.event.host else "medium"
            assets.append({"name": e.event.host, "type": "host", "criticality": criticality})
            
    return {"incident_id": incident_id, "affected_assets": assets, "event_ids": [e.event.event_id for e in inc.events]}

def build_timeline(incident_id: str) -> Dict[str, Any]:
    """Extract an ordered timeline of stages and timestamps."""
    inc = next((i for i in main.incidents if i.id == incident_id), None)
    if not inc:
        return {"error": "Incident not found."}
        
    timeline = []
    for e in inc.events:
        timeline.append({
            "timestamp": e.event.timestamp.isoformat(),
            "stage": e.stage,
            "description": f"{e.event.source}:{e.event.event_type} on {e.event.host or e.event.dest_ip}",
            "event_id": e.event.event_id
        })
        
    return {"timeline": timeline, "event_ids": [e.event.event_id for e in inc.events]}

def generate_containment_plan(incident_id: str) -> Dict[str, Any]:
    """Generate prioritized recommended containment actions for an incident."""
    inc = next((i for i in main.incidents if i.id == incident_id), None)
    if not inc:
        return {"error": "Incident not found."}
        
    actions = []
    
    # We build standard recommendations based on stages reached
    stages = {e.stage for e in inc.events}
    users = {e.event.user for e in inc.events if e.event.user}
    hosts = {e.event.host for e in inc.events if e.event.host}
    ips = {e.event.source_ip for e in inc.events if e.event.source_ip and not e.event.source_ip.startswith("10.")}
    
    if "initial_access" in stages or "credential_compromise" in stages:
        for u in users:
            actions.append({
                "priority": 1, "action": "revoke_sessions", "target": u,
                "reason": f"Account {u} shows signs of compromise.",
                "risk_of_action": "User will be logged out and must reset password.",
                "requires_human_approval": True
            })
            
    if ips:
        for ip in ips:
            actions.append({
                "priority": 1, "action": "block_ip", "target": ip,
                "reason": f"IP {ip} is conducting malicious activity.",
                "risk_of_action": "May block legitimate traffic if IP is shared (e.g. NAT).",
                "requires_human_approval": True
            })
            
    if "lateral_movement" in stages or "privilege_escalation" in stages:
        for h in hosts:
            actions.append({
                "priority": 2, "action": "isolate_host", "target": h,
                "reason": f"Host {h} is being used for lateral movement.",
                "risk_of_action": "Will disrupt services running on this host.",
                "requires_human_approval": True
            })
            
    # Universal recommendations
    actions.append({
        "priority": 3, "action": "preserve_logs", "target": "all_affected",
        "reason": "Preserve evidence for post-incident forensics.",
        "risk_of_action": "None.",
        "requires_human_approval": False
    })
    
    return {"containment_plan": actions, "event_ids": [e.event.event_id for e in inc.events]}

# Expose available tools for the LLM
AVAILABLE_TOOLS = {
    "search_auth_logs": search_auth_logs,
    "correlate_ip": correlate_ip,
    "analyze_user_behavior": analyze_user_behavior,
    "map_attack_path": map_attack_path,
    "check_vulnerabilities": check_vulnerabilities,
    "identify_affected_assets": identify_affected_assets,
    "build_timeline": build_timeline,
    "generate_containment_plan": generate_containment_plan
}
