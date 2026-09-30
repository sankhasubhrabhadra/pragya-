from typing import Optional, Tuple
from loader import Event

def map_stage(event: Event, previous_event: Optional[Event] = None) -> Tuple[str, str]:
    """
    Labels an event with a cyber attack stage and provides a reason.
    Possible stages: initial_access, credential_compromise, privilege_escalation, 
                     lateral_movement, data_access, exfiltration, none
    """
    stage = "unknown"
    reason = "Does not match any specific attack stage patterns."

    # 1. Credential Compromise (Successful auth after previous failed auths, or unusual hour)
    if event.source == "auth" and event.event_type == "success":
        # Check if previous was a fail for the same user
        if previous_event and previous_event.source == "auth" and previous_event.event_type == "fail" and previous_event.user == event.user:
            stage = "credential_compromise"
            reason = "Successful login immediately following a failed attempt."
        elif event.timestamp.hour < 5 or event.timestamp.hour > 22:
            stage = "credential_compromise"
            reason = "Successful login at an highly unusual hour."
        else:
            stage = "initial_access"
            reason = "Standard authentication success."
            
    # 2. Initial Access (Failed auths, VPN logins)
    elif event.source == "auth" and event.event_type == "fail":
        stage = "initial_access"
        reason = "Failed authentication attempt (possible brute-force)."
        
    elif event.source == "app" and event.host == "VPN" and event.event_type == "login":
        stage = "initial_access"
        reason = "VPN access establishes initial foothold."

    # 3. Privilege Escalation (Endpoint log indicating privilege change)
    elif event.source == "endpoint" and event.event_type == "privilege_change":
        stage = "privilege_escalation"
        reason = f"Explicit privilege escalation event on {event.host}."
        
    # 4. Lateral Movement (Firewall allowing internal traffic, SSH/RDP, or internal process starts)
    elif event.source == "firewall" and event.event_type == "allow" and event.details and ("Port: 22" in event.details or "Port: 3389" in event.details or "Port: 445" in event.details):
        stage = "lateral_movement"
        reason = f"Internal movement allowed on management port: {event.details}."
        
    elif event.source == "endpoint" and event.event_type == "process_start" and ("bash" in str(event.details) or "cmd" in str(event.details)):
        stage = "lateral_movement"
        reason = "Command shell spawned, indicating possible remote execution."

    # 5. Data Access (DB queries, mass file modifications)
    elif event.source == "app" and "DB" in str(event.host):
        stage = "data_access"
        reason = "Direct interaction with a database server."
        
    elif event.source == "endpoint" and event.event_type == "file_modify":
        stage = "data_access" # could also be "impact" for ransomware, but mapping to data_access as requested
        reason = "File modification detected, possible data staging or encryption."

    # 6. Exfiltration (Large outbound firewall traffic or connections to external IPs on 443/80)
    elif event.source == "firewall" and event.event_type == "allow" and event.details and ("Port: 443" in event.details or "Port: 80" in event.details):
        # If dest_ip is not in the 10.x.x.x range (our internal asset IP space from Stage 1)
        if event.dest_ip and not event.dest_ip.startswith("10."):
            stage = "exfiltration"
            reason = "Outbound external connection allowed, possible exfiltration."
        else:
            stage = "lateral_movement"
            reason = "Internal web/API traffic."

    return stage, reason
