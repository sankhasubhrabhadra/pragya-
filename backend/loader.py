import json
import os
from typing import Optional, List
from pydantic import BaseModel
from datetime import datetime

class Event(BaseModel):
    """Common Event model to standardize all log types."""
    event_id: str
    timestamp: datetime
    source: str  # auth, firewall, endpoint, app
    user: Optional[str] = None
    host: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    event_type: Optional[str] = None
    details: Optional[str] = None
    anomaly_score: float = 0.0
    anomaly_reasons: List[str] = []

def load_logs(data_dir: str = "data") -> List[Event]:
    """Reads all log files from the given directory, standardizes them into Event objects, and sorts them chronologically."""
    events = []
    
    # 1. Load Auth Logs
    auth_path = os.path.join(data_dir, "auth_logs.json")
    if os.path.exists(auth_path):
        with open(auth_path, "r") as f:
            for item in json.load(f):
                events.append(Event(
                    event_id=item["event_id"],
                    timestamp=datetime.fromisoformat(item["timestamp"]),
                    source="auth",
                    user=item.get("user"),
                    source_ip=item.get("source_ip"),
                    event_type=item.get("result"),  # e.g., success, fail
                    details=f"Method: {item.get('method')}"
                ))

    # 2. Load Firewall Logs
    fw_path = os.path.join(data_dir, "firewall_logs.json")
    if os.path.exists(fw_path):
        with open(fw_path, "r") as f:
            for item in json.load(f):
                events.append(Event(
                    event_id=item["event_id"],
                    timestamp=datetime.fromisoformat(item["timestamp"]),
                    source="firewall",
                    source_ip=item.get("source_ip"),
                    dest_ip=item.get("dest_ip"),
                    event_type=item.get("action"),  # e.g., allow, deny
                    details=f"Port: {item.get('port')}"
                ))

    # 3. Load Endpoint Logs
    ep_path = os.path.join(data_dir, "endpoint_logs.json")
    if os.path.exists(ep_path):
        with open(ep_path, "r") as f:
            for item in json.load(f):
                events.append(Event(
                    event_id=item["event_id"],
                    timestamp=datetime.fromisoformat(item["timestamp"]),
                    source="endpoint",
                    user=item.get("user"),
                    host=item.get("host"),
                    event_type=item.get("event_type"),  # e.g., process_start
                    details=item.get("details")
                ))

    # 4. Load App Logs
    app_path = os.path.join(data_dir, "app_logs.json")
    if os.path.exists(app_path):
        with open(app_path, "r") as f:
            for item in json.load(f):
                events.append(Event(
                    event_id=item["event_id"],
                    timestamp=datetime.fromisoformat(item["timestamp"]),
                    source="app",
                    user=item.get("user"),
                    host=item.get("app"),  # treat app name as the host/asset
                    event_type=item.get("action"),  # e.g., login, query
                    details=f"Status: {item.get('status')}"
                ))

    # Sort all events chronologically by timestamp
    events.sort(key=lambda x: x.timestamp)
    return events
