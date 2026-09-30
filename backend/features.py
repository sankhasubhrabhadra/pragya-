import pandas as pd
import numpy as np
from typing import List, Dict, Any
from loader import Event

def events_to_features(events: List[Event], profiles: Dict[str, Any]) -> pd.DataFrame:
    """
    Converts a list of events into a pandas DataFrame of 10-minute windowed features per user.
    """
    if not events:
        return pd.DataFrame()

    # Convert events to a flattened dictionary list for pandas
    rows = []
    for e in events:
        user = e.user or "SYSTEM"
        rows.append({
            "event_id": e.event_id,
            "timestamp": e.timestamp,
            "user": user,
            "source": e.source,
            "event_type": e.event_type,
            "host": e.host or e.dest_ip,
            "source_ip": e.source_ip,
            "details": e.details or ""
        })
        
    df = pd.DataFrame(rows)
    df.set_index("timestamp", inplace=True)
    
    # We will compute windowed features per user
    feature_rows = []
    
    # Group by user and 10-minute bins efficiently
    grouped = df.groupby(["user", pd.Grouper(freq="10min")])
    
    last_activity_time_map = {}
    
    for (user, window_start), window_df in grouped:
        if window_df.empty:
            continue
            
        profile = profiles.get(user, {})
        known_ips = set(profile.get("usual_ips", []))
        known_hours = set(profile.get("usual_hours", []))
        last_activity_time = last_activity_time_map.get(user)
                
        # Compute features for this window
        login_failures = len(window_df[(window_df["source"] == "auth") & (window_df["event_type"] == "fail")])
        login_successes = len(window_df[(window_df["source"] == "auth") & (window_df["event_type"] == "success")])
        
        # New IP flag
        window_ips = set(window_df["source_ip"].dropna())
        new_ip_flag = 1 if (window_ips - known_ips) else 0
        
        # Off hours flag (if any event in window is outside usual hours)
        window_hours = set(window_df.index.hour)
        off_hours_flag = 1 if (known_hours and (window_hours - known_hours)) else 0
        
        distinct_hosts = window_df["host"].nunique()
        priv_changes = len(window_df[(window_df["source"] == "endpoint") & (window_df["event_type"] == "privilege_change")])
        file_mods = len(window_df[(window_df["source"] == "endpoint") & (window_df["event_type"] == "file_modify")])
        
        # Outbound data (approximation: firewall allows to non-10.x IPs on ports 80/443)
        outbound_events = window_df[
            (window_df["source"] == "firewall") & 
            (window_df["event_type"] == "allow") & 
            (~window_df["host"].str.startswith("10.", na=False)) &
            (window_df["details"].str.contains("Port: 443") | window_df["details"].str.contains("Port: 80"))
        ]
        outbound_count = len(outbound_events) # We use count as proxy for bytes
        
        # Hours since last activity
        hours_since_last = 0.0
        if last_activity_time:
            hours_since_last = (window_start - last_activity_time).total_seconds() / 3600.0
        last_activity_time_map[user] = window_start
        
        # Save all event IDs in this window so we can map scores back to them
        event_ids = window_df["event_id"].tolist()
        
        feature_rows.append({
            "user": user,
            "window_start": window_start,
            "event_ids": event_ids,
            "login_failures": login_failures,
            "login_successes": login_successes,
            "new_ip_flag": new_ip_flag,
            "off_hours_flag": off_hours_flag,
                "distinct_hosts": distinct_hosts,
                "priv_changes": priv_changes,
                "file_mods": file_mods,
                "outbound_count": outbound_count,
                "hours_since_last": hours_since_last
            })
            
    features_df = pd.DataFrame(feature_rows)
    return features_df
