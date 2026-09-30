import json
import os
from typing import List, Dict, Any
from datetime import datetime
from collections import defaultdict
from loader import Event

def build_profiles(events: List[Event], save_path: str = "data/profiles.json") -> Dict[str, Any]:
    """
    Builds normal-behavior profiles per user using baseline days (all but the last day).
    Treats the last calendar day in the dataset as 'live' and ignores it for baselining.
    """
    if not events:
        return {}

    # Determine the final day
    max_date = max(e.timestamp.date() for e in events)
    
    # Structure: user -> { "hours": set, "ips": set, "hosts": set, 
    # "failed_login_count": int, "file_mod_counts": dict(date -> dict(hour -> int)) }
    raw_profiles = defaultdict(lambda: {
        "hours": set(),
        "ips": set(),
        "hosts": set(),
        "failed_logins": 0,
        "total_logins": 0,
        "hourly_file_mods": defaultdict(int)
    })
    
    for e in events:
        # Only use baseline days
        if e.timestamp.date() >= max_date:
            continue
            
        user = e.user
        if not user:
            continue
            
        profile = raw_profiles[user]
        
        # Track active hours
        profile["hours"].add(e.timestamp.hour)
        
        # Track IPs
        if e.source_ip:
            profile["ips"].add(e.source_ip)
            
        # Track Hosts touched
        if e.host:
            profile["hosts"].add(e.host)
        if e.dest_ip:
            profile["hosts"].add(e.dest_ip)
            
        # Track Logins
        if e.source == "auth":
            profile["total_logins"] += 1
            if e.event_type == "fail":
                profile["failed_logins"] += 1
                
        # Track File mods
        if e.source == "endpoint" and e.event_type == "file_modify":
            time_key = e.timestamp.strftime("%Y-%m-%d-%H")
            profile["hourly_file_mods"][time_key] += 1
            
    # Compile final JSON-serializable profiles
    profiles = {}
    for user, rp in raw_profiles.items():
        hourly_mods = list(rp["hourly_file_mods"].values())
        max_file_mods_per_hour = max(hourly_mods) if hourly_mods else 0
        avg_file_mods_per_hour = sum(hourly_mods)/len(hourly_mods) if hourly_mods else 0
        
        fail_rate = (rp["failed_logins"] / rp["total_logins"]) if rp["total_logins"] > 0 else 0.0
        
        profiles[user] = {
            "usual_hours": list(rp["hours"]),
            "usual_ips": list(rp["ips"]),
            "usual_hosts": list(rp["hosts"]),
            "max_file_mods_per_hour": max_file_mods_per_hour,
            "avg_file_mods_per_hour": avg_file_mods_per_hour,
            "failed_login_rate": fail_rate
        }
        
    with open(save_path, "w") as f:
        json.dump(profiles, f, indent=2)
        
    return profiles

def load_profiles(path: str = "data/profiles.json") -> Dict[str, Any]:
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}
