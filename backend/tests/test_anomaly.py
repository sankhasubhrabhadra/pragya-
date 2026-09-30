import pytest
from datetime import datetime, timedelta
from loader import Event
import baseline
import anomaly
import pandas as pd
import config

def test_baseline_building():
    # Setup 2 days of baseline for user Alice
    t1 = datetime(2024, 5, 1, 10, 0, 0)
    t2 = datetime(2024, 5, 2, 11, 0, 0)
    # Day 3 is live day
    t3 = datetime(2024, 5, 3, 10, 0, 0)
    
    events = [
        Event(event_id="1", timestamp=t1, source="auth", user="Alice", event_type="success", source_ip="1.1.1.1"),
        Event(event_id="2", timestamp=t2, source="auth", user="Alice", event_type="success", source_ip="1.1.1.2"),
        Event(event_id="3", timestamp=t3, source="auth", user="Alice", event_type="success", source_ip="2.2.2.2")
    ]
    
    profiles = baseline.build_profiles(events)
    
    assert "Alice" in profiles
    profile = profiles["Alice"]
    # Only t1 and t2 should be in baseline (day 1 and 2), t3 is day 3 (max date)
    assert set(profile["usual_hours"]) == {10, 11}
    assert set(profile["usual_ips"]) == {"1.1.1.1", "1.1.1.2"}
    assert "2.2.2.2" not in profile["usual_ips"]

def test_rule_unusual_hour():
    df = pd.DataFrame([{
        "user": "Alice", "window_start": datetime.now(), "event_ids": ["1"],
        "login_failures": 0, "login_successes": 1, "new_ip_flag": 0, "off_hours_flag": 1,
        "distinct_hosts": 1, "priv_changes": 0, "file_mods": 0, "outbound_count": 0, "hours_since_last": 0
    }])
    profiles = {"Alice": {"usual_hours": [10, 11]}}
    
    scored_df = anomaly.apply_rule_layer(df, profiles)
    assert scored_df["rule_score"].iloc[0] == 0.8
    assert "Login during unusual off-hours." in scored_df["rule_reasons"].iloc[0]

def test_rule_burst_fails():
    df = pd.DataFrame([{
        "user": "Bob", "window_start": datetime.now(), "event_ids": ["2"],
        "login_failures": 6, "login_successes": 1, "new_ip_flag": 0, "off_hours_flag": 0,
        "distinct_hosts": 1, "priv_changes": 0, "file_mods": 0, "outbound_count": 0, "hours_since_last": 0
    }])
    profiles = {"Bob": {}}
    
    scored_df = anomaly.apply_rule_layer(df, profiles)
    assert scored_df["rule_score"].iloc[0] >= 1.0
    assert any("Burst of" in r or "Suspicious burst" in r for r in scored_df["rule_reasons"].iloc[0])

def test_rule_file_mods():
    df = pd.DataFrame([{
        "user": "Charlie", "window_start": datetime.now(), "event_ids": ["3"],
        "login_failures": 0, "login_successes": 0, "new_ip_flag": 0, "off_hours_flag": 0,
        "distinct_hosts": 1, "priv_changes": 0, "file_mods": 50, "outbound_count": 0, "hours_since_last": 0
    }])
    profiles = {"Charlie": {"max_file_mods_per_hour": 10}}
    
    scored_df = anomaly.apply_rule_layer(df, profiles)
    assert scored_df["rule_score"].iloc[0] == 0.9
    assert any("Excessive file modifications" in r for r in scored_df["rule_reasons"].iloc[0])
