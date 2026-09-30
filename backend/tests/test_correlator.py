import pytest
from datetime import datetime
from loader import Event
from correlator import correlate_events
import config

@pytest.fixture
def sample_events():
    t1 = datetime(2026, 1, 1, 12, 0, 0)
    t2 = datetime(2026, 1, 1, 12, 5, 0) # 5 mins later
    t3 = datetime(2026, 1, 1, 12, 10, 0) # 10 mins later
    t4 = datetime(2026, 1, 1, 12, 14, 0) # 14 mins later
    
    return [
        Event(event_id="1", timestamp=t1, source="auth", user="alice", source_ip="1.1.1.1", event_type="fail"),
        Event(event_id="2", timestamp=t2, source="auth", user="alice", source_ip="1.1.1.1", event_type="success"),
        Event(event_id="3", timestamp=t3, source="firewall", source_ip="1.1.1.1", dest_ip="10.0.0.1", event_type="allow"),
        Event(event_id="4", timestamp=t4, source="endpoint", user="alice", host="10.0.0.1", event_type="process_start")
    ]

def test_correlator_chains_events(sample_events, monkeypatch):
    # Temporarily lower thresholds for testing
    monkeypatch.setattr(config, 'MIN_CHAIN_LENGTH', 2)
    monkeypatch.setattr(config, 'MIN_RISK_SCORE', 0.5)
    
    incidents = correlate_events(sample_events)
    
    assert len(incidents) == 1
    assert len(incidents[0].events) == 4
    assert incidents[0].severity in ["low", "medium", "high", "critical"]

def test_correlator_time_window(sample_events, monkeypatch):
    # Make the time window too short to link t1 and t2 (5 min gap)
    monkeypatch.setattr(config, 'TIME_WINDOW_MINUTES', 3)
    monkeypatch.setattr(config, 'MIN_CHAIN_LENGTH', 1)
    monkeypatch.setattr(config, 'MIN_RISK_SCORE', 0.0)
    
    incidents = correlate_events(sample_events)
    
    # Should break into multiple incidents because they exceed time window
    assert len(incidents) > 1
