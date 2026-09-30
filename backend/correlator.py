import uuid
from typing import List, Dict, Any
from datetime import datetime

from loader import Event
import config
from stage_mapper import map_stage

class ChainEvent:
    """Wraps an Event with correlation and stage mapping context."""
    def __init__(self, event: Event, link_reason: str, stage: str, stage_reason: str):
        self.event = event
        self.link_reason = link_reason
        self.stage = stage
        self.stage_reason = stage_reason
        
    def to_dict(self):
        return {
            **self.event.dict(),
            "link_reason": self.link_reason,
            "stage": self.stage,
            "stage_reason": self.stage_reason
        }

class IncidentChain:
    """Represents a sequence of correlated events forming an attack timeline."""
    def __init__(self, first_event: Event):
        # We will assign a formal INC-ID later if it passes thresholds
        self.id = str(uuid.uuid4())
        
        stage, stage_reason = map_stage(first_event, None)
        self.events: List[ChainEvent] = [
            ChainEvent(first_event, "Initial event in sequence.", stage, stage_reason)
        ]
        self.risk_score = 0.0
        self.severity = "low"
        
    def get_last_event(self) -> Event:
        return self.events[-1].event

    def try_add_event(self, event: Event) -> bool:
        """
        Evaluates if an event belongs to this chain. If it does, adds it and returns True.
        """
        last_evt = self.get_last_event()
        
        # 1. Check time window
        time_diff = (event.timestamp - last_evt.timestamp).total_seconds() / 60.0
        if time_diff < 0 or time_diff > config.TIME_WINDOW_MINUTES:
            return False
            
        # 2. Check rule matches (Same user, Same Source IP, Same Host)
        match_reasons = []
        rules_matched = 0
        
        if event.user and last_evt.user and event.user == last_evt.user:
            match_reasons.append(f"Same user ({event.user})")
            rules_matched += 1
            
        if event.source_ip and last_evt.source_ip and event.source_ip == last_evt.source_ip:
            match_reasons.append(f"Same source IP ({event.source_ip})")
            rules_matched += 1
            
        # Also check if it matches ANY previous host or dest_ip in the chain
        assets_in_chain = {e.event.host for e in self.events if e.event.host}.union({e.event.dest_ip for e in self.events if e.event.dest_ip})
        
        target_asset = event.host or event.dest_ip
        if target_asset and target_asset in assets_in_chain:
            match_reasons.append(f"Shared target asset ({target_asset})")
            rules_matched += 1

        if rules_matched == 0:
            return False
            
        # 3. Calculate link score (0 to 1 based on how many rules matched)
        # 1 match = 0.5, 2 matches = 0.8, 3+ matches = 1.0
        link_score = 0.5 if rules_matched == 1 else (0.8 if rules_matched == 2 else 1.0)
        
        # Bonus for logical attack progression (e.g., initial_access -> lateral_movement)
        stage, stage_reason = map_stage(event, last_evt)
        if stage != "unknown" and stage != self.events[-1].stage:
            link_score = min(1.0, link_score + 0.2)
            
        self.risk_score += link_score
        
        reason_text = f"{', '.join(match_reasons)} within {int(time_diff)} mins."
        self.events.append(ChainEvent(event, reason_text, stage, stage_reason))
        return True
        
    def compute_severity(self):
        """Assigns a formal Incident ID and computes severity."""
        # Use a stable but fake sequence number for demo
        hash_id = str(abs(hash(self.id)))[:4]
        self.id = f"INC-2026-{hash_id}"
        
        stages_reached = {e.stage for e in self.events}
        hosts_touched = {e.event.host for e in self.events if e.event.host}
        
        if "exfiltration" in stages_reached or "data_access" in stages_reached:
            base_severity = "critical"
        elif "privilege_escalation" in stages_reached or len(hosts_touched) >= 3:
            base_severity = "high"
        elif "lateral_movement" in stages_reached or len(hosts_touched) >= 2:
            base_severity = "medium"
        else:
            base_severity = "low"
            
        self.severity = base_severity
            
        # Boost risk score and potentially severity based on anomaly scores of events in the chain
        max_anomaly = max([e.event.anomaly_score for e in self.events], default=0.0)
        if max_anomaly > config.ANOMALY_THRESHOLD:
            self.risk_score = 0.5 * len(self.events) + config.ANOMALY_SEVERITY_BOOST
            
            # Simple severity bump logic applied to base severity
            bump_map = {"low": "medium", "medium": "high", "high": "critical", "critical": "critical"}
            if max_anomaly > 0.8: # If highly anomalous, bump severity
                self.severity = bump_map.get(base_severity, base_severity)
        else:
            self.risk_score = 0.5 * len(self.events)

def correlate_events(events: List[Event]) -> List[IncidentChain]:
    """
    Main rule-based correlation engine.
    Groups raw events into incident chains based on rules and thresholds.
    """
    active_chains: List[IncidentChain] = []
    completed_chains: List[IncidentChain] = []
    
    for event in events:
        matched = False
        
        # Try to add to existing active chains
        # We iterate backwards to prefer matching with more recent chains
        for chain in reversed(active_chains):
            if chain.try_add_event(event):
                matched = True
                break # Greedy match: assign to the first valid chain and stop
                
        if not matched:
            # Start a new chain
            active_chains.append(IncidentChain(event))
            
        # Clean up stale chains
        fresh_chains = []
        for chain in active_chains:
            time_since_last = (event.timestamp - chain.get_last_event().timestamp).total_seconds() / 60.0
            if time_since_last > config.TIME_WINDOW_MINUTES:
                completed_chains.append(chain)
            else:
                fresh_chains.append(chain)
        active_chains = fresh_chains
        
    # Add remaining active chains to completed
    completed_chains.extend(active_chains)
    
    # Filter by thresholds
    valid_incidents = []
    for chain in completed_chains:
        if len(chain.events) >= config.MIN_CHAIN_LENGTH and chain.risk_score >= config.MIN_RISK_SCORE:
            chain.compute_severity()
            valid_incidents.append(chain)
            
    # Sort incidents by severity (critical first) then by risk score
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    valid_incidents.sort(key=lambda c: (severity_order.get(c.severity, 0), c.risk_score), reverse=True)
    
    return valid_incidents
