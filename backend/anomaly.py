import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from typing import List, Dict, Any

from loader import Event
import config
from features import events_to_features

def apply_rule_layer(features_df: pd.DataFrame, profiles: Dict[str, Any]) -> pd.DataFrame:
    """
    Layer A: Explainable Rules.
    Evaluates each window against baseline profiles and adds a rule score and reasons.
    """
    rule_scores = []
    rule_reasons = []
    
    for _, row in features_df.iterrows():
        user = row["user"]
        profile = profiles.get(user, {})
        
        score = 0.0
        reasons = []
        
        # 1. Login at an hour never seen
        if row["off_hours_flag"] == 1 and row["login_successes"] > 0:
            score += 0.8
            reasons.append("Login during unusual off-hours.")
            
        # 2. Login from an IP never seen
        if row["new_ip_flag"] == 1 and row["login_successes"] > 0:
            score += 0.8
            reasons.append("Login from previously unseen IP address.")
            
        # 3. Burst of failed logins followed by success (or just in same window)
        if row["login_failures"] > 5 and row["login_successes"] > 0:
            score += 1.0
            reasons.append(f"Suspicious burst of {row['login_failures']} failed logins coinciding with a success.")
            
        # 4. Access to a host this user never touched
        # (Approximated here by checking if distinct hosts is larger than usual, or relying on correlator. 
        # Actually, let's just flag if they touch multiple hosts in a short window if they usually don't)
        if row["distinct_hosts"] > len(profile.get("usual_hosts", [])) and len(profile.get("usual_hosts", [])) > 0:
             score += 0.7
             reasons.append("Accessed more distinct hosts in this window than their entire baseline.")
             
        # 5. File modifications far above normal rate
        max_normal = profile.get("max_file_mods_per_hour", 0)
        # Scale max_normal down to 10 min window (roughly divide by 6), but give some buffer
        if row["file_mods"] > max(5, max_normal):
            score += 0.9
            reasons.append(f"Excessive file modifications ({row['file_mods']}) far above baseline.")
            
        # 6. Unusually large outbound transfer
        if row["outbound_count"] > 2:
            score += 0.9
            reasons.append(f"Unusually large volume of outbound external connections.")
            
        # Cap score at 1.0
        rule_scores.append(min(1.0, score))
        rule_reasons.append(reasons)
        
    features_df["rule_score"] = rule_scores
    features_df["rule_reasons"] = rule_reasons
    return features_df

def apply_ml_layer(features_df: pd.DataFrame, max_date: pd.Timestamp) -> pd.DataFrame:
    """
    Layer B: IsolationForest.
    Trains on baseline days, scores all days.
    """
    if features_df.empty:
        features_df["ml_score"] = 0.0
        return features_df
        
    feature_cols = ["login_failures", "login_successes", "new_ip_flag", "off_hours_flag", 
                    "distinct_hosts", "priv_changes", "file_mods", "outbound_count", "hours_since_last"]
                    
    X_all = features_df[feature_cols].fillna(0)
    
    # Train on baseline data
    baseline_mask = features_df["window_start"].dt.date < max_date.date()
    X_train = X_all[baseline_mask]
    
    # If not enough baseline data, just train on everything
    if len(X_train) < 10:
        X_train = X_all
        
    clf = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    clf.fit(X_train)
    
    # decision_function returns >0 for normal, <0 for anomalies (lower is more anomalous)
    scores = clf.decision_function(X_all)
    
    # Normalize to 0-1 where 1 is most anomalous
    # Scores are typically in range [-0.5, 0.5]. 
    # Let's invert and scale.
    scores_inverted = -scores
    min_s, max_s = scores_inverted.min(), scores_inverted.max()
    
    if max_s > min_s:
        normalized_scores = (scores_inverted - min_s) / (max_s - min_s)
    else:
        normalized_scores = np.zeros_like(scores_inverted)
        
    features_df["ml_score"] = normalized_scores
    return features_df

def score_events(events: List[Event], profiles: Dict[str, Any]) -> List[Event]:
    """
    Main anomaly scoring function.
    Groups events into windows, applies rules and ML, and writes scores back to the events.
    """
    if not events:
        return events
        
    features_df = events_to_features(events, profiles)
    if features_df.empty:
        return events
        
    max_date = pd.Timestamp(max(e.timestamp.date() for e in events))
    
    features_df = apply_rule_layer(features_df, profiles)
    features_df = apply_ml_layer(features_df, max_date)
    
    # Combine scores
    features_df["final_score"] = (features_df["rule_score"] * config.ANOMALY_RULE_WEIGHT) + \
                                 (features_df["ml_score"] * config.ANOMALY_ML_WEIGHT)
                                 
    # Map back to event IDs
    event_score_map = {}
    event_reason_map = {}
    
    for _, row in features_df.iterrows():
        # Only attach reasons if the score exceeds threshold
        if row["final_score"] > config.ANOMALY_THRESHOLD:
            reasons = row["rule_reasons"].copy()
            if row["ml_score"] > 0.7:
                reasons.append(f"ML model flagged behavior pattern as highly anomalous (Score: {row['ml_score']:.2f}).")
            
            for eid in row["event_ids"]:
                event_score_map[eid] = row["final_score"]
                event_reason_map[eid] = reasons
                
    # Update Event objects
    for e in events:
        if e.event_id in event_score_map:
            e.anomaly_score = event_score_map[e.event_id]
            e.anomaly_reasons = event_reason_map[e.event_id]
            
    return events
