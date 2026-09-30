import json
import os
from loader import load_logs
import baseline
import anomaly
import config

def evaluate():
    print("--- PRAGYA Anomaly Detection Evaluation ---")
    
    # 1. Load Ground Truth
    gt_path = os.path.join("data", "ground_truth.json")
    if not os.path.exists(gt_path):
        print("Error: data/ground_truth.json not found.")
        return
        
    with open(gt_path, "r") as f:
        ground_truth_raw = json.load(f)
        
    gt_event_ids = set([item["event_id"] for item in ground_truth_raw])
    
    # 2. Run Anomaly Detection
    print("Loading events...")
    events = load_logs("data")
    
    # Find decoys for reporting
    decoy_student_events = [e for e in events if e.user == "Student-101" and e.source == "auth" and e.timestamp.hour == 14]
    decoy_faculty_events = [e for e in events if e.user == "Faculty-10" and e.timestamp.hour == 3]
    
    print("Building baseline profiles from normal days...")
    profiles = baseline.build_profiles(events)
    
    print("Scoring anomalous behavior...")
    events = anomaly.score_events(events, profiles)
    
    # 3. Analyze Results
    anomalous_events = [e for e in events if e.anomaly_score > config.ANOMALY_THRESHOLD]
    anomalous_event_ids = set(e.event_id for e in anomalous_events)
    
    true_positives = len(anomalous_event_ids.intersection(gt_event_ids))
    false_positives = len(anomalous_event_ids - gt_event_ids)
    false_negatives = len(gt_event_ids - anomalous_event_ids)
    
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
    
    print("\n--- Results ---")
    print(f"Total Events Scored: {len(events)}")
    print(f"Total Anomalies Flagged: {len(anomalous_events)}")
    print(f"Caught Attack Events (True Positives): {true_positives} / {len(gt_event_ids)}")
    print(f"Missed Attack Events (False Negatives): {false_negatives}")
    print(f"Normal/Decoy Events Flagged (False Positives): {false_positives}")
    print(f"Precision: {precision:.2f}")
    print(f"Recall:    {recall:.2f}")
    
    print("\n--- Sample Anomaly Reasons (Attack Events) ---")
    attack_samples = [e for e in anomalous_events if e.event_id in gt_event_ids][:3]
    for e in attack_samples:
        print(f"- {e.event_type} on {e.host or e.dest_ip or e.source_ip} (Score: {e.anomaly_score:.2f})")
        for r in e.anomaly_reasons:
            print(f"  Reason: {r}")
            
    print("\n--- Decoy Check ---")
    # Did the decoys get flagged?
    print("Decoy 1: Student-101 typos")
    d1_scores = [e.anomaly_score for e in decoy_student_events]
    d1_max = max(d1_scores) if d1_scores else 0
    print(f"Max score: {d1_max:.2f} (Threshold: {config.ANOMALY_THRESHOLD})")
    if d1_max > config.ANOMALY_THRESHOLD:
        print("-> FAILED: Decoy 1 was flagged as an anomaly.")
        decoy1_evt = max(decoy_student_events, key=lambda x: x.anomaly_score)
        print("Reasons:")
        for r in decoy1_evt.anomaly_reasons:
            print(f"  - {r}")
    else:
        print("-> PASSED: Decoy 1 correctly ignored.")

    print("\nDecoy 2: Faculty-10 working late")
    d2_scores = [e.anomaly_score for e in decoy_faculty_events]
    d2_max = max(d2_scores) if d2_scores else 0
    print(f"Max score: {d2_max:.2f} (Threshold: {config.ANOMALY_THRESHOLD})")
    if d2_max > config.ANOMALY_THRESHOLD:
        print("-> FAILED: Decoy 2 was flagged as an anomaly.")
        decoy2_evt = max(decoy_faculty_events, key=lambda x: x.anomaly_score)
        print("Reasons:")
        for r in decoy2_evt.anomaly_reasons:
            print(f"  - {r}")
    else:
        print("-> PASSED: Decoy 2 correctly ignored.")
        decoy2_evt = max(decoy_faculty_events, key=lambda x: x.anomaly_score) if decoy_faculty_events else None
        if decoy2_evt and hasattr(decoy2_evt, 'anomaly_reasons') and decoy2_evt.anomaly_reasons:
             print("Reasons evaluated:")
             for r in decoy2_evt.anomaly_reasons:
                 print(f"  - {r}")

if __name__ == "__main__":
    evaluate()
