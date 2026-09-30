import json
import os
from loader import load_logs
from correlator import correlate_events

def evaluate():
    print("--- PRAGYA Correlation Engine Evaluation ---")
    
    # 1. Load Ground Truth
    gt_path = os.path.join("data", "ground_truth.json")
    if not os.path.exists(gt_path):
        print("Error: data/ground_truth.json not found.")
        return
        
    with open(gt_path, "r") as f:
        ground_truth_raw = json.load(f)
        
    gt_event_ids = set([item["event_id"] for item in ground_truth_raw])
    gt_stages = {item["event_id"]: item["attack_stage"] for item in ground_truth_raw}
    
    print(f"Ground truth attack events: {len(gt_event_ids)}")
    
    # 2. Run Correlator
    print("Loading events and running correlator...")
    events = load_logs("data")
    incidents = correlate_events(events)
    
    # 3. Analyze Results
    detected_event_ids = set()
    stage_matches = 0
    total_detected = 0
    
    for inc in incidents:
        for c_evt in inc.events:
            eid = c_evt.event.event_id
            detected_event_ids.add(eid)
            total_detected += 1
            
            # Check stage matching if it's a true positive
            if eid in gt_stages:
                # Stage matching might be fuzzy because our rules map to standardized names,
                # while ground truth has names like "credential compromise"
                # Let's do a simple substring/lower comparison
                predicted = c_evt.stage.lower().replace("_", " ")
                actual = gt_stages[eid].lower().replace("_", " ")
                if predicted in actual or actual in predicted:
                    stage_matches += 1
                    
    true_positives = len(detected_event_ids.intersection(gt_event_ids))
    false_positives = len(detected_event_ids - gt_event_ids)
    missed = len(gt_event_ids - detected_event_ids)
    
    print("\n--- Results ---")
    print(f"Total Incidents Detected: {len(incidents)}")
    print(f"Total Events Flagged: {total_detected}")
    print(f"Caught Attack Events (True Positives): {true_positives} / {len(gt_event_ids)}")
    print(f"Missed Attack Events (False Negatives): {missed}")
    print(f"Normal Events Wrongly Flagged (False Positives): {false_positives}")
    if true_positives > 0:
        print(f"Stage Label Matches (Approximate): {stage_matches} / {true_positives}")
        
    print("\n--- Analysis ---")
    if false_positives > 0:
        print("Note: False positives are expected in a purely rule-based engine due to coincidental noise (e.g. users sharing IPs within the time window).")
    if missed > 0:
        print("Note: Missed events occurred because the hardcoded time windows or exact IP matching rules broke the chain.")
        
if __name__ == "__main__":
    evaluate()
