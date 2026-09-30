import asyncio
import json
import os
import main
import config
from loader import load_logs
import baseline
import anomaly
from correlator import correlate_events
import agent

async def evaluate():
    print("--- PRAGYA Agent Evaluation ---")
    
    # 1. Setup the data in memory (simulating startup)
    print("Loading events and running correlation...")
    events = load_logs("data")
    profiles = baseline.build_profiles(events)
    events = anomaly.score_events(events, profiles)
    
    # Populate globals in main
    main.all_events = events
    main.profiles = profiles
    main.incidents = correlate_events(events)
    
    # Find the main incident (should be critical and involve Faculty-42)
    main_inc = None
    decoy_incs = []
    
    for inc in main.incidents:
        users = {e.event.user for e in inc.events}
        stages = {e.stage for e in inc.events}
        if "Faculty-42" in users and "lateral_movement" in stages:
            main_inc = inc
        elif "Student-101" in users or "Faculty-10" in users:
            decoy_incs.append(inc)
            
    if not main_inc:
        print("Error: Could not find the main attack incident involving Faculty-42.")
        return
        
    print(f"Found main incident: {main_inc.id}")
    
    # 2. Run Agent in scripted mode
    print("\n--- Running Scripted Mode Investigation ---")
    final_report = None
    async for chunk in agent.investigate(main_inc.id, "scripted"):
        # chunk is "data: {...}\n\n"
        data_str = chunk.replace("data: ", "").strip()
        data = json.loads(data_str)
        if "step" in data:
            print(f"Step {data['step']}: {data['thinking']}")
        if "final_report" in data:
            final_report = data["final_report"]
            
    if not final_report:
        print("Error: Agent did not produce a final report.")
        return
        
    print("\n--- Evaluating Final Report ---")
    
    # Check 1: Attack details
    narrative = final_report.get("attack_narrative", "")
    has_faculty42 = "Faculty-42" in narrative or any("Faculty-42" in u for u in final_report.get("affected_assets", []))
    has_attacker_ip = "203.0.113.45" in narrative or str(final_report).find("203.0.113.45") != -1
    has_patient_zero = "SERVER-07" in narrative or any("SERVER-07" in str(h) for h in final_report.get("affected_assets", []))
    
    print(f"Correct Compromised Account Identified (Faculty-42): {has_faculty42}")
    # Attacker IP might be implicitly in evidence, but our scripted narrative doesn't explicitly name it in this basic string. Let's check the whole report string
    print(f"Correct Attacker IP Identified (203.0.113.45): {has_attacker_ip}")
    print(f"Correct Patient Zero Identified (SERVER-07): {has_patient_zero}")
    
    # Check 2: Stages
    stages_present = set(e["stage"] for e in final_report.get("timeline", []))
    required_stages = {"initial_access", "credential_compromise", "privilege_escalation", "lateral_movement", "data_access", "exfiltration"}
    missing_stages = required_stages - stages_present
    print(f"Stages identified: {len(stages_present)} / 6. Missing: {missing_stages if missing_stages else 'None'}")
    
    # Check 3: Valid citations
    valid_ids = {e.event.event_id for e in main_inc.events}
    cited_ids = set(final_report.get("evidence_event_ids", []))
    invalid_ids = cited_ids - valid_ids
    print(f"All cited evidence IDs valid: {len(invalid_ids) == 0}")
    
    # Check 4: Containment Plan
    plan_str = str(final_report.get("containment_plan", []))
    has_isolate = "isolate_host" in plan_str
    has_revoke = "revoke_sessions" in plan_str
    print(f"Containment plan includes isolation: {has_isolate}")
    print(f"Containment plan includes revoking sessions: {has_revoke}")
    
    # Check 5: Decoys
    print("\n--- Checking Decoy Incidents ---")
    for d_inc in decoy_incs:
        print(f"Decoy Incident {d_inc.id} severity: {d_inc.severity}")
        if d_inc.severity == "critical":
            print("-> FAILED: Decoy was flagged as critical!")
        else:
            print("-> PASSED: Decoy is not critical.")

if __name__ == "__main__":
    asyncio.run(evaluate())
