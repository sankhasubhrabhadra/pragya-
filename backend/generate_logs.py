import argparse
import json
import random
import uuid
import os
from datetime import datetime, timedelta

# Import Faker for generating realistic dummy data
try:
    from faker import Faker
except ImportError:
    print("Faker is not installed. Please run: pip install faker")
    exit(1)

# --- Constants & Configuration ---
# Fictional university assets
ASSETS = {
    "student-portal": "10.0.10.5",
    "ADMIN-SERVER": "10.0.1.10",
    "SERVER-07": "10.0.2.7",
    "DB-SERVER-01": "10.0.3.50",
    "FILE-SERVER-01": "10.0.4.100",
}

# Fictional university users
STUDENTS = [f"Student-{i:03d}" for i in range(1, 201)]
FACULTY = [f"Faculty-{i:02d}" for i in range(1, 51)]
ADMINS = [f"Admin-{i}" for i in range(1, 4)]
ALL_USERS = STUDENTS + FACULTY + ADMINS

# Attack parameters
ATTACKER_IP = "203.0.113.45"
COMPROMISED_USER = "Faculty-42"

def get_random_ip(faker_inst):
    """Returns a random IP address (mostly private, sometimes public)."""
    return faker_inst.ipv4_private() if random.random() > 0.3 else faker_inst.ipv4_public()

def generate_noise(start_date, days, noise_level, faker):
    """
    Generates normal background noise events representing daily activity.
    """
    auth_logs = []
    firewall_logs = []
    endpoint_logs = []
    app_logs = []
    
    events_per_day = 200 * noise_level
    
    for day in range(days):
        current_date = start_date + timedelta(days=day)
        
        for _ in range(events_per_day):
            # Pick a random time during the day, clustered around midday
            hour = int(random.gauss(14, 4))
            hour = max(0, min(23, hour))
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            
            event_time = current_date.replace(hour=hour, minute=minute, second=second)
            user = random.choice(ALL_USERS)
            source_ip = get_random_ip(faker)
            
            # Randomly select which type of event to generate
            event_type_choice = random.choice(["auth", "firewall", "endpoint", "app"])
            
            if event_type_choice == "auth":
                # Simulate occasional typo (failed login followed by success)
                if random.random() < 0.05:
                    auth_logs.append({
                        "event_id": str(uuid.uuid4()),
                        "timestamp": event_time.isoformat(),
                        "user": user,
                        "source_ip": source_ip,
                        "result": "fail",
                        "method": "password"
                    })
                    # Add a few seconds for the retry
                    event_time += timedelta(seconds=random.randint(5, 15))
                    
                auth_logs.append({
                    "event_id": str(uuid.uuid4()),
                    "timestamp": event_time.isoformat(),
                    "user": user,
                    "source_ip": source_ip,
                    "result": "success",
                    "method": "password"
                })
                
            elif event_type_choice == "firewall":
                dest_asset = random.choice(list(ASSETS.values()))
                firewall_logs.append({
                    "event_id": str(uuid.uuid4()),
                    "timestamp": event_time.isoformat(),
                    "source_ip": source_ip,
                    "dest_ip": dest_asset,
                    "port": random.choice([80, 443, 22, 3389]),
                    "action": "allow" if random.random() > 0.1 else "deny"
                })
                
            elif event_type_choice == "endpoint":
                host = random.choice(list(ASSETS.keys()))
                endpoint_logs.append({
                    "event_id": str(uuid.uuid4()),
                    "timestamp": event_time.isoformat(),
                    "host": host,
                    "user": user,
                    "event_type": random.choice(["process_start", "file_access"]),
                    "details": faker.file_path() if random.random() > 0.5 else faker.file_name()
                })
                
            elif event_type_choice == "app":
                app = random.choice(["student-portal", "HR-app", "email-client"])
                app_logs.append({
                    "event_id": str(uuid.uuid4()),
                    "timestamp": event_time.isoformat(),
                    "app": app,
                    "user": user,
                    "action": random.choice(["login", "view", "edit", "logout"]),
                    "status": "success"
                })

    return auth_logs, firewall_logs, endpoint_logs, app_logs

def inject_attack(start_date, days):
    """
    Injects a hidden ransomware attack scenario into the logs.
    The attack happens around 02:13 AM on the final day of the simulation.
    """
    # The attack happens on the final day
    attack_date = start_date + timedelta(days=days-1)
    
    # Base time: 02:13 AM
    base_time = attack_date.replace(hour=2, minute=13, second=0)
    
    auth_logs = []
    firewall_logs = []
    endpoint_logs = []
    app_logs = []
    ground_truth = []

    def add_event(log_list, event_dict, stage):
        """Helper to assign a unique ID and track in ground truth."""
        eid = str(uuid.uuid4())
        event_dict["event_id"] = eid
        log_list.append(event_dict)
        ground_truth.append({
            "event_id": eid,
            "attack_stage": stage,
            "details": f"Mapped to {stage}"
        })

    # Step 1: Repeated failed logins from unusual IP
    t = base_time - timedelta(minutes=3)
    for _ in range(5):
        add_event(auth_logs, {
            "timestamp": t.isoformat(),
            "user": COMPROMISED_USER,
            "source_ip": ATTACKER_IP,
            "result": "fail",
            "method": "password"
        }, "initial access")
        t += timedelta(seconds=random.randint(10, 30))
        
    # Step 2: Successful login from that same IP
    t = base_time
    add_event(auth_logs, {
        "timestamp": t.isoformat(),
        "user": COMPROMISED_USER,
        "source_ip": ATTACKER_IP,
        "result": "success",
        "method": "password"
    }, "credential compromise")
    
    # Step 3: VPN login from that IP
    t += timedelta(minutes=2)
    add_event(app_logs, {
        "timestamp": t.isoformat(),
        "app": "VPN",
        "user": COMPROMISED_USER,
        "action": "login",
        "status": "success"
    }, "initial access")
    
    # Step 4: Access to SERVER-07 at unusual hour
    t += timedelta(minutes=5)
    add_event(firewall_logs, {
        "timestamp": t.isoformat(),
        "source_ip": ATTACKER_IP,
        "dest_ip": ASSETS["SERVER-07"],
        "port": 22,
        "action": "allow"
    }, "lateral movement")
    
    add_event(endpoint_logs, {
        "timestamp": (t + timedelta(seconds=2)).isoformat(),
        "host": "SERVER-07",
        "user": COMPROMISED_USER,
        "event_type": "process_start",
        "details": "/bin/bash"
    }, "lateral movement")
    
    # Step 5: Admin credential attempts from SERVER-07
    t += timedelta(minutes=5)
    add_event(auth_logs, {
        "timestamp": t.isoformat(),
        "user": "Admin-1",
        "source_ip": ASSETS["SERVER-07"],
        "result": "fail",
        "method": "password"
    }, "privilege escalation")
    
    t += timedelta(seconds=15)
    add_event(auth_logs, {
        "timestamp": t.isoformat(),
        "user": "Admin-1",
        "source_ip": ASSETS["SERVER-07"],
        "result": "success",
        "method": "password"
    }, "privilege escalation")
    
    # Step 6: Privilege escalation event
    t += timedelta(minutes=5)
    add_event(endpoint_logs, {
        "timestamp": t.isoformat(),
        "host": "SERVER-07",
        "user": "Admin-1",
        "event_type": "privilege_change",
        "details": "su to root"
    }, "privilege escalation")
    
    # Step 7: Database access on DB-SERVER-01
    t += timedelta(minutes=15)
    add_event(firewall_logs, {
        "timestamp": t.isoformat(),
        "source_ip": ASSETS["SERVER-07"],
        "dest_ip": ASSETS["DB-SERVER-01"],
        "port": 3306,
        "action": "allow"
    }, "lateral movement")
    
    add_event(app_logs, {
        "timestamp": (t + timedelta(seconds=2)).isoformat(),
        "app": "DB-SERVER-01",
        "user": "Admin-1",
        "action": "query",
        "status": "success"
    }, "data access")
    
    # Step 8: Mass file modification on FILE-SERVER-01 (ransomware behavior)
    t += timedelta(minutes=15)
    for i in range(10):
        add_event(endpoint_logs, {
            "timestamp": t.isoformat(),
            "host": "FILE-SERVER-01",
            "user": "Admin-1",
            "event_type": "file_modify",
            "details": f"/shares/data/research_data_{i}.docx.encrypted"
        }, "impact")
        t += timedelta(seconds=random.randint(1, 3))
        
    # Step 9: Large outbound data transfer (exfiltration attempt)
    t += timedelta(minutes=15)
    add_event(firewall_logs, {
        "timestamp": t.isoformat(),
        "source_ip": ASSETS["FILE-SERVER-01"],
        "dest_ip": ATTACKER_IP,
        "port": 443,
        "action": "allow"
    }, "exfiltration")

    return auth_logs, firewall_logs, endpoint_logs, app_logs, ground_truth

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="PRAGYA Synthetic Log Generator (Stage 1)")
    parser.add_argument("--days", type=int, default=7, help="Number of days to simulate (default: 7)")
    parser.add_argument("--noise-level", type=int, default=5, help="Multiplier for background noise (default: 5)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility (default: 42)")
    args = parser.parse_args()

    # Ensure reproducibility
    random.seed(args.seed)
    Faker.seed(args.seed)
    faker = Faker()

    # Simulation start date
    start_date = datetime(2024, 5, 1, 8, 0, 0)

    print(f"[*] Generating normal background noise for {args.days} days with noise level {args.noise_level}...")
    auth_noise, fw_noise, ep_noise, app_noise = generate_noise(start_date, args.days, args.noise_level, faker)
    
    print("[*] Injecting hidden ransomware attack scenario...")
    auth_atk, fw_atk, ep_atk, app_atk, ground_truth = inject_attack(start_date, args.days)

    # Combine noise and attack logs, then sort them by timestamp
    auth_logs = sorted(auth_noise + auth_atk, key=lambda x: x["timestamp"])
    firewall_logs = sorted(fw_noise + fw_atk, key=lambda x: x["timestamp"])
    endpoint_logs = sorted(ep_noise + ep_atk, key=lambda x: x["timestamp"])
    app_logs = sorted(app_noise + app_atk, key=lambda x: x["timestamp"])

    data_dir = "data"
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)

    def write_json(filename, data):
        """Helper to write logs to a JSON file."""
        filepath = os.path.join(data_dir, filename)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    print("[*] Writing generated logs to disk (backend/data/)...")
    write_json("auth_logs.json", auth_logs)
    write_json("firewall_logs.json", firewall_logs)
    write_json("endpoint_logs.json", endpoint_logs)
    write_json("app_logs.json", app_logs)
    
    # Write the ground truth file for testing future correlation engine
    with open(os.path.join(data_dir, "ground_truth.json"), "w") as f:
        json.dump(ground_truth, f, indent=2)

    # Output summary
    print("\n--- Generation Summary ---")
    print(f"Total Auth Logs: {len(auth_logs)}")
    print(f"Total Firewall Logs: {len(firewall_logs)}")
    print(f"Total Endpoint Logs: {len(endpoint_logs)}")
    print(f"Total App Logs: {len(app_logs)}")
    print(f"Total Attack Events Hidden: {len(ground_truth)}")
    print("--------------------------")
    print("Logs generated successfully in backend/data/ directory.")

if __name__ == "__main__":
    main()
