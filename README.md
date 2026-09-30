# PRAGYA - Synthetic Log Generator

This is Stage 1 of PRAGYA, an AI cyber incident investigator. This module generates synthetic security logs for a fictional university environment.

It simulates daily operational noise across four log types (Auth, Firewall, Endpoint, and Application logs) and injects a hidden ransomware attack scenario (approximately 25 events) to test the upcoming correlation engine.

## Prerequisites
- Python 3.11+
- `faker` library

## Setup
Create a virtual environment and install the required dependencies:
```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
pip install faker
```

## Running the Generator
Run the script from the `backend/` directory:
```bash
cd backend
python generate_logs.py
```

### Options
You can customize the simulation using command-line arguments:
- `--days`: Number of days to simulate (default: 7)
- `--noise-level`: Multiplier for the amount of background noise (default: 5)
- `--seed`: Random seed for reproducible output (default: 42)

Example:
```bash
python generate_logs.py --days 10 --noise-level 10 --seed 42
```

## Output
The generated logs are saved as JSON files in `backend/data/`:
- `auth_logs.json`
- `firewall_logs.json`
- `endpoint_logs.json`
- `app_logs.json`

A `ground_truth.json` file is also generated, detailing the exact events that belong to the hidden attack. This file is strictly for testing and validation.
