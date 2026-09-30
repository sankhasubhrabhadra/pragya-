# config.py
# Configuration values for the PRAGYA correlation engine

# Maximum time gap (in minutes) allowed between two consecutive related events in a chain
TIME_WINDOW_MINUTES = 15 

# Minimum number of linked events required to form a valid incident chain
MIN_CHAIN_LENGTH = 4 

# Minimum total risk score for a chain to be considered an incident
MIN_RISK_SCORE = 2.0 

# Anomaly Configuration
ANOMALY_RULE_WEIGHT = 0.5
ANOMALY_ML_WEIGHT = 0.5
ANOMALY_THRESHOLD = 0.6  # Score above this is flagged anomalous
ANOMALY_SEVERITY_BOOST = 1.0  # Amount to add to chain risk score if an event is highly anomalous
