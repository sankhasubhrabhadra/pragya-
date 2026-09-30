from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional

from loader import load_logs
from correlator import correlate_events
from graph_builder import build_attack_graph
import baseline
import anomaly

app = FastAPI(title="PRAGYA API", description="AI Cyber Incident Investigator API")

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

all_events = []
incidents = []
profiles = {}
reports = {}

@app.on_event("startup")
def startup_event():
    """Loads logs, builds baseline, scores anomalies, and correlates incidents."""
    global all_events, incidents, profiles
    print("Loading raw events from disk...")
    all_events = load_logs("data")
    
    print("Building baseline profiles from normal days...")
    profiles = baseline.build_profiles(all_events)
    
    print("Scoring anomalous behavior...")
    all_events = anomaly.score_events(all_events, profiles)
    
    print(f"Loaded {len(all_events)} events. Running correlation engine...")
    incidents = correlate_events(all_events)
    print(f"Detected {len(incidents)} incidents.")

@app.get("/health")
def health_check():
    """Simple health check endpoint."""
    return {"status": "ok", "incidents_detected": len(incidents)}

@app.get("/incidents")
def get_incidents():
    """List all detected incidents with summary data."""
    summary = []
    for inc in incidents:
        summary.append({
            "id": inc.id,
            "severity": inc.severity,
            "risk_score": round(inc.risk_score, 2),
            "event_count": len(inc.events),
            "start_time": inc.events[0].event.timestamp.isoformat(),
            "end_time": inc.events[-1].event.timestamp.isoformat()
        })
    return summary

@app.get("/incidents/{incident_id}")
def get_incident_details(incident_id: str):
    """Get full details of a specific incident, including its event timeline."""
    for inc in incidents:
        if inc.id == incident_id:
            return {
                "id": inc.id,
                "severity": inc.severity,
                "risk_score": round(inc.risk_score, 2),
                "timeline": [e.to_dict() for e in inc.events]
            }
    raise HTTPException(status_code=404, detail="Incident not found")

@app.get("/incidents/{incident_id}/graph")
def get_incident_graph(incident_id: str):
    """Get the NetworkX graph JSON representation of the attack chain."""
    for inc in incidents:
        if inc.id == incident_id:
            return build_attack_graph(inc)
    raise HTTPException(status_code=404, detail="Incident not found")

@app.get("/events")
def get_events(
    user: Optional[str] = Query(None, description="Filter by user"),
    ip: Optional[str] = Query(None, description="Filter by IP address (source or dest)"),
    host: Optional[str] = Query(None, description="Filter by host asset")
):
    """Retrieve raw merged events, with optional filtering."""
    filtered = all_events
    if user:
        filtered = [e for e in filtered if e.user == user]
    if ip:
        filtered = [e for e in filtered if e.source_ip == ip or e.dest_ip == ip]
    if host:
        filtered = [e for e in filtered if e.host == host]
        
    return [e.dict() for e in filtered]

@app.get("/incidents/{incident_id}/anomalies")
def get_incident_anomalies(incident_id: str):
    """Retrieve only the anomalous events for a specific incident."""
    for inc in incidents:
        if inc.id == incident_id:
            anomalous = [e.to_dict() for e in inc.events if e.event.anomaly_score > 0]
            return anomalous
    raise HTTPException(status_code=404, detail="Incident not found")

@app.get("/users/{user}/profile")
def get_user_profile(user: str):
    """Retrieve the baseline behavior profile for a user."""
    if user in profiles:
        return profiles[user]
    raise HTTPException(status_code=404, detail="Profile not found")

@app.get("/anomalies")
def get_all_anomalies():
    """Retrieve the top most anomalous events across all data."""
    # Filter and sort raw events by anomaly score
    anomalies = [e.dict() for e in all_events if e.anomaly_score > 0.5]
    anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
    return anomalies[:100]  # Return top 100

from sse_starlette.sse import EventSourceResponse
import agent
import tools
import config

@app.post("/incidents/{incident_id}/investigate")
def investigate_incident(incident_id: str, mode: Optional[str] = None):
    """Starts the agent investigation and streams steps via SSE."""
    active_mode = mode or config.AGENT_MODE
    return EventSourceResponse(agent.investigate(incident_id, active_mode))

@app.get("/incidents/{incident_id}/report")
def get_incident_report(incident_id: str):
    """Retrieve the latest completed agent report."""
    if incident_id in reports:
        return reports[incident_id]
    raise HTTPException(status_code=404, detail="Report not found. You must run the investigation first.")

@app.post("/incidents/{incident_id}/contain")
def contain_incident(incident_id: str):
    """Simulate applying the containment plan (Read-Only)."""
    # This is a simulation endpoint that proves we do not execute actions.
    if incident_id not in reports:
         # Fallback to generating it on the fly if report isn't ready
         plan = tools.AVAILABLE_TOOLS["generate_containment_plan"](incident_id)
         actions = plan.get("containment_plan", [])
    else:
         actions = reports[incident_id].get("containment_plan", [])
         
    return {
        "status": "pending_approval",
        "message": "Containment actions staged. Awaiting human approval.",
        "actions_staged": actions
    }

@app.get("/agent/status")
def agent_status():
    """Returns the current configured LLM mode and reachability."""
    mode = config.AGENT_MODE
    status = "reachable"
    if mode == "gemini" and not config.GEMINI_API_KEY:
        status = "missing_api_key"
    elif mode == "ollama":
        # In a real app we'd ping localhost:11434
        status = "assumed_reachable"
        
    return {
        "configured_mode": mode,
        "status": status,
        "max_steps": config.MAX_AGENT_STEPS
    }

if __name__ == "__main__":
    import uvicorn
    # Run with: uvicorn main:app --reload
    uvicorn.run(app, host="0.0.0.0", port=8000)
