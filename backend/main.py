from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional

from loader import load_logs
from correlator import correlate_events
from graph_builder import build_attack_graph

app = FastAPI(title="PRAGYA API", description="AI Cyber Incident Investigator API")

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict to actual frontend domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state to hold loaded logs and correlated incidents for the demo
# In a real app, these would be in a database
all_events = []
incidents = []

@app.on_event("startup")
def startup_event():
    """Loads logs and runs correlation engine on startup."""
    global all_events, incidents
    print("Loading raw events from disk...")
    all_events = load_logs("data")
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

if __name__ == "__main__":
    import uvicorn
    # Run with: uvicorn main:app --reload
    uvicorn.run(app, host="0.0.0.0", port=8000)
