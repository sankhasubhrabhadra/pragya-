from typing import List, Dict, Any

def build_report(incident_id: str, narrative: str, timeline: list, affected_assets: list, 
                 vulns: list, confidence: str, confidence_reason: str, evidence: list, containment_plan: list) -> Dict[str, Any]:
    """Formats the final investigation report."""
    
    return {
        "incident_id": incident_id,
        "summary": "AI Incident Investigation Report",
        "attack_narrative": narrative,
        "timeline": timeline,
        "affected_assets": affected_assets,
        "vulnerabilities_involved": vulns,
        "confidence": confidence,
        "confidence_reason": confidence_reason,
        "evidence_event_ids": evidence,
        "containment_plan": containment_plan,
        "disclaimer": "This attack chain is PROBABLE, not certain. The agent relies purely on available logs. Missing logs or out-of-band activity is NOT shown."
    }
