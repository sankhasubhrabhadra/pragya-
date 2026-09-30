import { AgentStatus, AttackGraph, IncidentChain, MappedEvent } from '../api';

export const DEMO_INCIDENT: IncidentChain = {
  id: "INC-DEMO-9999",
  risk_score: 95.5,
  severity: "critical",
  events: [
    {
      event: { event_id: "evt-1", timestamp: "2026-09-30T10:00:00Z", source: "auth", user: "Faculty-42", source_ip: "10.0.1.55", dest_ip: null, host: null, event_type: "fail", details: "Bad password", anomaly_score: 0.1 },
      stage: "initial_access", reason: "Failed authentication attempt (possible brute-force)."
    },
    {
      event: { event_id: "evt-2", timestamp: "2026-09-30T10:05:00Z", source: "auth", user: "Faculty-42", source_ip: "10.0.1.55", dest_ip: null, host: null, event_type: "success", details: "Login success", anomaly_score: 0.95 },
      stage: "credential_compromise", reason: "Successful login immediately following a failed attempt."
    },
    {
      event: { event_id: "evt-3", timestamp: "2026-09-30T10:10:00Z", source: "firewall", user: null, source_ip: "10.0.1.55", dest_ip: "10.0.2.100", host: null, event_type: "allow", details: "Port: 22", anomaly_score: 0.8 },
      stage: "lateral_movement", reason: "Internal movement allowed on management port: Port: 22."
    },
    {
      event: { event_id: "evt-4", timestamp: "2026-09-30T10:15:00Z", source: "endpoint", user: "root", source_ip: null, dest_ip: null, host: "SERVER-07", event_type: "privilege_change", details: "User added to sudoers", anomaly_score: 0.9 },
      stage: "privilege_escalation", reason: "Explicit privilege escalation event on SERVER-07."
    },
    {
      event: { event_id: "evt-5", timestamp: "2026-09-30T10:20:00Z", source: "app", user: "service_account", source_ip: null, dest_ip: null, host: "DB-MAIN", event_type: "query", details: "SELECT * FROM users", anomaly_score: 0.7 },
      stage: "data_access", reason: "Direct interaction with a database server."
    },
    {
      event: { event_id: "evt-6", timestamp: "2026-09-30T10:25:00Z", source: "firewall", user: null, source_ip: "10.0.2.100", dest_ip: "203.0.113.45", host: null, event_type: "allow", details: "Port: 443", anomaly_score: 0.99 },
      stage: "exfiltration", reason: "Outbound external connection allowed, possible exfiltration."
    }
  ]
};

export const DEMO_GRAPH: AttackGraph = {
  nodes: [
    { id: "Faculty-42", label: "Faculty-42", type: "user" },
    { id: "10.0.1.55", label: "10.0.1.55", type: "ip" },
    { id: "SERVER-07", label: "SERVER-07", type: "host" },
    { id: "DB-MAIN", label: "DB-MAIN", type: "host" },
    { id: "203.0.113.45", label: "203.0.113.45", type: "ip", is_attacker: true }
  ],
  edges: [
    { source: "10.0.1.55", target: "Faculty-42", label: "Login" },
    { source: "Faculty-42", target: "SERVER-07", label: "SSH" },
    { source: "SERVER-07", target: "DB-MAIN", label: "Query" },
    { source: "SERVER-07", target: "203.0.113.45", label: "Exfil" }
  ]
};

const DEMO_STREAM_CHUNKS = [
  { step: 1, thinking: "I need to see which users and hosts were involved.", tool: "map_attack_path", args: { incident_id: "INC-DEMO-9999" } },
  { summary: "Found 1 users and 2 hosts." },
  { step: 2, thinking: "I need the chronological sequence of the attack.", tool: "build_timeline", args: { incident_id: "INC-DEMO-9999" } },
  { summary: "Timeline has 6 events." },
  { step: 3, thinking: "Checking if SERVER-07 has known vulnerabilities.", tool: "check_vulnerabilities", args: { host: "SERVER-07" } },
  { summary: "Found 1 vulnerabilities on SERVER-07." },
  { step: 4, thinking: "Identifying impacted systems and data criticality.", tool: "identify_affected_assets", args: { incident_id: "INC-DEMO-9999" } },
  { summary: "Identified 3 assets at risk." },
  { step: 5, thinking: "Generating prioritized containment recommendations.", tool: "generate_containment_plan", args: { incident_id: "INC-DEMO-9999" } },
  { summary: "Generated 3 recommendations." },
  { step: 6, thinking: "I have enough evidence to build the final report." },
  { final_report: {
      incident_id: "INC-DEMO-9999",
      attack_narrative: "The incident started with unusual behavior from Faculty-42. The attacker IP was found to be 203.0.113.45 in the logs. They moved laterally through SERVER-07, DB-MAIN. Evidence clearly points to a multi-stage attack hitting critical assets.",
      confidence: "high",
      confidence_reason: "Multiple distinct attack stages matched known ransomware kill chains with strong anomaly correlation.",
      evidence_event_ids: ["evt-1", "evt-2", "evt-3", "evt-4", "evt-5", "evt-6"],
      timeline: DEMO_INCIDENT.events.map(e => ({ timestamp: e.event.timestamp, stage: e.stage, description: e.reason, event_id: e.event.event_id })),
      affected_assets: ["Faculty-42", "SERVER-07 (High)", "DB-MAIN (Critical)"],
      containment_plan: [
        { action: "isolate_host", target: "SERVER-07", reason: "Prevent lateral movement", risk: "Disrupts internal services" },
        { action: "revoke_sessions", target: "Faculty-42", reason: "Stop compromised account", risk: "User will be logged out" },
        { action: "block_ip", target: "203.0.113.45", reason: "Stop exfiltration", risk: "None" }
      ]
    }
  }
];

export async function* getDemoInvestigationStream() {
  for (const chunk of DEMO_STREAM_CHUNKS) {
    await new Promise(r => setTimeout(r, 1000));
    yield chunk;
  }
}
