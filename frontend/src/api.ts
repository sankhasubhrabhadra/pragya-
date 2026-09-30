export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

export interface EventLog {
  event_id: string;
  timestamp: string;
  source: string;
  user: string | null;
  source_ip: string | null;
  dest_ip: string | null;
  host: string | null;
  event_type: string;
  details: string;
  anomaly_score: number;
}

export interface MappedEvent {
  event: EventLog;
  stage: string;
  reason: string;
}

export interface IncidentChain {
  id: string;
  events?: MappedEvent[]; // Full detail view has this
  event_count?: number; // Summary view from /incidents has this
  start_time?: string;
  end_time?: string;
  risk_score: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface NodeData {
  id: string;
  label: string;
  type: 'user' | 'ip' | 'host';
  is_attacker?: boolean;
}

export interface EdgeData {
  source: string;
  target: string;
  label: string;
}

export interface AttackGraph {
  nodes: NodeData[];
  edges: EdgeData[];
}

export interface AgentStatus {
  configured_mode: string;
  status: string;
  max_steps: number;
}

export interface FinalReport {
  incident_id: string;
  attack_narrative: string;
  confidence: string;
  confidence_reason: string;
  evidence_event_ids: string[];
  timeline: any[];
  affected_assets: string[];
  containment_plan: any[];
}

export async function fetchHealth() {
  const res = await fetch(`${API_BASE_URL}/health`);
  return res.json();
}

export async function fetchAgentStatus(): Promise<AgentStatus> {
  const res = await fetch(`${API_BASE_URL}/agent/status`);
  if (!res.ok) throw new Error('Failed to fetch status');
  return res.json();
}

export async function fetchIncidents(): Promise<IncidentChain[]> {
  const res = await fetch(`${API_BASE_URL}/incidents`);
  if (!res.ok) throw new Error('Failed to fetch incidents');
  return res.json();
}

export async function fetchIncident(id: string): Promise<IncidentChain> {
  const res = await fetch(`${API_BASE_URL}/incidents/${id}`);
  if (!res.ok) throw new Error('Failed to fetch incident');
  return res.json();
}

export async function fetchGraph(id: string): Promise<AttackGraph> {
  const res = await fetch(`${API_BASE_URL}/incidents/${id}/graph`);
  if (!res.ok) throw new Error('Failed to fetch graph');
  return res.json();
}

export async function containIncident(id: string) {
  const res = await fetch(`${API_BASE_URL}/incidents/${id}/contain`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to contain');
  return res.json();
}
