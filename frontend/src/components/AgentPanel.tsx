import { useState, useRef, useEffect } from 'react';
import { parseSSE } from '../lib/sse';
import { FinalReport, containIncident, API_BASE_URL } from '../api';
import { Bot, CheckCircle, CircleDashed, Server, Terminal, ShieldAlert, ArrowRight, Download } from 'lucide-react';
import clsx from 'clsx';
import { getDemoInvestigationStream } from '../demo/replay';

interface AgentPanelProps {
  incidentId: string;
  demoMode: boolean;
  onCitationClick: (eventId: string) => void;
}

type Step = { step: number; thinking: string; tool?: string; args?: any; summary?: string; status: 'running' | 'done' | 'error' };

export default function AgentPanel({ incidentId, demoMode, onCitationClick }: AgentPanelProps) {
  const [active, setActive] = useState(false);
  const [steps, setSteps] = useState<Step[]>([]);
  const [report, setReport] = useState<FinalReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [containmentStaged, setContainmentStaged] = useState<any[] | null>(null);
  const [approvedActions, setApprovedActions] = useState<Set<number>>(new Set());
  
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [steps, report]);

  const handleInvestigate = async () => {
    setActive(true);
    setSteps([]);
    setReport(null);
    setError(null);
    setContainmentStaged(null);

    try {
      let stream: AsyncIterable<any>;

      if (demoMode) {
        stream = getDemoInvestigationStream();
      } else {
        const res = await fetch(`${API_BASE_URL}/incidents/${incidentId}/investigate?mode=scripted`, { method: 'POST' });
        if (!res.ok) throw new Error('Failed to start investigation');
        if (!res.body) throw new Error('No body in response');
        stream = parseSSE(res.body);
      }

      for await (const data of stream) {
        if (data.error) {
          setError(data.error);
          break;
        }

        if (data.step) {
          setSteps(prev => {
            const newSteps = [...prev];
            if (newSteps.length > 0 && newSteps[newSteps.length - 1].status === 'running') {
              newSteps[newSteps.length - 1].status = 'done';
            }
            newSteps.push({ ...data, status: 'running' });
            return newSteps;
          });
        }

        if (data.summary) {
          setSteps(prev => {
            const newSteps = [...prev];
            if (newSteps.length > 0) {
              newSteps[newSteps.length - 1].summary = data.summary;
              newSteps[newSteps.length - 1].status = 'done';
            }
            return newSteps;
          });
        }

        if (data.final_report) {
          setSteps(prev => {
            const newSteps = [...prev];
            if (newSteps.length > 0) newSteps[newSteps.length - 1].status = 'done';
            return newSteps;
          });
          setReport(data.final_report);
        }
      }
    } catch (err: any) {
      setError(err.message || 'Stream interrupted');
    }
  };

  const handleContain = async () => {
    try {
      let actions = report?.containment_plan || [];
      if (!demoMode) {
        const res = await containIncident(incidentId);
        actions = res.actions_staged;
      }
      setContainmentStaged(actions);
      setApprovedActions(new Set());
    } catch (err: any) {
      setError('Failed to stage containment: ' + err.message);
    }
  };

  const approveAction = (idx: number) => {
    setApprovedActions(prev => {
      const n = new Set(prev);
      n.add(idx);
      return n;
    });
  };

  return (
    <div className="flex flex-col h-full bg-slate-900 border-l border-slate-800 w-[500px] shrink-0">
      <div className="p-4 border-b border-slate-800 flex justify-between items-center">
        <h3 className="font-bold text-slate-200 flex items-center gap-2">
          <Bot className="w-5 h-5 text-indigo-400" />
          AI Investigator
        </h3>
        {!active && !report && (
          <button 
            onClick={handleInvestigate}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded font-medium shadow transition-colors flex items-center gap-2"
          >
            <Play className="w-4 h-4" />
            INVESTIGATE
          </button>
        )}
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {steps.map((s, i) => (
          <div key={i} className="p-3 bg-slate-950 rounded-lg border border-slate-800 animate-in fade-in slide-in-from-bottom-2">
            <div className="flex gap-3">
              <div className="mt-0.5">
                {s.status === 'running' ? (
                  <CircleDashed className="w-5 h-5 text-indigo-400 animate-spin" />
                ) : (
                  <CheckCircle className="w-5 h-5 text-emerald-500" />
                )}
              </div>
              <div className="flex-1">
                <p className="text-sm font-medium text-slate-200">Step {s.step}: {s.thinking}</p>
                {s.tool && (
                  <div className="mt-2 inline-flex items-center gap-1.5 px-2 py-1 bg-slate-800 border border-slate-700 rounded text-xs font-mono text-slate-300">
                    <Terminal className="w-3 h-3" />
                    {s.tool}
                  </div>
                )}
                {s.summary && (
                  <p className="mt-2 text-xs text-slate-400 bg-slate-900 p-2 rounded">{s.summary}</p>
                )}
              </div>
            </div>
          </div>
        ))}

        {error && (
          <div className="p-3 bg-red-900/20 border border-red-500/30 rounded-lg text-red-400 text-sm flex items-start gap-2">
            <ShieldAlert className="w-5 h-5 shrink-0" />
            <p>{error}</p>
            <button onClick={handleInvestigate} className="ml-auto underline">Retry</button>
          </div>
        )}

        {report && (
          <div className="mt-6 animate-in fade-in">
            <h4 className="text-lg font-bold text-slate-200 border-b border-slate-800 pb-2 mb-4">Final Report</h4>
            
            <div className="space-y-4">
              <div>
                <span className="text-xs uppercase text-slate-500 font-bold tracking-wider">Confidence</span>
                <p className={clsx("text-sm font-medium", report.confidence === 'high' ? 'text-emerald-400' : 'text-amber-400')}>
                  {report.confidence.toUpperCase()} - {report.confidence_reason}
                </p>
              </div>

              <div>
                <span className="text-xs uppercase text-slate-500 font-bold tracking-wider">Attack Narrative (Probable)</span>
                <p className="text-sm text-slate-300 leading-relaxed mt-1">
                  {/* Safely render text only. No HTML parsing. */}
                  {report.attack_narrative}
                </p>
              </div>

              <div>
                <span className="text-xs uppercase text-slate-500 font-bold tracking-wider">Cited Evidence</span>
                <div className="flex flex-wrap gap-2 mt-2">
                  {report.evidence_event_ids.map(id => (
                    <button 
                      key={id}
                      onClick={() => onCitationClick(id)}
                      className="px-2 py-1 text-[10px] font-mono bg-indigo-900/30 text-indigo-300 border border-indigo-500/30 rounded hover:bg-indigo-500 hover:text-white transition-colors"
                    >
                      {id}
                    </button>
                  ))}
                </div>
              </div>

              {!containmentStaged ? (
                <button 
                  onClick={handleContain}
                  className="w-full py-3 mt-4 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded-lg shadow-lg flex justify-center items-center gap-2"
                >
                  <ShieldAlert className="w-5 h-5" />
                  CONTAIN ATTACK
                </button>
              ) : (
                <div className="mt-6 p-4 bg-slate-950 border border-slate-800 rounded-lg">
                  <h5 className="font-bold text-slate-200 flex items-center gap-2 mb-3">
                    <Server className="w-4 h-4 text-emerald-400" />
                    Recommended Containment Plan
                  </h5>
                  <p className="text-xs text-slate-500 mb-4 uppercase">Pragya recommends. A human decides.</p>
                  
                  <div className="space-y-3">
                    {containmentStaged.map((action, idx) => {
                      const isApproved = approvedActions.has(idx);
                      return (
                        <div key={idx} className="p-3 bg-slate-900 border border-slate-700 rounded text-sm">
                          <div className="flex justify-between items-start mb-2">
                            <strong className="text-slate-200 capitalize">{action.action.replace('_', ' ')}</strong>
                            <span className="font-mono text-xs text-indigo-400">{action.target}</span>
                          </div>
                          <p className="text-xs text-slate-400 mb-1"><span className="text-slate-500">Reason:</span> {action.reason}</p>
                          <p className="text-xs text-amber-400 mb-3"><span className="text-amber-500/50">Risk:</span> {action.risk}</p>
                          
                          <button 
                            disabled={isApproved}
                            onClick={() => approveAction(idx)}
                            className={clsx("w-full py-1.5 text-xs font-bold rounded transition-colors", isApproved ? "bg-emerald-900/50 text-emerald-400 border border-emerald-800 cursor-not-allowed" : "bg-slate-800 text-slate-300 hover:bg-slate-700 border border-slate-600")}
                          >
                            {isApproved ? 'Approved (Simulation Only)' : 'Approve Action'}
                          </button>
                        </div>
                      );
                    })}
                  </div>
                  
                  <button className="w-full mt-4 py-2 flex items-center justify-center gap-2 text-xs font-medium text-slate-400 hover:text-slate-200 bg-slate-800 rounded">
                    <Download className="w-3 h-3" /> Export Incident Report
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
        <div ref={endRef} />
      </div>
    </div>
  );
}
