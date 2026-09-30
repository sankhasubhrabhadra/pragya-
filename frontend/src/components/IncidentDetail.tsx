import { IncidentChain } from '../api';
import clsx from 'clsx';
import { Network, Server, User, Globe, AlertTriangle } from 'lucide-react';

interface IncidentDetailProps {
  incident: IncidentChain;
  activeEventId: string | null;
}

const STAGES = [
  "initial_access",
  "credential_compromise",
  "privilege_escalation",
  "lateral_movement",
  "data_access",
  "exfiltration"
];

function getSourceIcon(source: string) {
  switch (source) {
    case 'auth': return <User className="w-4 h-4" />;
    case 'firewall': return <Network className="w-4 h-4" />;
    case 'endpoint': return <Server className="w-4 h-4" />;
    case 'app': return <Globe className="w-4 h-4" />;
    default: return <Server className="w-4 h-4" />;
  }
}

export default function IncidentDetail({ incident, activeEventId }: IncidentDetailProps) {
  const reachedStages = new Set(incident.events.map(e => e.stage));

  return (
    <div className="flex flex-col h-full bg-slate-950 text-slate-300 overflow-y-auto">
      {/* Banner */}
      <div className="p-6 bg-slate-900 border-b border-slate-800">
        <div className="flex items-center gap-4 mb-2">
          <h2 className="text-2xl font-mono font-bold text-white">{incident.id}</h2>
          <span className="px-3 py-1 text-xs font-semibold uppercase rounded-full bg-slate-800 border border-slate-700 text-slate-300">
            Risk Score: {incident.risk_score.toFixed(1)}
          </span>
        </div>
        <p className="text-sm text-slate-400">
          {incident.events.length} seemingly unrelated events correlated into a probable attack chain.
        </p>
      </div>

      <div className="p-6 flex-1 max-w-5xl">
        <h3 className="text-lg font-semibold text-slate-200 mb-6 flex items-center gap-2">
          <Network className="w-5 h-5 text-indigo-400" />
          Attack Timeline
        </h3>

        <div className="relative pl-6 space-y-8 before:absolute before:inset-0 before:ml-[1.125rem] before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-slate-800 before:to-transparent">
          {STAGES.map((stageName, idx) => {
            const isReached = reachedStages.has(stageName);
            const stageEvents = incident.events.filter(e => e.stage === stageName);
            
            return (
              <div key={stageName} className={clsx("relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group is-active", isReached ? 'opacity-100' : 'opacity-40')}>
                <div className={clsx("flex items-center justify-center w-8 h-8 rounded-full border-4 border-slate-950 shrink-0 md:order-1 md:group-odd:-translate-x-1/2 md:group-even:translate-x-1/2 shadow", isReached ? 'bg-indigo-500' : 'bg-slate-700')}>
                  <span className="text-slate-950 text-xs font-bold">{idx + 1}</span>
                </div>
                
                <div className="w-[calc(100%-4rem)] md:w-[calc(50%-2.5rem)] bg-slate-900 p-4 rounded-xl border border-slate-800 shadow-lg">
                  <div className="flex items-center justify-between mb-3">
                    <h4 className="font-bold text-slate-200 capitalize">{stageName.replace('_', ' ')}</h4>
                  </div>
                  
                  {isReached ? (
                    <div className="space-y-3">
                      {stageEvents.map((evt, i) => (
                        <div key={i} id={`event-${evt.event.event_id}`} className={clsx("p-3 rounded-lg border text-sm transition-colors duration-500", activeEventId === evt.event.event_id ? 'bg-indigo-900/30 border-indigo-500' : 'bg-slate-950 border-slate-800')}>
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center gap-2 text-indigo-400">
                              {getSourceIcon(evt.event.source)}
                              <span className="uppercase text-[10px] tracking-wider font-bold">{evt.event.source}</span>
                            </div>
                            <span className="text-[10px] text-slate-500 font-mono">{evt.event.event_id}</span>
                          </div>
                          
                          {/* XSS Prevention: render as pure text block */}
                          <div className="text-slate-300 font-mono text-xs p-2 bg-slate-900 rounded border border-slate-800 break-all mb-2">
                            {evt.event.details}
                          </div>
                          
                          <p className="text-xs text-slate-400 mb-2">
                            <span className="font-semibold text-slate-300">Link reason:</span> {evt.reason}
                          </p>
                          
                          {evt.event.anomaly_score > 0.5 && (
                            <div className="flex items-start gap-1.5 mt-2 text-[10px] text-amber-400 bg-amber-400/10 px-2 py-1 rounded">
                              <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5" />
                              <span>Anomaly Score: {evt.event.anomaly_score.toFixed(2)}</span>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-slate-500 italic">Stage not reached or undetected.</p>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
