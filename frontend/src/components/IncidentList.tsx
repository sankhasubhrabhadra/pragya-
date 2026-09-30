import { IncidentChain } from '../api';
import clsx from 'clsx';
import { ShieldAlert, Shield, ShieldCheck, AlertTriangle } from 'lucide-react';

interface IncidentListProps {
  incidents: IncidentChain[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

const severityConfig = {
  critical: { color: 'text-red-400', bg: 'bg-red-400/10', border: 'border-red-400/20', icon: ShieldAlert },
  high: { color: 'text-orange-400', bg: 'bg-orange-400/10', border: 'border-orange-400/20', icon: AlertTriangle },
  medium: { color: 'text-yellow-400', bg: 'bg-yellow-400/10', border: 'border-yellow-400/20', icon: Shield },
  low: { color: 'text-blue-400', bg: 'bg-blue-400/10', border: 'border-blue-400/20', icon: ShieldCheck },
};

export default function IncidentList({ incidents, selectedId, onSelect }: IncidentListProps) {
  // Sort critical first, then by risk score
  const sorted = [...incidents].sort((a, b) => {
    const sevScore = { critical: 4, high: 3, medium: 2, low: 1 };
    if (sevScore[a.severity] !== sevScore[b.severity]) {
      return sevScore[b.severity] - sevScore[a.severity];
    }
    return b.risk_score - a.risk_score;
  });

  return (
    <div className="w-80 border-r border-slate-800 bg-slate-900/50 flex flex-col h-full overflow-hidden">
      <div className="p-4 border-b border-slate-800">
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Detected Incidents</h2>
        <p className="text-xs text-slate-500 mt-1">{incidents.length} chains analyzed</p>
      </div>
      <div className="flex-1 overflow-y-auto p-2 space-y-2">
        {sorted.map(inc => {
          const config = severityConfig[inc.severity];
          const Icon = config.icon;
          const isSelected = selectedId === inc.id;

          // Simple time range
          const times = inc.events.map(e => new Date(e.event.timestamp).getTime());
          const min = Math.min(...times);
          const max = Math.max(...times);
          const timeRange = `${new Date(min).toLocaleTimeString()} - ${new Date(max).toLocaleTimeString()}`;

          return (
            <button
              key={inc.id}
              onClick={() => onSelect(inc.id)}
              className={clsx(
                "w-full text-left p-3 rounded-lg border transition-all duration-200",
                isSelected 
                  ? "bg-slate-800 border-indigo-500 shadow-sm shadow-indigo-500/20" 
                  : "bg-slate-900/50 border-slate-800 hover:border-slate-700 hover:bg-slate-800"
              )}
            >
              <div className="flex items-start justify-between mb-2">
                <span className="font-mono text-sm text-slate-200">{inc.id}</span>
                <span className={clsx("flex items-center gap-1 text-[10px] uppercase tracking-wider px-2 py-0.5 rounded-full font-medium border", config.color, config.bg, config.border)}>
                  <Icon className="w-3 h-3" />
                  {inc.severity}
                </span>
              </div>
              <p className="text-xs text-slate-400 mb-2 truncate">
                {inc.events.length} correlated events
              </p>
              <div className="flex justify-between items-center text-[10px] text-slate-500">
                <span>Score: {inc.risk_score.toFixed(1)}</span>
                <span>{timeRange}</span>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
