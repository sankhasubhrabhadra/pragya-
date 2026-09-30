import { Activity, ShieldAlert, Server, Play, StopCircle } from 'lucide-react';
import { AgentStatus } from '../api';

interface HeaderProps {
  status: AgentStatus | null;
  demoMode: boolean;
  setDemoMode: (val: boolean) => void;
  resetDemo: () => void;
}

export default function Header({ status, demoMode, setDemoMode, resetDemo }: HeaderProps) {
  return (
    <header className="flex items-center justify-between px-6 py-4 bg-slate-900 border-b border-slate-800">
      <div className="flex items-center gap-4">
        <div className="flex items-center justify-center w-10 h-10 bg-indigo-600 rounded-lg shadow-lg shadow-indigo-900/50">
          <ShieldAlert className="w-6 h-6 text-white" />
        </div>
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white">PRAGYA</h1>
          <p className="text-xs text-slate-400">From scattered alerts to an attack story.</p>
        </div>
      </div>

      <div className="flex items-center gap-6 text-sm">
        <div className="flex items-center gap-2 px-3 py-1 bg-slate-800 rounded-full border border-slate-700">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span className="font-medium text-slate-300">SIMULATED DATA</span>
        </div>

        <div className="flex items-center gap-2">
          <Server className="w-4 h-4 text-slate-400" />
          <span className={status ? 'text-emerald-400' : 'text-red-400'}>
            {status ? 'Backend Connected' : 'Backend Disconnected'}
          </span>
        </div>

        {status && (
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-slate-400" />
            <span className="text-indigo-400 capitalize">Mode: {status.configured_mode}</span>
          </div>
        )}

        <div className="flex items-center gap-3 border-l border-slate-700 pl-6">
          <label className="flex items-center gap-2 cursor-pointer">
            <input 
              type="checkbox" 
              checked={demoMode} 
              onChange={(e) => setDemoMode(e.target.checked)}
              className="accent-indigo-500"
            />
            <span className={demoMode ? 'text-indigo-400 font-medium' : 'text-slate-400'}>
              Demo Replay
            </span>
          </label>
          {demoMode && (
            <button 
              onClick={resetDemo}
              className="text-xs px-2 py-1 bg-slate-800 hover:bg-slate-700 rounded text-slate-300 transition-colors"
            >
              Reset Demo
            </button>
          )}
        </div>
      </div>
    </header>
  );
}
