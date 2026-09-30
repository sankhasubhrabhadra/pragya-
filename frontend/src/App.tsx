import { useState, useEffect } from 'react';
import { fetchAgentStatus, fetchIncidents, type IncidentChain, type AgentStatus } from './api';
import Header from './components/Header';
import IncidentList from './components/IncidentList';
import IncidentDetail from './components/IncidentDetail';
import GraphTab from './components/GraphTab';
import AgentPanel from './components/AgentPanel';
import { DEMO_INCIDENT } from './demo/replay';

export default function App() {
  const [incidents, setIncidents] = useState<IncidentChain[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [fullIncident, setFullIncident] = useState<IncidentChain | null>(null);
  const [status, setStatus] = useState<AgentStatus | null>(null);
  const [demoMode, setDemoMode] = useState(false);
  const [activeEventId, setActiveEventId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'timeline' | 'graph'>('timeline');

  useEffect(() => {
    async function init() {
      try {
        const [stat, incs] = await Promise.all([fetchAgentStatus(), fetchIncidents()]);
        setStatus(stat);
        setIncidents(incs);
      } catch (err) {
        console.error("Backend not reachable. Falling back to demo mode.");
        setDemoMode(true);
      }
    }
    init();
  }, []);

  useEffect(() => {
    async function loadFullIncident() {
      if (!selectedId || demoMode) return;
      try {
        // api.ts has fetchIncident
        const { fetchIncident } = await import('./api');
        const full = await fetchIncident(selectedId);
        setFullIncident(full);
      } catch(err) {
        console.error(err);
      }
    }
    loadFullIncident();
  }, [selectedId, demoMode]);

  const currentIncident = demoMode 
    ? DEMO_INCIDENT 
    : fullIncident;

  const handleCitationClick = (eventId: string) => {
    setActiveTab('timeline');
    setActiveEventId(eventId);
    setTimeout(() => {
      document.getElementById(`event-${eventId}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }, 100);
  };

  const handleResetDemo = () => {
    // Just force a re-render of the selected incident
    const id = selectedId;
    setSelectedId(null);
    setTimeout(() => setSelectedId(id), 0);
  };

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (_e: KeyboardEvent) => {
      // Just a simple simulation of shortcut keys if a panel was active. 
      // Ignored for now to avoid accidental triggers, but hooked up.
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  return (
    <div className="flex flex-col h-screen bg-slate-950 text-slate-200 overflow-hidden">
      <Header 
        status={status} 
        demoMode={demoMode} 
        setDemoMode={setDemoMode} 
        resetDemo={handleResetDemo}
      />
      
      <div className="flex flex-1 overflow-hidden">
        <IncidentList 
          incidents={demoMode ? [DEMO_INCIDENT] : incidents} 
          selectedId={demoMode ? DEMO_INCIDENT.id : selectedId} 
          onSelect={setSelectedId} 
        />
        
        {currentIncident ? (
          <div className="flex flex-1 overflow-hidden">
            <div className="flex-1 flex flex-col min-w-0">
              <div className="flex border-b border-slate-800 bg-slate-900 px-4">
                <button 
                  className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors ${activeTab === 'timeline' ? 'border-indigo-500 text-indigo-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`}
                  onClick={() => setActiveTab('timeline')}
                >
                  Attack Timeline
                </button>
                <button 
                  className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors ${activeTab === 'graph' ? 'border-indigo-500 text-indigo-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`}
                  onClick={() => setActiveTab('graph')}
                >
                  Attack Graph
                </button>
              </div>
              
              {activeTab === 'timeline' ? (
                <IncidentDetail incident={currentIncident} activeEventId={activeEventId} />
              ) : (
                <GraphTab incidentId={currentIncident.id} demoMode={demoMode} />
              )}
            </div>
            
            {/* Make sure we pass a key to AgentPanel so it completely resets when we switch incidents or click reset demo */}
            <AgentPanel 
              key={currentIncident.id}
              incidentId={currentIncident.id} 
              demoMode={demoMode} 
              onCitationClick={handleCitationClick} 
            />
          </div>
        ) : (
          <div className="flex-1 flex items-center justify-center text-slate-500">
            <p>Select an incident to view details</p>
          </div>
        )}
      </div>
    </div>
  );
}
