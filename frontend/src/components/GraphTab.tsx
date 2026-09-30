import { useEffect, useState } from 'react';
import ReactFlow, { Background, Controls, type Node, type Edge, MarkerType } from 'reactflow';
import 'reactflow/dist/style.css';
import { type AttackGraph, fetchGraph } from '../api';
import { DEMO_GRAPH } from '../demo/replay';
import { Network } from 'lucide-react';

interface GraphTabProps {
  incidentId: string;
  demoMode: boolean;
}

export default function GraphTab({ incidentId, demoMode }: GraphTabProps) {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);

  useEffect(() => {
    async function load() {
      try {
        let graph: AttackGraph;
        if (demoMode) {
          graph = DEMO_GRAPH;
        } else {
          graph = await fetchGraph(incidentId);
        }

        // Extremely simple auto-layout for demo purposes (distribute horizontally)
        const typedNodes = graph.nodes.map((n, i) => ({
          id: n.id,
          data: { label: n.label },
          position: { x: (i % 3) * 200 + 50, y: Math.floor(i / 3) * 150 + 50 },
          style: {
            background: n.is_attacker ? '#450a0a' : '#0f172a',
            color: n.is_attacker ? '#f87171' : '#cbd5e1',
            border: n.is_attacker ? '1px solid #dc2626' : '1px solid #334155',
            borderRadius: '8px',
            padding: '10px',
            fontFamily: 'monospace',
            fontSize: '12px',
            boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)'
          }
        }));

        const typedEdges = graph.edges.map(e => ({
          id: `${e.source}-${e.target}`,
          source: e.source,
          target: e.target,
          label: e.label,
          animated: true,
          style: { stroke: '#6366f1', strokeWidth: 2 },
          labelStyle: { fill: '#94a3b8', fontSize: 10, fontWeight: 700 },
          labelBgStyle: { fill: '#0f172a' },
          markerEnd: { type: MarkerType.ArrowClosed, color: '#6366f1' }
        }));

        setNodes(typedNodes);
        setEdges(typedEdges);
      } catch (err) {
        console.error(err);
      }
    }
    load();
  }, [incidentId, demoMode]);

  return (
    <div className="flex-1 bg-slate-950 flex flex-col h-full border-l border-slate-800">
      <div className="p-4 border-b border-slate-800 flex items-center gap-2">
        <Network className="w-5 h-5 text-indigo-400" />
        <h3 className="font-bold text-slate-200">Attack Graph</h3>
      </div>
      <div className="flex-1 relative">
        <ReactFlow nodes={nodes} edges={edges} fitView>
          <Background color="#334155" gap={20} />
          <Controls className="bg-slate-900 border-slate-700 fill-slate-300" />
        </ReactFlow>
      </div>
    </div>
  );
}
