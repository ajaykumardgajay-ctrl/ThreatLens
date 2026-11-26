import React, { useMemo, useState } from 'react';
import {
  Background,
  Controls,
  Edge,
  Handle,
  MarkerType,
  Node,
  NodeProps,
  Position,
  ReactFlow,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  Activity,
  ArrowUpRight,
  FileWarning,
  Globe,
  KeyRound,
  Server,
  ShieldAlert,
  User,
  X,
} from 'lucide-react';
import type { AttackGraph, GraphEdgeData, GraphNodeData } from '../types/tracepoint';
import { formatUtcTime } from '../utils/format';

interface CustomNodeData extends Record<string, unknown> {
  raw: GraphNodeData;
  highlighted: boolean;
  dimmed: boolean;
}

function EntityIcon({ type }: { type: GraphNodeData['node_type'] }) {
  switch (type) {
    case 'User':
      return <User className="w-3.5 h-3.5 text-amber-400" />;
    case 'IP address':
      return <Globe className="w-3.5 h-3.5 text-rose-400" />;
    case 'Host':
      return <Server className="w-3.5 h-3.5 text-zinc-300" />;
    case 'Session':
      return <KeyRound className="w-3.5 h-3.5 text-zinc-400" />;
    case 'Resource':
      return <FileWarning className="w-3.5 h-3.5 text-amber-300" />;
    case 'External endpoint':
      return <ArrowUpRight className="w-3.5 h-3.5 text-rose-400" />;
    default:
      return <Activity className="w-3.5 h-3.5 text-rose-400" />;
  }
}

function TraceNode({ data }: NodeProps<Node<CustomNodeData>>) {
  const { raw, highlighted, dimmed } = data;
  const isEvent = raw.node_type === 'Event';

  if (isEvent) {
    const sevBorder =
      raw.severity === 'critical'
        ? 'border-l-rose-500'
        : raw.severity === 'high'
        ? 'border-l-red-500'
        : 'border-l-amber-400';

    return (
      <div
        className={`w-[235px] rounded-md border bg-[#121216] px-3 py-2 shadow-lg transition-all border-l-4 ${sevBorder} ${
          highlighted
            ? 'border-amber-400 ring-2 ring-amber-400/30 shadow-amber-950/40'
            : 'border-zinc-800'
        } ${dimmed ? 'opacity-30' : 'opacity-100'}`}
      >
        <Handle type="target" position={Position.Left} className="!bg-amber-400 !w-2 !h-2 !border-0" />
        <Handle type="target" position={Position.Top} className="!bg-amber-400 !w-2 !h-2 !border-0" />
        <div className="flex items-center justify-between gap-2 mb-1">
          <span className="inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-rose-400">
            <ShieldAlert className="w-3 h-3" />
            Event Stage
          </span>
          {raw.timestamp && (
            <span className="font-mono text-[10px] text-zinc-400">
              {raw.timestamp.slice(11, 19)}Z
            </span>
          )}
        </div>
        <div className="text-xs font-semibold text-zinc-100 leading-snug">{raw.label}</div>
        {raw.event_ids[0] && (
          <div className="mt-1.5 font-mono text-[10px] text-amber-300/90 truncate">
            {raw.event_ids[0]}
          </div>
        )}
        <Handle type="source" position={Position.Right} className="!bg-amber-400 !w-2 !h-2 !border-0" />
        <Handle type="source" position={Position.Bottom} className="!bg-amber-400 !w-2 !h-2 !border-0" />
      </div>
    );
  }

  return (
    <div
      className={`min-w-[165px] max-w-[225px] rounded-full border bg-[#0f0f13] px-3.5 py-2 shadow transition-all ${
        highlighted
          ? 'border-amber-400 ring-2 ring-amber-400/25'
          : raw.is_suspicious
          ? 'border-rose-500/40'
          : 'border-zinc-800'
      } ${dimmed ? 'opacity-30' : 'opacity-100'}`}
    >
      <Handle type="target" position={Position.Top} className="!bg-zinc-400 !w-1.5 !h-1.5 !border-0" />
      <Handle type="target" position={Position.Left} className="!bg-zinc-400 !w-1.5 !h-1.5 !border-0" />
      <div className="flex items-center gap-2">
        <span className="p-1 rounded-full bg-zinc-900 border border-zinc-800">
          <EntityIcon type={raw.node_type} />
        </span>
        <div className="min-w-0">
          <div className="text-[9px] uppercase tracking-wider text-zinc-400 leading-none mb-0.5">
            {raw.node_type}
          </div>
          <div className="font-mono text-[11px] font-medium text-zinc-100 truncate" title={raw.label}>
            {raw.label}
          </div>
        </div>
      </div>
      <Handle type="source" position={Position.Bottom} className="!bg-zinc-400 !w-1.5 !h-1.5 !border-0" />
      <Handle type="source" position={Position.Right} className="!bg-zinc-400 !w-1.5 !h-1.5 !border-0" />
    </div>
  );
}

const nodeTypes = { traceNode: TraceNode };

interface AttackGraphCanvasProps {
  graph: AttackGraph;
  highlightNodeIds?: string[];
  highlightEdgeIds?: string[];
  dimUnfocused?: boolean;
  heightClass?: string;
}

export const AttackGraphCanvas: React.FC<AttackGraphCanvasProps> = ({
  graph,
  highlightNodeIds,
  highlightEdgeIds,
  dimUnfocused = false,
  heightClass = 'h-[500px]',
}) => {
  const [selectedNode, setSelectedNode] = useState<GraphNodeData | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdgeData | null>(null);

  const activeNodesSet = useMemo(
    () => new Set(highlightNodeIds ?? graph.attack_path_node_ids),
    [highlightNodeIds, graph.attack_path_node_ids]
  );
  const activeEdgesSet = useMemo(
    () => new Set(highlightEdgeIds ?? graph.attack_path_edge_ids),
    [highlightEdgeIds, graph.attack_path_edge_ids]
  );

  const { nodes, edges } = useMemo(() => {
    const eventNodes = graph.nodes
      .filter((n) => n.node_type === 'Event')
      .sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));
    const topEntities = graph.nodes.filter(
      (n) => n.node_type === 'User' || n.node_type === 'IP address'
    );
    const bottomEntities = graph.nodes.filter(
      (n) =>
        n.node_type !== 'Event' &&
        n.node_type !== 'User' &&
        n.node_type !== 'IP address'
    );

    const positions = new Map<string, { x: number; y: number }>();

    eventNodes.forEach((n, idx) => {
      positions.set(n.id, { x: 80 + idx * 290, y: 230 });
    });

    const topSpacing = Math.max(210, (Math.max(1, eventNodes.length) * 280) / Math.max(1, topEntities.length));
    topEntities.forEach((n, idx) => {
      const rowOffset = n.node_type === 'IP address' ? 20 : 105;
      positions.set(n.id, { x: 90 + idx * topSpacing, y: rowOffset });
    });

    const botSpacing = Math.max(210, (Math.max(1, eventNodes.length) * 280) / Math.max(1, bottomEntities.length));
    bottomEntities.forEach((n, idx) => {
      const rowOffset =
        n.node_type === 'Resource' || n.node_type === 'External endpoint' ? 465 : 375;
      positions.set(n.id, { x: 70 + idx * botSpacing, y: rowOffset });
    });

    const rfNodes: Node<CustomNodeData>[] = graph.nodes.map((n) => {
      const isHi = activeNodesSet.has(n.id);
      return {
        id: n.id,
        type: 'traceNode',
        position: positions.get(n.id) || { x: 100, y: 200 },
        data: {
          raw: n,
          highlighted: isHi,
          dimmed: dimUnfocused && activeNodesSet.size > 0 && !isHi,
        },
      };
    });

    const rfEdges: Edge[] = graph.edges.map((e) => {
      const isHi = activeEdgesSet.has(e.id);
      const isPivot = e.relationship_type === 'ESCALATED_TO';
      const isCorr = e.relationship_type === 'CORRELATED_WITH';
      const isExfil = e.relationship_type === 'TRANSFERRED_TO';

      const stroke = isPivot
        ? '#f59e0b'
        : isExfil
        ? '#f43f5e'
        : isHi || isCorr
        ? '#fbbf24'
        : '#3f3f46';

      return {
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.relationship_type,
        animated: isHi && (isCorr || isPivot || isExfil),
        style: {
          stroke,
          strokeWidth: isHi ? 2.4 : 1.3,
          opacity: dimUnfocused && activeEdgesSet.size > 0 && !isHi ? 0.2 : 0.95,
        },
        labelStyle: {
          fill: isHi ? '#f4f4f5' : '#a1a1aa',
          fontSize: 9,
          fontFamily: 'JetBrains Mono, monospace',
          fontWeight: isHi ? 600 : 400,
        },
        labelBgStyle: {
          fill: '#09090b',
          fillOpacity: 0.92,
        },
        labelBgPadding: [4, 2] as [number, number],
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: stroke,
          width: 15,
          height: 15,
        },
        data: { raw: e },
      };
    });

    return { nodes: rfNodes, edges: rfEdges };
  }, [graph, activeNodesSet, activeEdgesSet, dimUnfocused]);

  return (
    <div className={`relative w-full ${heightClass} rounded-lg border border-zinc-800 bg-[#09090b] overflow-hidden`}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.18 }}
        minZoom={0.25}
        maxZoom={1.7}
        onNodeClick={(_, node) => {
          setSelectedEdge(null);
          setSelectedNode(node.data.raw);
        }}
        onEdgeClick={(_, edge) => {
          setSelectedNode(null);
          const raw = (edge.data as { raw?: GraphEdgeData } | undefined)?.raw || null;
          setSelectedEdge(raw);
        }}
      >
        <Background color="#1c1c22" gap={20} size={1} />
        <Controls position="bottom-left" />
      </ReactFlow>

      <div className="pointer-events-none absolute top-3 left-3 flex flex-wrap items-center gap-2 rounded-md border border-zinc-800 bg-zinc-950/90 px-2.5 py-1.5 text-[10px] text-zinc-300 backdrop-blur">
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-sm bg-rose-500" /> Event Stage
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-amber-400" /> User / Entity
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-0.5 w-4 bg-amber-500" /> ESCALATED_TO / CORRELATED_WITH
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-0.5 w-4 bg-rose-500" /> TRANSFERRED_TO
        </span>
      </div>

      {(selectedNode || selectedEdge) && (
        <div className="absolute top-3 right-3 z-20 w-80 max-h-[85%] overflow-y-auto rounded-lg border border-zinc-700 bg-zinc-950/95 p-3.5 shadow-2xl backdrop-blur">
          <div className="flex items-start justify-between gap-2 border-b border-zinc-800 pb-2 mb-2.5">
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-wider text-amber-400">
                {selectedNode ? `${selectedNode.node_type} Node` : `Edge: ${selectedEdge?.relationship_type}`}
              </div>
              <div className="text-xs font-semibold text-zinc-100 mt-0.5 break-all">
                {selectedNode ? selectedNode.label : `${selectedEdge?.source} -> ${selectedEdge?.target}`}
              </div>
            </div>
            <button
              onClick={() => {
                setSelectedNode(null);
                setSelectedEdge(null);
              }}
              className="p-1 text-zinc-400 hover:text-white rounded"
              aria-label="Close inspector"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>

          {selectedNode && (
            <div className="space-y-2 text-xs">
              {selectedNode.timestamp && (
                <div>
                  <span className="text-zinc-400">Timestamp:</span>{' '}
                  <span className="font-mono text-zinc-200">{formatUtcTime(selectedNode.timestamp)}</span>
                </div>
              )}
              <div>
                <span className="text-zinc-400">Supporting Events ({selectedNode.event_ids.length}):</span>
                <div className="mt-1 flex flex-wrap gap-1">
                  {selectedNode.event_ids.map((eid) => (
                    <span
                      key={eid}
                      className="rounded bg-zinc-900 border border-zinc-800 px-1.5 py-0.5 font-mono text-[10px] text-amber-300"
                    >
                      {eid}
                    </span>
                  ))}
                </div>
              </div>
              {Boolean(selectedNode.metadata?.raw_log) && (
                <div>
                  <div className="text-zinc-400 mb-1">Raw Log Evidence:</div>
                  <pre className="rounded bg-black border border-zinc-800 p-2 font-mono text-[10px] text-zinc-200 whitespace-pre-wrap break-all">
                    {String(selectedNode.metadata.raw_log)}
                  </pre>
                </div>
              )}
            </div>
          )}

          {selectedEdge && (
            <div className="space-y-2 text-xs">
              <div>
                <span className="text-zinc-400">Correlation Reason:</span>
                <p className="text-zinc-200 mt-0.5 leading-relaxed">{selectedEdge.correlation_reason}</p>
              </div>
              <div className="grid grid-cols-2 gap-2 pt-1">
                <div className="rounded bg-zinc-900 p-2 border border-zinc-800">
                  <div className="text-[10px] text-zinc-400">Time Delta</div>
                  <div className="font-mono text-xs text-zinc-100">{selectedEdge.time_difference_seconds}s</div>
                </div>
                <div className="rounded bg-zinc-900 p-2 border border-zinc-800">
                  <div className="text-[10px] text-zinc-400">Confidence</div>
                  <div className="font-mono text-xs text-amber-400">
                    {Math.round(selectedEdge.confidence * 100)}%
                  </div>
                </div>
              </div>
              <div>
                <span className="text-zinc-400">Supporting Events:</span>
                <div className="mt-1 flex flex-wrap gap-1">
                  {selectedEdge.supporting_event_ids.map((eid) => (
                    <span
                      key={eid}
                      className="rounded bg-zinc-900 border border-zinc-800 px-1.5 py-0.5 font-mono text-[10px] text-amber-300"
                    >
                      {eid}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
