import React, { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import type { Core } from 'cytoscape';
import type { CytoscapeElement } from '../types/event';

interface Props {
  elements: CytoscapeElement[];
  onSelectNode?: (nodeData: any) => void;
}

export const InvestigationGraphView: React.FC<Props> = ({ elements, onSelectNode }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [selectedElement, setSelectedElement] = useState<any>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    // Clean up previous instance
    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements: elements as any,
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(label)',
            'font-size': '11px',
            'font-family': 'Inter, system-ui, sans-serif',
            color: '#e2e8f0',
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'background-color': '#475569',
            'border-width': 2,
            'border-color': '#64748b',
            width: 32,
            height: 32,
          },
        },
        {
          selector: 'node[node_type = "event"]',
          style: {
            shape: 'round-rectangle',
            width: 28,
            height: 28,
            'background-color': '#0ea5e9',
            'border-color': '#38bdf8',
          },
        },
        {
          selector: 'node[node_type = "event"][is_suspicious]',
          style: {
            'background-color': '#ef4444',
            'border-color': '#f87171',
            'border-width': 3,
          },
        },
        {
          selector: 'node[node_type = "host"]',
          style: {
            shape: 'barrel',
            'background-color': '#8b5cf6',
            'border-color': '#a78bfa',
            width: 38,
            height: 38,
          },
        },
        {
          selector: 'node[node_type = "user"]',
          style: {
            shape: 'ellipse',
            'background-color': '#10b981',
            'border-color': '#34d399',
            width: 34,
            height: 34,
          },
        },
        {
          selector: 'node[node_type = "ip"]',
          style: {
            shape: 'diamond',
            'background-color': '#f59e0b',
            'border-color': '#fbbf24',
            width: 36,
            height: 36,
          },
        },
        {
          selector: 'node[node_type = "file"]',
          style: {
            shape: 'tag',
            'background-color': '#ec4899',
            'border-color': '#f472b6',
          },
        },
        {
          selector: 'node[node_type = "process"]',
          style: {
            shape: 'hexagon',
            'background-color': '#6366f1',
            'border-color': '#818cf8',
          },
        },
        {
          selector: 'edge',
          style: {
            width: 2,
            'line-color': '#475569',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            label: 'data(relation)',
            'font-size': '8px',
            'font-family': 'Inter, system-ui, sans-serif',
            color: '#94a3b8',
            'text-rotation': 'autorotate',
            'text-background-opacity': 0.8,
            'text-background-color': '#0f172a',
            'text-background-padding': '2px',
          },
        },
        {
          selector: 'edge[relation = "PRECEDES_TEMPORALLY"]',
          style: {
            'line-style': 'dashed',
            'line-color': '#38bdf8',
            'target-arrow-color': '#38bdf8',
            width: 1.5,
          },
        },
        {
          selector: ':selected',
          style: {
            'border-width': 4,
            'border-color': '#38bdf8',
            'line-color': '#38bdf8',
            'target-arrow-color': '#38bdf8',
          },
        },
      ],
      layout: {
        name: 'breadthfirst',
        directed: true,
        padding: 40,
        spacingFactor: 1.3,
      },
    });

    cy.on('tap', 'node', (evt) => {
      const data = evt.target.data();
      setSelectedElement(data);
      if (onSelectNode) onSelectNode(data);
    });

    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setSelectedElement(null);
      }
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
    };
  }, [elements, onSelectNode]);

  const fitGraph = () => {
    cyRef.current?.fit(undefined, 30);
  };

  const relayout = (layoutName: string) => {
    cyRef.current?.layout({ name: layoutName, animate: true } as any).run();
  };

  return (
    <div className="graph-container">
      <div className="graph-toolbar">
        <div className="graph-legend">
          <span className="legend-item"><span className="legend-dot host"></span>Host</span>
          <span className="legend-item"><span className="legend-dot user"></span>User</span>
          <span className="legend-item"><span className="legend-dot ip"></span>IP</span>
          <span className="legend-item"><span className="legend-dot proc"></span>Process</span>
          <span className="legend-item"><span className="legend-dot file"></span>File</span>
          <span className="legend-item"><span className="legend-dot event"></span>Routine Event</span>
          <span className="legend-item"><span className="legend-dot alert"></span>Suspicious Event</span>
        </div>
        <div className="graph-actions">
          <button className="btn-secondary" onClick={() => relayout('circle')}>Circle</button>
          <button className="btn-secondary" onClick={() => relayout('concentric')}>Concentric</button>
          <button className="btn-secondary" onClick={() => relayout('breadthfirst')}>Hierarchy</button>
          <button className="btn-secondary" onClick={fitGraph}>Reset View</button>
        </div>
      </div>

      <div className="cytoscape-canvas" ref={containerRef} />

      {selectedElement && (
        <div className="graph-node-inspect">
          <div className="inspect-header">
            <h4>Node Inspection: {selectedElement.node_type?.toUpperCase()}</h4>
            <button className="close-btn" onClick={() => setSelectedElement(null)}>✕</button>
          </div>
          <div className="inspect-body">
            <div><strong>ID:</strong> <code>{selectedElement.id}</code></div>
            <div><strong>Label:</strong> {selectedElement.label}</div>
            {selectedElement.severity && (
              <div><strong>Severity:</strong> <span className={`badge badge-${selectedElement.severity.toLowerCase()}`}>{selectedElement.severity}</span></div>
            )}
            {selectedElement.mitre_attack_id && (
              <div><strong>MITRE ATT&CK:</strong> <span className="badge badge-mitre">{selectedElement.mitre_attack_id}</span></div>
            )}
            {selectedElement.description && (
              <div><strong>Description:</strong> {selectedElement.description}</div>
            )}
            {selectedElement.timestamp && (
              <div><strong>Timestamp:</strong> {new Date(selectedElement.timestamp).toLocaleString()}</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
