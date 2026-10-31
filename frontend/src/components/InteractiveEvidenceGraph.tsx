import React, { useEffect, useRef, useState, useCallback } from 'react';
import cytoscape from 'cytoscape';
import type { Core, EventObject, NodeSingular, EdgeSingular } from 'cytoscape';
import type { CytoscapeElement, SecurityEvent } from '../types/event';
import type { SelectedNodeInfo, SelectedEdgeInfo } from './EvidenceDetailDrawer';

interface Props {
  elements: CytoscapeElement[];
  allEvents: SecurityEvent[];
  selectedEventId: string | null;
  onSelectNode: (info: SelectedNodeInfo | null) => void;
  onSelectEdge: (info: SelectedEdgeInfo | null) => void;
  onClearSelection: () => void;
  // Scenario control
  scenarios: Array<{ id: string; name: string; description: string }>;
  currentScenarioId: string;
  onSelectScenario: (scenarioId: string) => void;
  // Multi-event / hypothesis highlighting
  highlightedEventIds?: string[] | null;
  hypothesisId?: string | null;
}

export const InteractiveEvidenceGraph: React.FC<Props> = ({
  elements,
  allEvents: _allEvents,
  selectedEventId,
  onSelectNode,
  onSelectEdge,
  onClearSelection,
  scenarios,
  currentScenarioId,
  onSelectScenario,
  highlightedEventIds,
  hypothesisId,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  // Filters state
  const [relevantOnly, setRelevantOnly] = useState<boolean>(false);
  const [showTemporalEdges, setShowTemporalEdges] = useState<boolean>(true);
  const [showHypotheses, setShowHypotheses] = useState<boolean>(true);
  const [visibleNodeTypes, setVisibleNodeTypes] = useState<Record<string, boolean>>({
    event: true,
    host: true,
    user: true,
    ip: true,
    session: true,
    process: true,
    file: true,
    hypothesis: true,
  });

  // Active layout name
  const [activeLayout, setActiveLayout] = useState<string>('breadthfirst');

  // Build and apply Cytoscape instance
  useEffect(() => {
    if (!containerRef.current) return;

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements: elements as any,
      style: [
        // Base Node Style
        {
          selector: 'node',
          style: {
            label: 'data(label)',
            'font-size': '10px',
            'font-family': 'JetBrains Mono, Inter, system-ui, sans-serif',
            color: '#c9d1d9',
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'text-background-opacity': 0.85,
            'text-background-color': '#0d1117',
            'text-background-padding': '3px',
            'text-background-shape': 'roundrectangle',
            'background-color': '#30363d',
            'border-width': 2,
            'border-color': '#484f58',
            width: 34,
            height: 34,
            'transition-property': 'background-color, border-color, border-width, opacity',
            'transition-duration': 0.2,
          },
        },
        // Routine Event Node
        {
          selector: 'node[node_type = "event"]',
          style: {
            shape: 'round-rectangle',
            width: 32,
            height: 32,
            'background-color': '#0369a1',
            'border-color': '#38bdf8',
          },
        },
        // Suspicious / Malicious Event Node
        {
          selector: 'node[node_type = "event"][is_suspicious]',
          style: {
            shape: 'round-rectangle',
            width: 36,
            height: 36,
            'background-color': '#b91c1c',
            'border-color': '#f87171',
            'border-width': 3,
          },
        },
        // Host Node
        {
          selector: 'node[node_type = "host"]',
          style: {
            shape: 'barrel',
            'background-color': '#6d28d9',
            'border-color': '#a78bfa',
            width: 38,
            height: 38,
          },
        },
        // User Principal Node
        {
          selector: 'node[node_type = "user"]',
          style: {
            shape: 'ellipse',
            'background-color': '#047857',
            'border-color': '#34d399',
            width: 36,
            height: 36,
          },
        },
        // IP Address Node
        {
          selector: 'node[node_type = "ip"]',
          style: {
            shape: 'diamond',
            'background-color': '#b45309',
            'border-color': '#fbbf24',
            width: 38,
            height: 38,
          },
        },
        // Session Node
        {
          selector: 'node[node_type = "session"]',
          style: {
            shape: 'round-tag',
            'background-color': '#0f766e',
            'border-color': '#2dd4bf',
            width: 34,
            height: 34,
          },
        },
        // Process Node
        {
          selector: 'node[node_type = "process"]',
          style: {
            shape: 'hexagon',
            'background-color': '#4338ca',
            'border-color': '#818cf8',
            width: 36,
            height: 36,
          },
        },
        // File Artifact Node
        {
          selector: 'node[node_type = "file"]',
          style: {
            shape: 'tag',
            'background-color': '#be185d',
            'border-color': '#f472b6',
            width: 34,
            height: 34,
          },
        },
        // Hypothesis Node
        {
          selector: 'node[node_type = "hypothesis"]',
          style: {
            shape: 'star',
            'background-color': '#7c3aed',
            'border-color': '#fbbf24',
            'border-width': 3,
            width: 44,
            height: 44,
          },
        },
        // Base Edge Style
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
            'font-family': 'JetBrains Mono, monospace',
            color: '#94a3b8',
            'text-rotation': 'autorotate',
            'text-background-opacity': 0.85,
            'text-background-color': '#07090e',
            'text-background-padding': '2px',
            'transition-property': 'line-color, target-arrow-color, width, opacity',
            'transition-duration': 0.2,
          },
        },
        // Temporal Sequence Edge (Explicitly Non-Causal, Dashed)
        {
          selector: 'edge[relation = "PRECEDES_TEMPORALLY"]',
          style: {
            'line-style': 'dashed',
            'line-dash-pattern': [6, 4],
            'line-color': '#38bdf8',
            'target-arrow-color': '#38bdf8',
            width: 1.5,
          },
        },
        // Hypothesis Support Edge
        {
          selector: 'edge[relation = "SUPPORTS_HYPOTHESIS"]',
          style: {
            'line-style': 'dotted',
            'line-color': '#fbbf24',
            'target-arrow-color': '#fbbf24',
            width: 2,
          },
        },
        // Selected / Highlighted States
        {
          selector: 'node:selected, node.highlighted',
          style: {
            'border-width': 4,
            'border-color': '#38bdf8',
            'underlay-color': '#38bdf8',
            'underlay-padding': 6,
            'underlay-opacity': 0.25,
            'z-index': 999,
          },
        },
        {
          selector: 'edge:selected, edge.highlighted',
          style: {
            width: 3.5,
            'line-color': '#38bdf8',
            'target-arrow-color': '#38bdf8',
            color: '#38bdf8',
            'z-index': 999,
          },
        },
        // Dimmed State (When focusing on a neighborhood)
        {
          selector: '.dimmed',
          style: {
            opacity: 0.15,
          },
        },
        // Hidden State (When filtered out)
        {
          selector: '.hidden',
          style: {
            display: 'none',
          },
        },
      ],
      layout: {
        name: activeLayout,
        directed: true,
        padding: 40,
        spacingFactor: 1.25,
      } as any,
    });

    // Node Click Handler
    cy.on('tap', 'node', (evt: EventObject) => {
      const node: NodeSingular = evt.target;
      const data = node.data();

      // Clear previous dimming and highlight 1-hop neighborhood
      cy.elements().removeClass('highlighted dimmed');
      const neighborhood = node.neighborhood().add(node);
      cy.elements().not(neighborhood).addClass('dimmed');
      neighborhood.addClass('highlighted');

      // Extract connected edges metadata
      const connected = node.connectedEdges().map((edge: EdgeSingular) => {
        const edgeData = edge.data();
        const isSource = edge.source().id() === node.id();
        const otherNode = isSource ? edge.target() : edge.source();
        return {
          id: edgeData.id,
          relation: edgeData.relation || 'CONNECTED',
          target_label: otherNode.data('label') || otherNode.id(),
          target_id: otherNode.id(),
          direction: (isSource ? 'outgoing' : 'incoming') as 'incoming' | 'outgoing',
          inferred: edgeData.inferred,
        };
      });

      const nodeInfo: SelectedNodeInfo = {
        id: data.id,
        label: data.label || data.id,
        node_type: data.node_type || 'entity',
        is_suspicious: data.is_suspicious,
        severity: data.severity,
        timestamp: data.timestamp,
        event_id: data.event_id,
        source: data.source,
        source_event_id: data.source_event_id,
        description: data.description,
        mitre_attack_id: data.mitre_attack_id,
        importance_reason: data.importance_reason,
        inferred: data.inferred || false,
        attributes: data,
        connected_edges: connected,
      };

      onSelectEdge(null);
      onSelectNode(nodeInfo);
    });

    // Edge Click Handler
    cy.on('tap', 'edge', (evt: EventObject) => {
      const edge: EdgeSingular = evt.target;
      const data = edge.data();

      cy.elements().removeClass('highlighted dimmed');
      const edgeWithEndpoints = edge.connectedNodes().add(edge);
      cy.elements().not(edgeWithEndpoints).addClass('dimmed');
      edgeWithEndpoints.addClass('highlighted');

      const edgeInfo: SelectedEdgeInfo = {
        id: data.id,
        source: data.source,
        source_label: edge.source().data('label') || data.source,
        target: data.target,
        target_label: edge.target().data('label') || data.target,
        relation: data.relation || 'CONNECTED',
        inferred: data.inferred || false,
        supporting_event_ids: data.supporting_event_ids || [],
        confidence: data.confidence !== undefined ? data.confidence : 1.0,
        rationale: data.rationale || 'Direct evidence link.',
        limitations: data.limitations || '',
      };

      onSelectNode(null);
      onSelectEdge(edgeInfo);
    });

    // Canvas Background Click Handler (Clear selection)
    cy.on('tap', (evt: EventObject) => {
      if (evt.target === cy) {
        cy.elements().removeClass('highlighted dimmed');
        onClearSelection();
      }
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
    };
  }, [elements, onSelectNode, onSelectEdge, onClearSelection, activeLayout]);

  // Synchronize graph selection when selectedEventId changes from timeline
  useEffect(() => {
    if (!cyRef.current || !selectedEventId) return;

    const cy = cyRef.current;
    const targetNode = cy.$(`#evt\\:${selectedEventId}`);

    if (targetNode && targetNode.length > 0) {
      cy.elements().removeClass('highlighted dimmed');
      const neighborhood = targetNode.neighborhood().add(targetNode);
      cy.elements().not(neighborhood).addClass('dimmed');
      neighborhood.addClass('highlighted');

      // Animate pan/zoom to center onto the selected event node
      cy.animate({
        center: { eles: targetNode },
        zoom: Math.max(cy.zoom(), 1.2),
        duration: 400,
      });
    }
  }, [selectedEventId]);

  // Highlight hypothesis supporting evidence cluster
  useEffect(() => {
    if (!cyRef.current) return;
    const cy = cyRef.current;

    if (highlightedEventIds && highlightedEventIds.length > 0) {
      cy.elements().removeClass('highlighted dimmed');
      const selectors = highlightedEventIds.map((id) => `#evt\\:${id}`);
      if (hypothesisId) {
        selectors.push(`#hypo\\:${hypothesisId}`);
      }
      const matchingNodes = cy.$(selectors.join(', '));
      if (matchingNodes.length > 0) {
        const connectedEdges = matchingNodes.edgesWith(matchingNodes);
        const highlightedGroup = matchingNodes.add(connectedEdges);
        cy.elements().not(highlightedGroup).addClass('dimmed');
        highlightedGroup.addClass('highlighted');
        cy.animate({
          fit: { eles: highlightedGroup, padding: 60 },
          duration: 500,
        });
      }
    }
  }, [highlightedEventIds, hypothesisId]);

  // Apply filters (node types, temporal edges, relevant-only) dynamically
  const applyFilters = useCallback(() => {
    if (!cyRef.current) return;
    const cy = cyRef.current;

    cy.batch(() => {
      // First show all elements by clearing hidden class
      cy.elements().removeClass('hidden');

      // 1. Filter by Node Types
      Object.entries(visibleNodeTypes).forEach(([type, isVisible]) => {
        if (!isVisible) {
          cy.$(`node[node_type = "${type}"]`).addClass('hidden');
        }
      });

      // 2. Filter Temporal Edges
      if (!showTemporalEdges) {
        cy.$('edge[relation = "PRECEDES_TEMPORALLY"]').addClass('hidden');
      }

      // 3. Filter Hypotheses
      if (!showHypotheses) {
        cy.$('node[node_type = "hypothesis"]').addClass('hidden');
        cy.$('edge[relation = "SUPPORTS_HYPOTHESIS"]').addClass('hidden');
      }

      // 4. Relevant-Only View: Hide isolated non-suspicious nodes
      if (relevantOnly) {
        cy.nodes().forEach((n) => {
          const isThreat = n.data('is_suspicious') === true;
          // Check if connected to any suspicious node
          const hasThreatNeighbor = n.neighborhood().some((nb) => nb.data('is_suspicious') === true);
          if (!isThreat && !hasThreatNeighbor) {
            n.addClass('hidden');
          }
        });
      }
    });
  }, [visibleNodeTypes, showTemporalEdges, showHypotheses, relevantOnly]);

  useEffect(() => {
    applyFilters();
  }, [applyFilters]);

  // Control Actions
  const handleResetView = () => {
    if (!cyRef.current) return;
    cyRef.current.elements().removeClass('highlighted dimmed');
    cyRef.current.fit(undefined, 35);
    onClearSelection();
  };

  const handleFitScreen = () => {
    cyRef.current?.fit(undefined, 35);
  };

  const handleFocusSelected = () => {
    if (!cyRef.current) return;
    const selected = cyRef.current.$('.highlighted');
    if (selected.length > 0) {
      cyRef.current.animate({
        fit: { eles: selected, padding: 60 },
        duration: 400,
      });
    } else {
      cyRef.current.fit(undefined, 35);
    }
  };

  const handleChangeLayout = (layoutName: string) => {
    setActiveLayout(layoutName);
    cyRef.current?.layout({ name: layoutName, animate: true, padding: 40 } as any).run();
  };

  const toggleNodeType = (type: string) => {
    setVisibleNodeTypes((prev) => ({ ...prev, [type]: !prev[type] }));
  };

  return (
    <div className="interactive-evidence-graph-wrapper">
      {/* Investigation Graph Action & Filter Bar */}
      <div className="graph-control-bar">
        {/* Left: Scenario Selector */}
        <div className="control-section scenario-select-area">
          <label className="ctrl-label">SIMULATED SCENARIO:</label>
          <select
            className="select-scenario"
            value={currentScenarioId}
            onChange={(e) => onSelectScenario(e.target.value)}
          >
            {scenarios.map((sc) => (
              <option key={sc.id} value={sc.id}>
                {sc.name}
              </option>
            ))}
          </select>
        </div>

        {/* Center: Graph Actions */}
        <div className="control-section graph-tools">
          <button className="ctrl-btn" onClick={handleResetView} title="Reset view and clear filters">
            ↺ Reset
          </button>
          <button className="ctrl-btn" onClick={handleFitScreen} title="Fit entire graph to screen">
            ⛶ Fit Screen
          </button>
          <button className="ctrl-btn" onClick={handleFocusSelected} title="Zoom into selected node and connected evidence">
            🔍 Focus Evidence
          </button>
          <button
            className={`ctrl-btn toggle-btn ${relevantOnly ? 'active' : ''}`}
            onClick={() => setRelevantOnly(!relevantOnly)}
            title="Toggle between complete graph and active incident evidence only"
          >
            {relevantOnly ? '✓ Incident Evidence Only' : 'Complete Graph'}
          </button>
        </div>

        {/* Right: Layout Switcher */}
        <div className="control-section layout-tools">
          <label className="ctrl-label">LAYOUT:</label>
          <button
            className={`layout-btn ${activeLayout === 'breadthfirst' ? 'active' : ''}`}
            onClick={() => handleChangeLayout('breadthfirst')}
          >
            Hierarchy
          </button>
          <button
            className={`layout-btn ${activeLayout === 'concentric' ? 'active' : ''}`}
            onClick={() => handleChangeLayout('concentric')}
          >
            Concentric
          </button>
          <button
            className={`layout-btn ${activeLayout === 'circle' ? 'active' : ''}`}
            onClick={() => handleChangeLayout('circle')}
          >
            Circle
          </button>
        </div>
      </div>

      {/* Filter Chips Bar (Node & Edge Types) */}
      <div className="graph-sub-toolbar">
        <div className="type-filter-group">
          <span className="sub-label">Node Types:</span>
          {Object.keys(visibleNodeTypes).map((type) => (
            <label key={type} className={`filter-chip ${visibleNodeTypes[type] ? 'active' : 'inactive'}`}>
              <input
                type="checkbox"
                checked={visibleNodeTypes[type]}
                onChange={() => toggleNodeType(type)}
              />
              <span className={`chip-dot dot-${type}`}></span>
              <span>{type.toUpperCase()}</span>
            </label>
          ))}
        </div>

        <div className="edge-filter-group">
          <span className="sub-label">Edges:</span>
          <label className="filter-chip">
            <input
              type="checkbox"
              checked={showTemporalEdges}
              onChange={(e) => setShowTemporalEdges(e.target.checked)}
            />
            <span className="dash-indicator">---</span>
            <span>Temporal Order</span>
          </label>
          <label className="filter-chip">
            <input
              type="checkbox"
              checked={showHypotheses}
              onChange={(e) => setShowHypotheses(e.target.checked)}
            />
            <span className="dot-indicator">···</span>
            <span>Hypotheses</span>
          </label>
        </div>
      </div>

      {/* Cytoscape Canvas Container */}
      <div className="cytoscape-evidence-canvas" ref={containerRef} />
    </div>
  );
};
