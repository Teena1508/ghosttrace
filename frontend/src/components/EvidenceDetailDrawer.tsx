import React from 'react';
import type { SecurityEvent } from '../types/event';

export interface SelectedNodeInfo {
  id: string;
  label: string;
  node_type: string;
  is_suspicious?: boolean;
  severity?: string;
  timestamp?: string;
  event_id?: string;
  source?: string;
  source_event_id?: string;
  description?: string;
  mitre_attack_id?: string;
  importance_reason?: string;
  inferred?: boolean;
  attributes?: Record<string, any>;
  connected_edges?: Array<{
    id: string;
    relation: string;
    target_label: string;
    target_id: string;
    direction: 'incoming' | 'outgoing';
    inferred?: boolean;
  }>;
}

export interface SelectedEdgeInfo {
  id: string;
  source: string;
  source_label: string;
  target: string;
  target_label: string;
  relation: string;
  inferred: boolean;
  supporting_event_ids: string[];
  confidence: number;
  rationale: string;
  limitations: string;
}

interface Props {
  selectedNode: SelectedNodeInfo | null;
  selectedEdge: SelectedEdgeInfo | null;
  allEvents: SecurityEvent[];
  onClose: () => void;
  onSelectNodeById: (nodeId: string) => void;
  onViewRawEvidence: (event: SecurityEvent) => void;
}

export const EvidenceDetailDrawer: React.FC<Props> = ({
  selectedNode,
  selectedEdge,
  allEvents,
  onClose,
  onSelectNodeById,
  onViewRawEvidence,
}) => {
  if (!selectedNode && !selectedEdge) return null;

  return (
    <aside className="evidence-drawer" aria-label="Evidence Inspection Drawer">
      <div className="drawer-header">
        <div className="drawer-title-group">
          <span className="drawer-eyebrow">
            {selectedNode ? `ENTITY / ${selectedNode.node_type.toUpperCase()}` : 'RELATIONSHIP / EDGE'}
          </span>
          <h3 className="drawer-title">
            {selectedNode ? selectedNode.label : selectedEdge?.relation}
          </h3>
        </div>
        <button className="drawer-close-btn" onClick={onClose} title="Close inspection panel">
          ✕
        </button>
      </div>

      <div className="drawer-body">
        {selectedNode && (
          <div className="node-inspection-content">
            {/* Importance / Forensic Significance Banner */}
            {selectedNode.importance_reason && (
              <div className="drawer-callout importance">
                <div className="callout-label">Why This Matters:</div>
                <div className="callout-text">{selectedNode.importance_reason}</div>
              </div>
            )}

            {/* Core Identification Meta */}
            <div className="drawer-section">
              <h4 className="drawer-section-title">Core Identifiers</h4>
              <dl className="property-list">
                <div className="prop-row">
                  <dt>Graph ID:</dt>
                  <dd><code>{selectedNode.id}</code></dd>
                </div>
                <div className="prop-row">
                  <dt>Category:</dt>
                  <dd><span className={`type-tag type-${selectedNode.node_type}`}>{selectedNode.node_type.toUpperCase()}</span></dd>
                </div>
                {selectedNode.timestamp && (
                  <div className="prop-row">
                    <dt>Timestamp (UTC):</dt>
                    <dd>{new Date(selectedNode.timestamp).toUTCString()}</dd>
                  </div>
                )}
                {selectedNode.severity && (
                  <div className="prop-row">
                    <dt>Severity:</dt>
                    <dd><span className={`badge badge-${selectedNode.severity.toLowerCase()}`}>{selectedNode.severity}</span></dd>
                  </div>
                )}
                {selectedNode.source && (
                  <div className="prop-row">
                    <dt>Telemetry Source:</dt>
                    <dd><code>{selectedNode.source}</code></dd>
                  </div>
                )}
                {selectedNode.source_event_id && (
                  <div className="prop-row">
                    <dt>Source Event ID:</dt>
                    <dd><code>{selectedNode.source_event_id}</code></dd>
                  </div>
                )}
                {selectedNode.mitre_attack_id && (
                  <div className="prop-row">
                    <dt>MITRE ATT&CK:</dt>
                    <dd><span className="badge badge-mitre">{selectedNode.mitre_attack_id}</span></dd>
                  </div>
                )}
              </dl>
            </div>

            {/* Description if present */}
            {selectedNode.description && (
              <div className="drawer-section">
                <h4 className="drawer-section-title">Forensic Description</h4>
                <p className="drawer-text">{selectedNode.description}</p>
              </div>
            )}

            {/* If node is an event, allow inspecting raw evidence payload */}
            {selectedNode.event_id && (
              <div className="drawer-section">
                <h4 className="drawer-section-title">Original Evidence</h4>
                <p className="drawer-subtext">Verified telemetry record preserved for chain of custody.</p>
                <button
                  className="btn-inspect-full"
                  onClick={() => {
                    const matched = allEvents.find((e) => e.event_id === selectedNode.event_id);
                    if (matched) onViewRawEvidence(matched);
                  }}
                >
                  Inspect Raw Source Record ({selectedNode.event_id})
                </button>
              </div>
            )}

            {/* Connected Evidence Relationships (1-Hop Neighbors) */}
            {selectedNode.connected_edges && selectedNode.connected_edges.length > 0 && (
              <div className="drawer-section">
                <h4 className="drawer-section-title">
                  Connected Evidence ({selectedNode.connected_edges.length})
                </h4>
                <div className="connections-list">
                  {selectedNode.connected_edges.map((conn) => (
                    <div key={conn.id} className="conn-item">
                      <div className="conn-direction">
                        <span className={`direction-indicator ${conn.direction}`}>
                          {conn.direction === 'outgoing' ? '➔' : '⬅'}
                        </span>
                        <span className="conn-relation">{conn.relation}</span>
                        {conn.inferred && <span className="inferred-badge">INFERRED</span>}
                      </div>
                      <button
                        className="conn-target-btn"
                        onClick={() => onSelectNodeById(conn.target_id)}
                        title="Locate connected node in graph"
                      >
                        {conn.target_label || conn.target_id}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {selectedEdge && (
          <div className="edge-inspection-content">
            {/* Relationship Overview */}
            <div className="drawer-section">
              <h4 className="drawer-section-title">Relationship Overview</h4>
              <dl className="property-list">
                <div className="prop-row">
                  <dt>Relation Type:</dt>
                  <dd><strong>{selectedEdge.relation}</strong></dd>
                </div>
                <div className="prop-row">
                  <dt>Inference Status:</dt>
                  <dd>
                    {selectedEdge.inferred ? (
                      <span className="badge badge-medium">INFERRED LINK</span>
                    ) : (
                      <span className="badge badge-low">DIRECT OBSERVED EVIDENCE</span>
                    )}
                  </dd>
                </div>
                <div className="prop-row">
                  <dt>Confidence Score:</dt>
                  <dd>
                    <strong>{Math.round(selectedEdge.confidence * 100)}%</strong>
                  </dd>
                </div>
                <div className="prop-row">
                  <dt>Source Entity:</dt>
                  <dd>
                    <button className="link-btn" onClick={() => onSelectNodeById(selectedEdge.source)}>
                      {selectedEdge.source_label || selectedEdge.source}
                    </button>
                  </dd>
                </div>
                <div className="prop-row">
                  <dt>Target Entity:</dt>
                  <dd>
                    <button className="link-btn" onClick={() => onSelectNodeById(selectedEdge.target)}>
                      {selectedEdge.target_label || selectedEdge.target}
                    </button>
                  </dd>
                </div>
              </dl>
            </div>

            {/* Rationale & Reasoning */}
            <div className="drawer-section">
              <h4 className="drawer-section-title">Forensic Reasoning & Rationale</h4>
              <p className="drawer-text">{selectedEdge.rationale || 'Direct correlation established by shared entity identifier.'}</p>
            </div>

            {/* Evidence Limitations Notice */}
            <div className="drawer-section">
              <h4 className="drawer-section-title">Evidence Limitations</h4>
              <div className="drawer-callout warning">
                <p className="callout-text">
                  {selectedEdge.limitations || (
                    selectedEdge.relation === 'PRECEDES_TEMPORALLY'
                      ? 'Temporal succession observed on telemetry stream. Timestamps alone do NOT establish causation without shared execution context.'
                      : 'Relationship derived from observable telemetry context without payload content inspection.'
                  )}
                </p>
              </div>
            </div>

            {/* Supporting Event References */}
            {selectedEdge.supporting_event_ids && selectedEdge.supporting_event_ids.length > 0 && (
              <div className="drawer-section">
                <h4 className="drawer-section-title">
                  Supporting Event Records ({selectedEdge.supporting_event_ids.length})
                </h4>
                <div className="supporting-chips">
                  {selectedEdge.supporting_event_ids.map((id) => {
                    const matched = allEvents.find((e) => e.event_id === id);
                    return (
                      <button
                        key={id}
                        className="chip-btn"
                        onClick={() => {
                          if (matched) onViewRawEvidence(matched);
                        }}
                        title="View raw supporting record"
                      >
                        {id} ↗
                      </button>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </aside>
  );
};
