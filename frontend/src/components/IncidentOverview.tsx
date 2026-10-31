import React, { useState } from 'react';
import type { SecurityEvent, InvestigationReconstructionResult } from '../types/event';

interface Props {
  reconstruction: InvestigationReconstructionResult | null;
  events: SecurityEvent[];
  scenarioName: string;
  onSelectEventId: (eventId: string) => void;
}

export const IncidentOverview: React.FC<Props> = ({
  reconstruction,
  events,
  scenarioName,
  onSelectEventId,
}) => {
  const [factsTab, setFactsTab] = useState<'facts' | 'inferences' | 'questions'>('facts');

  if (!reconstruction) {
    return (
      <div className="incident-overview-empty">
        <div className="empty-message">No incident reconstruction data available for overview.</div>
      </div>
    );
  }

  const suspiciousEvents = events.filter((e) => e.is_suspicious);
  const routineEvents = events.filter((e) => !e.is_suspicious);
  const isThreatDetected = suspiciousEvents.length > 0;

  // Extract key affected assets
  const affectedUsers = Array.from(new Set(events.map((e) => e.user_id).filter(Boolean))) as string[];
  const affectedHosts = Array.from(new Set(events.map((e) => e.host_id).filter(Boolean))) as string[];
  const affectedProcesses = Array.from(
    new Set(events.map((e) => e.process_name || (e.command_line ? e.command_line.split(' ')[0] : null)).filter(Boolean))
  ) as string[];
  const affectedFiles = Array.from(new Set(events.map((e) => e.file_path).filter(Boolean))) as string[];
  const destinationIps = Array.from(new Set(events.map((e) => e.destination_ip).filter(Boolean))) as string[];

  // Observation window
  const sortedEvents = [...events].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );
  const firstSeen = sortedEvents[0]?.timestamp;
  const lastSeen = sortedEvents[sortedEvents.length - 1]?.timestamp;

  let elapsedDuration = '0s';
  if (firstSeen && lastSeen) {
    const diffSec = Math.max(0, Math.round((new Date(lastSeen).getTime() - new Date(firstSeen).getTime()) / 1000));
    const mins = Math.floor(diffSec / 60);
    const secs = diffSec % 60;
    elapsedDuration = mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
  }

  const entryPoint = reconstruction.candidate_entry_points[0];
  const primaryHypothesis = reconstruction.hypotheses[0];

  return (
    <div className="incident-overview-wrapper">
      {/* Incident Status Banner */}
      <div className="incident-banner">
        <div className="banner-left">
          <div className="banner-meta">
            <span className="investigation-id-tag">
              INVESTIGATION: <strong>{reconstruction.investigation_id}</strong>
            </span>
            <span className={`status-pill ${isThreatDetected ? 'status-threat' : 'status-clean'}`}>
              {isThreatDetected ? '● ACTIVE THREAT INVESTIGATION' : '✓ BENIGN BASELINE BENCHMARK'}
            </span>
            <span className="scenario-pill">{scenarioName}</span>
          </div>
          <h2 className="banner-title">
            {primaryHypothesis
              ? primaryHypothesis.title
              : isThreatDetected
              ? 'Multi-Stage Simulated Intrusion Sequence'
              : 'Routine Operational Telemetry Baseline'}
          </h2>
          <p className="banner-summary">
            {primaryHypothesis
              ? primaryHypothesis.description
              : 'Observed forensic records indicate normal business activity with zero anomalous indicators.'}
          </p>
        </div>

        <div className="banner-stats">
          <div className="stat-box">
            <span className="stat-label">TIME WINDOW</span>
            <span className="stat-val">{elapsedDuration}</span>
            <span className="stat-sub">{events.length} Records</span>
          </div>
          <div className="stat-box highlight">
            <span className="stat-label">INCIDENT SIGNALS</span>
            <span className="stat-val">{suspiciousEvents.length}</span>
            <span className="stat-sub">Correlated Evidence</span>
          </div>
          <div className="stat-box">
            <span className="stat-label">BASELINE EVENTS</span>
            <span className="stat-val">{routineEvents.length}</span>
            <span className="stat-sub">Benign Operations</span>
          </div>
        </div>
      </div>

      {/* Two-Column Forensic Core: Entry Point & Affected Assets */}
      <div className="overview-two-col">
        {/* Likely Entry Point Card */}
        <div className="overview-card entry-point-card">
          <div className="card-header">
            <span className="card-eyebrow">INITIAL COMPROMISE ASSESSMENT</span>
            <h3 className="card-title">Likely Entry Point</h3>
          </div>

          <div className="card-body">
            {entryPoint ? (
              <div className="entry-point-details">
                <div className="ep-badge-row">
                  <span className={`badge ${entryPoint.evidence_grade === 'Strong' ? 'badge-critical' : 'badge-warning'}`}>
                    {entryPoint.evidence_grade ? `${entryPoint.evidence_grade.toUpperCase()} EVIDENCE` : 'CANDIDATE ENTRY POINT'}
                  </span>
                  <span className="ep-confidence" title="Deterministic heuristic forensic weighting (not a probability)">
                    Evidence Weight: <strong>{entryPoint.confidence.toFixed(2)}</strong>
                  </span>
                </div>

                <p className="ep-rationale">{entryPoint.rationale}</p>

                <div className="ep-meta-grid">
                  <div className="meta-item">
                    <span className="m-label">Target Host:</span>
                    <span className="m-val"><code>{entryPoint.host_id || 'N/A'}</code></span>
                  </div>
                  <div className="meta-item">
                    <span className="m-label">Principal User:</span>
                    <span className="m-val"><code>{entryPoint.user_id || 'N/A'}</code></span>
                  </div>
                  <div className="meta-item">
                    <span className="m-label">Source IP:</span>
                    <span className="m-val"><code>{entryPoint.source_ip || 'N/A'}</code></span>
                  </div>
                  <div className="meta-item">
                    <span className="m-label">Timestamp (UTC):</span>
                    <span className="m-val"><code>{new Date(entryPoint.timestamp).toUTCString()}</code></span>
                  </div>
                </div>

                <div className="ep-evidence-links">
                  <span className="ep-evidence-label">Primary Evidence:</span>
                  <button
                    className="btn-link-evidence"
                    onClick={() => onSelectEventId(entryPoint.event_id)}
                    title="Highlight entry point in graph and timeline"
                  >
                    🔍 Focus Entry Event ({entryPoint.event_id})
                  </button>
                  {entryPoint.supporting_event_ids
                    .filter((id) => id !== entryPoint.event_id)
                    .map((id) => (
                      <button
                        key={id}
                        className="btn-link-evidence secondary"
                        onClick={() => onSelectEventId(id)}
                      >
                        {id}
                      </button>
                    ))}
                </div>
              </div>
            ) : (
              <div className="no-entry-point">
                <div className="no-ep-icon">🛡️</div>
                <div className="no-ep-title">No Adversary Entry Point Detected</div>
                <p className="no-ep-desc">
                  All telemetry records reflect expected, authorized operational tasks. No external
                  compromise, unauthorized login, or initial access was discovered in this dataset.
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Affected Principals & Entities Card */}
        <div className="overview-card affected-entities-card">
          <div className="card-header">
            <span className="card-eyebrow">ENVIRONMENT IMPACT</span>
            <h3 className="card-title">Key Entities & Scoped Assets</h3>
          </div>

          <div className="card-body entity-groups">
            <div className="entity-group">
              <span className="group-label">AFFECTED USERS ({affectedUsers.length}):</span>
              <div className="pill-wrap">
                {affectedUsers.length > 0 ? (
                  affectedUsers.map((u) => (
                    <span key={u} className="entity-pill user-pill">
                      👤 {u}
                    </span>
                  ))
                ) : (
                  <span className="entity-dim">None recorded</span>
                )}
              </div>
            </div>

            <div className="entity-group">
              <span className="group-label">TARGET HOSTS ({affectedHosts.length}):</span>
              <div className="pill-wrap">
                {affectedHosts.length > 0 ? (
                  affectedHosts.map((h) => (
                    <span key={h} className="entity-pill host-pill">
                      🖥️ {h}
                    </span>
                  ))
                ) : (
                  <span className="entity-dim">None recorded</span>
                )}
              </div>
            </div>

            <div className="entity-group">
              <span className="group-label">SUSPICIOUS / INVOLVED PROCESSES:</span>
              <div className="pill-wrap">
                {affectedProcesses.length > 0 ? (
                  affectedProcesses.map((p) => (
                    <span key={p} className="entity-pill proc-pill">
                      ⚙️ {p}
                    </span>
                  ))
                ) : (
                  <span className="entity-dim">None recorded</span>
                )}
              </div>
            </div>

            <div className="entity-group">
              <span className="group-label">AUDITED / SENSITIVE FILES:</span>
              <div className="pill-wrap">
                {affectedFiles.length > 0 ? (
                  affectedFiles.map((f) => (
                    <span key={f} className="entity-pill file-pill" title={f}>
                      📄 {f.split('/').pop()}
                    </span>
                  ))
                ) : (
                  <span className="entity-dim">None recorded</span>
                )}
              </div>
            </div>

            {destinationIps.length > 0 && (
              <div className="entity-group">
                <span className="group-label">DESTINATION IP ENDPOINTS:</span>
                <div className="pill-wrap">
                  {destinationIps.map((ip) => (
                    <span key={ip} className="entity-pill ip-pill">
                      🌐 {ip}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Distinction Between Observed Facts and Inferred Conclusions */}
      <div className="epistemology-section">
        <div className="epistemology-tabs">
          <button
            className={`tab-btn ${factsTab === 'facts' ? 'active' : ''}`}
            onClick={() => setFactsTab('facts')}
          >
            Observed Telemetry Facts ({reconstruction.observed_facts.length})
          </button>
          <button
            className={`tab-btn ${factsTab === 'inferences' ? 'active' : ''}`}
            onClick={() => setFactsTab('inferences')}
          >
            Inferred Forensic Conclusions ({reconstruction.inferred_conclusions.length})
          </button>
          <button
            className={`tab-btn ${factsTab === 'questions' ? 'active' : ''}`}
            onClick={() => setFactsTab('questions')}
          >
            Unresolved Forensic Questions ({reconstruction.unresolved_questions.length})
          </button>
        </div>

        <div className="epistemology-content">
          {factsTab === 'facts' && (
            <div className="facts-list">
              <div className="section-disclaimer">
                <strong>Observed Facts</strong> represent ground-level telemetry records preserved directly from source logs without analytical extrapolation.
              </div>
              {reconstruction.observed_facts.map((fact) => (
                <div key={fact.fact_id} className="fact-item">
                  <div className="fact-header">
                    <span className="fact-id">{fact.fact_id}</span>
                    <span className="fact-time">
                      {new Date(fact.observed_at).toISOString().replace('T', ' ').replace('.000Z', '')} UTC
                    </span>
                    <span className="fact-source">Source: {fact.source}</span>
                  </div>
                  <div className="fact-statement">{fact.statement}</div>
                  <div className="fact-links">
                    <span className="links-label">Supporting Events:</span>
                    {fact.supporting_event_ids.map((id) => (
                      <button
                        key={id}
                        className="btn-tiny-event"
                        onClick={() => onSelectEventId(id)}
                        title="Focus event in graph and timeline"
                      >
                        {id}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}

          {factsTab === 'inferences' && (
            <div className="inferences-list">
              <div className="section-disclaimer">
                <strong>Inferred Conclusions</strong> represent probabilistic causal linkages reconstructed across sessions, processes, and network lineage.
              </div>
              {reconstruction.inferred_conclusions.map((conc) => (
                <div key={conc.conclusion_id} className="inference-item">
                  <div className="inference-header">
                    <span className="inference-id">{conc.conclusion_id}</span>
                    <span className={`badge badge-${conc.confidence.toLowerCase()}`}>
                      {conc.confidence} CONFIDENCE
                    </span>
                  </div>
                  <div className="inference-statement">{conc.statement}</div>
                  <div className="inference-rationale">
                    <strong>Forensic Rationale:</strong> {conc.confidence_rationale}
                  </div>
                  {conc.alternative_explanations.length > 0 && (
                    <div className="inference-alternatives">
                      <span className="alt-label">Alternative Non-Malicious Explanations Considered:</span>
                      <ul>
                        {conc.alternative_explanations.map((alt, i) => (
                          <li key={i}>{alt}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  <div className="fact-links">
                    <span className="links-label">Linked Evidence:</span>
                    {conc.supporting_event_ids.map((id) => (
                      <button
                        key={id}
                        className="btn-tiny-event"
                        onClick={() => onSelectEventId(id)}
                        title="Focus event in graph and timeline"
                      >
                        {id}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}

          {factsTab === 'questions' && (
            <div className="questions-list">
              <div className="section-disclaimer">
                <strong>Unresolved Questions</strong> identify missing telemetry, unverified transfer channels, and analytical limitations where data does not permit definitive attribution.
              </div>
              {reconstruction.unresolved_questions.map((q) => (
                <div key={q.question_id} className="question-item">
                  <div className="q-title">{q.question}</div>
                  <div className="q-context">{q.context}</div>
                  <div className="q-missing-banner">
                    ⚠️ <strong>Missing Telemetry Requirement:</strong> {q.missing_evidence_type}
                  </div>
                  <div className="fact-links">
                    <span className="links-label">Related Events:</span>
                    {q.related_event_ids.map((id) => (
                      <button
                        key={id}
                        className="btn-tiny-event"
                        onClick={() => onSelectEventId(id)}
                      >
                        {id}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
