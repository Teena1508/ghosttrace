import type { InvestigationReconstructionResult } from '../types/event';

interface Props {
  reconstruction: InvestigationReconstructionResult | null;
  onInspectEventId: (eventId: string) => void;
}

export const AttackReconstructionView: React.FC<Props> = ({
  reconstruction,
  onInspectEventId,
}) => {
  if (!reconstruction) {
    return (
      <div className="reconstruction-empty">
        <p>No attack reconstruction data available.</p>
      </div>
    );
  }

  const {
    candidate_entry_points,
    hypotheses,
    timeline,
    observed_facts,
    inferred_conclusions,
    unresolved_questions,
    defensive_recommendations,
  } = reconstruction;

  return (
    <div className="reconstruction-container">
      {/* 0. Chronological Incident Phase Timeline */}
      <section className="reconstruction-section">
        <h3 className="section-title">
          <span className="section-icon">⏱️</span> Incident Lifecycle Timeline (Chronologically Reconstructed)
        </h3>
        <div className="lifecycle-timeline">
          {timeline.map((item, idx) => (
            <div key={item.event_id} className={`timeline-phase-item ${item.is_suspicious ? 'suspicious' : 'routine'}`}>
              <div className="phase-marker">{idx + 1}</div>
              <div className="phase-content">
                <div className="phase-header">
                  <span className="phase-name">{item.phase}</span>
                  <span className="phase-time">{new Date(item.timestamp).toUTCString()}</span>
                </div>
                <div className="phase-summary">{item.summary}</div>
                <div className="phase-meta">
                  <span>Type: <code>{item.event_type}</code></span>
                  {item.host_id && <span>Host: <code>{item.host_id}</code></span>}
                  {item.user_id && <span>User: <code>{item.user_id}</code></span>}
                  <button className="inline-link-btn" onClick={() => onInspectEventId(item.event_id)}>
                    Inspect Event ({item.event_id})
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>
      {/* 1. Candidate Entry Points */}
      <section className="reconstruction-section">
        <h3 className="section-title">
          <span className="section-icon">🎯</span> Candidate Entry Points
        </h3>
        <div className="entry-points-grid">
          {candidate_entry_points.length === 0 ? (
            <div className="no-entry-card">
              No unauthorized entry points detected. Activity represents routine administrative baselines.
            </div>
          ) : (
            candidate_entry_points.map((ep) => (
              <div key={ep.event_id} className="entry-point-card">
                <div className="entry-card-header">
                  <span className="entry-tag">PRIMARY CANDIDATE</span>
                  {ep.evidence_grade && (
                    <span
                      style={{
                        padding: '0.2rem 0.5rem',
                        borderRadius: '4px',
                        fontSize: '0.72rem',
                        fontWeight: 700,
                        textTransform: 'uppercase',
                        background:
                          ep.evidence_grade === 'Strong'
                            ? 'rgba(16, 185, 129, 0.2)'
                            : ep.evidence_grade === 'Moderate'
                            ? 'rgba(56, 189, 248, 0.2)'
                            : 'rgba(245, 158, 11, 0.2)',
                        color:
                          ep.evidence_grade === 'Strong'
                            ? '#34d399'
                            : ep.evidence_grade === 'Moderate'
                            ? '#38bdf8'
                            : '#fbbf24',
                        border: `1px solid ${
                          ep.evidence_grade === 'Strong'
                            ? '#10b981'
                            : ep.evidence_grade === 'Moderate'
                            ? '#38bdf8'
                            : '#f59e0b'
                        }`,
                      }}
                    >
                      GRADE: {ep.evidence_grade}
                    </span>
                  )}
                  <span className="confidence-pill" title="Deterministic heuristic forensic weighting (not a probability)">
                    Weight: {ep.confidence.toFixed(2)}
                  </span>
                </div>
                <div className="entry-card-body">
                  <p className="entry-rationale">{ep.rationale}</p>
                  <div className="entry-meta">
                    <div><strong>Origin IP:</strong> <code>{ep.source_ip || 'Internal / Local'}</code></div>
                    <div><strong>Target User:</strong> <code>{ep.user_id || 'N/A'}</code></div>
                    <div><strong>Host:</strong> <code>{ep.host_id || 'N/A'}</code></div>
                    <div><strong>Timestamp:</strong> {new Date(ep.timestamp).toUTCString()}</div>
                  </div>
                  <div className="supporting-chips">
                    <span className="chip-label">Supporting Evidence:</span>
                    {ep.supporting_event_ids.map((id) => (
                      <button
                        key={id}
                        className="chip-btn"
                        onClick={() => onInspectEventId(id)}
                        title="View raw evidence record"
                      >
                        {id}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </section>

      {/* 2. Ranked Competing Hypotheses */}
      <section className="reconstruction-section">
        <h3 className="section-title">
          <span className="section-icon">⚖️</span> Competing Attack Hypotheses (Evidence Quality Ranking)
        </h3>
        <div className="hypotheses-grid">
          {hypotheses.map((hypo) => (
            <div
              key={hypo.hypothesis_id}
              className={`hypothesis-card ${hypo.rank === 1 ? 'rank-primary' : 'rank-alternative'}`}
            >
              <div className="hypo-header">
                <div className="hypo-rank-badge">
                  {hypo.rank === 1 ? 'Rank 1 (Primary Explanation)' : `Rank ${hypo.rank} (Alternative Explanation)`}
                </div>
                <div className="hypo-score">
                  Score: <strong>{(hypo.score * 100).toFixed(0)}%</strong> · Confidence: <strong>{hypo.confidence}</strong>
                </div>
              </div>

              <h4 className="hypo-title">{hypo.title}</h4>
              <p className="hypo-description">{hypo.description}</p>

              <div className="hypo-explanation">
                <strong>Evidence Quality Rationale:</strong> {hypo.confidence_explanation}
              </div>

              {hypo.assumptions.length > 0 && (
                <div className="hypo-assumptions">
                  <strong>Assumptions Required:</strong>
                  <ul>
                    {hypo.assumptions.map((a, i) => (
                      <li key={i}>{a}</li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="hypo-evidence-tags">
                <div className="evidence-col">
                  <span className="col-label text-green">Supporting Events ({hypo.supporting_event_ids.length}):</span>
                  <div className="chip-container">
                    {hypo.supporting_event_ids.map((id) => (
                      <button key={id} className="chip-btn green" onClick={() => onInspectEventId(id)}>
                        {id}
                      </button>
                    ))}
                  </div>
                </div>

                {hypo.contradicting_event_ids.length > 0 && (
                  <div className="evidence-col">
                    <span className="col-label text-red">Contradicting Events ({hypo.contradicting_event_ids.length}):</span>
                    <div className="chip-container">
                      {hypo.contradicting_event_ids.map((id) => (
                        <button key={id} className="chip-btn red" onClick={() => onInspectEventId(id)}>
                          {id}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* 3. Observed Facts vs. Inferred Conclusions */}
      <section className="reconstruction-section split-section">
        <div className="split-column">
          <h3 className="section-title">
            <span className="section-icon">👁️</span> Observed Facts (Raw Telemetry Verification)
          </h3>
          <div className="facts-list">
            {observed_facts.map((fact) => (
              <div key={fact.fact_id} className="fact-item">
                <div className="fact-statement">{fact.statement}</div>
                <div className="fact-meta">
                  <span>Source: <code>{fact.source}</code></span>
                  <span>Events: {fact.supporting_event_ids.map((id) => (
                    <button key={id} className="inline-link-btn" onClick={() => onInspectEventId(id)}>
                      {id}
                    </button>
                  ))}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="split-column">
          <h3 className="section-title">
            <span className="section-icon">🧠</span> Inferred Conclusions (Deductive Forensic Reasoning)
          </h3>
          <div className="conclusions-list">
            {inferred_conclusions.map((conc) => (
              <div key={conc.conclusion_id} className="conclusion-item">
                <div className="conclusion-header">
                  <span className={`confidence-badge ${conc.confidence.toLowerCase()}`}>
                    Confidence: {conc.confidence}
                  </span>
                </div>
                <div className="conclusion-statement">{conc.statement}</div>
                <div className="conclusion-rationale">
                  <em>Rationale:</em> {conc.confidence_rationale}
                </div>
                {conc.alternative_explanations.length > 0 && (
                  <div className="conclusion-alternatives">
                    <em>Alternative Explanation:</em> {conc.alternative_explanations[0]}
                  </div>
                )}
                <div className="supporting-links">
                  Supporting: {conc.supporting_event_ids.map((id) => (
                    <button key={id} className="inline-link-btn" onClick={() => onInspectEventId(id)}>
                      {id}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* 4. Unresolved Questions & Missing Evidence */}
      <section className="reconstruction-section">
        <h3 className="section-title">
          <span className="section-icon">❓</span> Unresolved Questions & Missing Evidence
        </h3>
        <div className="questions-grid">
          {unresolved_questions.map((q) => (
            <div key={q.question_id} className="question-card">
              <div className="question-title">{q.question}</div>
              <p className="question-context">{q.context}</p>
              <div className="missing-evidence-banner">
                <strong>Missing Evidence Required:</strong> {q.missing_evidence_type}
              </div>
              <div className="question-events">
                Related Events: {q.related_event_ids.map((id) => (
                  <button key={id} className="inline-link-btn" onClick={() => onInspectEventId(id)}>
                    {id}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* 5. Defensive Recommendations */}
      <section className="reconstruction-section">
        <h3 className="section-title">
          <span className="section-icon">🛡️</span> Actionable Defensive Recommendations (Simulated Environment)
        </h3>
        <div className="recommendations-grid">
          {defensive_recommendations.map((rec) => (
            <div key={rec.recommendation_id} className={`recommendation-card priority-${rec.priority.toLowerCase()}`}>
              <div className="rec-header">
                <span className={`priority-badge ${rec.priority.toLowerCase()}`}>
                  {rec.priority} PRIORITY
                </span>
                {rec.target_entity && (
                  <span className="target-pill">Target: {rec.target_entity}</span>
                )}
              </div>
              <h4 className="rec-title">{rec.title}</h4>
              <p className="rec-action">{rec.action}</p>
              {rec.mitre_mitigation && (
                <div className="rec-mitre">
                  <code>MITRE Mitigation: {rec.mitre_mitigation}</code>
                </div>
              )}
            </div>
          ))}
        </div>
      </section>
    </div>
  );
};
