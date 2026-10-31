import React, { useState } from 'react';
import type { AttackHypothesis } from '../types/event';

interface Props {
  hypotheses: AttackHypothesis[];
  selectedHypothesisId: string | null;
  onSelectHypothesis: (hypo: AttackHypothesis) => void;
  onSelectEventId: (eventId: string) => void;
}

export const HypothesisInvestigation: React.FC<Props> = ({
  hypotheses,
  selectedHypothesisId,
  onSelectHypothesis,
  onSelectEventId,
}) => {
  const [expandedBreakdownId, setExpandedBreakdownId] = useState<string | null>(null);

  if (!hypotheses || hypotheses.length === 0) {
    return (
      <div className="hypotheses-empty">
        <p>No attack hypotheses formulated for this dataset.</p>
      </div>
    );
  }

  const toggleBreakdown = (id: string) => {
    setExpandedBreakdownId((prev) => (prev === id ? null : id));
  };

  return (
    <div className="hypotheses-investigation-wrapper">
      <div className="hypotheses-header">
        <div>
          <span className="section-eyebrow">EVIDENCE-DRIVEN RECONSTRUCTION & COMPETING EXPLANATIONS</span>
          <h3 className="section-title">Forensic Hypothesis Evaluation</h3>
        </div>
        <div className="hypo-disclaimer-tag">
          🛡️ Explainable Forensic Heuristic · Not a frequentist probability · Causation requires corroborated evidence
        </div>
      </div>

      <div className="hypotheses-grid">
        {hypotheses.map((hypo) => {
          const isSelected = selectedHypothesisId === hypo.hypothesis_id;
          const isBreakdownOpen = expandedBreakdownId === hypo.hypothesis_id;
          const grade = hypo.evidence_grade || 'Moderate';
          const breakdown = hypo.score_breakdown || {};

          return (
            <div
              key={hypo.hypothesis_id}
              className={`hypothesis-card rank-${hypo.rank} ${isSelected ? 'is-selected' : ''}`}
            >
              <div className="hypo-top-bar">
                <div className="hypo-rank-group">
                  <span className="hypo-rank-badge">#{hypo.rank}</span>
                  <span
                    style={{
                      padding: '0.2rem 0.55rem',
                      borderRadius: '4px',
                      fontSize: '0.72rem',
                      fontWeight: 700,
                      textTransform: 'uppercase',
                      letterSpacing: '0.04em',
                      background:
                        grade === 'Strong'
                          ? 'rgba(16, 185, 129, 0.2)'
                          : grade === 'Moderate'
                          ? 'rgba(56, 189, 248, 0.2)'
                          : grade === 'Weak'
                          ? 'rgba(245, 158, 11, 0.2)'
                          : 'rgba(239, 68, 68, 0.2)',
                      color:
                        grade === 'Strong'
                          ? '#34d399'
                          : grade === 'Moderate'
                          ? '#38bdf8'
                          : grade === 'Weak'
                          ? '#fbbf24'
                          : '#f87171',
                      border: `1px solid ${
                        grade === 'Strong'
                          ? '#10b981'
                          : grade === 'Moderate'
                          ? '#38bdf8'
                          : grade === 'Weak'
                          ? '#f59e0b'
                          : '#ef4444'
                      }`,
                    }}
                  >
                    GRADE: {grade}
                  </span>
                  <span className={`confidence-badge conf-${hypo.confidence.toLowerCase()}`}>
                    {hypo.confidence}
                  </span>
                </div>

                <div
                  className="score-meter"
                  title={`Deterministic heuristic score: ${hypo.score.toFixed(2)} (Heuristic weighting, not a probability)`}
                  style={{ textAlign: 'right' }}
                >
                  <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#f8fafc' }}>
                    {hypo.score.toFixed(2)} <span style={{ fontSize: '0.7rem', color: '#64748b' }}>/ 1.00</span>
                  </div>
                  <div style={{ fontSize: '0.68rem', color: '#94a3b8' }}>Evidence Score</div>
                </div>
              </div>

              <h4 className="hypo-title">{hypo.title}</h4>
              <p className="hypo-narrative">{hypo.description}</p>

              {/* Confidence Explanation */}
              <div className="hypo-callout confidence-explanation">
                <span className="callout-heading">Evidence Strength & Forensic Assessment:</span>
                <p className="callout-body">{hypo.confidence_explanation}</p>
              </div>

              {/* Deterministic Score Calculation & Limitations Toggle */}
              {Object.keys(breakdown).length > 0 && (
                <div style={{ margin: '0.75rem 0' }}>
                  <button
                    onClick={() => toggleBreakdown(hypo.hypothesis_id)}
                    style={{
                      background: 'none',
                      border: '1px solid #334155',
                      borderRadius: '4px',
                      color: '#94a3b8',
                      fontSize: '0.72rem',
                      padding: '0.3rem 0.6rem',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.4rem',
                    }}
                  >
                    <span>{isBreakdownOpen ? '▼' : '►'}</span>
                    <span>Explain Score Calculation & Deterministic Rules</span>
                  </button>

                  {isBreakdownOpen && (
                    <div
                      style={{
                        marginTop: '0.5rem',
                        background: '#090d16',
                        border: '1px solid #1e293b',
                        borderRadius: '6px',
                        padding: '0.75rem',
                        fontSize: '0.75rem',
                        color: '#cbd5e1',
                      }}
                    >
                      <div style={{ fontWeight: 600, color: '#38bdf8', marginBottom: '0.4rem' }}>
                        Deterministic Scoring Components:
                      </div>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.4rem', marginBottom: '0.5rem' }}>
                        <div>Lifecycle Stages: <strong>{breakdown.lifecycle_stages_count ?? 'N/A'}</strong></div>
                        <div>Stage Weight: <strong>+{breakdown.stage_weight ?? 0}</strong></div>
                        <div>Causal Continuity: <strong>+{breakdown.causal_continuity_bonus ?? 0}</strong></div>
                        <div>Untrusted Origin: <strong>+{breakdown.untrusted_origin_bonus ?? 0}</strong></div>
                        <div>Contradiction Penalty: <strong style={{ color: '#f87171' }}>-{breakdown.contradiction_penalty ?? 0}</strong></div>
                        <div>Missing Telemetry Gap: <strong style={{ color: '#f87171' }}>-{breakdown.missing_evidence_penalty ?? 0}</strong></div>
                      </div>

                      {breakdown.calculation_formula && (
                        <div style={{ marginBottom: '0.4rem', fontFamily: 'monospace', fontSize: '0.7rem', color: '#94a3b8' }}>
                          Formula: {breakdown.calculation_formula}
                        </div>
                      )}

                      {breakdown.limitations && (
                        <div style={{ color: '#f59e0b', fontSize: '0.7rem', borderTop: '1px solid #1e293b', paddingTop: '0.4rem' }}>
                          ⚠️ Limitations: {breakdown.limitations}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* Supporting Evidence */}
              <div className="evidence-section">
                <span className="evidence-section-title">
                  Corroborating Supporting Evidence ({hypo.supporting_event_ids.length}):
                </span>
                {hypo.supporting_event_ids.length > 0 ? (
                  <div className="event-pill-row">
                    {hypo.supporting_event_ids.map((id) => (
                      <button
                        key={id}
                        className="btn-event-pill supporting"
                        onClick={() => onSelectEventId(id)}
                        title="Highlight event in graph and timeline"
                      >
                        ✓ {id}
                      </button>
                    ))}
                  </div>
                ) : (
                  <span className="empty-evidence-text">No direct supporting events mapped.</span>
                )}
              </div>

              {/* Contradicting Evidence */}
              <div className="evidence-section">
                <span className="evidence-section-title contradicting-title">
                  Contradicting / Incongruous Evidence ({hypo.contradicting_event_ids.length}):
                </span>
                {hypo.contradicting_event_ids.length > 0 ? (
                  <div className="event-pill-row">
                    {hypo.contradicting_event_ids.map((id) => (
                      <button
                        key={id}
                        className="btn-event-pill contradicting"
                        onClick={() => onSelectEventId(id)}
                        title="Inspect contradictory evidence"
                      >
                        ✕ {id}
                      </button>
                    ))}
                  </div>
                ) : (
                  <span className="empty-evidence-text">No direct contradictory evidence discovered.</span>
                )}
              </div>

              {/* Assumptions & Telemetry Gaps */}
              {hypo.assumptions.length > 0 && (
                <div className="hypo-assumptions">
                  <span className="assumptions-title">Explicit Assumptions & Hypothesized Context:</span>
                  <ul className="assumptions-list">
                    {hypo.assumptions.map((asm, idx) => (
                      <li key={idx}>{asm}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Action Button */}
              <div className="hypo-actions">
                <button
                  className={`btn-select-hypo ${isSelected ? 'active' : ''}`}
                  onClick={() => onSelectHypothesis(hypo)}
                >
                  {isSelected ? '✓ Hypothesis Highlighted in Graph' : '🔍 Highlight Hypothesis in Evidence Graph'}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
