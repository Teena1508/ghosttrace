import React, { useState } from 'react';
import type { DefensiveRecommendation } from '../types/event';

interface Props {
  recommendations: DefensiveRecommendation[];
  onSelectEventId: (eventId: string) => void;
}

export const DefensiveRecommendations: React.FC<Props> = ({
  recommendations,
  onSelectEventId,
}) => {
  // State for interactive containment simulation
  const [simulatedActions, setSimulatedActions] = useState<Record<string, boolean>>({});

  const toggleSimulatedAction = (recId: string) => {
    setSimulatedActions((prev) => ({
      ...prev,
      [recId]: !prev[recId],
    }));
  };

  if (!recommendations || recommendations.length === 0) {
    return (
      <div className="recommendations-empty">
        <p>No defensive recommendations generated for this investigation.</p>
      </div>
    );
  }

  const enforcedCount = Object.values(simulatedActions).filter(Boolean).length;

  return (
    <div className="defensive-recommendations-wrapper">
      {/* Prominent Advisory Disclaimer Banner */}
      <div className="advisory-disclaimer-banner">
        <div className="banner-icon">🛡️</div>
        <div className="banner-text">
          <strong>DEFENSIVE RESPONSE ADVISORY · SIMULATED ENVIRONMENT ONLY</strong>
          <p>
            All recommendations are analytical guidance derived from observed and inferred findings.
            GhostTrace operates in an advisory mode and does NOT execute containment commands against real accounts,
            operating systems, or production network firewalls.
          </p>
        </div>
      </div>

      {/* Simulated Containment Sandbox Control Bar */}
      <div className="containment-sandbox-header">
        <div className="sandbox-title-area">
          <span className="sandbox-eyebrow">INTERACTIVE CONTAINMENT DEMONSTRATION</span>
          <h3 className="sandbox-title">Simulated Incident Containment Sandbox</h3>
        </div>

        <div className="sandbox-counter">
          <span className="counter-label">Simulated Actions Applied:</span>
          <span className="counter-number">
            {enforcedCount} of {recommendations.length}
          </span>
        </div>
      </div>

      {/* Recommendations Cards Grid */}
      <div className="recommendations-cards-grid">
        {recommendations.map((rec) => {
          const isSimulated = !!simulatedActions[rec.recommendation_id];
          const isDirect = rec.measure_type === 'DIRECT_RESPONSE';

          return (
            <div
              key={rec.recommendation_id}
              className={`recommendation-card priority-${rec.priority.toLowerCase()} ${
                isSimulated ? 'simulated-enforced' : ''
              }`}
            >
              <div className="rec-top-row">
                <div className="rec-badge-group">
                  <span className={`priority-badge ${rec.priority.toLowerCase()}`}>
                    {rec.priority} PRIORITY
                  </span>
                  <span className={`measure-type-badge ${isDirect ? 'direct' : 'precautionary'}`}>
                    {isDirect ? 'DIRECT RESPONSE' : 'PRECAUTIONARY HARDENING'}
                  </span>
                  {isSimulated && (
                    <span className="simulated-applied-badge">✓ SIMULATED APPLIED</span>
                  )}
                </div>

                {rec.target_entity && (
                  <span className="rec-target-entity">Target: <code>{rec.target_entity}</code></span>
                )}
              </div>

              <h4 className="rec-heading">{rec.title}</h4>
              <p className="rec-action-text">{rec.action}</p>

              {/* Forensic Rationale */}
              <div className="rec-field-box rationale-box">
                <span className="field-box-title">Why This Is Recommended:</span>
                <p className="field-box-text">
                  {rec.why_recommended || 'Derived from correlated incident findings and attack sequence telemetry.'}
                </p>
              </div>

              {/* Benefit & Operational Risk */}
              <div className="rec-two-col-fields">
                <div className="rec-field-box benefit-box">
                  <span className="field-box-title">Expected Benefit:</span>
                  <p className="field-box-text">
                    {rec.expected_benefit || 'Mitigates attack progression and reduces vulnerability footprint.'}
                  </p>
                </div>

                <div className="rec-field-box risk-box">
                  <span className="field-box-title">Potential Operational Impact / Risk:</span>
                  <p className="field-box-text">
                    {rec.potential_impact_risk || 'Standard operational review recommended prior to deployment.'}
                  </p>
                </div>
              </div>

              {/* Supporting Evidence IDs */}
              {rec.supporting_event_ids && rec.supporting_event_ids.length > 0 && (
                <div className="rec-supporting-evidence">
                  <span className="supp-label">Supporting Evidence:</span>
                  <div className="supp-buttons">
                    {rec.supporting_event_ids.map((id) => (
                      <button
                        key={id}
                        className="btn-tiny-event"
                        onClick={() => onSelectEventId(id)}
                        title="Highlight supporting event in graph and timeline"
                      >
                        {id}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* MITRE Technique */}
              {rec.mitre_mitigation && (
                <div className="rec-mitre-strip">
                  <span className="mitre-label">MITRE Mitigation:</span>
                  <span className="mitre-code">{rec.mitre_mitigation}</span>
                </div>
              )}

              {/* Interactive Simulation Button */}
              <div className="rec-sandbox-action">
                <button
                  className={`btn-simulate-toggle ${isSimulated ? 'active-enforced' : ''}`}
                  onClick={() => toggleSimulatedAction(rec.recommendation_id)}
                >
                  {isSimulated ? '✓ Revert Simulated Action' : '⚡ Simulate Defensive Containment'}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
