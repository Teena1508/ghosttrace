/**
 * ChallengeEvaluationView.tsx
 * Phase 6: Demonstration Mode for Hidden-Attack Challenge and Evaluation.
 * 
 * Features:
 * - Blind scenario selection with zero answer leakage.
 * - Reproducible seed configuration.
 * - One-click reconstruction & automated scoring.
 * - Inspection of reconstructed timeline, graph summary, and competing hypotheses.
 * - On-demand ground-truth revelation with diff comparison (correct, missed, unsupported conclusions).
 */

import React, { useState, useEffect } from 'react';
import {
  fetchEvaluationScenarios,
  runEvaluationScenario,
  fetchGroundTruthComparison,
} from '../services/api';
import type {
  BlindScenarioSummary,
  RunEvaluationResponse,
  GroundTruthComparisonResponse,
} from '../services/api';

interface Props {
  onLoadScenarioToWorkspace?: (scenarioId: string) => void;
}

export const ChallengeEvaluationView: React.FC<Props> = ({ onLoadScenarioToWorkspace }) => {
  const [scenarios, setScenarios] = useState<BlindScenarioSummary[]>([]);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('');
  const [seed, setSeed] = useState<number>(42);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Evaluation Run Result
  const [evalResult, setEvalResult] = useState<RunEvaluationResponse | null>(null);

  // Ground Truth State (Revealed only on demand)
  const [groundTruthData, setGroundTruthData] = useState<GroundTruthComparisonResponse | null>(null);
  const [revealingGroundTruth, setRevealingGroundTruth] = useState<boolean>(false);

  // Active view tab within evaluation
  const [subTab, setSubTab] = useState<'metrics' | 'timeline' | 'hypotheses' | 'conclusions'>('metrics');

  // Load scenarios on mount
  useEffect(() => {
    fetchEvaluationScenarios(seed)
      .then((data) => {
        setScenarios(data);
        if (data.length > 0) {
          setSelectedScenarioId(data[0].scenario_id);
        }
      })
      .catch((err) => {
        setError(`Failed to load challenge scenarios: ${err.message}`);
      });
  }, [seed]);

  const handleRunEvaluation = async () => {
    if (!selectedScenarioId) return;
    setLoading(true);
    setError(null);
    setGroundTruthData(null); // Reset revealed ground truth on new run
    try {
      const res = await runEvaluationScenario(selectedScenarioId, seed);
      setEvalResult(res);
    } catch (err: any) {
      setError(`Evaluation failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleRevealGroundTruth = async () => {
    if (!selectedScenarioId) return;
    setRevealingGroundTruth(true);
    try {
      const res = await fetchGroundTruthComparison(selectedScenarioId, seed);
      setGroundTruthData(res);
    } catch (err: any) {
      setError(`Failed to retrieve ground truth: ${err.message}`);
    } finally {
      setRevealingGroundTruth(false);
    }
  };

  const selectedMeta = scenarios.find((s) => s.scenario_id === selectedScenarioId);

  return (
    <div className="challenge-eval-container" style={{ padding: '1.5rem', color: '#e2e8f0' }}>
      {/* Header & Protocol Disclaimer */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '1.5rem', color: '#38bdf8', fontWeight: 600 }}>
            Defensive Challenge & Evaluation Lab
          </h2>
          <p style={{ margin: '0.25rem 0 0 0', color: '#94a3b8', fontSize: '0.875rem' }}>
            Blind incident reconstruction testing, automated forensic scoring, and ground-truth comparison.
          </p>
        </div>
        <div style={{
          backgroundColor: '#0f172a',
          border: '1px solid #334155',
          borderRadius: '6px',
          padding: '0.5rem 0.75rem',
          fontSize: '0.75rem',
          color: '#38bdf8',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
        }}>
          <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#10b981', display: 'inline-block' }} />
          Zero-Leakage Sandbox Active
        </div>
      </div>

      {/* Protocol Safeguards Box */}
      <div style={{
        backgroundColor: '#1e293b',
        border: '1px solid #334155',
        borderRadius: '8px',
        padding: '1rem',
        marginBottom: '1.5rem',
        fontSize: '0.8125rem',
        lineHeight: 1.5,
        color: '#cbd5e1',
      }}>
        <div style={{ fontWeight: 600, color: '#f8fafc', marginBottom: '0.25rem' }}>
          Forensic Integrity & Answer Isolation Protocol:
        </div>
        <div>
          The reconstruction engine receives only blinded, anonymized telemetry records. Ground-truth labels (<code style={{ color: '#38bdf8' }}>is_suspicious</code>, expected answers, intended incident IDs) are stripped, and event ordering is randomized with reproducible seeds. Ground truth remains isolated and cannot be accessed by the engine.
        </div>
      </div>

      {/* Controls Bar: Scenario Selector & Execution */}
      <div style={{
        backgroundColor: '#0f172a',
        border: '1px solid #1e293b',
        borderRadius: '8px',
        padding: '1.25rem',
        marginBottom: '1.5rem',
        display: 'flex',
        flexWrap: 'wrap',
        gap: '1.25rem',
        alignItems: 'flex-end',
      }}>
        {/* Scenario Select */}
        <div style={{ flex: '1 1 320px' }}>
          <label style={{ display: 'block', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.375rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Select Blind Challenge Scenario
          </label>
          <select
            value={selectedScenarioId}
            onChange={(e) => {
              setSelectedScenarioId(e.target.value);
              setEvalResult(null);
              setGroundTruthData(null);
            }}
            disabled={loading}
            style={{
              width: '100%',
              backgroundColor: '#1e293b',
              color: '#f8fafc',
              border: '1px solid #475569',
              borderRadius: '6px',
              padding: '0.625rem 0.75rem',
              fontSize: '0.875rem',
            }}
          >
            {scenarios.map((sc) => (
              <option key={sc.scenario_id} value={sc.scenario_id}>
                {sc.title} ({sc.event_count} Events)
              </option>
            ))}
          </select>
          {selectedMeta && (
            <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.25rem' }}>
              {selectedMeta.description}
            </div>
          )}
        </div>

        {/* Reproducibility Seed */}
        <div style={{ width: '120px' }}>
          <label style={{ display: 'block', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.375rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Seed
          </label>
          <input
            type="number"
            value={seed}
            onChange={(e) => setSeed(parseInt(e.target.value, 10) || 0)}
            disabled={loading}
            style={{
              width: '100%',
              backgroundColor: '#1e293b',
              color: '#f8fafc',
              border: '1px solid #475569',
              borderRadius: '6px',
              padding: '0.625rem 0.75rem',
              fontSize: '0.875rem',
            }}
          />
        </div>

        {/* Run Button */}
        <div>
          <button
            onClick={handleRunEvaluation}
            disabled={loading || !selectedScenarioId}
            style={{
              backgroundColor: loading ? '#475569' : '#0284c7',
              color: '#ffffff',
              border: 'none',
              borderRadius: '6px',
              padding: '0.625rem 1.25rem',
              fontSize: '0.875rem',
              fontWeight: 600,
              cursor: loading ? 'not-allowed' : 'pointer',
              transition: 'background-color 0.2s',
            }}
          >
            {loading ? 'Reconstructing Blindly...' : 'Run Blind Challenge & Evaluate'}
          </button>
        </div>

        {/* Reveal Ground Truth Button */}
        {evalResult && (
          <div>
            <button
              onClick={handleRevealGroundTruth}
              disabled={revealingGroundTruth || groundTruthData !== null}
              style={{
                backgroundColor: groundTruthData ? '#059669' : '#7c3aed',
                color: '#ffffff',
                border: 'none',
                borderRadius: '6px',
                padding: '0.625rem 1.25rem',
                fontSize: '0.875rem',
                fontWeight: 600,
                cursor: groundTruthData ? 'default' : 'pointer',
                transition: 'background-color 0.2s',
              }}
            >
              {revealingGroundTruth
                ? 'Retrieving Ground Truth...'
                : groundTruthData
                ? '✓ Ground Truth Revealed'
                : 'Reveal Ground Truth Scorecard'}
            </button>
          </div>
        )}

        {/* Open in Investigation Workspace Button */}
        {evalResult && onLoadScenarioToWorkspace && (
          <div>
            <button
              onClick={() => onLoadScenarioToWorkspace(selectedScenarioId)}
              style={{
                backgroundColor: '#0284c7',
                color: '#ffffff',
                border: 'none',
                borderRadius: '6px',
                padding: '0.625rem 1.25rem',
                fontSize: '0.875rem',
                fontWeight: 600,
                cursor: 'pointer',
                transition: 'background-color 0.2s',
              }}
              title="Load this scenario directly into the primary forensic workspace"
            >
              🔍 Open in Investigation Workspace
            </button>
          </div>
        )}
      </div>

      {error && (
        <div style={{
          backgroundColor: '#450a0a',
          border: '1px solid #b91c1c',
          borderRadius: '6px',
          padding: '0.75rem 1rem',
          color: '#fca5a5',
          marginBottom: '1.5rem',
          fontSize: '0.875rem',
        }}>
          {error}
        </div>
      )}

      {/* Main Results Container */}
      {evalResult && (
        <div>
          {/* Top Scorecard Metrics Strip */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
            gap: '0.75rem',
            marginBottom: '1.5rem',
          }}>
            <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '0.75rem', textAlign: 'center' }}>
              <div style={{ fontSize: '0.7rem', color: '#94a3b8', textTransform: 'uppercase' }}>Entry Point</div>
              <div style={{ fontSize: '1.25rem', fontWeight: 700, color: evalResult.metrics.entry_point_accuracy === 1 ? '#10b981' : '#f59e0b', marginTop: '0.25rem' }}>
                {(evalResult.metrics.entry_point_accuracy * 100).toFixed(0)}%
              </div>
            </div>

            <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '0.75rem', textAlign: 'center' }}>
              <div style={{ fontSize: '0.7rem', color: '#94a3b8', textTransform: 'uppercase' }}>Event Prec / Rec</div>
              <div style={{ fontSize: '1.125rem', fontWeight: 700, color: '#38bdf8', marginTop: '0.25rem' }}>
                {(evalResult.metrics.relevant_event_precision * 100).toFixed(0)}% / {(evalResult.metrics.relevant_event_recall * 100).toFixed(0)}%
              </div>
            </div>

            <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '0.75rem', textAlign: 'center' }}>
              <div style={{ fontSize: '0.7rem', color: '#94a3b8', textTransform: 'uppercase' }}>Timeline Order</div>
              <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#10b981', marginTop: '0.25rem' }}>
                {(evalResult.metrics.timeline_ordering_accuracy * 100).toFixed(0)}%
              </div>
            </div>

            <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '0.75rem', textAlign: 'center' }}>
              <div style={{ fontSize: '0.7rem', color: '#94a3b8', textTransform: 'uppercase' }}>Relationships</div>
              <div style={{ fontSize: '1.125rem', fontWeight: 700, color: '#a78bfa', marginTop: '0.25rem' }}>
                {(evalResult.metrics.relationship_precision * 100).toFixed(0)}% / {(evalResult.metrics.relationship_recall * 100).toFixed(0)}%
              </div>
            </div>

            <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '0.75rem', textAlign: 'center' }}>
              <div style={{ fontSize: '0.7rem', color: '#94a3b8', textTransform: 'uppercase' }}>Traceability</div>
              <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#10b981', marginTop: '0.25rem' }}>
                {(evalResult.metrics.source_event_traceability * 100).toFixed(0)}%
              </div>
            </div>

            <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '0.75rem', textAlign: 'center' }}>
              <div style={{ fontSize: '0.7rem', color: '#94a3b8', textTransform: 'uppercase' }}>Forensic Restraint</div>
              <div style={{
                fontSize: '1.25rem',
                fontWeight: 700,
                color: evalResult.metrics.unsupported_claim_rate === 0 ? '#10b981' : '#ef4444',
                marginTop: '0.25rem',
              }}>
                {((1 - evalResult.metrics.unsupported_claim_rate) * 100).toFixed(0)}%
              </div>
            </div>

            <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '0.75rem', textAlign: 'center' }}>
              <div style={{ fontSize: '0.7rem', color: '#94a3b8', textTransform: 'uppercase' }}>Exec Time</div>
              <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#f8fafc', marginTop: '0.25rem' }}>
                {evalResult.execution_time_ms} ms
              </div>
            </div>
          </div>

          {/* Sub-tab Navigation */}
          <div style={{ display: 'flex', gap: '0.5rem', borderBottom: '1px solid #334155', marginBottom: '1.25rem' }}>
            <button
              onClick={() => setSubTab('metrics')}
              style={{
                backgroundColor: 'transparent',
                border: 'none',
                borderBottom: subTab === 'metrics' ? '2px solid #38bdf8' : '2px solid transparent',
                color: subTab === 'metrics' ? '#38bdf8' : '#94a3b8',
                padding: '0.5rem 1rem',
                fontWeight: 600,
                fontSize: '0.875rem',
                cursor: 'pointer',
              }}
            >
              Forensic Evaluation Details
            </button>
            <button
              onClick={() => setSubTab('timeline')}
              style={{
                backgroundColor: 'transparent',
                border: 'none',
                borderBottom: subTab === 'timeline' ? '2px solid #38bdf8' : '2px solid transparent',
                color: subTab === 'timeline' ? '#38bdf8' : '#94a3b8',
                padding: '0.5rem 1rem',
                fontWeight: 600,
                fontSize: '0.875rem',
                cursor: 'pointer',
              }}
            >
              Reconstructed Timeline ({evalResult.reconstruction.timeline.length})
            </button>
            <button
              onClick={() => setSubTab('hypotheses')}
              style={{
                backgroundColor: 'transparent',
                border: 'none',
                borderBottom: subTab === 'hypotheses' ? '2px solid #38bdf8' : '2px solid transparent',
                color: subTab === 'hypotheses' ? '#38bdf8' : '#94a3b8',
                padding: '0.5rem 1rem',
                fontWeight: 600,
                fontSize: '0.875rem',
                cursor: 'pointer',
              }}
            >
              Ranked Hypotheses ({evalResult.reconstruction.hypotheses.length})
            </button>
            <button
              onClick={() => setSubTab('conclusions')}
              style={{
                backgroundColor: 'transparent',
                border: 'none',
                borderBottom: subTab === 'conclusions' ? '2px solid #38bdf8' : '2px solid transparent',
                color: subTab === 'conclusions' ? '#38bdf8' : '#94a3b8',
                padding: '0.5rem 1rem',
                fontWeight: 600,
                fontSize: '0.875rem',
                cursor: 'pointer',
              }}
            >
              Facts vs Inferences ({evalResult.reconstruction.observed_facts.length} / {evalResult.reconstruction.inferred_conclusions.length})
            </button>
          </div>

          {/* Sub-tab 1: Forensic Evaluation Details */}
          {subTab === 'metrics' && (
            <div style={{ backgroundColor: '#1e293b', borderRadius: '8px', border: '1px solid #334155', padding: '1.25rem', marginBottom: '1.5rem' }}>
              <h3 style={{ fontSize: '1rem', color: '#f8fafc', marginTop: 0, marginBottom: '1rem' }}>
                Reconstruction Evaluation Diagnostic Report
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', fontSize: '0.8125rem' }}>
                <div style={{ backgroundColor: '#0f172a', padding: '0.75rem', borderRadius: '6px', border: '1px solid #334155' }}>
                  <div style={{ color: '#94a3b8', marginBottom: '0.25rem' }}>Entry Point Status</div>
                  <div style={{ fontWeight: 600, color: '#f8fafc' }}>
                    {evalResult.metrics.details.entry_point_status || 'N/A'}
                  </div>
                </div>

                <div style={{ backgroundColor: '#0f172a', padding: '0.75rem', borderRadius: '6px', border: '1px solid #334155' }}>
                  <div style={{ color: '#94a3b8', marginBottom: '0.25rem' }}>Suspicious Incident Event Hits</div>
                  <div style={{ fontWeight: 600, color: '#10b981' }}>
                    True Positives: {evalResult.metrics.details.tp_events?.length || 0} | False Positives: {evalResult.metrics.details.fp_events?.length || 0}
                  </div>
                </div>

                <div style={{ backgroundColor: '#0f172a', padding: '0.75rem', borderRadius: '6px', border: '1px solid #334155' }}>
                  <div style={{ color: '#94a3b8', marginBottom: '0.25rem' }}>Unsupported Claims (Restraint Test)</div>
                  <div style={{
                    fontWeight: 600,
                    color: evalResult.metrics.unsupported_claim_rate === 0 ? '#10b981' : '#ef4444',
                  }}>
                    {evalResult.metrics.unsupported_claim_rate === 0
                      ? '0 (No premature exfiltration or unsupported assertions)'
                      : `${evalResult.metrics.details.unsupported_claims_count} unsupported claims detected`}
                  </div>
                </div>

                <div style={{ backgroundColor: '#0f172a', padding: '0.75rem', borderRadius: '6px', border: '1px solid #334155' }}>
                  <div style={{ color: '#94a3b8', marginBottom: '0.25rem' }}>Traceability & Evidence Citations</div>
                  <div style={{ fontWeight: 600, color: '#f8fafc' }}>
                    {evalResult.metrics.details.valid_event_references} / {evalResult.metrics.details.total_event_references} references verified valid
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Sub-tab 2: Timeline */}
          {subTab === 'timeline' && (
            <div style={{ backgroundColor: '#1e293b', borderRadius: '8px', border: '1px solid #334155', padding: '1.25rem', marginBottom: '1.5rem' }}>
              <h3 style={{ fontSize: '1rem', color: '#f8fafc', marginTop: 0, marginBottom: '1rem' }}>
                Reconstructed Attack Timeline
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {evalResult.reconstruction.timeline.map((item, idx) => (
                  <div
                    key={item.event_id}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '1rem',
                      padding: '0.75rem',
                      backgroundColor: item.is_suspicious ? '#26161c' : '#0f172a',
                      border: item.is_suspicious ? '1px solid #e11d48' : '1px solid #334155',
                      borderRadius: '6px',
                    }}
                  >
                    <div style={{
                      width: '24px',
                      height: '24px',
                      borderRadius: '50%',
                      backgroundColor: item.is_suspicious ? '#e11d48' : '#334155',
                      color: '#ffffff',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '0.75rem',
                      fontWeight: 700,
                    }}>
                      {idx + 1}
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                        <span style={{ fontWeight: 600, color: '#f8fafc', fontSize: '0.875rem' }}>{item.event_id}</span>
                        <span style={{
                          fontSize: '0.7rem',
                          padding: '0.125rem 0.375rem',
                          borderRadius: '4px',
                          backgroundColor: '#334155',
                          color: '#cbd5e1',
                        }}>
                          {item.phase}
                        </span>
                        {item.is_suspicious && (
                          <span style={{
                            fontSize: '0.7rem',
                            padding: '0.125rem 0.375rem',
                            borderRadius: '4px',
                            backgroundColor: '#be123c',
                            color: '#ffe4e6',
                            fontWeight: 600,
                          }}>
                            SUSPICIOUS
                          </span>
                        )}
                      </div>
                      <div style={{ fontSize: '0.8125rem', color: '#cbd5e1' }}>{item.summary}</div>
                    </div>
                    <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                      {new Date(item.timestamp).toLocaleTimeString()}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Sub-tab 3: Hypotheses */}
          {subTab === 'hypotheses' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginBottom: '1.5rem' }}>
              {evalResult.reconstruction.hypotheses.map((hypo) => (
                <div
                  key={hypo.hypothesis_id}
                  style={{
                    backgroundColor: '#1e293b',
                    border: hypo.rank === 1 ? '1px solid #38bdf8' : '1px solid #334155',
                    borderRadius: '8px',
                    padding: '1.25rem',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span style={{
                        backgroundColor: hypo.rank === 1 ? '#0284c7' : '#475569',
                        color: '#ffffff',
                        fontSize: '0.75rem',
                        fontWeight: 700,
                        padding: '0.25rem 0.5rem',
                        borderRadius: '4px',
                      }}>
                        Rank #{hypo.rank}
                      </span>
                      <span style={{ fontWeight: 600, color: '#f8fafc', fontSize: '1rem' }}>
                        {hypo.title}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.875rem', color: '#38bdf8', fontWeight: 600 }}>
                      Score: {(hypo.score * 100).toFixed(0)}% ({hypo.confidence} Confidence)
                    </div>
                  </div>
                  <p style={{ fontSize: '0.8125rem', color: '#cbd5e1', lineHeight: 1.5, margin: '0 0 0.75rem 0' }}>
                    {hypo.description}
                  </p>
                  <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                    <strong>Supporting Evidence:</strong> {hypo.supporting_event_ids.join(', ')}
                    {hypo.contradicting_event_ids && hypo.contradicting_event_ids.length > 0 && (
                      <span style={{ color: '#f87171', marginLeft: '1rem' }}>
                        <strong>Contradicting:</strong> {hypo.contradicting_event_ids.join(', ')}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Sub-tab 4: Facts vs Inferences */}
          {subTab === 'conclusions' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
              <div style={{ backgroundColor: '#1e293b', borderRadius: '8px', border: '1px solid #334155', padding: '1.25rem' }}>
                <h4 style={{ color: '#38bdf8', marginTop: 0, marginBottom: '0.75rem', fontSize: '0.9rem' }}>
                  Observed Facts (Direct Empirical Telemetry)
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {evalResult.reconstruction.observed_facts.map((fact) => (
                    <div key={fact.fact_id} style={{ backgroundColor: '#0f172a', padding: '0.5rem 0.75rem', borderRadius: '4px', fontSize: '0.75rem', color: '#cbd5e1' }}>
                      <span style={{ color: '#10b981', fontWeight: 600, marginRight: '0.5rem' }}>✓</span>
                      {fact.statement}
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ backgroundColor: '#1e293b', borderRadius: '8px', border: '1px solid #334155', padding: '1.25rem' }}>
                <h4 style={{ color: '#f59e0b', marginTop: 0, marginBottom: '0.75rem', fontSize: '0.9rem' }}>
                  Inferred Conclusions (Subject to Restraint Verification)
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {evalResult.reconstruction.inferred_conclusions.map((conc) => (
                    <div key={conc.conclusion_id} style={{ backgroundColor: '#0f172a', padding: '0.5rem 0.75rem', borderRadius: '4px', fontSize: '0.75rem', color: '#cbd5e1' }}>
                      <div style={{ fontWeight: 600, color: '#f8fafc', marginBottom: '0.25rem' }}>{conc.statement}</div>
                      <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>
                        Confidence: {conc.confidence} | Supporting: {conc.supporting_event_ids.join(', ')}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Ground Truth Reveal & Comparison Diff (Only visible when revealed) */}
          {groundTruthData && (
            <div style={{
              backgroundColor: '#0f172a',
              border: '2px solid #7c3aed',
              borderRadius: '8px',
              padding: '1.5rem',
              marginTop: '1.5rem',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '1px solid #334155', paddingBottom: '0.75rem' }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: '1.25rem', color: '#c084fc', fontWeight: 600 }}>
                    Ground Truth Verification & Differential Scorecard
                  </h3>
                  <div style={{ fontSize: '0.8125rem', color: '#94a3b8', marginTop: '0.25rem' }}>
                    Isolated Ground Truth: <strong>{groundTruthData.ground_truth.name}</strong>
                  </div>
                </div>
                <div style={{
                  backgroundColor: '#7c3aed',
                  color: '#ffffff',
                  fontSize: '0.75rem',
                  fontWeight: 700,
                  padding: '0.25rem 0.75rem',
                  borderRadius: '9999px',
                }}>
                  REVEALED ANSWER KEY
                </div>
              </div>

              {/* Comparison Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginBottom: '1.25rem' }}>
                <div style={{ backgroundColor: '#1e293b', padding: '1rem', borderRadius: '6px', border: '1px solid #334155' }}>
                  <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.25rem' }}>
                    Entry Point Match
                  </div>
                  <div style={{
                    fontSize: '1rem',
                    fontWeight: 700,
                    color: groundTruthData.comparison.entry_point_match ? '#10b981' : '#f59e0b',
                  }}>
                    {groundTruthData.comparison.entry_point_match
                      ? `✓ Exact Match (${groundTruthData.ground_truth.expected_entry_point_id || 'None'})`
                      : `⚠ Mismatch: Expected ${groundTruthData.ground_truth.expected_entry_point_id || 'None'}`}
                  </div>
                </div>

                <div style={{ backgroundColor: '#1e293b', padding: '1rem', borderRadius: '6px', border: '1px solid #334155' }}>
                  <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.25rem' }}>
                    Detection Classification
                  </div>
                  <div style={{ fontSize: '0.875rem', fontWeight: 600, color: '#f8fafc' }}>
                    <span style={{ color: '#10b981' }}>TP: {groundTruthData.comparison.true_positives.length}</span> |{' '}
                    <span style={{ color: '#f59e0b' }}>FP: {groundTruthData.comparison.false_positives.length}</span> |{' '}
                    <span style={{ color: '#ef4444' }}>FN: {groundTruthData.comparison.false_negatives.length}</span>
                  </div>
                </div>

                <div style={{ backgroundColor: '#1e293b', padding: '1rem', borderRadius: '6px', border: '1px solid #334155' }}>
                  <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.25rem' }}>
                    Exfiltration Restraint Check
                  </div>
                  <div style={{
                    fontSize: '0.875rem',
                    fontWeight: 600,
                    color: groundTruthData.comparison.forensic_restraint_preserved ? '#10b981' : '#ef4444',
                  }}>
                    {groundTruthData.comparison.forensic_restraint_preserved
                      ? '✓ Restraint Verified (No premature claims)'
                      : `⚠ Violation: ${groundTruthData.comparison.unsupported_claims.length} unsupported claim(s)`}
                  </div>
                </div>
              </div>

              {/* Explicitly Unknown Facts List */}
              {groundTruthData.ground_truth.explicitly_unknown_facts.length > 0 && (
                <div style={{ backgroundColor: '#1e293b', padding: '1rem', borderRadius: '6px', border: '1px solid #334155', marginBottom: '1rem' }}>
                  <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#f59e0b', marginBottom: '0.25rem' }}>
                    Explicitly Unknown Facts (Telemetry Insufficient to Prove):
                  </div>
                  <ul style={{ margin: '0.25rem 0 0 1rem', padding: 0, fontSize: '0.75rem', color: '#cbd5e1' }}>
                    {groundTruthData.ground_truth.explicitly_unknown_facts.map((fact, i) => (
                      <li key={i}><code style={{ color: '#f59e0b' }}>{fact}</code>: Must not be asserted as fact without packet payload telemetry.</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Competing Explanations Comparison */}
              {groundTruthData.ground_truth.is_ambiguous && (
                <div style={{ backgroundColor: '#1e293b', padding: '1rem', borderRadius: '6px', border: '1px solid #334155' }}>
                  <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#38bdf8', marginBottom: '0.25rem' }}>
                    Ambiguous Scenario Expected Plausible Explanations:
                  </div>
                  <ul style={{ margin: '0.25rem 0 0 1rem', padding: 0, fontSize: '0.75rem', color: '#cbd5e1' }}>
                    {groundTruthData.ground_truth.plausible_explanations.map((exp, i) => (
                      <li key={i}>{exp}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
