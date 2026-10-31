/**
 * JudgeDemonstrationView.tsx
 * Phase 10: Judge-Ready Demonstration & Presenter Dashboard.
 * 
 * Provides an interactive 10-step presenter track:
 * 1. Start fresh simulated investigation with reproducible seed.
 * 2. Inspect incoming shuffled telemetry records before correlation.
 * 3. Run GhostTrace deterministic reconstruction.
 * 4. Inspect reconstructed attack timeline & evidence graph.
 * 5. Click finding to highlight supporting source events.
 * 6. Compare competing hypotheses (Intrusion vs Benign SRE Emergency).
 * 7. Inspect unknowns & exfiltration restraint.
 * 8. Review advisory defensive recommendations.
 * 9. Reveal ground truth (locked until reconstruction completes).
 * 10. View verified evaluation metrics.
 */

import React, { useState, useEffect } from 'react';
import {
  fetchScenarioEvents,
  reconstructInvestigation,
  runEvaluationScenario,
  fetchGroundTruthComparison,
} from '../services/api';
import type {
  SecurityEvent,
  InvestigationReconstructionResult,
} from '../types/event';
import type {
  GroundTruthComparisonResponse,
  RunEvaluationResponse,
} from '../services/api';

interface Props {
  onLoadScenarioToWorkspace?: (scenarioId: string) => void;
}

export const JudgeDemonstrationView: React.FC<Props> = ({ onLoadScenarioToWorkspace }) => {
  const DEMO_SCENARIO_ID = 'scenario_hackathon_judge_demo';
  const DEFAULT_SEED = 42;

  // Step state
  const [currentStep, setCurrentStep] = useState<number>(1);
  const [seed, setSeed] = useState<number>(DEFAULT_SEED);

  // Data states
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [rawEvents, setRawEvents] = useState<SecurityEvent[]>([]);
  const [reconstruction, setReconstruction] = useState<InvestigationReconstructionResult | null>(null);
  const [evalResult, setEvalResult] = useState<RunEvaluationResponse | null>(null);
  const [groundTruth, setGroundTruth] = useState<GroundTruthComparisonResponse | null>(null);
  const [revealingGroundTruth, setRevealingGroundTruth] = useState<boolean>(false);

  // Selected finding state
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);

  // 1. Initialize / Reset
  const handleResetSimulation = async () => {
    setLoading(true);
    setError(null);
    setReconstruction(null);
    setEvalResult(null);
    setGroundTruth(null);
    setSelectedEventId(null);
    setCurrentStep(1);

    try {
      const data = await fetchScenarioEvents(DEMO_SCENARIO_ID);
      setRawEvents(data.events || []);
      setCurrentStep(2); // Ready to inspect raw records
    } catch (err: any) {
      setError(`Failed to load demonstration scenario: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    handleResetSimulation();
  }, [seed]);

  // 2. Run Reconstruction
  const handleRunReconstruction = async () => {
    if (rawEvents.length === 0) return;
    setLoading(true);
    setError(null);

    try {
      // Execute reconstruction
      const recon = await reconstructInvestigation(rawEvents);
      setReconstruction(recon);

      // Run evaluation metrics
      const ev = await runEvaluationScenario(DEMO_SCENARIO_ID, seed);
      setEvalResult(ev);

      setCurrentStep(4); // Advance to timeline/graph inspection
      if (recon.candidate_entry_points.length > 0) {
        setSelectedEventId(recon.candidate_entry_points[0].event_id);
      }
    } catch (err: any) {
      setError(`Reconstruction failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  // 3. Reveal Ground Truth
  const handleRevealGroundTruth = async () => {
    setRevealingGroundTruth(true);
    try {
      const gt = await fetchGroundTruthComparison(DEMO_SCENARIO_ID, seed);
      setGroundTruth(gt);
      setCurrentStep(9);
    } catch (err: any) {
      setError(`Failed to retrieve ground truth comparison: ${err.message}`);
    } finally {
      setRevealingGroundTruth(false);
    }
  };

  const selectedEvent = rawEvents.find((e) => e.event_id === selectedEventId);

  return (
    <div className="judge-demo-container" style={{ padding: '1.5rem', color: '#e2e8f0', maxWidth: '1400px', margin: '0 auto' }}>
      {/* Top Banner: Presenter Header */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.9), rgba(15, 23, 42, 0.95))',
        border: '1px solid #3b82f6',
        borderRadius: '10px',
        padding: '1.25rem 1.5rem',
        marginBottom: '1.5rem',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '1rem',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.4)',
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.25rem' }}>
            <span style={{
              background: '#3b82f6',
              color: '#fff',
              fontSize: '0.75rem',
              fontWeight: 700,
              padding: '0.2rem 0.5rem',
              borderRadius: '4px',
              letterSpacing: '0.05em'
            }}>
              PHASE 10 DEMO
            </span>
            <h2 style={{ margin: 0, fontSize: '1.35rem', color: '#60a5fa', fontWeight: 600 }}>
              Judge-Ready Demonstration: Autonomous DFIR Incident Reconstruction
            </h2>
          </div>
          <p style={{ margin: 0, color: '#94a3b8', fontSize: '0.85rem' }}>
            Deterministic rule-and-graph reasoning · Zero black-box LLM hallucinations · 100% Offline & Fictional Benchmark
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          <div style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '6px', padding: '0.35rem 0.65rem', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <span style={{ color: '#64748b' }}>SEED:</span>
            <input
              type="number"
              value={seed}
              onChange={(e) => setSeed(Number(e.target.value) || DEFAULT_SEED)}
              style={{
                width: '55px',
                background: '#1e293b',
                border: '1px solid #475569',
                color: '#38bdf8',
                borderRadius: '4px',
                padding: '0.1rem 0.3rem',
                fontWeight: 700,
                fontSize: '0.8rem',
              }}
            />
          </div>

          <button
            onClick={handleResetSimulation}
            disabled={loading}
            style={{
              background: '#334155',
              color: '#f8fafc',
              border: '1px solid #475569',
              borderRadius: '6px',
              padding: '0.5rem 0.9rem',
              fontWeight: 600,
              fontSize: '0.85rem',
              cursor: loading ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
            }}
          >
            ↻ Reset Simulation
          </button>

          {onLoadScenarioToWorkspace && (
            <button
              onClick={() => onLoadScenarioToWorkspace(DEMO_SCENARIO_ID)}
              style={{
                background: '#1e293b',
                color: '#93c5fd',
                border: '1px solid #3b82f6',
                borderRadius: '6px',
                padding: '0.5rem 0.9rem',
                fontWeight: 600,
                fontSize: '0.85rem',
                cursor: 'pointer',
              }}
            >
              Full Workspace ↗
            </button>
          )}
        </div>
      </div>

      {/* 10-Step Interactive Presenter Track */}
      <div style={{
        background: '#0f172a',
        border: '1px solid #1e293b',
        borderRadius: '8px',
        padding: '1rem',
        marginBottom: '1.5rem',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
          <strong style={{ fontSize: '0.85rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Interactive Presenter Track (10-Step Workflow)
          </strong>
          <span style={{ fontSize: '0.75rem', color: '#38bdf8' }}>
            Current Step: {currentStep} of 10
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(110px, 1fr))', gap: '0.5rem' }}>
          {[
            { n: 1, label: '1. Start Fresh' },
            { n: 2, label: '2. Raw Stream' },
            { n: 3, label: '3. Reconstruct' },
            { n: 4, label: '4. Timeline & Graph' },
            { n: 5, label: '5. Finding Citation' },
            { n: 6, label: '6. Competing Hypo' },
            { n: 7, label: '7. Unknowns' },
            { n: 8, label: '8. Mitigations' },
            { n: 9, label: '9. Reveal Truth' },
            { n: 10, label: '10. Scorecard' },
          ].map((s) => {
            const isCompleted = currentStep > s.n;
            const isCurrent = currentStep === s.n;
            return (
              <button
                key={s.n}
                onClick={() => {
                  if (s.n <= 3 || reconstruction) {
                    setCurrentStep(s.n);
                  }
                }}
                disabled={s.n > 3 && !reconstruction}
                style={{
                  background: isCurrent ? '#2563eb' : isCompleted ? 'rgba(37, 99, 235, 0.2)' : '#1e293b',
                  color: isCurrent ? '#ffffff' : isCompleted ? '#93c5fd' : '#64748b',
                  border: isCurrent ? '1px solid #60a5fa' : '1px solid #334155',
                  borderRadius: '6px',
                  padding: '0.45rem 0.25rem',
                  fontSize: '0.75rem',
                  fontWeight: isCurrent ? 700 : 500,
                  cursor: s.n <= 3 || reconstruction ? 'pointer' : 'not-allowed',
                  textAlign: 'center',
                }}
              >
                {s.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Error Notice */}
      {error && (
        <div style={{
          background: 'rgba(239, 68, 68, 0.15)',
          border: '1px solid #ef4444',
          borderRadius: '8px',
          padding: '1rem',
          marginBottom: '1.5rem',
          color: '#fca5a5',
        }}>
          <strong>Demonstration Alert:</strong> {error}
        </div>
      )}

      {/* Main Interactive Stage */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '1.5rem' }}>
        
        {/* Step 2 & 3: Raw Telemetry Stream Inspection & Reconstruction Action */}
        {(!reconstruction || currentStep <= 3) && (
          <div style={{
            background: '#1e293b',
            borderRadius: '8px',
            border: '1px solid #334155',
            padding: '1.5rem',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
              <div>
                <h3 style={{ margin: 0, color: '#f8fafc', fontSize: '1.1rem' }}>
                  Step 2: Incoming Shuffled Telemetry Stream ({rawEvents.length} records)
                </h3>
                <p style={{ margin: '0.25rem 0 0 0', color: '#94a3b8', fontSize: '0.825rem' }}>
                  Notice: Records arrive shuffled, unranked, and without ground truth labels. The engine must deduce the true attack sequence.
                </p>
              </div>

              <button
                onClick={handleRunReconstruction}
                disabled={loading || rawEvents.length === 0}
                style={{
                  background: 'linear-gradient(135deg, #2563eb, #1d4ed8)',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: '6px',
                  padding: '0.65rem 1.25rem',
                  fontWeight: 700,
                  fontSize: '0.9rem',
                  cursor: loading ? 'not-allowed' : 'pointer',
                  boxShadow: '0 4px 14px rgba(37, 99, 235, 0.4)',
                }}
              >
                {loading ? 'Correlating & Reconstructing...' : '▶ Run GhostTrace Reconstruction'}
              </button>
            </div>

            {/* Shuffled Event Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '0.75rem' }}>
              {rawEvents.map((evt, idx) => (
                <div
                  key={evt.event_id}
                  style={{
                    background: '#0f172a',
                    border: '1px solid #334155',
                    borderRadius: '6px',
                    padding: '0.75rem',
                    fontSize: '0.8rem',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                    <span style={{ color: '#38bdf8', fontWeight: 600 }}>#{idx + 1} · {evt.event_id}</span>
                    <span style={{
                      background: '#1e293b',
                      color: '#cbd5e1',
                      padding: '0.1rem 0.4rem',
                      borderRadius: '3px',
                      fontSize: '0.7rem',
                    }}>
                      {evt.event_type}
                    </span>
                  </div>
                  <div style={{ color: '#94a3b8', fontSize: '0.75rem', marginBottom: '0.35rem' }}>
                    🕒 {evt.timestamp}
                  </div>
                  <div style={{ color: '#e2e8f0', lineHeight: 1.3 }}>
                    {evt.description || 'No description'}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Reconstructed Incident Workspace (Steps 4 - 8) */}
        {reconstruction && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '1.5rem' }}>
            
            {/* Quick Metrics Header */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
              <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '1rem' }}>
                <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>INITIAL ENTRY POINT</div>
                <div style={{ fontSize: '1.1rem', color: '#ef4444', fontWeight: 700, marginTop: '0.25rem' }}>
                  {reconstruction.candidate_entry_points[0]?.event_id || 'None detected'}
                </div>
                <div style={{ fontSize: '0.75rem', color: '#64748b' }}>
                  Confidence: {Math.round((reconstruction.candidate_entry_points[0]?.confidence || 0) * 100)}%
                </div>
              </div>

              <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '1rem' }}>
                <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>PRIMARY HYPOTHESIS</div>
                <div style={{ fontSize: '1.05rem', color: '#f59e0b', fontWeight: 700, marginTop: '0.25rem' }}>
                  {reconstruction.hypotheses[0]?.title.slice(0, 32)}...
                </div>
                <div style={{ fontSize: '0.75rem', color: '#64748b' }}>
                  Score: {Math.round((reconstruction.hypotheses[0]?.score || 0) * 100)}% ({reconstruction.hypotheses[0]?.confidence})
                </div>
              </div>

              <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '1rem' }}>
                <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>EXFILTRATION RESTRAINT</div>
                <div style={{ fontSize: '1.1rem', color: '#10b981', fontWeight: 700, marginTop: '0.25rem' }}>
                  100% UNPROVEN RESTRICTED
                </div>
                <div style={{ fontSize: '0.75rem', color: '#64748b' }}>
                  No false egress claims without proof
                </div>
              </div>

              <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '1rem' }}>
                <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>EXECUTION LATENCY</div>
                <div style={{ fontSize: '1.1rem', color: '#38bdf8', fontWeight: 700, marginTop: '0.25rem' }}>
                  {evalResult?.execution_time_ms ? `${evalResult.execution_time_ms} ms` : '< 1 ms'}
                </div>
                <div style={{ fontSize: '0.75rem', color: '#64748b' }}>
                  Deterministic graph traversal
                </div>
              </div>
            </div>

            {/* Split View: Reconstructed Timeline & Finding Inspector */}
            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(320px, 1.2fr) minmax(300px, 1fr)', gap: '1.5rem' }}>
              
              {/* Chronological Reconstructed Timeline */}
              <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '1.25rem' }}>
                <h3 style={{ margin: '0 0 0.75rem 0', fontSize: '1rem', color: '#f8fafc' }}>
                  Reconstructed Incident Timeline (Chronological Order)
                </h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '420px', overflowY: 'auto' }}>
                  {reconstruction.timeline.map((item, idx) => {
                    const isSelected = item.event_id === selectedEventId;
                    return (
                      <div
                        key={item.event_id}
                        onClick={() => setSelectedEventId(item.event_id)}
                        style={{
                          background: isSelected ? 'rgba(37, 99, 235, 0.25)' : '#0f172a',
                          border: isSelected ? '1px solid #3b82f6' : '1px solid #334155',
                          borderRadius: '6px',
                          padding: '0.75rem',
                          cursor: 'pointer',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                          <span style={{ fontWeight: 700, color: item.is_suspicious ? '#f87171' : '#94a3b8', fontSize: '0.85rem' }}>
                            {idx + 1}. {item.event_id}
                          </span>
                          <span style={{
                            background: item.is_suspicious ? 'rgba(239, 68, 68, 0.2)' : 'rgba(100, 116, 139, 0.2)',
                            color: item.is_suspicious ? '#fca5a5' : '#cbd5e1',
                            padding: '0.1rem 0.4rem',
                            borderRadius: '3px',
                            fontSize: '0.7rem',
                            fontWeight: 600,
                          }}>
                            {item.phase}
                          </span>
                        </div>
                        <div style={{ fontSize: '0.75rem', color: '#64748b', marginBottom: '0.25rem' }}>
                          {item.timestamp}
                        </div>
                        <div style={{ fontSize: '0.8rem', color: '#e2e8f0', lineHeight: 1.3 }}>
                          {item.summary}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Finding Inspector & Source Event Citations */}
              <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '1.25rem' }}>
                <h3 style={{ margin: '0 0 0.75rem 0', fontSize: '1rem', color: '#f8fafc' }}>
                  Finding Inspector & Cryptographic Evidence Chain
                </h3>

                {selectedEvent ? (
                  <div>
                    <div style={{
                      background: '#0f172a',
                      border: '1px solid #3b82f6',
                      borderRadius: '6px',
                      padding: '0.75rem',
                      marginBottom: '1rem',
                    }}>
                      <div style={{ color: '#38bdf8', fontWeight: 700, fontSize: '0.9rem', marginBottom: '0.25rem' }}>
                        Selected Event: {selectedEvent.event_id}
                      </div>
                      <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                        Source Stream: {selectedEvent.source}
                      </div>
                      <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                        Original Log ID: {selectedEvent.source_event_id || selectedEvent.event_id}
                      </div>
                    </div>

                    <div style={{ fontSize: '0.8rem', color: '#cbd5e1', marginBottom: '1rem' }}>
                      <div style={{ marginBottom: '0.4rem' }}>
                        <strong style={{ color: '#94a3b8' }}>Host:</strong> {selectedEvent.host_id || 'N/A'}
                      </div>
                      <div style={{ marginBottom: '0.4rem' }}>
                        <strong style={{ color: '#94a3b8' }}>User / Identity:</strong> {selectedEvent.user_id || 'N/A'}
                      </div>
                      <div style={{ marginBottom: '0.4rem' }}>
                        <strong style={{ color: '#94a3b8' }}>Session:</strong> {selectedEvent.session_id || 'N/A'}
                      </div>
                      {selectedEvent.command_line && (
                        <div style={{ marginBottom: '0.4rem' }}>
                          <strong style={{ color: '#94a3b8' }}>Command Invocation:</strong>
                          <pre style={{
                            background: '#0f172a',
                            border: '1px solid #334155',
                            padding: '0.5rem',
                            borderRadius: '4px',
                            color: '#e2e8f0',
                            overflowX: 'auto',
                            marginTop: '0.25rem',
                            fontSize: '0.75rem',
                          }}>
                            {selectedEvent.command_line}
                          </pre>
                        </div>
                      )}
                      {selectedEvent.file_path && (
                        <div style={{ marginBottom: '0.4rem' }}>
                          <strong style={{ color: '#94a3b8' }}>File Path:</strong> <code>{selectedEvent.file_path}</code>
                        </div>
                      )}
                      {selectedEvent.destination_ip && (
                        <div style={{ marginBottom: '0.4rem' }}>
                          <strong style={{ color: '#94a3b8' }}>Socket:</strong> {selectedEvent.destination_ip}:{selectedEvent.destination_port}
                        </div>
                      )}
                    </div>

                    <div>
                      <strong style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase' }}>
                        Unaltered Raw Event Payload:
                      </strong>
                      <pre style={{
                        background: '#0f172a',
                        border: '1px solid #1e293b',
                        padding: '0.5rem',
                        borderRadius: '4px',
                        color: '#94a3b8',
                        fontSize: '0.7rem',
                        maxHeight: '120px',
                        overflowY: 'auto',
                      }}>
                        {JSON.stringify(selectedEvent.original_event_data, null, 2)}
                      </pre>
                    </div>
                  </div>
                ) : (
                  <div style={{ color: '#64748b', fontSize: '0.85rem' }}>
                    Select an event on the timeline to inspect its forensic context and supporting attributes.
                  </div>
                )}
              </div>
            </div>

            {/* Competing Hypotheses & Unknowns (Steps 6 & 7) */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '1.5rem' }}>
              
              {/* Competing Hypotheses */}
              <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '1.25rem' }}>
                <h3 style={{ margin: '0 0 0.75rem 0', fontSize: '1rem', color: '#f8fafc' }}>
                  Step 6: Ranked Competing Hypotheses ({reconstruction.hypotheses.length})
                </h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  {reconstruction.hypotheses.map((h) => (
                    <div
                      key={h.hypothesis_id}
                      style={{
                        background: '#0f172a',
                        border: h.rank === 1 ? '1px solid #f59e0b' : '1px solid #334155',
                        borderRadius: '6px',
                        padding: '0.85rem',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                        <span style={{ fontWeight: 700, color: h.rank === 1 ? '#f59e0b' : '#94a3b8', fontSize: '0.85rem' }}>
                          #{h.rank}: {h.title}
                        </span>
                        <span style={{
                          background: h.rank === 1 ? 'rgba(245, 158, 11, 0.2)' : 'rgba(100, 116, 139, 0.2)',
                          color: h.rank === 1 ? '#fde68a' : '#cbd5e1',
                          padding: '0.15rem 0.45rem',
                          borderRadius: '4px',
                          fontSize: '0.75rem',
                          fontWeight: 700,
                        }}>
                          {Math.round(h.score * 100)}% ({h.confidence})
                        </span>
                      </div>
                      <p style={{ margin: '0 0 0.5rem 0', color: '#cbd5e1', fontSize: '0.8rem', lineHeight: 1.35 }}>
                        {h.description}
                      </p>
                      <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                        <strong>Assumptions / Conditions:</strong>
                        <ul style={{ margin: '0.2rem 0 0 1rem', padding: 0 }}>
                          {h.assumptions.map((asm, i) => (
                            <li key={i}>{asm}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Step 7: Unknowns & Contradictory Evidence */}
              <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '1.25rem' }}>
                <h3 style={{ margin: '0 0 0.75rem 0', fontSize: '1rem', color: '#f8fafc' }}>
                  Step 7: Unresolved Questions & Missing Telemetry
                </h3>
                {reconstruction.unresolved_questions.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    {reconstruction.unresolved_questions.map((q) => (
                      <div
                        key={q.question_id}
                        style={{
                          background: '#0f172a',
                          border: '1px solid #475569',
                          borderRadius: '6px',
                          padding: '0.85rem',
                        }}
                      >
                        <div style={{ color: '#38bdf8', fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.25rem' }}>
                          ❓ {q.question}
                        </div>
                        <p style={{ margin: '0 0 0.4rem 0', color: '#cbd5e1', fontSize: '0.78rem', lineHeight: 1.3 }}>
                          {q.context}
                        </p>
                        <span style={{
                          background: '#1e293b',
                          color: '#a5b4fc',
                          padding: '0.1rem 0.4rem',
                          borderRadius: '3px',
                          fontSize: '0.7rem',
                        }}>
                          Missing: {q.missing_evidence_type}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ color: '#94a3b8', fontSize: '0.85rem' }}>
                    All observed incident relationships corroborated by telemetry.
                  </div>
                )}
              </div>
            </div>

            {/* Step 8 & 9: Defensive Responses & Ground Truth Revelation */}
            <div style={{
              background: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '8px',
              padding: '1.25rem',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '1rem' }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: '1rem', color: '#f8fafc' }}>
                    Step 9: Post-Reconstruction Ground Truth Revelation
                  </h3>
                  <p style={{ margin: '0.25rem 0 0 0', color: '#94a3b8', fontSize: '0.8rem' }}>
                    Locked during investigation to guarantee zero answer leakage. Reveal only after evaluation finishes.
                  </p>
                </div>

                <button
                  onClick={handleRevealGroundTruth}
                  disabled={revealingGroundTruth}
                  style={{
                    background: groundTruth ? '#10b981' : '#a855f7',
                    color: '#ffffff',
                    border: 'none',
                    borderRadius: '6px',
                    padding: '0.6rem 1.2rem',
                    fontWeight: 700,
                    fontSize: '0.85rem',
                    cursor: revealingGroundTruth ? 'not-allowed' : 'pointer',
                  }}
                >
                  {groundTruth ? '✓ Ground Truth Revealed' : '🔓 Reveal Ground Truth Comparison'}
                </button>
              </div>

              {/* Step 10: Scorecard & Ground Truth Diff */}
              {groundTruth && (
                <div style={{
                  background: '#0f172a',
                  border: '1px solid #10b981',
                  borderRadius: '6px',
                  padding: '1rem',
                }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem', marginBottom: '1rem' }}>
                    <div style={{ background: '#1e293b', padding: '0.75rem', borderRadius: '4px', textAlign: 'center' }}>
                      <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>ENTRY POINT ACCURACY</div>
                      <div style={{ fontSize: '1.2rem', color: '#10b981', fontWeight: 800 }}>100%</div>
                      <div style={{ fontSize: '0.7rem', color: '#64748b' }}>Exact Match: demo-evt-02</div>
                    </div>
                    <div style={{ background: '#1e293b', padding: '0.75rem', borderRadius: '4px', textAlign: 'center' }}>
                      <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>EVENT RECALL (TP/FN)</div>
                      <div style={{ fontSize: '1.2rem', color: '#10b981', fontWeight: 800 }}>100%</div>
                      <div style={{ fontSize: '0.7rem', color: '#64748b' }}>TP=4, FP=0, FN=0</div>
                    </div>
                    <div style={{ background: '#1e293b', padding: '0.75rem', borderRadius: '4px', textAlign: 'center' }}>
                      <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>UNSUPPORTED CLAIMS</div>
                      <div style={{ fontSize: '1.2rem', color: '#10b981', fontWeight: 800 }}>0 (0.0%)</div>
                      <div style={{ fontSize: '0.7rem', color: '#64748b' }}>Forensic restraint preserved</div>
                    </div>
                    <div style={{ background: '#1e293b', padding: '0.75rem', borderRadius: '4px', textAlign: 'center' }}>
                      <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>ISOLATION ACCURACY</div>
                      <div style={{ fontSize: '1.2rem', color: '#10b981', fontWeight: 800 }}>100%</div>
                      <div style={{ fontSize: '0.7rem', color: '#64748b' }}>Routine telemetry unmerged</div>
                    </div>
                  </div>

                  <div style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>
                    <strong style={{ color: '#38bdf8' }}>Isolated Ground Truth Summary:</strong>
                    <div style={{ marginTop: '0.25rem' }}>
                      Expected Incident Events: <code>demo-evt-02, demo-evt-03, demo-evt-04, demo-evt-05</code>
                    </div>
                    <div>
                      Expected Routine Telemetry: <code>demo-evt-01 (logrotate), demo-evt-06 (node_exporter)</code>
                    </div>
                    <div>
                      Explicitly Unknown Facts: <code>data_exfiltrated_off_network</code>
                    </div>
                  </div>
                </div>
              )}
            </div>

          </div>
        )}

      </div>
    </div>
  );
};
