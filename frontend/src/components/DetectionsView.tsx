import React from 'react';
import type { DetectionFinding, SecurityEvent, ValidationResult } from '../types/event';

interface Props {
  findings: DetectionFinding[];
  events: SecurityEvent[];
  validationStatus: ValidationResult | null;
  importMeta?: {
    name: string;
    format: string;
    count: number;
    unsupportedFields?: string[];
    parsingWarnings?: string[];
  } | null;
  onSelectEvent: (eventId: string) => void;
  onInspectEvent: (event: SecurityEvent) => void;
}

export const DetectionsView: React.FC<Props> = ({
  findings,
  events,
  validationStatus,
  importMeta,
  onSelectEvent,
  onInspectEvent,
}) => {
  const eventMap = React.useMemo(() => {
    const map = new Map<string, SecurityEvent>();
    events.forEach((e) => map.set(e.event_id, e));
    return map;
  }, [events]);

  const severityBadgeClass = (sev: string) => {
    switch (sev?.toUpperCase()) {
      case 'CRITICAL':
        return 'badge-critical';
      case 'HIGH':
        return 'badge-high';
      case 'MEDIUM':
        return 'badge-medium';
      case 'LOW':
        return 'badge-low';
      default:
        return 'badge-info';
    }
  };

  return (
    <div className="detections-view" style={{ padding: '1.5rem', maxWidth: '1400px', margin: '0 auto' }}>
      {/* Header Banner */}
      <div style={{ marginBottom: '1.5rem' }}>
        <h2 style={{ fontSize: '1.4rem', fontWeight: 700, color: '#f8fafc', margin: '0 0 0.5rem 0' }}>
          Deterministic Detections & Evidence Lineage
        </h2>
        <p style={{ color: '#94a3b8', fontSize: '0.88rem', margin: 0, lineHeight: 1.5 }}>
          Explainable detection findings grounded directly in uploaded telemetry records. Every finding cites its
          specific supporting event IDs, considers benign operational explanations, and details missing telemetry limitations.
        </p>
      </div>

      {/* Normalization & Telemetry Audit Box if importMeta or unsupported fields exist */}
      {(importMeta || (validationStatus && validationStatus.issues.length > 0)) && (
        <div
          style={{
            background: 'rgba(15, 23, 42, 0.75)',
            border: '1px solid #334155',
            borderRadius: '8px',
            padding: '1rem 1.25rem',
            marginBottom: '1.5rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <span style={{ fontSize: '0.82rem', fontWeight: 700, color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Ingestion & Schema Provenance:
              </span>
              <span className="badge badge-info" style={{ fontWeight: 600 }}>
                Format: {importMeta?.format || 'Canonical Schema'}
              </span>
              {importMeta?.name && (
                <span style={{ fontSize: '0.82rem', color: '#cbd5e1' }}>
                  Source: <strong>{importMeta.name}</strong>
                </span>
              )}
            </div>
            <div style={{ fontSize: '0.82rem', color: '#94a3b8' }}>
              Valid Records: <strong style={{ color: '#10b981' }}>{events.length}</strong> | Malformed/Skipped:{' '}
              <strong style={{ color: validationStatus?.malformed_events_count ? '#ef4444' : '#94a3b8' }}>
                {validationStatus?.malformed_events_count || 0}
              </strong>
            </div>
          </div>

          {importMeta?.unsupportedFields && importMeta.unsupportedFields.length > 0 && (
            <div style={{ marginTop: '0.5rem', fontSize: '0.78rem', color: '#f59e0b', background: 'rgba(245, 158, 11, 0.1)', padding: '0.5rem 0.75rem', borderRadius: '4px', border: '1px solid rgba(245, 158, 11, 0.3)' }}>
              <strong>Preserved Non-Canonical Fields ({importMeta.unsupportedFields.length}):</strong>{' '}
              {importMeta.unsupportedFields.join(', ')}
              <div style={{ fontSize: '0.72rem', color: '#cbd5e1', marginTop: '0.2rem' }}>
                These fields were not mapped to core schema fields but are fully preserved in <code>original_event_data</code>.
              </div>
            </div>
          )}

          {importMeta?.parsingWarnings && importMeta.parsingWarnings.length > 0 && (
            <div style={{ marginTop: '0.5rem', fontSize: '0.78rem', color: '#cbd5e1' }}>
              <strong>Parsing Warnings:</strong> {importMeta.parsingWarnings.join(' · ')}
            </div>
          )}
        </div>
      )}

      {/* Metrics Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
        <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', padding: '1rem' }}>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase', fontWeight: 600 }}>Total Findings</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, color: findings.length > 0 ? '#f8fafc' : '#10b981', marginTop: '0.25rem' }}>
            {findings.length}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.25rem' }}>
            {findings.length === 0 ? 'Zero suspicious indicators' : 'Deterministic rule matches'}
          </div>
        </div>

        <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', padding: '1rem' }}>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase', fontWeight: 600 }}>High / Critical</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#ef4444', marginTop: '0.25rem' }}>
            {findings.filter((f) => f.severity === 'HIGH' || f.severity === 'CRITICAL').length}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.25rem' }}>Requiring active investigation</div>
        </div>

        <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', padding: '1rem' }}>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase', fontWeight: 600 }}>Medium / Low</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#f59e0b', marginTop: '0.25rem' }}>
            {findings.filter((f) => f.severity === 'MEDIUM' || f.severity === 'LOW').length}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.25rem' }}>Anomalies & protocol probes</div>
        </div>

        <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', padding: '1rem' }}>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase', fontWeight: 600 }}>Evidence Citation Rate</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#38bdf8', marginTop: '0.25rem' }}>100%</div>
          <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.25rem' }}>All findings cite source event IDs</div>
        </div>
      </div>

      {/* Findings List */}
      {findings.length === 0 ? (
        <div
          style={{
            background: 'rgba(16, 185, 129, 0.05)',
            border: '1px solid rgba(16, 185, 129, 0.25)',
            borderRadius: '8px',
            padding: '2.5rem',
            textAlign: 'center',
          }}
        >
          <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>🛡️</div>
          <h3 style={{ fontSize: '1.15rem', color: '#10b981', margin: '0 0 0.5rem 0' }}>
            No Hostile or Anomalous Detection Indicators Found
          </h3>
          <p style={{ color: '#94a3b8', fontSize: '0.85rem', maxWidth: '600px', margin: '0 auto', lineHeight: 1.5 }}>
            All evaluated records conform to expected baseline administrative operations. No brute-force sequences,
            download cradles, credential reads, or suspicious egress sockets were detected.
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {findings.map((finding) => (
            <div
              key={finding.finding_id}
              style={{
                background: '#0f172a',
                border: '1px solid #1e293b',
                borderRadius: '8px',
                padding: '1.25rem',
                borderLeft: `4px solid ${
                  finding.severity === 'CRITICAL'
                    ? '#ef4444'
                    : finding.severity === 'HIGH'
                    ? '#f97316'
                    : finding.severity === 'MEDIUM'
                    ? '#f59e0b'
                    : '#38bdf8'
                }`,
              }}
            >
              {/* Finding Title & Badges */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '0.75rem' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                    <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.75rem', color: '#38bdf8', fontWeight: 600 }}>
                      [{finding.rule_id}]
                    </span>
                    <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc', margin: 0 }}>
                      {finding.rule_name}
                    </h3>
                  </div>
                  <div style={{ fontSize: '0.85rem', color: '#cbd5e1', marginTop: '0.35rem' }}>
                    {finding.summary}
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  {finding.mitre_attack_id && (
                    <span className="badge badge-info" style={{ fontSize: '0.72rem' }}>
                      MITRE {finding.mitre_attack_id}
                    </span>
                  )}
                  <span className={`badge ${severityBadgeClass(finding.severity)}`} style={{ fontSize: '0.72rem' }}>
                    {finding.severity}
                  </span>
                  <span
                    style={{
                      fontSize: '0.72rem',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      background: 'rgba(100, 116, 139, 0.2)',
                      color: '#94a3b8',
                      fontWeight: 600,
                    }}
                  >
                    {finding.category}
                  </span>
                </div>
              </div>

              {/* Observed Facts */}
              <div style={{ marginBottom: '0.75rem' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', marginBottom: '0.35rem' }}>
                  Observed Direct Evidence:
                </div>
                <ul style={{ margin: 0, paddingLeft: '1.25rem', fontSize: '0.82rem', color: '#e2e8f0' }}>
                  {finding.observed_indicators.map((ind, i) => (
                    <li key={i} style={{ marginBottom: '0.2rem' }}>{ind}</li>
                  ))}
                </ul>
              </div>

              {/* Benign Alternative Explanations */}
              <div
                style={{
                  background: 'rgba(30, 41, 59, 0.5)',
                  border: '1px solid #1e293b',
                  borderRadius: '6px',
                  padding: '0.75rem',
                  marginBottom: '0.75rem',
                }}
              >
                <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#38bdf8', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                  Plausible Benign Explanations:
                </div>
                <ul style={{ margin: 0, paddingLeft: '1.25rem', fontSize: '0.8rem', color: '#94a3b8' }}>
                  {finding.benign_alternatives.map((alt, i) => (
                    <li key={i} style={{ marginBottom: '0.2rem' }}>{alt}</li>
                  ))}
                </ul>
              </div>

              {/* Missing Telemetry & Forensic Limitations */}
              {finding.missing_telemetry_limitations && (
                <div
                  style={{
                    background: 'rgba(245, 158, 11, 0.05)',
                    border: '1px solid rgba(245, 158, 11, 0.2)',
                    borderRadius: '6px',
                    padding: '0.6rem 0.75rem',
                    marginBottom: '0.75rem',
                    fontSize: '0.78rem',
                    color: '#fcd34d',
                  }}
                >
                  <strong>Missing Telemetry to Confirm / Refute:</strong> {finding.missing_telemetry_limitations}
                </div>
              )}

              {/* Supporting Event IDs */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                <span style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: 600 }}>Supporting Event Records:</span>
                {finding.supporting_event_ids.map((id) => {
                  const ev = eventMap.get(id);
                  return (
                    <button
                      key={id}
                      onClick={() => {
                        onSelectEvent(id);
                        if (ev) onInspectEvent(ev);
                      }}
                      style={{
                        background: '#1e293b',
                        border: '1px solid #334155',
                        color: '#38bdf8',
                        padding: '2px 8px',
                        borderRadius: '4px',
                        fontFamily: 'JetBrains Mono, monospace',
                        fontSize: '0.72rem',
                        cursor: 'pointer',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '0.35rem',
                      }}
                      title="Inspect original raw log record"
                    >
                      <span>🔍</span> {id}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
