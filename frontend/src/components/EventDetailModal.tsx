import React, { useState } from 'react';
import type { SecurityEvent } from '../types/event';

interface Props {
  event: SecurityEvent | null;
  onClose: () => void;
}

export const EventDetailModal: React.FC<Props> = ({ event, onClose }) => {
  const [copied, setCopied] = useState(false);

  if (!event) return null;

  const copyRawJson = () => {
    navigator.clipboard.writeText(JSON.stringify(event.original_event_data, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-area">
            <span className={`badge badge-${event.severity.toLowerCase()}`}>
              {event.severity}
            </span>
            <h3>{event.event_id}</h3>
            {event.is_suspicious && (
              <span className="badge badge-alert">SUSPICIOUS ACTIVITY</span>
            )}
            {event.mitre_attack_id && (
              <span className="badge badge-mitre">{event.mitre_attack_id}</span>
            )}
          </div>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>

        <div className="modal-body">
          {event.description && (
            <div className="event-description-callout">
              <strong>Forensic Analyst Summary:</strong> {event.description}
            </div>
          )}

          <div className="detail-grid">
            <div className="detail-item">
              <span className="detail-label">Event Category:</span>
              <span className="detail-value">{event.event_type}</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Timestamp (UTC):</span>
              <span className="detail-value">{new Date(event.timestamp).toUTCString()}</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Telemetry Source:</span>
              <span className="detail-value"><code>{event.source}</code></span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Source Event ID:</span>
              <span className="detail-value"><code>{event.source_event_id || 'N/A'}</code></span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Target Host:</span>
              <span className="detail-value">{event.host_id || '—'}</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">User Principal:</span>
              <span className="detail-value">{event.user_id || '—'}</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Source IP:</span>
              <span className="detail-value">{event.source_ip || '—'}</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Destination IP:</span>
              <span className="detail-value">{event.destination_ip ? `${event.destination_ip}:${event.destination_port || ''}` : '—'}</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Process ID / Name:</span>
              <span className="detail-value">
                {event.process_name || event.process_id ? `${event.process_name || ''} (PID: ${event.process_id || 'N/A'})` : '—'}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-label">File Path:</span>
              <span className="detail-value">{event.file_path || '—'}</span>
            </div>
            {event.command_line && (
              <div className="detail-item full-width">
                <span className="detail-label">Command Line:</span>
                <pre className="command-box">{event.command_line}</pre>
              </div>
            )}
          </div>

          <div className="raw-evidence-section">
            <div className="evidence-header">
              <h4>Chain of Custody: Raw Source Telemetry (`original_event_data`)</h4>
              <button className="btn-copy" onClick={copyRawJson}>
                {copied ? '✓ Copied' : 'Copy Raw Record'}
              </button>
            </div>
            <p className="evidence-note">
              This payload is preserved verbatim from the originating log stream to ensure forensic provenance and non-repudiation.
            </p>
            <pre className="json-viewer">
              {JSON.stringify(event.original_event_data, null, 2)}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
