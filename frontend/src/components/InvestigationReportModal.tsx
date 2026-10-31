import React, { useState } from 'react';
import type { SecurityEvent, InvestigationReconstructionResult } from '../types/event';
import { generateMarkdownReport, generateJsonReport, downloadFile } from '../utils/exportReport';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  reconstruction: InvestigationReconstructionResult | null;
  events: SecurityEvent[];
  scenarioName: string;
  scenarioId: string;
}

export const InvestigationReportModal: React.FC<Props> = ({
  isOpen,
  onClose,
  reconstruction,
  events,
  scenarioName,
  scenarioId,
}) => {
  const [copied, setCopied] = useState(false);

  if (!isOpen || !reconstruction) return null;

  const reportInput = {
    scenarioName,
    scenarioId,
    reconstruction,
    events,
  };

  const markdownContent = generateMarkdownReport(reportInput);

  const handleDownloadMarkdown = () => {
    const filename = `ghosttrace_report_${scenarioId}_${reconstruction.investigation_id}.md`;
    downloadFile(markdownContent, filename, 'text/markdown;charset=utf-8;');
  };

  const handleDownloadJson = () => {
    const jsonContent = generateJsonReport(reportInput);
    const filename = `ghosttrace_evidence_${scenarioId}_${reconstruction.investigation_id}.json`;
    downloadFile(jsonContent, filename, 'application/json;charset=utf-8;');
  };

  const handleCopyClipboard = async () => {
    try {
      await navigator.clipboard.writeText(markdownContent);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.warn('Failed to copy to clipboard:', err);
    }
  };

  return (
    <div className="report-modal-backdrop" onClick={onClose}>
      <div className="report-modal-container" onClick={(e) => e.stopPropagation()}>
        <div className="report-modal-header">
          <div className="modal-title-group">
            <span className="modal-eyebrow">DIGITAL FORENSICS & INCIDENT RESPONSE</span>
            <h3 className="modal-title">Export Investigation Report</h3>
            <span className="modal-sub">
              Investigation: <code>{reconstruction.investigation_id}</code> · Target: {scenarioName}
            </span>
          </div>

          <div className="modal-header-actions">
            <button className="btn-modal-action" onClick={handleCopyClipboard}>
              {copied ? '✓ Copied to Clipboard!' : '📋 Copy Markdown'}
            </button>
            <button className="btn-modal-action primary" onClick={handleDownloadMarkdown}>
              ⬇ Download Report (.md)
            </button>
            <button className="btn-modal-action secondary" onClick={handleDownloadJson}>
              ⬇ Download Evidence (.json)
            </button>
            <button className="btn-modal-close" onClick={onClose} title="Close report modal">
              ✕
            </button>
          </div>
        </div>

        <div className="report-modal-body">
          <div className="report-preview-banner">
            Previewing live forensic investigation report synthesized from currently loaded telemetry:
          </div>
          <pre className="report-markdown-preview">
            <code>{markdownContent}</code>
          </pre>
        </div>
      </div>
    </div>
  );
};
