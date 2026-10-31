import React, { useRef, useEffect } from 'react';
import type { SecurityEvent } from '../types/event';

interface Props {
  events: SecurityEvent[];
  selectedEventId: string | null;
  onSelectEvent: (eventId: string) => void;
  filterType: string;
  onFilterTypeChange: (type: string) => void;
  filterSeverity: string;
  onFilterSeverityChange: (severity: string) => void;
  showSuspiciousOnly: boolean;
  onToggleSuspiciousOnly: (val: boolean) => void;
  searchQuery: string;
  onSearchQueryChange: (q: string) => void;
}

export const SynchronizedTimeline: React.FC<Props> = ({
  events,
  selectedEventId,
  onSelectEvent,
  filterType,
  onFilterTypeChange,
  filterSeverity,
  onFilterSeverityChange,
  showSuspiciousOnly,
  onToggleSuspiciousOnly,
  searchQuery,
  onSearchQueryChange,
}) => {
  const activeItemRef = useRef<HTMLDivElement | null>(null);

  // Auto-scroll selected event into view when selected from graph
  useEffect(() => {
    if (activeItemRef.current) {
      activeItemRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }, [selectedEventId]);

  // Sort chronologically strictly while preserving original timestamps
  const sorted = [...events].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  // Filter events
  const filtered = sorted.filter((evt) => {
    if (showSuspiciousOnly && !evt.is_suspicious) return false;
    if (filterType !== 'ALL' && evt.event_type !== filterType) return false;
    if (filterSeverity !== 'ALL' && evt.severity !== filterSeverity) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchText = [
        evt.event_id,
        evt.user_id,
        evt.host_id,
        evt.source_ip,
        evt.destination_ip,
        evt.description,
        evt.command_line,
        evt.file_path,
      ].filter(Boolean).join(' ').toLowerCase();
      if (!matchText.includes(q)) return false;
    }
    return true;
  });

  return (
    <div className="synchronized-timeline-container" aria-label="Incident Investigation Timeline">
      {/* Timeline Controls / Filter Bar */}
      <div className="timeline-filter-bar">
        <div className="timeline-header-meta">
          <span className="timeline-title-icon">⏱️</span>
          <span className="timeline-title-text">Investigation Timeline</span>
          <span className="timeline-counter">
            Showing {filtered.length} of {events.length} events
          </span>
        </div>

        <div className="timeline-controls">
          <label className="timeline-toggle">
            <input
              type="checkbox"
              checked={showSuspiciousOnly}
              onChange={(e) => onToggleSuspiciousOnly(e.target.checked)}
            />
            <span>Threat Signals Only</span>
          </label>

          <select
            className="select-compact"
            value={filterType}
            onChange={(e) => onFilterTypeChange(e.target.value)}
          >
            <option value="ALL">All Categories</option>
            <option value="AUTHENTICATION">Authentication</option>
            <option value="PROCESS_EXECUTION">Process</option>
            <option value="FILE_AUDIT">File Audit</option>
            <option value="NETWORK_CONNECTION">Network</option>
          </select>

          <select
            className="select-compact"
            value={filterSeverity}
            onChange={(e) => onFilterSeverityChange(e.target.value)}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFORMATIONAL">Informational</option>
          </select>

          <input
            type="text"
            className="input-compact"
            placeholder="Search timeline..."
            value={searchQuery}
            onChange={(e) => onSearchQueryChange(e.target.value)}
          />
        </div>
      </div>

      {/* Horizontal / Vertical Timeline Stream */}
      <div className="timeline-stream">
        {filtered.length === 0 ? (
          <div className="timeline-empty-notice">
            No events match the active timeline filters.
          </div>
        ) : (
          filtered.map((evt, idx) => {
            const isSelected = selectedEventId === evt.event_id;
            return (
              <div
                key={evt.event_id}
                ref={isSelected ? activeItemRef : null}
                className={`timeline-card ${isSelected ? 'active-selected' : ''} ${evt.is_suspicious ? 'is-threat' : 'is-routine'}`}
                onClick={() => onSelectEvent(evt.event_id)}
                title="Click to locate and focus node in graph"
              >
                <div className="card-top-row">
                  <span className="card-index">#{idx + 1}</span>
                  <span className="card-timestamp">
                    {new Date(evt.timestamp).toISOString().substring(11, 19)} UTC
                  </span>
                  <span className={`badge badge-${evt.severity.toLowerCase()}`}>
                    {evt.severity}
                  </span>
                </div>

                <div className="card-main-title">
                  <span className={`category-tag cat-${evt.event_type.toLowerCase()}`}>
                    {evt.event_type.replace('_', ' ')}
                  </span>
                  {evt.is_suspicious ? (
                    <span className="tag-threat">THREAT</span>
                  ) : (
                    <span className="tag-routine">ROUTINE</span>
                  )}
                </div>

                <div className="card-summary">
                  {evt.description || `${evt.action || evt.event_type} on ${evt.host_id || 'system'}`}
                </div>

                <div className="card-entities">
                  {evt.user_id && <span>User: <strong>{evt.user_id}</strong></span>}
                  {evt.host_id && <span>Host: <strong>{evt.host_id}</strong></span>}
                  {evt.source_ip && <span>Src IP: <strong>{evt.source_ip}</strong></span>}
                  {evt.destination_ip && <span>Dst IP: <strong>{evt.destination_ip}</strong></span>}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
