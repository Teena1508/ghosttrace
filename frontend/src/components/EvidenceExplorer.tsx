import React, { useState, useMemo } from 'react';
import type { SecurityEvent, InvestigationReconstructionResult } from '../types/event';

interface Props {
  events: SecurityEvent[];
  reconstruction: InvestigationReconstructionResult | null;
  onSelectEventId: (eventId: string) => void;
  onInspectRawEvent: (event: SecurityEvent) => void;
}

export const EvidenceExplorer: React.FC<Props> = ({
  events,
  reconstruction,
  onSelectEventId,
  onInspectRawEvent,
}) => {
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedType, setSelectedType] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [threatFilter, setThreatFilter] = useState<'ALL' | 'THREAT' | 'ROUTINE'>('ALL');
  const [sortOrder, setSortOrder] = useState<'ASC' | 'DESC'>('ASC');

  // Build a reverse index of which conclusions / hypotheses reference each event ID
  const eventConclusionsMap = useMemo(() => {
    const map: Record<string, { hypotheses: string[]; conclusions: string[]; entryPoint: boolean; facts: string[] }> = {};

    events.forEach((e) => {
      map[e.event_id] = { hypotheses: [], conclusions: [], entryPoint: false, facts: [] };
    });

    if (reconstruction) {
      // Check entry points
      reconstruction.candidate_entry_points.forEach((ep) => {
        ep.supporting_event_ids.forEach((id) => {
          if (map[id]) map[id].entryPoint = true;
        });
      });

      // Check hypotheses
      reconstruction.hypotheses.forEach((hypo) => {
        hypo.supporting_event_ids.forEach((id) => {
          if (map[id]) map[id].hypotheses.push(`Hypo #${hypo.rank}`);
        });
      });

      // Check conclusions
      reconstruction.inferred_conclusions.forEach((conc) => {
        conc.supporting_event_ids.forEach((id) => {
          if (map[id]) map[id].conclusions.push(conc.conclusion_id);
        });
      });

      // Check facts
      reconstruction.observed_facts.forEach((fact) => {
        fact.supporting_event_ids.forEach((id) => {
          if (map[id]) map[id].facts.push(fact.fact_id);
        });
      });
    }

    return map;
  }, [events, reconstruction]);

  // Filter and sort events
  const filteredEvents = useMemo(() => {
    let result = [...events];

    // Threat status
    if (threatFilter === 'THREAT') {
      result = result.filter((e) => e.is_suspicious);
    } else if (threatFilter === 'ROUTINE') {
      result = result.filter((e) => !e.is_suspicious);
    }

    // Type filter
    if (selectedType !== 'ALL') {
      result = result.filter((e) => e.event_type === selectedType);
    }

    // Severity filter
    if (selectedSeverity !== 'ALL') {
      result = result.filter((e) => e.severity === selectedSeverity);
    }

    // Search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter((e) => {
        const hay = [
          e.event_id,
          e.user_id,
          e.host_id,
          e.source_ip,
          e.destination_ip,
          e.process_name,
          e.command_line,
          e.file_path,
          e.description,
          e.source,
          e.mitre_attack_id,
        ]
          .filter(Boolean)
          .join(' ')
          .toLowerCase();
        return hay.includes(q);
      });
    }

    // Sort order
    result.sort((a, b) => {
      const timeA = new Date(a.timestamp).getTime();
      const timeB = new Date(b.timestamp).getTime();
      return sortOrder === 'ASC' ? timeA - timeB : timeB - timeA;
    });

    return result;
  }, [events, threatFilter, selectedType, selectedSeverity, searchQuery, sortOrder]);

  return (
    <div className="evidence-explorer-wrapper">
      {/* Explorer Controls */}
      <div className="explorer-toolbar">
        <div className="search-box-wrap">
          <input
            type="text"
            className="explorer-search-input"
            placeholder="Search by ID, User, Host, IP, Process, File, or MITRE technique..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
          {searchQuery && (
            <button className="btn-clear-search" onClick={() => setSearchQuery('')}>
              ✕
            </button>
          )}
        </div>

        <div className="explorer-filters">
          <select
            className="select-explorer"
            value={threatFilter}
            onChange={(e) => setThreatFilter(e.target.value as any)}
          >
            <option value="ALL">All Records ({events.length})</option>
            <option value="THREAT">Threat Evidence Only</option>
            <option value="ROUTINE">Routine Baseline Only</option>
          </select>

          <select
            className="select-explorer"
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
          >
            <option value="ALL">All Event Types</option>
            <option value="AUTHENTICATION">Authentication</option>
            <option value="PROCESS_EXECUTION">Process Execution</option>
            <option value="FILE_AUDIT">File Audit</option>
            <option value="NETWORK_CONNECTION">Network Connection</option>
          </select>

          <select
            className="select-explorer"
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFORMATIONAL">Informational</option>
          </select>

          <button
            className="btn-sort-toggle"
            onClick={() => setSortOrder(sortOrder === 'ASC' ? 'DESC' : 'ASC')}
            title="Toggle sort order"
          >
            Sort: {sortOrder === 'ASC' ? 'Oldest First ↑' : 'Newest First ↓'}
          </button>
        </div>
      </div>

      {/* Results Count Banner */}
      <div className="results-count-banner">
        <span>Showing <strong>{filteredEvents.length}</strong> of {events.length} telemetry records</span>
        <span className="results-provenance-note">
          Evidence provenance preserved · Direct link to Graph and Timeline
        </span>
      </div>

      {/* Evidence Cards List */}
      <div className="evidence-cards-list">
        {filteredEvents.length === 0 ? (
          <div className="empty-results-box">
            <p>No telemetry records matched the current filter criteria.</p>
          </div>
        ) : (
          filteredEvents.map((evt) => {
            const references = eventConclusionsMap[evt.event_id] || { hypotheses: [], conclusions: [], entryPoint: false, facts: [] };
            const hasReferences =
              references.entryPoint ||
              references.hypotheses.length > 0 ||
              references.conclusions.length > 0;

            return (
              <div
                key={evt.event_id}
                className={`evidence-record-card ${evt.is_suspicious ? 'is-suspicious' : 'is-routine'}`}
              >
                <div className="record-header">
                  <div className="record-identifiers">
                    <span className="event-id-badge">{evt.event_id}</span>
                    <span className="event-type-pill">{evt.event_type}</span>
                    <span className={`badge badge-${evt.severity.toLowerCase()}`}>
                      {evt.severity}
                    </span>
                    {evt.is_suspicious ? (
                      <span className="status-threat-tag">THREAT SIGNAL</span>
                    ) : (
                      <span className="status-routine-tag">ROUTINE BASELINE</span>
                    )}
                    {evt.mitre_attack_id && (
                      <span className="badge badge-mitre">{evt.mitre_attack_id}</span>
                    )}
                  </div>

                  <div className="record-timestamp">
                    <code>{new Date(evt.timestamp).toISOString().replace('T', ' ').replace('.000Z', '')} UTC</code>
                  </div>
                </div>

                <div className="record-description">
                  {evt.description || `${evt.action || evt.event_type} recorded on ${evt.host_id || 'system'}.`}
                </div>

                {/* Entity Context Grid */}
                <div className="record-entity-grid">
                  {evt.host_id && (
                    <div className="entity-item">
                      <span className="ent-label">Host:</span>
                      <span className="ent-val"><code>{evt.host_id}</code></span>
                    </div>
                  )}
                  {evt.user_id && (
                    <div className="entity-item">
                      <span className="ent-label">User:</span>
                      <span className="ent-val"><code>{evt.user_id}</code></span>
                    </div>
                  )}
                  {evt.source_ip && (
                    <div className="entity-item">
                      <span className="ent-label">Src IP:</span>
                      <span className="ent-val"><code>{evt.source_ip}</code></span>
                    </div>
                  )}
                  {evt.destination_ip && (
                    <div className="entity-item">
                      <span className="ent-label">Dst IP:</span>
                      <span className="ent-val">
                        <code>{evt.destination_ip}{evt.destination_port ? `:${evt.destination_port}` : ''}</code>
                      </span>
                    </div>
                  )}
                  {evt.file_path && (
                    <div className="entity-item span-two">
                      <span className="ent-label">File:</span>
                      <span className="ent-val"><code>{evt.file_path}</code></span>
                    </div>
                  )}
                  {evt.command_line && (
                    <div className="entity-item span-two">
                      <span className="ent-label">Command:</span>
                      <span className="ent-val"><code>{evt.command_line}</code></span>
                    </div>
                  )}
                </div>

                {/* Referenced by Conclusions */}
                <div className="referenced-conclusions-strip">
                  <span className="ref-label">Referenced By Investigation Findings:</span>
                  {hasReferences ? (
                    <div className="ref-tags">
                      {references.entryPoint && (
                        <span className="ref-tag entry-tag">★ Candidate Entry Point</span>
                      )}
                      {references.hypotheses.map((h, i) => (
                        <span key={i} className="ref-tag hypo-tag">{h}</span>
                      ))}
                      {references.conclusions.map((c, i) => (
                        <span key={i} className="ref-tag conc-tag">{c}</span>
                      ))}
                      {references.facts.map((f, i) => (
                        <span key={i} className="ref-tag fact-tag">{f}</span>
                      ))}
                    </div>
                  ) : (
                    <span className="ref-none">Not cited in active threat conclusions (routine context)</span>
                  )}
                </div>

                {/* Actions */}
                <div className="record-actions">
                  <button
                    className="btn-locate-graph"
                    onClick={() => onSelectEventId(evt.event_id)}
                    title="Center and focus this node in the graph and timeline"
                  >
                    🔍 Focus in Graph & Timeline
                  </button>
                  <button
                    className="btn-view-raw"
                    onClick={() => onInspectRawEvent(evt)}
                    title="Inspect normalized and raw JSON record"
                  >
                    Inspect Full Record
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
