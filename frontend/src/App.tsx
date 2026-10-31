import React, { useEffect, useState, useMemo, useCallback } from 'react';
import type {
  CytoscapeElement,
  HealthResponse,
  SecurityEvent,
  ValidationResult,
  InvestigationReconstructionResult,
  AttackHypothesis,
} from './types/event';
import {
  fetchHealth,
  fetchInvestigationGraph,
  reconstructInvestigation,
  fetchScenarios,
  fetchScenarioEvents,
  fetchDeviceStatus,
  scanLiveDevice,
} from './services/api';
import type { ScenarioMeta, DeviceStatus } from './services/api';
import { InteractiveEvidenceGraph } from './components/InteractiveEvidenceGraph';
import { EvidenceDetailDrawer } from './components/EvidenceDetailDrawer';
import type { SelectedNodeInfo, SelectedEdgeInfo } from './components/EvidenceDetailDrawer';
import { SynchronizedTimeline } from './components/SynchronizedTimeline';
import { EventDetailModal } from './components/EventDetailModal';
import { IncidentOverview } from './components/IncidentOverview';
import { HypothesisInvestigation } from './components/HypothesisInvestigation';
import { EvidenceExplorer } from './components/EvidenceExplorer';
import { DefensiveRecommendations } from './components/DefensiveRecommendations';
import { InvestigationReportModal } from './components/InvestigationReportModal';
import { ChallengeEvaluationView } from './components/ChallengeEvaluationView';
import { JudgeDemonstrationView } from './components/JudgeDemonstrationView';
import { LogImportModal } from './components/LogImportModal';
import { DetectionsView } from './components/DetectionsView';

export const App: React.FC = () => {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [validationStatus, setValidationStatus] = useState<ValidationResult | null>(null);
  const [graphElements, setGraphElements] = useState<CytoscapeElement[]>([]);
  const [reconstruction, setReconstruction] = useState<InvestigationReconstructionResult | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Scenarios state
  const [scenarios, setScenarios] = useState<ScenarioMeta[]>([]);
  const [currentScenarioId, setCurrentScenarioId] = useState<string>('live_device');
  const [deviceStatus, setDeviceStatus] = useState<DeviceStatus | null>(null);
  const [isScanningLive, setIsScanningLive] = useState<boolean>(false);

  // Primary workspace navigation tabs
  const [activeTab, setActiveTab] = useState<'overview' | 'detections' | 'graph' | 'hypotheses' | 'evidence' | 'recommendations' | 'evaluation' | 'demo'>('overview');

  // Synchronized Selection State
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<SelectedNodeInfo | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<SelectedEdgeInfo | null>(null);
  const [inspectEvent, setInspectEvent] = useState<SecurityEvent | null>(null);

  // Hypothesis highlighting state
  const [selectedHypothesisId, setSelectedHypothesisId] = useState<string | null>(null);
  const [highlightedEventIds, setHighlightedEventIds] = useState<string[] | null>(null);

  // Report modal state
  const [isReportModalOpen, setIsReportModalOpen] = useState<boolean>(false);

  // Local log import modal state
  const [isImportModalOpen, setIsImportModalOpen] = useState<boolean>(false);
  const [importedDatasetMeta, setImportedDatasetMeta] = useState<{
    name: string;
    format: string;
    count: number;
    unsupportedFields?: string[];
    parsingWarnings?: string[];
  } | null>(null);

  // Timeline Filters
  const [timelineType, setTimelineType] = useState<string>('ALL');
  const [timelineSeverity, setTimelineSeverity] = useState<string>('ALL');
  const [timelineSuspiciousOnly, setTimelineSuspiciousOnly] = useState<boolean>(false);
  const [timelineSearch, setTimelineSearch] = useState<string>('');

  // Current scenario name
  const currentScenarioName = useMemo(() => {
    if (currentScenarioId === 'user_imported') {
      return importedDatasetMeta?.name || 'Local Log Ingestion';
    }
    const sc = scenarios.find((s) => s.id === currentScenarioId);
    return sc ? sc.name : currentScenarioId;
  }, [scenarios, currentScenarioId, importedDatasetMeta]);

  // Load scenarios + health on mount, then keep health alive with a heartbeat
  useEffect(() => {
    // Initial fetch of device status + scenarios + health
    fetchDeviceStatus().then(setDeviceStatus).catch(console.warn);
    fetchHealth().then(setHealth).catch(() => setHealth(null));
    fetchScenarios()
      .then((res) => {
        if (Array.isArray(res) && res.length > 0) {
          setScenarios(res);
        }
      })
      .catch((err) => {
        console.warn('Scenarios endpoint unavailable, using defaults:', err);
        setScenarios([
          {
            id: 'live_device',
            name: '🖥️ Live Host Telemetry (This Device)',
            description: 'Real-time host telemetry: active processes, network sockets, and persistence mechanisms.',
            file: 'live_device_collector',
            is_suspicious: false,
          },
        ]);
      });

    // Heartbeat: poll /health every 15s to keep the status badge live
    const heartbeat = setInterval(() => {
      fetchHealth()
        .then(setHealth)
        .catch(() => setHealth(null));
    }, 15000);
    return () => clearInterval(heartbeat);
  }, []);

  // Dedicated Live Host Scanner
  const handleScanDevice = useCallback(async (includeProbe: boolean = false, probeType: string = 'reverse_shell') => {
    setIsScanningLive(true);
    setLoading(true);
    setError(null);
    setSelectedEventId(null);
    setSelectedNode(null);
    setSelectedEdge(null);
    setSelectedHypothesisId(null);
    setHighlightedEventIds(null);
    setImportedDatasetMeta(null);
    setCurrentScenarioId('live_device');

    try {
      const [status, reconResult] = await Promise.all([
        fetchDeviceStatus().catch(() => null),
        scanLiveDevice({ max_events: 350, include_test_probe: includeProbe, test_probe_type: probeType }),
      ]);
      if (status) setDeviceStatus(status);
      setReconstruction(reconResult);
      if (reconResult.evidence_graph && reconResult.evidence_graph.cytoscape_elements.length > 0) {
        setGraphElements(reconResult.evidence_graph.cytoscape_elements);
      } else {
        setGraphElements([]);
      }
      // TimelineEvent objects are used directly — they contain event_id, is_suspicious, etc.
      const timelineEvents = (reconResult.timeline || []).filter((te: any) => te != null);
      setEvents(timelineEvents as any);

      if (reconResult.detection_findings && reconResult.detection_findings.length > 0) {
        setActiveTab('detections');
      } else {
        setActiveTab('overview');
      }
    } catch (err: any) {
      console.error('Live scan failed:', err);
      setError(err.message || 'Failed to scan device telemetry');
    } finally {
      setIsScanningLive(false);
      setLoading(false);
    }
  }, []);

  // Main data loader for selected scenario
  const loadScenarioData = useCallback(async (scenarioId: string) => {
    if (scenarioId === 'live_device') {
      return handleScanDevice(false);
    }

    setLoading(true);
    setError(null);

    // CRITICAL: Prevent stale data from previous investigation from leaking into new incident
    setReconstruction(null);
    setEvents([]);
    setGraphElements([]);
    setValidationStatus(null);
    setSelectedEventId(null);
    setSelectedNode(null);
    setSelectedEdge(null);
    setSelectedHypothesisId(null);
    setHighlightedEventIds(null);
    setTimelineSearch('');
    setTimelineType('ALL');
    setTimelineSeverity('ALL');
    setTimelineSuspiciousOnly(false);

    try {
      const [healthData, scenarioData] = await Promise.all([
        fetchHealth().catch((err) => {
          console.warn('Health check failed:', err);
          return null;
        }),
        fetchScenarioEvents(scenarioId),
      ]);

      setHealth(healthData);
      const loadedEvents = scenarioData.events || [];
      setEvents(loadedEvents);
      setValidationStatus(scenarioData.validation_status || null);

      // Reconstruct attack timeline and rich evidence graph
      if (loadedEvents.length > 0) {
        try {
          const reconResult = await reconstructInvestigation(loadedEvents);
          setReconstruction(reconResult);

          if (reconResult.evidence_graph && reconResult.evidence_graph.cytoscape_elements.length > 0) {
            setGraphElements(reconResult.evidence_graph.cytoscape_elements);
          } else {
            // Target scenario graph fallback
            const graphData = await fetchInvestigationGraph({ scenario_id: scenarioId });
            setGraphElements(graphData.elements);
          }
        } catch (reconErr: any) {
          console.error('Reconstruction error:', reconErr);
          setError(`Timeline reconstruction failed: ${reconErr.message || 'Unable to correlate events'}`);
          setGraphElements([]);
          setReconstruction(null);
        }
      } else {
        setReconstruction(null);
        setGraphElements([]);
      }
    } catch (err: any) {
      console.error('Scenario load error:', err);
      setError(err.message || 'Failed to connect to GhostTrace investigation engine');
      setEvents([]);
      setReconstruction(null);
      setGraphElements([]);
    } finally {
      setLoading(false);
    }
  }, [handleScanDevice]);

  useEffect(() => {
    loadScenarioData(currentScenarioId);
  }, [currentScenarioId, loadScenarioData]);

  // Handler when a scenario is selected
  const handleSelectScenario = (scenarioId: string) => {
    if (scenarioId === 'user_imported') {
      return;
    }
    setImportedDatasetMeta(null);
    setCurrentScenarioId(scenarioId);
  };

  // Handler for successful local log file import
  const handleImportSuccess = async (result: {
    events: SecurityEvent[];
    validationStatus: ValidationResult;
    datasetName: string;
    formatDetected: string;
    recordCount: number;
    unsupportedFields?: string[];
    parsingWarnings?: string[];
  }) => {
    setLoading(true);
    setError(null);
    setSelectedEventId(null);
    setSelectedNode(null);
    setSelectedEdge(null);
    setSelectedHypothesisId(null);
    setHighlightedEventIds(null);

    setEvents(result.events);
    setValidationStatus(result.validationStatus);
    setImportedDatasetMeta({
      name: result.datasetName,
      format: result.formatDetected,
      count: result.recordCount,
      unsupportedFields: result.unsupportedFields,
      parsingWarnings: result.parsingWarnings,
    });
    setCurrentScenarioId('user_imported');

    try {
      const reconResult = await reconstructInvestigation(result.events);
      setReconstruction(reconResult);
      if (reconResult.evidence_graph && reconResult.evidence_graph.cytoscape_elements.length > 0) {
        setGraphElements(reconResult.evidence_graph.cytoscape_elements);
      } else {
        setGraphElements([]);
      }
      // If detection findings exist, immediately show detections tab, otherwise overview
      if (reconResult.detection_findings && reconResult.detection_findings.length > 0) {
        setActiveTab('detections');
      } else {
        setActiveTab('overview');
      }
    } catch (err: any) {
      console.error('Reconstruction of imported logs failed:', err);
      setError(`Reconstruction failed: ${err.message || 'Unable to correlate events'}`);
      setActiveTab('overview');
    } finally {
      setLoading(false);
    }
  };

  // Synchronized Selection: When an event is clicked in the Timeline or anywhere in the UI
  const handleSelectAndFocusEvent = useCallback(
    (eventId: string) => {
      setSelectedEventId(eventId);
      setSelectedEdge(null);

      // Find event and construct SelectedNodeInfo so the drawer opens immediately
      const matchedEvt = events.find((e) => e.event_id === eventId);
      if (matchedEvt) {
        const connectedEdges: Array<{
          id: string;
          relation: string;
          target_label: string;
          target_id: string;
          direction: 'incoming' | 'outgoing';
          inferred?: boolean;
        }> = [];

        const nodeGraphId = `evt:${eventId}`;
        graphElements.forEach((el) => {
          if (el.data && el.data.source && el.data.target) {
            if (el.data.source === nodeGraphId) {
              connectedEdges.push({
                id: el.data.id || `${el.data.source}-${el.data.target}`,
                relation: el.data.relation || 'CONNECTED',
                target_label: el.data.target_label || el.data.target,
                target_id: el.data.target,
                direction: 'outgoing',
                inferred: el.data.inferred,
              });
            } else if (el.data.target === nodeGraphId) {
              connectedEdges.push({
                id: el.data.id || `${el.data.source}-${el.data.target}`,
                relation: el.data.relation || 'CONNECTED',
                target_label: el.data.source_label || el.data.source,
                target_id: el.data.source,
                direction: 'incoming',
                inferred: el.data.inferred,
              });
            }
          }
        });

        setSelectedNode({
          id: nodeGraphId,
          label: `${matchedEvt.event_type} (${matchedEvt.event_id})`,
          node_type: 'event',
          is_suspicious: matchedEvt.is_suspicious,
          severity: matchedEvt.severity,
          timestamp: matchedEvt.timestamp,
          event_id: matchedEvt.event_id,
          source: matchedEvt.source,
          source_event_id: matchedEvt.source_event_id || matchedEvt.event_id,
          description: matchedEvt.description || undefined,
          mitre_attack_id: matchedEvt.mitre_attack_id || undefined,
          importance_reason: matchedEvt.is_suspicious
            ? `Flagged as suspicious incident evidence: ${matchedEvt.description || matchedEvt.action || 'Anomalous activity'}.`
            : 'Baseline administrative / routine event providing benign context.',
          inferred: false,
          attributes: {
            event_type: matchedEvt.event_type,
            user_id: matchedEvt.user_id,
            host_id: matchedEvt.host_id,
            source_ip: matchedEvt.source_ip,
            destination_ip: matchedEvt.destination_ip,
            file_path: matchedEvt.file_path,
            command_line: matchedEvt.command_line,
          },
          connected_edges: connectedEdges,
        });
      }

      // Automatically switch to the graph tab if currently on another tab
      setActiveTab('graph');
    },
    [events, graphElements]
  );

  // Synchronized Selection: When a node is clicked in Cytoscape
  const handleGraphSelectNode = (node: SelectedNodeInfo | null) => {
    setSelectedNode(node);
    if (node && node.event_id) {
      setSelectedEventId(node.event_id);
    }
  };

  // Hypothesis Selection & Highlighting
  const handleSelectHypothesis = (hypo: AttackHypothesis) => {
    setSelectedHypothesisId(hypo.hypothesis_id);
    setHighlightedEventIds(hypo.supporting_event_ids);
    setActiveTab('graph');
  };

  // Telemetry Metrics
  const stats = useMemo(() => {
    const safeEvents = events.filter((e) => e != null);
    const total = safeEvents.length;
    const suspicious = safeEvents.filter((e) => e.is_suspicious).length;
    const routine = total - suspicious;
    const hypothesesCount = reconstruction?.hypotheses ? reconstruction.hypotheses.length : 0;
    const topScore = reconstruction?.hypotheses?.[0]?.score || 0;
    const confidence = Math.round(topScore * 100);
    return { total, suspicious, routine, hypothesesCount, confidence };
  }, [events, reconstruction]);

  return (
    <div className="ghost-app">
      {/* Top Banner / Navbar */}
      <header className="ghost-header">
        <div className="brand-area">
          <div className="brand-logo">
            <span className="logo-symbol">⌁</span>
            <span className="brand-name">GHOST<span className="accent">TRACE</span></span>
          </div>
          <span className="version-tag">Host Defense & Forensics</span>
          <div
            className="live-host-badge"
            style={{
              background: 'rgba(16, 185, 129, 0.12)',
              border: '1px solid #10b981',
              color: '#10b981',
              padding: '0.25rem 0.65rem',
              borderRadius: '4px',
              fontSize: '0.72rem',
              fontWeight: 700,
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
            }}
            title="Actively monitoring local host environment"
          >
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#10b981', boxShadow: '0 0 8px #10b981' }}></span>
            LIVE DEVICE: {deviceStatus?.hostname || 'THIS MACHINE'} ({deviceStatus?.current_user || 'Active User'})
          </div>
        </div>

        <div className="header-actions-area">
          {/* Live Device Scan Action Button */}
          <button
            className="btn-scan-device"
            onClick={() => handleScanDevice(false)}
            disabled={isScanningLive}
            style={{
              background: 'linear-gradient(135deg, #10b981, #059669)',
              color: '#ffffff',
              border: '1px solid #34d399',
              borderRadius: '6px',
              padding: '0.45rem 0.85rem',
              fontWeight: 700,
              fontSize: '0.8rem',
              cursor: isScanningLive ? 'wait' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
            }}
            title="Scan live processes, open sockets, and persistence mechanisms on this device"
          >
            {isScanningLive ? '🔄 Scanning Device...' : '⚡ Scan Device Now'}
          </button>

          {/* Test Threat Detection Probe Button */}
          <button
            className="btn-test-threat"
            onClick={() => handleScanDevice(true, 'reverse_shell')}
            disabled={isScanningLive}
            style={{
              background: 'linear-gradient(135deg, #dc2626, #b91c1c)',
              color: '#ffffff',
              border: '1px solid #f87171',
              borderRadius: '6px',
              padding: '0.45rem 0.85rem',
              fontWeight: 700,
              fontSize: '0.8rem',
              cursor: isScanningLive ? 'wait' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
            }}
            title="Inject an authorized test threat probe to verify real-time threat detection on this device"
          >
            🧪 Test Threat Detection
          </button>

          {/* Local Log Import Workflow Button */}
          <button
            className="btn-import-logs"
            onClick={() => setIsImportModalOpen(true)}
            style={{
              background: 'linear-gradient(135deg, #0284c7, #0369a1)',
              color: '#ffffff',
              border: '1px solid #38bdf8',
              borderRadius: '6px',
              padding: '0.45rem 0.85rem',
              fontWeight: 700,
              fontSize: '0.8rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
            }}
            title="Import local Windows XML, Linux auth.log, or JSON security files"
          >
            📥 Import Logs
          </button>

          {/* Telemetry Source Selector */}
          <div className="header-scenario-picker">
            <label className="header-picker-label">SOURCE:</label>
            <select
              className="header-select-scenario"
              value={currentScenarioId}
              onChange={(e) => handleSelectScenario(e.target.value)}
              title="Select active telemetry source"
            >
              <optgroup label="Live Host Telemetry">
                <option value="live_device">
                  🖥️ This Device ({deviceStatus?.hostname || 'Local Machine'})
                </option>
              </optgroup>
              {importedDatasetMeta && (
                <optgroup label="Imported Real Logs">
                  <option value="user_imported">
                    ★ {importedDatasetMeta.name} ({importedDatasetMeta.count} records)
                  </option>
                </optgroup>
              )}
              <optgroup label="Reference Datasets & Forensic Benchmarks">
                {scenarios.filter((s) => s.id !== 'live_device').map((sc) => (
                  <option key={sc.id} value={sc.id}>
                    {sc.name}
                  </option>
                ))}
              </optgroup>
            </select>
          </div>

          {/* Export Report Action */}
          <button
            className="btn-export-report"
            onClick={() => setIsReportModalOpen(true)}
            disabled={!reconstruction}
            title="Generate and export formal forensic investigation report"
          >
            📄 Export Report
          </button>

          {/* Backend Status */}
          <div className="status-area">
            {health ? (
              <div className="health-badge healthy" title={`Connected to ${health.service} v${health.version}`}>
                <span className="pulse-indicator"></span>
                Backend: ONLINE
              </div>
            ) : (
              <div
                className="health-badge offline"
                title="Reconnecting to backend…"
                style={{ cursor: 'pointer' }}
                onClick={() => fetchHealth().then(setHealth).catch(() => setHealth(null))}
              >
                <span className="pulse-indicator offline"></span>
                Reconnecting…
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Main Forensic Workspace */}
      <main className="ghost-main">
        {/* Metric Overview Strip */}
        <section className="metrics-grid">
          <div className="metric-card">
            <div className="metric-title">TELEMETRY RECORDS</div>
            <div className="metric-value">{stats.total}</div>
            <div className="metric-sub">Host Entities Audited</div>
          </div>
          <div className="metric-card warning">
            <div className="metric-title">THREAT SIGNALS DETECTED</div>
            <div className="metric-value">{reconstruction?.detection_findings?.length || 0}</div>
            <div className="metric-sub">Active Threat Detections</div>
          </div>
          <div className="metric-card neutral">
            <div className="metric-title">ROUTINE BASELINE</div>
            <div className="metric-value">{stats.routine}</div>
            <div className="metric-sub">Benign Operations Context</div>
          </div>
          <div className="metric-card success">
            <div className="metric-title">SYSTEM INTEGRITY ASSESSMENT</div>
            <div className="metric-value">
              {reconstruction?.hypotheses?.[0]
                ? `${reconstruction.hypotheses[0].evidence_grade || 'High'} (${reconstruction.hypotheses[0].score.toFixed(2)})`
                : 'N/A'}
            </div>
            <div className="metric-sub">
              {reconstruction?.hypotheses?.[0]?.title || 'System Assessment'}
            </div>
          </div>
        </section>

        {/* Forensic Workspace Navigation Tabs */}
        <section className="controls-panel">
          <div className="tab-group">
            <button
              className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
              onClick={() => setActiveTab('overview')}
            >
              1. Incident Overview
            </button>
            <button
              className={`tab-btn ${activeTab === 'detections' ? 'active' : ''}`}
              onClick={() => setActiveTab('detections')}
              style={{
                borderColor: activeTab === 'detections' ? '#38bdf8' : undefined,
                color: activeTab === 'detections' ? '#38bdf8' : undefined,
              }}
            >
              2. Threat Detections ({reconstruction?.detection_findings?.length || 0})
            </button>
            <button
              className={`tab-btn ${activeTab === 'graph' ? 'active' : ''}`}
              onClick={() => setActiveTab('graph')}
            >
              3. Live Evidence Graph
            </button>
            <button
              className={`tab-btn ${activeTab === 'hypotheses' ? 'active' : ''}`}
              onClick={() => setActiveTab('hypotheses')}
            >
              4. Forensic Hypotheses ({reconstruction?.hypotheses?.length || 0})
            </button>
            <button
              className={`tab-btn ${activeTab === 'evidence' ? 'active' : ''}`}
              onClick={() => setActiveTab('evidence')}
            >
              5. Host Evidence Explorer ({events.length})
            </button>
            <button
              className={`tab-btn ${activeTab === 'recommendations' ? 'active' : ''}`}
              onClick={() => setActiveTab('recommendations')}
            >
              6. Defensive Containment ({reconstruction?.defensive_recommendations?.length || 0})
            </button>
          </div>

          <div className="filter-group">
            <button
              className="btn-refresh"
              onClick={() => loadScenarioData(currentScenarioId)}
              title="Reload investigation data"
            >
              ↻ Reload Data
            </button>
          </div>
        </section>

        {/* Error Banner */}
        {error && (
          <div className="error-banner">
            <h3>Investigation Engine Notice</h3>
            <p>{error}</p>
            <p className="subtext">
              Ensure the FastAPI backend is running via <code>python3 -m uvicorn backend.app.main:app --port 8000</code>.
            </p>
          </div>
        )}

        {/* Loading Spinner */}
        {loading ? (
          <div className="loading-state">
            <div className="spinner"></div>
            <span>Reconstructing incident workspace, correlating evidence, and evaluating hypotheses...</span>
          </div>
        ) : activeTab === 'overview' ? (
          /* STEP 1: INCIDENT OVERVIEW */
          <IncidentOverview
            reconstruction={reconstruction}
            events={events}
            scenarioName={currentScenarioName}
            onSelectEventId={handleSelectAndFocusEvent}
          />
        ) : activeTab === 'detections' ? (
          /* STEP 2: DETERMINISTIC DETECTIONS & EVIDENCE LINEAGE */
          <DetectionsView
            findings={reconstruction?.detection_findings || []}
            events={events}
            validationStatus={validationStatus}
            importMeta={importedDatasetMeta}
            onSelectEvent={(id) => handleSelectAndFocusEvent(id)}
            onInspectEvent={(ev) => setInspectEvent(ev)}
          />
        ) : activeTab === 'graph' ? (
          /* STEP 2: EVIDENCE GRAPH & SYNCHRONIZED TIMELINE */
          <div className="evidence-investigation-workspace">
            {/* Interactive Cytoscape Graph with Hypothesis Highlighting */}
            <InteractiveEvidenceGraph
              elements={graphElements}
              allEvents={events}
              selectedEventId={selectedEventId}
              onSelectNode={handleGraphSelectNode}
              onSelectEdge={(edge) => {
                setSelectedEdge(edge);
                setSelectedNode(null);
              }}
              onClearSelection={() => {
                setSelectedNode(null);
                setSelectedEdge(null);
                setSelectedEventId(null);
                setSelectedHypothesisId(null);
                setHighlightedEventIds(null);
              }}
              scenarios={scenarios}
              currentScenarioId={currentScenarioId}
              onSelectScenario={handleSelectScenario}
              highlightedEventIds={highlightedEventIds}
              hypothesisId={selectedHypothesisId}
            />

            {/* Synchronized Chronological Timeline */}
            <SynchronizedTimeline
              events={events}
              selectedEventId={selectedEventId}
              onSelectEvent={handleSelectAndFocusEvent}
              filterType={timelineType}
              onFilterTypeChange={setTimelineType}
              filterSeverity={timelineSeverity}
              onFilterSeverityChange={setTimelineSeverity}
              showSuspiciousOnly={timelineSuspiciousOnly}
              onToggleSuspiciousOnly={setTimelineSuspiciousOnly}
              searchQuery={timelineSearch}
              onSearchQueryChange={setTimelineSearch}
            />
          </div>
        ) : activeTab === 'hypotheses' ? (
          /* STEP 3: ATTACK HYPOTHESES EVALUATION */
          <HypothesisInvestigation
            hypotheses={reconstruction?.hypotheses || []}
            selectedHypothesisId={selectedHypothesisId}
            onSelectHypothesis={handleSelectHypothesis}
            onSelectEventId={handleSelectAndFocusEvent}
          />
        ) : activeTab === 'evidence' ? (
          /* STEP 4: EVIDENCE EXPLORER & CONCLUSION MAPPING */
          <EvidenceExplorer
            events={events}
            reconstruction={reconstruction}
            onSelectEventId={handleSelectAndFocusEvent}
            onInspectRawEvent={(evt) => setInspectEvent(evt)}
          />
        ) : activeTab === 'recommendations' ? (
          /* STEP 5: DEFENSIVE RECOMMENDATIONS & SIMULATED SANDBOX */
          <DefensiveRecommendations
            recommendations={reconstruction?.defensive_recommendations || []}
            onSelectEventId={handleSelectAndFocusEvent}
          />
        ) : activeTab === 'demo' ? (
          /* STEP 7: PHASE 10 JUDGE-READY DEMONSTRATION & PRESENTER TRACK */
          <JudgeDemonstrationView
            onLoadScenarioToWorkspace={(scId) => {
              handleSelectScenario(scId);
              setActiveTab('overview');
            }}
          />
        ) : (
          /* STEP 6: PHASE 6 CHALLENGE & EVALUATION DEMONSTRATION */
          <ChallengeEvaluationView
            onLoadScenarioToWorkspace={(scId) => {
              handleSelectScenario(scId);
              setActiveTab('overview');
            }}
          />
        )}
      </main>

      {/* Slide-out Evidence & Relationship Inspection Drawer */}
      <EvidenceDetailDrawer
        selectedNode={selectedNode}
        selectedEdge={selectedEdge}
        allEvents={events}
        onClose={() => {
          setSelectedNode(null);
          setSelectedEdge(null);
        }}
        onSelectNodeById={(nodeId) => {
          if (nodeId.startsWith('evt:')) {
            handleSelectAndFocusEvent(nodeId.replace('evt:', ''));
          }
        }}
        onViewRawEvidence={(event) => setInspectEvent(event)}
      />

      {/* Raw Event Detail Modal */}
      <EventDetailModal
        event={inspectEvent}
        onClose={() => setInspectEvent(null)}
      />

      {/* Exportable Investigation Report Modal */}
      <InvestigationReportModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        reconstruction={reconstruction}
        events={events}
        scenarioName={currentScenarioName}
        scenarioId={currentScenarioId}
      />

      {/* Local Log Ingestion Modal */}
      <LogImportModal
        isOpen={isImportModalOpen}
        onClose={() => setIsImportModalOpen(false)}
        onImportSuccess={handleImportSuccess}
      />
    </div>
  );
};

export default App;
