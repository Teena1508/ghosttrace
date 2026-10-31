/**
 * API service client for GhostTrace backend.
 */

import type {
  EventListResponse,
  GraphElementsResponse,
  HealthResponse,
  ValidationResult,
  SecurityEvent,
} from '../types/event';

const BACKEND_DIRECT_URL = 'http://127.0.0.1:8000';

/**
 * Resilient fetch client with automatic direct backend fallback
 * in case development server proxy returns 502/504 or network error.
 */
async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  try {
    const res = await fetch(path, init);
    if ((res.status === 502 || res.status === 504) && !path.startsWith('http')) {
      const directUrl = `${BACKEND_DIRECT_URL}${path.startsWith('/') ? '' : '/'}${path}`;
      return await fetch(directUrl, init);
    }
    return res;
  } catch (err) {
    if (!path.startsWith('http')) {
      const directUrl = `${BACKEND_DIRECT_URL}${path.startsWith('/') ? '' : '/'}${path}`;
      return await fetch(directUrl, init);
    }
    throw err;
  }
}

export async function fetchHealth(): Promise<HealthResponse> {
  const res = await apiFetch(`/health`);
  if (!res.ok) {
    throw new Error(`Health check failed with HTTP ${res.status}`);
  }
  return res.json();
}

export interface DeviceStatus {
  hostname: string;
  os: string;
  current_user: string;
  total_processes: number;
  total_active_sockets: number;
  status: string;
  timestamp: string;
  cpu_percent: number;
  memory_percent: number;
}

export async function fetchDeviceStatus(): Promise<DeviceStatus> {
  const res = await apiFetch(`/api/v1/device/status`);
  if (!res.ok) {
    throw new Error(`Failed to query device status with HTTP ${res.status}`);
  }
  return res.json();
}

export async function scanLiveDevice(options?: {
  max_events?: number;
  include_test_probe?: boolean;
  test_probe_type?: string;
}): Promise<import('../types/event').InvestigationReconstructionResult> {
  const res = await apiFetch(`/api/v1/device/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(options || {}),
  });
  if (!res.ok) {
    throw new Error(`Device scan failed with HTTP ${res.status}`);
  }
  return res.json();
}

export async function fetchEvents(params?: {
  suspicious_only?: boolean;
  event_type?: string;
}): Promise<EventListResponse> {
  const query = new URLSearchParams();
  if (params?.suspicious_only) {
    query.set('suspicious_only', 'true');
  }
  if (params?.event_type) {
    query.set('event_type', params.event_type);
  }

  const url = `/api/v1/events${query.toString() ? `?${query.toString()}` : ''}`;
  const res = await apiFetch(url);
  if (!res.ok) {
    throw new Error(`Failed to fetch events with HTTP ${res.status}`);
  }
  return res.json();
}

export async function fetchInvestigationGraph(params?: {
  suspicious_only?: boolean;
  scenario_id?: string;
}): Promise<GraphElementsResponse> {
  const query = new URLSearchParams();
  if (params?.suspicious_only) {
    query.set('suspicious_only', 'true');
  }
  if (params?.scenario_id) {
    query.set('scenario_id', params.scenario_id);
  }

  const url = `/api/v1/events/graph${query.toString() ? `?${query.toString()}` : ''}`;
  const res = await apiFetch(url);
  if (!res.ok) {
    throw new Error(`Failed to fetch graph elements with HTTP ${res.status}`);
  }
  return res.json();
}

export async function validateRecords(records: any[]): Promise<ValidationResult> {
  const res = await apiFetch(`/api/v1/events/validate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(records),
  });
  if (!res.ok) {
    throw new Error(`Validation request failed with HTTP ${res.status}`);
  }
  return res.json();
}

export async function importLogs(
  content: string,
  filename?: string | null,
  deduplicate: boolean = true
): Promise<import('../types/event').ImportLogResult> {
  const res = await apiFetch(`/api/v1/events/import`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ content, filename, deduplicate }),
  });
  if (!res.ok) {
    const errorBody = await res.json().catch(() => ({}));
    const message = errorBody.detail || `HTTP ${res.status}`;
    throw new Error(`Log import failed: ${message}`);
  }
  return res.json();
}

export async function reconstructInvestigation(
  events: any[],
  deduplicate: boolean = true
): Promise<import('../types/event').InvestigationReconstructionResult> {
  const res = await apiFetch(`/api/investigations/reconstruct`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ events, deduplicate }),
  });
  if (!res.ok) {
    const errorBody = await res.json().catch(() => ({}));
    const message = errorBody.detail?.error || errorBody.detail || `HTTP ${res.status}`;
    throw new Error(`Reconstruction failed: ${message}`);
  }
  return res.json();
}

export interface ScenarioMeta {
  id: string;
  name: string;
  description: string;
  file: string;
  is_suspicious: boolean;
}

export async function fetchScenarios(): Promise<ScenarioMeta[]> {
  const res = await apiFetch(`/api/v1/events/scenarios`);
  if (!res.ok) {
    throw new Error(`Failed to fetch scenarios with HTTP ${res.status}`);
  }
  return res.json();
}

export interface ScenarioDetailResponse {
  scenario_id: string;
  events: SecurityEvent[];
  validation_status: ValidationResult;
}

export async function fetchScenarioEvents(scenarioId: string): Promise<ScenarioDetailResponse> {
  const res = await apiFetch(`/api/v1/events/scenarios/${scenarioId}`);
  if (!res.ok) {
    throw new Error(`Failed to load scenario '${scenarioId}' with HTTP ${res.status}`);
  }
  const data = await res.json();
  return {
    scenario_id: data.scenario_id,
    events: data.events || [],
    validation_status: data.validation_status,
  };
}

export interface BlindScenarioSummary {
  scenario_id: string;
  title: string;
  description: string;
  event_count: number;
}

export interface EvaluationMetrics {
  entry_point_accuracy: number;
  relevant_event_precision: number;
  relevant_event_recall: number;
  relevant_event_f1: number;
  timeline_ordering_accuracy: number;
  relationship_precision: number;
  relationship_recall: number;
  source_event_traceability: number;
  unsupported_claim_rate: number;
  ambiguity_handling_score: number;
  unrelated_isolation_accuracy: number;
  details: Record<string, any>;
}

export interface RunEvaluationResponse {
  scenario_id: string;
  seed: number;
  execution_time_ms: number;
  reconstruction: import('../types/event').InvestigationReconstructionResult;
  metrics: EvaluationMetrics;
  evaluated_at: string;
}

export interface GroundTruthComparisonResponse {
  scenario_id: string;
  ground_truth: {
    scenario_id: string;
    name: string;
    description: string;
    expected_entry_point_id?: string;
    incident_event_ids: string[];
    routine_event_ids: string[];
    expected_chronological_order: string[];
    expected_relationships: [string, string, string][];
    explicitly_unknown_facts: string[];
    is_ambiguous: boolean;
    plausible_explanations: string[];
  };
  comparison: {
    entry_point_match: boolean;
    entry_point_details?: string;
    true_positives: string[];
    false_positives: string[];
    false_negatives: string[];
    ordering_accuracy: number;
    relationship_recall: number;
    unsupported_claims: string[];
    forensic_restraint_preserved: boolean;
    ambiguity_handled: boolean;
    unrelated_isolation_accuracy: number;
  };
}

export async function fetchEvaluationScenarios(seed: number = 42): Promise<BlindScenarioSummary[]> {
  const res = await apiFetch(`/api/v1/evaluation/scenarios?seed=${seed}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch evaluation scenarios with HTTP ${res.status}`);
  }
  return res.json();
}

export async function runEvaluationScenario(scenarioId: string, seed: number = 42): Promise<RunEvaluationResponse> {
  const res = await apiFetch(`/api/v1/evaluation/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scenario_id: scenarioId, seed }),
  });
  if (!res.ok) {
    throw new Error(`Evaluation run failed with HTTP ${res.status}`);
  }
  return res.json();
}

export async function fetchGroundTruthComparison(scenarioId: string, seed: number = 42): Promise<GroundTruthComparisonResponse> {
  const res = await apiFetch(`/api/v1/evaluation/ground-truth/${scenarioId}?seed=${seed}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch ground truth comparison with HTTP ${res.status}`);
  }
  return res.json();
}

