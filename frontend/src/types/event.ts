/**
 * GhostTrace Canonical Event Schema Types.
 * Matches backend Pydantic model and investigation engine representations.
 */

export type EventType =
  | 'AUTHENTICATION'
  | 'PROCESS_EXECUTION'
  | 'FILE_AUDIT'
  | 'NETWORK_CONNECTION';

export type EventSeverity =
  | 'INFORMATIONAL'
  | 'LOW'
  | 'MEDIUM'
  | 'HIGH'
  | 'CRITICAL';

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  event_type: EventType;
  host_id?: string | null;
  user_id?: string | null;
  source_ip?: string | null;
  session_id?: string | null;
  process_id?: number | string | null;
  file_path?: string | null;
  severity: EventSeverity;
  source: string;
  original_event_data: Record<string, any>;
  source_event_id?: string | null;
  description?: string | null;
  is_suspicious: boolean;
  mitre_attack_id?: string | null;
  destination_ip?: string | null;
  destination_port?: number | null;
  process_name?: string | null;
  command_line?: string | null;
  action?: string | null;
}

export interface ValidationIssue {
  field?: string | null;
  message: string;
  severity: 'INFO' | 'WARNING' | 'ERROR';
  raw_record_id?: string | null;
}

export interface ValidationResult {
  is_valid: boolean;
  events_processed: number;
  valid_events_count: number;
  duplicate_events_count: number;
  malformed_events_count: number;
  issues: ValidationIssue[];
}

export interface EventListResponse {
  total: number;
  count: number;
  suspicious_count: number;
  events: SecurityEvent[];
  validation_status: ValidationResult;
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  environment: string;
  timestamp: string;
  checks: Record<string, any>;
}

export interface CytoscapeElement {
  group: 'nodes' | 'edges';
  data: {
    id: string;
    label?: string;
    node_type?: 'event' | 'host' | 'user' | 'ip' | 'process' | 'file';
    source?: string;
    target?: string;
    relation?: string;
    severity?: string;
    is_suspicious?: boolean;
    timestamp?: string;
    [key: string]: any;
  };
}

export interface GraphElementsResponse {
  event_count: number;
  element_count: number;
  elements: CytoscapeElement[];
}

export interface CandidateEntryPoint {
  event_id: string;
  timestamp: string;
  user_id?: string | null;
  source_ip?: string | null;
  host_id?: string | null;
  rationale: string;
  confidence: number;
  evidence_grade?: 'Strong' | 'Moderate' | 'Weak' | 'Insufficient';
  confidence_breakdown?: Record<string, any>;
  supporting_event_ids: string[];
}

export interface AttackHypothesis {
  hypothesis_id: string;
  title: string;
  description: string;
  rank: number;
  score: number;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'TENTATIVE';
  evidence_grade?: 'Strong' | 'Moderate' | 'Weak' | 'Insufficient';
  confidence_explanation: string;
  score_breakdown?: Record<string, any>;
  supporting_event_ids: string[];
  contradicting_event_ids: string[];
  assumptions: string[];
}

export interface ImportLogResult {
  format_detected: string;
  source_filename?: string | null;
  total_records_read: number;
  valid_events_count: number;
  malformed_count: number;
  duplicate_count: number;
  unsupported_fields: string[];
  parsing_warnings: string[];
  events: SecurityEvent[];
  validation_status: ValidationResult;
}

export interface ObservedFact {
  fact_id: string;
  statement: string;
  supporting_event_ids: string[];
  source: string;
  observed_at: string;
}

export interface InferredConclusion {
  conclusion_id: string;
  statement: string;
  confidence: string;
  confidence_rationale: string;
  supporting_event_ids: string[];
  alternative_explanations: string[];
}

export interface UnresolvedQuestion {
  question_id: string;
  question: string;
  context: string;
  missing_evidence_type: string;
  related_event_ids: string[];
}

export interface DefensiveRecommendation {
  recommendation_id: string;
  title: string;
  action: string;
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  target_entity?: string | null;
  mitre_mitigation?: string | null;
  why_recommended?: string;
  supporting_event_ids?: string[];
  expected_benefit?: string;
  potential_impact_risk?: string;
  measure_type?: 'DIRECT_RESPONSE' | 'PRECAUTIONARY';
  is_simulated_action?: boolean;
}

export interface ReconstructionTimelineEvent {
  event_id: string;
  timestamp: string;
  event_type: EventType;
  phase: string;
  summary: string;
  is_suspicious: boolean;
  supporting_event_ids: string[];
  host_id?: string | null;
  user_id?: string | null;
}

export interface DetectionFinding {
  finding_id: string;
  rule_id: string;
  rule_name: string;
  severity: EventSeverity;
  category: string;
  mitre_attack_id?: string | null;
  summary: string;
  observed_indicators: string[];
  benign_alternatives: string[];
  supporting_event_ids: string[];
  confidence_assessment: string;
  missing_telemetry_limitations?: string | null;
}

export interface InvestigationReconstructionResult {
  investigation_id: string;
  timeline: ReconstructionTimelineEvent[];
  candidate_entry_points: CandidateEntryPoint[];
  evidence_graph: {
    nodes: any[];
    edges: any[];
    cytoscape_elements: CytoscapeElement[];
  };
  hypotheses: AttackHypothesis[];
  observed_facts: ObservedFact[];
  inferred_conclusions: InferredConclusion[];
  unresolved_questions: UnresolvedQuestion[];
  defensive_recommendations: DefensiveRecommendation[];
  detection_findings?: DetectionFinding[];
  metadata: Record<string, any>;
}

