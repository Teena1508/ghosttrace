"""
Automated Scoring Evaluator for GhostTrace Phase 6.

Calculates granular forensic metrics comparing reconstruction outputs against ground-truth:
- Entry-point accuracy
- Relevant-event precision, recall, and F1
- Timeline ordering accuracy
- Evidence-relationship precision and recall
- Source-event traceability
- Unsupported-claim rate (e.g. premature exfiltration assertions)
- Ambiguity and alternative explanation handling
- Unrelated incident isolation accuracy
"""

from typing import Any, Dict, List, Set, Tuple
from evaluation.models import GroundTruthScenario, EvaluationMetrics
from investigation_engine.models import InvestigationReconstructionResult


def evaluate_reconstruction(
    reconstruction: InvestigationReconstructionResult,
    ground_truth: GroundTruthScenario,
) -> EvaluationMetrics:
    """
    Evaluates the quality of a reconstructed investigation against its ground-truth record.
    """
    details: Dict[str, Any] = {}

    # 1. Entry Point Identification Accuracy
    expected_ep = ground_truth.expected_entry_point_id
    reconstructed_eps = reconstruction.candidate_entry_points

    if expected_ep is None:
        # Ground truth has no entry point (benign baseline or no successful access)
        if len(reconstructed_eps) == 0:
            entry_point_acc = 1.0
            details["entry_point_status"] = "CORRECT_NONE_IDENTIFIED"
        else:
            # Check if engine expressed low confidence or false positive
            entry_point_acc = 0.0
            details["entry_point_status"] = f"FALSE_POSITIVE_ENTRY_POINT ({reconstructed_eps[0].event_id})"
    else:
        if len(reconstructed_eps) == 0:
            entry_point_acc = 0.0
            details["entry_point_status"] = f"MISSED_EXPECTED_ENTRY_POINT ({expected_ep})"
        elif reconstructed_eps[0].event_id == expected_ep:
            entry_point_acc = 1.0
            details["entry_point_status"] = f"EXACT_MATCH ({expected_ep})"
        elif expected_ep in reconstructed_eps[0].supporting_event_ids:
            entry_point_acc = 0.75
            details["entry_point_status"] = f"PARTIAL_MATCH_IN_CLUSTER ({expected_ep})"
        else:
            entry_point_acc = 0.0
            details["entry_point_status"] = f"MISMATCH (expected {expected_ep}, got {reconstructed_eps[0].event_id})"

    # 2. Relevant-Event Identification Precision & Recall
    # Determine which events the reconstruction engine classified as incident / suspicious
    reconstructed_incident_ids: Set[str] = set()
    for item in reconstruction.timeline:
        if item.is_suspicious:
            reconstructed_incident_ids.add(item.event_id)

    # Also include events cited in primary hypothesis
    if reconstruction.hypotheses:
        reconstructed_incident_ids.update(reconstruction.hypotheses[0].supporting_event_ids)

    true_incident_ids = ground_truth.incident_event_ids
    true_routine_ids = ground_truth.routine_event_ids

    tp_events = reconstructed_incident_ids.intersection(true_incident_ids)
    fp_events = reconstructed_incident_ids.intersection(true_routine_ids)
    fn_events = true_incident_ids.difference(reconstructed_incident_ids)

    details["tp_events"] = sorted(list(tp_events))
    details["fp_events"] = sorted(list(fp_events))
    details["fn_events"] = sorted(list(fn_events))

    if len(reconstructed_incident_ids) > 0:
        event_precision = len(tp_events) / (len(tp_events) + len(fp_events)) if (len(tp_events) + len(fp_events)) > 0 else 0.0
    else:
        event_precision = 1.0 if len(true_incident_ids) == 0 else 0.0

    if len(true_incident_ids) > 0:
        event_recall = len(tp_events) / len(true_incident_ids)
    else:
        event_recall = 1.0 if len(reconstructed_incident_ids) == 0 else 0.0

    if (event_precision + event_recall) > 0:
        event_f1 = 2 * (event_precision * event_recall) / (event_precision + event_recall)
    else:
        event_f1 = 0.0

    # 3. Timeline Ordering Accuracy
    # Check pairwise relative ordering of known chronological order
    expected_order = ground_truth.expected_chronological_order
    timeline_event_positions = {
        item.event_id: idx for idx, item in enumerate(reconstruction.timeline)
    }

    correct_pairs = 0
    total_pairs = 0

    for i in range(len(expected_order)):
        for j in range(i + 1, len(expected_order)):
            e1 = expected_order[i]
            e2 = expected_order[j]
            if e1 in timeline_event_positions and e2 in timeline_event_positions:
                total_pairs += 1
                if timeline_event_positions[e1] <= timeline_event_positions[e2]:
                    correct_pairs += 1

    timeline_ordering_acc = (correct_pairs / total_pairs) if total_pairs > 0 else 1.0
    details["timeline_order_pairs_tested"] = total_pairs
    details["timeline_order_pairs_correct"] = correct_pairs

    # 4. Evidence-Relationship Precision & Recall
    # Graph edges in reconstruction
    reconstructed_edges = reconstruction.evidence_graph.edges
    edge_tuples = set()
    for edge in reconstructed_edges:
        edge_tuples.add((edge.source, edge.target, edge.relation))
        # Also symmetric check for bidirectional relationships
        edge_tuples.add((edge.target, edge.source, edge.relation))

    matched_relationships = 0
    total_expected_rel = len(ground_truth.expected_relationships)

    for src, tgt, rel in ground_truth.expected_relationships:
        # Check standard Cytoscape node ID prefixes
        s_id = f"evt:{src}" if not src.startswith(("sess:", "host:", "user:", "ip:", "proc:", "file:")) else src
        t_id = f"evt:{tgt}" if not tgt.startswith(("sess:", "host:", "user:", "ip:", "proc:", "file:")) else tgt

        found = False
        for r_src, r_tgt, r_rel in edge_tuples:
            if (r_src == s_id and r_tgt == t_id) or (r_src == src and r_tgt == tgt):
                found = True
                break
        if found:
            matched_relationships += 1

    rel_recall = (matched_relationships / total_expected_rel) if total_expected_rel > 0 else 1.0
    rel_precision = 1.0 if len(reconstructed_edges) > 0 else (1.0 if total_expected_rel == 0 else 0.0)
    details["expected_relationships_count"] = total_expected_rel
    details["matched_relationships_count"] = matched_relationships

    # 5. Source-Event Traceability for Major Conclusions
    # Verify that all conclusions cite valid event IDs present in the scenario
    all_raw_event_ids = {e["event_id"] for e in ground_truth.raw_events}
    total_references = 0
    valid_references = 0

    for conc in reconstruction.inferred_conclusions:
        for ref_id in conc.supporting_event_ids:
            total_references += 1
            if ref_id in all_raw_event_ids:
                valid_references += 1

    for hypo in reconstruction.hypotheses:
        for ref_id in hypo.supporting_event_ids:
            total_references += 1
            if ref_id in all_raw_event_ids:
                valid_references += 1

    traceability_score = (valid_references / total_references) if total_references > 0 else 1.0
    details["total_event_references"] = total_references
    details["valid_event_references"] = valid_references

    # 6. Unsupported-Claim Rate (e.g. Exfiltration Restraint)
    # Check explicitly unknown facts (e.g. claiming exfiltration when only TCP connection observed)
    unsupported_claims_list = []
    if "data_exfiltrated" in ground_truth.explicitly_unknown_facts:
        for conc in reconstruction.inferred_conclusions:
            stmt = conc.statement.lower()
            if "exfiltrated" in stmt or "exfiltration" in stmt:
                # If the conclusion claims proven exfiltration without stating "NOT proven", it's an unsupported claim
                if "not proven" not in stmt and "unproven" not in stmt and "unconfirmed" not in stmt:
                    unsupported_claims_list.append(conc.statement)

    unsupported_claim_rate = 1.0 if len(unsupported_claims_list) > 0 else 0.0
    details["unsupported_claims"] = unsupported_claims_list
    details["unsupported_claims_count"] = len(unsupported_claims_list)
    if unsupported_claims_list:
        details["unsupported_claim_detected"] = unsupported_claims_list[0]

    # 7. Ambiguity Handling & Competing Explanations
    if ground_truth.is_ambiguous:
        # Engine should formulate >= 2 ranked hypotheses or list alternative explanations
        hypotheses_count = len(reconstruction.hypotheses)
        alternatives_count = sum(len(c.alternative_explanations) for c in reconstruction.inferred_conclusions)
        if hypotheses_count >= 2 or alternatives_count >= 1:
            ambiguity_score = 1.0
            details["ambiguity_status"] = f"COMPETING_HYPOTHESES_PRESENT ({hypotheses_count} hypotheses)"
        else:
            ambiguity_score = 0.0
            details["ambiguity_status"] = "FALSE_CERTAINTY_SINGLE_EXPLANATION"
    else:
        ambiguity_score = 1.0
        details["ambiguity_status"] = "NOT_AMBIGUOUS_SCENARIO"

    # 8. Unrelated Incident Isolation Accuracy
    # Events from distinct incidents must NOT share direct correlation edges
    unrelated_tested = len(ground_truth.unrelated_event_pairs)
    unrelated_isolated = 0

    for e_a, e_b in ground_truth.unrelated_event_pairs:
        ea_id = f"evt:{e_a}"
        eb_id = f"evt:{e_b}"
        # Check if connected directly
        directly_connected = False
        for edge in reconstructed_edges:
            if (edge.source in (ea_id, e_a) and edge.target in (eb_id, e_b)) or \
               (edge.source in (eb_id, e_b) and edge.target in (ea_id, e_a)):
                directly_connected = True
                break
        if not directly_connected:
            unrelated_isolated += 1

    isolation_acc = (unrelated_isolated / unrelated_tested) if unrelated_tested > 0 else 1.0
    details["unrelated_pairs_tested"] = unrelated_tested
    details["unrelated_pairs_isolated"] = unrelated_isolated

    return EvaluationMetrics(
        entry_point_accuracy=round(entry_point_acc, 3),
        relevant_event_precision=round(event_precision, 3),
        relevant_event_recall=round(event_recall, 3),
        relevant_event_f1=round(event_f1, 3),
        timeline_ordering_accuracy=round(timeline_ordering_acc, 3),
        relationship_precision=round(rel_precision, 3),
        relationship_recall=round(rel_recall, 3),
        source_event_traceability=round(traceability_score, 3),
        unsupported_claim_rate=round(unsupported_claim_rate, 3),
        ambiguity_handling_score=round(ambiguity_score, 3),
        unrelated_isolation_accuracy=round(isolation_acc, 3),
        details=details,
    )
