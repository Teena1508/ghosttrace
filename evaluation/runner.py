"""
Command-Line Repeatable Evaluation Runner for GhostTrace Phase 6.

Executes offline forensic evaluations against hidden synthetic benchmark incidents:
1. Generates or loads hidden simulated scenarios with strict ground-truth separation.
2. Sends ONLY blinded, shuffled event data to the reconstruction engine.
3. Collects reconstruction results without any answer leakage.
4. Evaluates results against the isolated ground-truth records.
5. Produces machine-readable JSON reports and formatted human-readable summaries.
6. Records seeds and configurations for exact reproducibility.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from evaluation.evaluator import evaluate_reconstruction
from evaluation.generator import generate_evaluation_suite
from evaluation.models import GroundTruthScenario, ScenarioEvaluationResult
from investigation_engine.models import SecurityEvent
from investigation_engine.reconstruction import reconstruct_attack_timeline


def run_scenario(
    scenario_id: str,
    blind_events: List[Dict[str, Any]],
    ground_truth: GroundTruthScenario,
    seed: int,
) -> ScenarioEvaluationResult:
    """
    Evaluates a single scenario ensuring complete answer isolation.
    Reconstruction engine ONLY receives the blind_events list.
    """
    # Convert blinded dicts to SecurityEvent models
    sec_events = [SecurityEvent(**e) for e in blind_events]

    # Measure reconstruction execution time
    start_time = time.perf_counter()
    reconstruction = reconstruct_attack_timeline(sec_events)
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    # Score reconstruction against isolated ground-truth
    metrics = evaluate_reconstruction(reconstruction, ground_truth)

    incident_cnt = len(ground_truth.incident_event_ids)
    routine_cnt = len(ground_truth.routine_event_ids)

    return ScenarioEvaluationResult(
        scenario_id=scenario_id,
        scenario_name=ground_truth.name,
        seed=seed,
        metrics=metrics,
        execution_time_ms=round(elapsed_ms, 2),
        reconstructed_investigation_id=reconstruction.investigation_id,
        total_events_evaluated=len(sec_events),
        incident_events_count=incident_cnt,
        routine_events_count=routine_cnt,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def run_evaluation_suite(
    seed: int = 42,
    target_scenario: Optional[str] = None,
) -> Tuple[List[ScenarioEvaluationResult], Dict[str, Any]]:
    """
    Runs the full evaluation benchmark or a specific scenario by ID.
    Returns individual scenario results and aggregate metrics.
    """
    suite = generate_evaluation_suite(seed=seed)

    if target_scenario:
        if target_scenario not in suite:
            available = list(suite.keys())
            raise ValueError(f"Scenario '{target_scenario}' not found. Available: {available}")
        scenarios_to_run = {target_scenario: suite[target_scenario]}
    else:
        scenarios_to_run = suite

    results: List[ScenarioEvaluationResult] = []

    for sc_id, (blind_events, ground_truth) in scenarios_to_run.items():
        res = run_scenario(
            scenario_id=sc_id,
            blind_events=blind_events,
            ground_truth=ground_truth,
            seed=seed,
        )
        results.append(res)

    # Compute macro-aggregates across evaluated scenarios
    count = len(results)
    if count > 0:
        avg_entry_point_acc = sum(r.metrics.entry_point_accuracy for r in results) / count
        avg_precision = sum(r.metrics.relevant_event_precision for r in results) / count
        avg_recall = sum(r.metrics.relevant_event_recall for r in results) / count
        avg_f1 = sum(r.metrics.relevant_event_f1 for r in results) / count
        avg_order_acc = sum(r.metrics.timeline_ordering_accuracy for r in results) / count
        avg_rel_prec = sum(r.metrics.relationship_precision for r in results) / count
        avg_rel_rec = sum(r.metrics.relationship_recall for r in results) / count
        avg_traceability = sum(r.metrics.source_event_traceability for r in results) / count
        avg_unsupported_rate = sum(r.metrics.unsupported_claim_rate for r in results) / count
        avg_ambiguity = sum(r.metrics.ambiguity_handling_score for r in results) / count
        avg_isolation = sum(r.metrics.unrelated_isolation_accuracy for r in results) / count
        avg_time = sum(r.execution_time_ms for r in results) / count
    else:
        avg_entry_point_acc = avg_precision = avg_recall = avg_f1 = avg_order_acc = 0.0
        avg_rel_prec = avg_rel_rec = avg_traceability = avg_unsupported_rate = 0.0
        avg_ambiguity = avg_isolation = avg_time = 0.0

    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "seed": seed,
        "total_scenarios_evaluated": count,
        "macro_averages": {
            "entry_point_accuracy": round(avg_entry_point_acc, 4),
            "relevant_event_precision": round(avg_precision, 4),
            "relevant_event_recall": round(avg_recall, 4),
            "relevant_event_f1": round(avg_f1, 4),
            "timeline_ordering_accuracy": round(avg_order_acc, 4),
            "relationship_precision": round(avg_rel_prec, 4),
            "relationship_recall": round(avg_rel_rec, 4),
            "source_event_traceability": round(avg_traceability, 4),
            "unsupported_claim_rate": round(avg_unsupported_rate, 4),
            "ambiguity_handling_score": round(avg_ambiguity, 4),
            "unrelated_isolation_accuracy": round(avg_isolation, 4),
            "average_execution_time_ms": round(avg_time, 2),
        },
    }

    return results, summary


def format_text_summary(results: List[ScenarioEvaluationResult], summary: Dict[str, Any]) -> str:
    """
    Formats evaluation results into a human-readable ASCII table and scorecard.
    """
    lines = []
    lines.append("=" * 115)
    lines.append("  GHOSTTRACE PHASE 6: HIDDEN-ATTACK CHALLENGE & FORENSIC RECONSTRUCTION BENCHMARK")
    lines.append("=" * 115)
    lines.append(f"Timestamp: {summary['timestamp']} | Reproducibility Seed: {summary['seed']}")
    lines.append(f"Scenarios Evaluated: {summary['total_scenarios_evaluated']}")
    lines.append("-" * 115)
    header = (
        f"{'Scenario ID':<18} | {'Events':<6} | {'EntryPt':<7} | {'Prec':<5} | {'Rec':<5} | "
        f"{'F1':<5} | {'Order':<5} | {'RelPrec':<7} | {'RelRec':<6} | {'Trace':<5} | {'Restraint':<9} | {'Time(ms)':<8}"
    )
    lines.append(header)
    lines.append("-" * 115)

    for r in results:
        m = r.metrics
        restraint_score = 1.0 - m.unsupported_claim_rate
        line = (
            f"{r.scenario_id:<18} | {r.total_events_evaluated:<6} | {m.entry_point_accuracy * 100:>6.1f}% | "
            f"{m.relevant_event_precision * 100:>4.1f}% | {m.relevant_event_recall * 100:>4.1f}% | "
            f"{m.relevant_event_f1 * 100:>4.1f}% | {m.timeline_ordering_accuracy * 100:>4.1f}% | "
            f"{m.relationship_precision * 100:>6.1f}% | {m.relationship_recall * 100:>5.1f}% | "
            f"{m.source_event_traceability * 100:>4.1f}% | {restraint_score * 100:>8.1f}% | "
            f"{r.execution_time_ms:>8.1f}"
        )
        lines.append(line)

    lines.append("-" * 115)
    avg = summary["macro_averages"]
    avg_restraint = 1.0 - avg["unsupported_claim_rate"]
    macro_line = (
        f"{'MACRO AVERAGE':<18} | {'-':<6} | {avg['entry_point_accuracy'] * 100:>6.1f}% | "
        f"{avg['relevant_event_precision'] * 100:>4.1f}% | {avg['relevant_event_recall'] * 100:>4.1f}% | "
        f"{avg['relevant_event_f1'] * 100:>4.1f}% | {avg['timeline_ordering_accuracy'] * 100:>4.1f}% | "
        f"{avg['relationship_precision'] * 100:>6.1f}% | {avg['relationship_recall'] * 100:>5.1f}% | "
        f"{avg['source_event_traceability'] * 100:>4.1f}% | {avg_restraint * 100:>8.1f}% | "
        f"{avg['average_execution_time_ms']:>8.1f}"
    )
    lines.append(macro_line)
    lines.append("=" * 115)

    lines.append("\nSCENARIO BREAKDOWN & QUALITATIVE FINDINGS:")
    for r in results:
        lines.append(f"\n[{r.scenario_id}] {r.scenario_name}")
        lines.append(f"  Execution Time: {r.execution_time_ms} ms | Events: {r.total_events_evaluated} ({r.incident_events_count} incident, {r.routine_events_count} routine)")
        m = r.metrics
        d = m.details
        lines.append(f"  - Entry Point Status: {d.get('entry_point_status', 'N/A')}")
        lines.append(f"  - Relevant Event Detection: TP={len(d.get('tp_events', []))}, FP={len(d.get('fp_events', []))}, FN={len(d.get('fn_events', []))}")
        if d.get("missed_relationships"):
            lines.append(f"  - Missed Relationships: {len(d['missed_relationships'])}")
        if d.get("unsupported_claims"):
            lines.append(f"  - Unsupported Exfiltration/Certainty Claims: {d['unsupported_claims']}")
        else:
            lines.append("  - Unsupported Claims: 0 (Proper forensic restraint maintained)")
        if "alternative_hypotheses_count" in d:
            lines.append(f"  - Alternative Hypotheses Formulated: {d['alternative_hypotheses_count']} (Ambiguity Score: {m.ambiguity_handling_score * 100:.1f}%)")
        if "unrelated_pairs_tested" in d and d["unrelated_pairs_tested"] > 0:
            lines.append(f"  - Unrelated Cluster Isolation: {m.unrelated_isolation_accuracy * 100:.1f}% ({d.get('isolated_pairs_count')}/{d.get('unrelated_pairs_tested')} pairs)")

    lines.append("\n" + "=" * 115)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="GhostTrace Phase 6: Hidden Attack Benchmark & Evaluation Runner"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducible event shuffling (default: 42)",
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default=None,
        help="Specific scenario ID to run (e.g. 'scenario_account_compromise_chain'). Default: all",
    )
    parser.add_argument(
        "--json-out",
        type=str,
        default=None,
        help="Path to write machine-readable JSON evaluation report",
    )
    parser.add_argument(
        "--summary-out",
        type=str,
        default=None,
        help="Path to write human-readable text summary",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress printing text summary to stdout",
    )

    args = parser.parse_args()

    results, summary = run_evaluation_suite(
        seed=args.seed,
        target_scenario=args.scenario,
    )

    text_summary = format_text_summary(results, summary)

    if not args.quiet:
        print(text_summary)

    if args.summary_out:
        with open(args.summary_out, "w", encoding="utf-8") as f:
            f.write(text_summary)
        print(f"\n[+] Wrote human-readable summary to: {args.summary_out}")

    if args.json_out:
        report_data = {
            "summary": summary,
            "results": [r.model_dump() for r in results],
        }
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        print(f"[+] Wrote machine-readable JSON report to: {args.json_out}")


if __name__ == "__main__":
    main()
