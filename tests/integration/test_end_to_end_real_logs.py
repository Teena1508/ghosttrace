"""
End-to-End Investigation Integration Tests with Non-Predefined Real Log Files.
Demonstrates:
1. Attack investigation from non-predefined Windows XML logs.
2. Attack investigation from non-predefined Linux auth.log.
3. Benign baseline investigation ensuring zero false-positive compromise claims.
4. Ambiguous dataset investigation ensuring competing explanations and honest uncertainty.
"""

from pathlib import Path
import pytest

from investigation_engine.importer import parse_and_import_logs
from investigation_engine.reconstruction import reconstruct_attack_timeline

LOGS_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "logs"


class TestEndToEndRealLogsInvestigation:
    def test_windows_xml_intrusion_end_to_end(self):
        xml_file = LOGS_DIR / "windows_host_intrusion.xml"
        assert xml_file.is_file(), f"File {xml_file} must exist."
        content = xml_file.read_text(encoding="utf-8")

        # 1. Import and normalize
        import_res = parse_and_import_logs(content, filename="windows_host_intrusion.xml")
        assert import_res.format_detected == "WINDOWS_XML"
        assert import_res.source_filename == "windows_host_intrusion.xml"
        assert import_res.valid_events_count == 6
        assert len(import_res.events) == 6

        # Check raw records and provenance preserved
        for evt in import_res.events:
            assert evt.original_event_data is not None
            assert evt.source_event_id is not None
            assert evt.original_event_data["source_file"] == "windows_host_intrusion.xml"

        # 2. Run reconstruction pipeline
        inv_result = reconstruct_attack_timeline(import_res.events)

        # 3. Verify detection findings
        findings = inv_result.detection_findings
        assert len(findings) >= 2

        # Verify brute force rule match
        bf = next((f for f in findings if f.rule_id == "GT-AUTH-001"), None)
        assert bf is not None
        assert "198.51.100.80" in bf.summary
        assert len(bf.benign_alternatives) >= 2
        assert bf.missing_telemetry_limitations is not None

        # Verify execution rule match (encoded powershell)
        exec_find = next((f for f in findings if f.rule_id == "GT-EXEC-001"), None)
        assert exec_find is not None
        assert len(exec_find.supporting_event_ids) >= 1

        # Verify network port 4444 rule match
        net_find = next((f for f in findings if f.rule_id == "GT-NET-001"), None)
        assert net_find is not None

        # 4. Verify candidate entry points
        assert len(inv_result.candidate_entry_points) >= 1
        entry = inv_result.candidate_entry_points[0]
        assert entry.user_id == "contractor_mark"
        assert entry.source_ip == "198.51.100.80"

        # 5. Verify hypotheses and timeline
        assert len(inv_result.hypotheses) >= 1
        top_hyp = inv_result.hypotheses[0]
        assert top_hyp.score > 0.0
        assert len(top_hyp.supporting_event_ids) > 0

    def test_linux_auth_log_intrusion_end_to_end(self):
        log_file = LOGS_DIR / "linux_auth_investigation.log"
        assert log_file.is_file()
        content = log_file.read_text(encoding="utf-8")

        import_res = parse_and_import_logs(content, filename="linux_auth_investigation.log")
        assert import_res.format_detected == "LINUX_AUTH_LOG"
        assert import_res.valid_events_count == 6

        inv_result = reconstruct_attack_timeline(import_res.events)

        # Detections: brute force and file read
        findings = inv_result.detection_findings
        assert any(f.rule_id == "GT-AUTH-001" for f in findings)
        assert any(f.rule_id == "GT-FILE-001" for f in findings)

        # Inferred conclusions cite supporting events and have alternatives
        for conc in inv_result.inferred_conclusions:
            assert len(conc.supporting_event_ids) > 0
            assert len(conc.alternative_explanations) > 0

    def test_benign_operations_dataset_produces_no_compromise(self):
        log_file = LOGS_DIR / "benign_operations.jsonl"
        assert log_file.is_file()
        content = log_file.read_text(encoding="utf-8")

        import_res = parse_and_import_logs(content, filename="benign_operations.jsonl")
        assert import_res.valid_events_count == 4

        inv_result = reconstruct_attack_timeline(import_res.events)

        # Must NOT detect any malicious rules on routine operations
        assert len(inv_result.detection_findings) == 0

        # Entry point must be empty or none
        assert len(inv_result.candidate_entry_points) == 0

        # Top hypothesis must be Routine/Normal Operations
        top_hyp = inv_result.hypotheses[0]
        assert any(term in top_hyp.title.lower() for term in ("routine", "benign", "normal", "baseline"))

    def test_ambiguous_dataset_produces_competing_hypotheses_and_unresolved_questions(self):
        log_file = LOGS_DIR / "ambiguous_off_hours.jsonl"
        assert log_file.is_file()
        content = log_file.read_text(encoding="utf-8")

        import_res = parse_and_import_logs(content, filename="ambiguous_off_hours.jsonl")
        assert import_res.valid_events_count == 3

        inv_result = reconstruct_attack_timeline(import_res.events)

        # Must have competing hypotheses
        assert len(inv_result.hypotheses) >= 2

        # Must have explicit unresolved questions highlighting what is missing
        assert len(inv_result.unresolved_questions) >= 1
        q = inv_result.unresolved_questions[0]
        assert q.missing_evidence_type != ""
