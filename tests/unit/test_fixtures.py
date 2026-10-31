"""
Unit tests validating the benchmark fictional security fixtures and graph modeling.
"""

from pathlib import Path
import pytest

from investigation_engine.graph.base import InvestigationGraph
from investigation_engine.loader import load_events_from_fixture, load_raw_fixture_file
from investigation_engine.models import EventSeverity, EventType


class TestSimulatedFixtures:
    def test_fixture_loading_and_zero_validation_errors(self, fixtures_dir: Path):
        fixture_path = fixtures_dir / "simulated_events.json"
        assert fixture_path.is_file(), f"Fixture file not found: {fixture_path}"

        events, validation_result = load_events_from_fixture(fixture_path)

        # Ensure all events are valid
        assert validation_result.is_valid is True
        assert validation_result.malformed_events_count == 0
        assert validation_result.duplicate_events_count == 0
        assert validation_result.valid_events_count > 0
        assert len(events) == validation_result.valid_events_count

    def test_both_routine_and_suspicious_activities_present(self, fixtures_dir: Path):
        fixture_path = fixtures_dir / "simulated_events.json"
        events, _ = load_events_from_fixture(fixture_path)

        routine_events = [e for e in events if not e.is_suspicious]
        suspicious_events = [e for e in events if e.is_suspicious]

        assert len(routine_events) >= 3, "Expected at least 3 routine activities"
        assert len(suspicious_events) >= 3, "Expected at least 3 suspicious activities"

        # Suspicious events should include MITRE ATT&CK labels
        for s_evt in suspicious_events:
            assert s_evt.mitre_attack_id is not None
            assert s_evt.severity in (EventSeverity.MEDIUM, EventSeverity.HIGH, EventSeverity.CRITICAL)

    def test_all_four_required_event_types_covered(self, fixtures_dir: Path):
        fixture_path = fixtures_dir / "simulated_events.json"
        events, _ = load_events_from_fixture(fixture_path)

        present_types = {e.event_type for e in events}
        required_types = {
            EventType.AUTHENTICATION,
            EventType.PROCESS_EXECUTION,
            EventType.FILE_AUDIT,
            EventType.NETWORK_CONNECTION,
        }
        assert required_types.issubset(present_types), f"Missing event types: {required_types - present_types}"

    def test_evidence_provenance_preserved(self, fixtures_dir: Path):
        """Every event must have non-empty original_event_data and a traceable source_event_id."""
        fixture_path = fixtures_dir / "simulated_events.json"
        events, _ = load_events_from_fixture(fixture_path)

        for evt in events:
            assert evt.original_event_data is not None
            assert isinstance(evt.original_event_data, dict)
            assert len(evt.original_event_data) > 0, f"Event {evt.event_id} has empty original_event_data"
            assert evt.source_event_id is not None, f"Event {evt.event_id} has missing source_event_id"
            assert len(evt.source_event_id) > 0

    def test_fictional_metadata_disclaimer_present(self, fixtures_dir: Path):
        """Verify the raw fixture file has explicit fictional simulation metadata."""
        fixture_path = fixtures_dir / "simulated_events.json"
        import json
        with fixture_path.open("r", encoding="utf-8") as f:
            raw = json.load(f)
        assert "dataset_metadata" in raw
        assert raw["dataset_metadata"]["is_fictional"] is True


class TestInvestigationGraphFoundation:
    def test_graph_construction_from_fixtures(self, fixtures_dir: Path):
        fixture_path = fixtures_dir / "simulated_events.json"
        events, _ = load_events_from_fixture(fixture_path)

        inv_graph = InvestigationGraph(name="Test-Investigation")
        inv_graph.build_from_events(events)

        # Graph should have nodes for events and extracted entities (hosts, users, IPs, etc.)
        assert inv_graph.graph.number_of_nodes() > len(events)
        assert inv_graph.graph.number_of_edges() > 0

    def test_cytoscape_elements_serialization(self, fixtures_dir: Path):
        fixture_path = fixtures_dir / "simulated_events.json"
        events, _ = load_events_from_fixture(fixture_path)

        inv_graph = InvestigationGraph()
        inv_graph.build_from_events(events)
        cytoscape_elements = inv_graph.to_cytoscape_elements()

        assert len(cytoscape_elements) > 0

        # Validate structure of Cytoscape.js elements
        nodes = [el for el in cytoscape_elements if el.get("group") == "nodes"]
        edges = [el for el in cytoscape_elements if el.get("group") == "edges"]

        assert len(nodes) > 0
        assert len(edges) > 0

        for node in nodes:
            assert "id" in node["data"]
            assert "node_type" in node["data"]

        for edge in edges:
            assert "id" in edge["data"]
            assert "source" in edge["data"]
            assert "target" in edge["data"]
            assert "relation" in edge["data"]
