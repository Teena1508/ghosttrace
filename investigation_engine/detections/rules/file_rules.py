"""
File Audit Detection Rules for GhostTrace.
Detects access, reading, or modification of sensitive credential stores, secrets, and system configuration.
"""

from __future__ import annotations

import re
from typing import List, Optional

from investigation_engine.models import DetectionFinding, EventSeverity, EventType, SecurityEvent
from investigation_engine.detections.rule import BaseDetectionRule

SENSITIVE_PATHS = [
    (re.compile(r"/etc/shadow", re.IGNORECASE), "Linux Shadow Password Hashes", "T1003.008", EventSeverity.HIGH),
    (re.compile(r"/etc/sudoers(\.d)?", re.IGNORECASE), "Sudo Configuration Policy", "T1548.003", EventSeverity.MEDIUM),
    (re.compile(r"(sim_secrets|api_keys|\.env|credentials)", re.IGNORECASE), "Application Secrets / Environment API Keys", "T1552.001", EventSeverity.HIGH),
    (re.compile(r"\.ssh/(id_rsa|id_ecdsa|authorized_keys)", re.IGNORECASE), "SSH Private Keys or Authorized Keys", "T1552.004", EventSeverity.HIGH),
    (re.compile(r"(\\config\\SYSTEM|\bSAM\b|\bNTDS\.dit\b)", re.IGNORECASE), "Windows Registry SAM/SYSTEM or Active Directory NTDS", "T1003.002", EventSeverity.CRITICAL),
]


class SensitiveFileAccessRule(BaseDetectionRule):
    """
    Detects audit events or commands accessing sensitive files.
    """

    @property
    def rule_id(self) -> str:
        return "GT-FILE-001"

    @property
    def rule_name(self) -> str:
        return "Sensitive File / Credential Store Access"

    @property
    def severity(self) -> EventSeverity:
        return EventSeverity.HIGH

    @property
    def category(self) -> str:
        return "CREDENTIAL_ACCESS"

    def evaluate(self, events: List[SecurityEvent]) -> List[DetectionFinding]:
        findings: List[DetectionFinding] = []

        for e in events:
            # Check file_path in FILE_AUDIT or command_line in PROCESS_EXECUTION
            target_str = ""
            if e.event_type == EventType.FILE_AUDIT and e.file_path:
                target_str = e.file_path
            elif e.command_line:
                target_str = e.command_line

            if not target_str:
                continue

            for pattern, label, mitre_id, sev in SENSITIVE_PATHS:
                if pattern.search(target_str):
                    indicators = [
                        f"Targeted file / resource: {target_str}.",
                        f"Sensitive resource classification: {label}.",
                    ]
                    if e.user_id:
                        indicators.append(f"Accessed by user account: {e.user_id}.")
                    if e.host_id:
                        indicators.append(f"Host: {e.host_id}.")

                    benign = [
                        "Automated system backup or disaster recovery daemon reading server state.",
                        "Vulnerability scanner, security audit agent (e.g. Lynis, Wazuh, Osquery), or compliance monitor.",
                        "Legitimate administrator intentionally updating configuration or rotating secrets.",
                    ]

                    findings.append(
                        DetectionFinding(
                            finding_id=f"finding-file-{e.event_id}",
                            rule_id=self.rule_id,
                            rule_name=f"{self.rule_name} ({label})",
                            severity=sev,
                            category=self.category,
                            mitre_attack_id=mitre_id,
                            summary=f"Access to sensitive resource detected: {label}",
                            observed_indicators=indicators,
                            benign_alternatives=benign,
                            supporting_event_ids=[e.event_id],
                            confidence_assessment="SUSPICIOUS_INDICATOR",
                            missing_telemetry_limitations=(
                                "Missing file system SACL/auditd records confirming whether data was modified or successfully read, "
                                "and missing outbound network socket auditing to prove whether exfiltration occurred."
                            ),
                        )
                    )
                    break

        return findings
