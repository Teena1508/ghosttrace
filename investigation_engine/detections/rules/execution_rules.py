"""
Process Execution Detection Rules for GhostTrace.
Detects suspicious command lines, encoded payloads, download cradles, and privilege abuse.
"""

from __future__ import annotations

import re
from typing import List, Optional

from investigation_engine.models import DetectionFinding, EventSeverity, EventType, SecurityEvent
from investigation_engine.detections.rule import BaseDetectionRule

SUSPICIOUS_PATTERNS = [
    (
        re.compile(r"(curl|wget)\s+.*\|\s*(sh|bash)", re.IGNORECASE),
        "Download Cradle (curl/wget pipe to shell)",
        "T1059.004",
        EventSeverity.HIGH,
    ),
    (
        re.compile(r"base64\s+(-d|--decode)", re.IGNORECASE),
        "Base64 Decoded Command Execution",
        "T1140",
        EventSeverity.HIGH,
    ),
    (
        re.compile(r"(powershell|pwsh).*(-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{10,}", re.IGNORECASE),
        "Encoded PowerShell Command Execution",
        "T1059.001",
        EventSeverity.HIGH,
    ),
    (
        re.compile(r"certutil.*(-urlcache|-decode)", re.IGNORECASE),
        "Living-off-the-Land Binary (CertUtil Ingress/Decode)",
        "T1105",
        EventSeverity.HIGH,
    ),
    (
        re.compile(r"vssadmin\s+delete\s+shadows", re.IGNORECASE),
        "Shadow Copy Deletion (Inhibited Recovery)",
        "T1490",
        EventSeverity.CRITICAL,
    ),
    (
        re.compile(r"sudo\s+cat\s+/etc/shadow", re.IGNORECASE),
        "Direct Shadow File Read via Sudo",
        "T1003.008",
        EventSeverity.HIGH,
    ),
    (
        re.compile(r"sudo\s+(/bin/)?(bash|sh|su)", re.IGNORECASE),
        "Interactive Shell Spawned via Sudo",
        "T1548.003",
        EventSeverity.MEDIUM,
    ),
    (
        re.compile(r"iptables\s+(-F|-X)", re.IGNORECASE),
        "Firewall Rule Flush (Impair Network Defenses)",
        "T1562.001",
        EventSeverity.MEDIUM,
    ),
    (
        re.compile(r"(nc|ncat|netcat)\s+.*(-e|-c)\s+(/bin/)?(sh|bash|zsh)", re.IGNORECASE),
        "Netcat Executable Reverse Shell",
        "T1059.004",
        EventSeverity.CRITICAL,
    ),
    (
        re.compile(r"(bash|sh|zsh)\s+-i\s+>&?\s*/dev/tcp", re.IGNORECASE),
        "Interactive Bash TCP Reverse Shell",
        "T1059.004",
        EventSeverity.CRITICAL,
    ),
    (
        re.compile(r"python.*(-c|exec).*socket.*connect.*(pty\.spawn|subprocess)", re.IGNORECASE),
        "Python Interactive Socket Reverse Shell",
        "T1059.006",
        EventSeverity.CRITICAL,
    ),
    (
        re.compile(r"security\s+dump-keychain", re.IGNORECASE),
        "macOS Keychain Credential Dump",
        "T1555.001",
        EventSeverity.CRITICAL,
    ),
    (
        re.compile(r"(xmrig|minerd|cryptonight|stratum\+tcp)", re.IGNORECASE),
        "Cryptocurrency Mining Worker",
        "T1496",
        EventSeverity.HIGH,
    ),
    (
        re.compile(r"GHOSTTRACE_TEST_THREAT", re.IGNORECASE),
        "Authorized Device Security Verification Probe",
        "T1059",
        EventSeverity.HIGH,
    ),
]


class SuspiciousCommandExecutionRule(BaseDetectionRule):
    """
    Detects command lines matching high-risk adversarial execution patterns.
    """

    @property
    def rule_id(self) -> str:
        return "GT-EXEC-001"

    @property
    def rule_name(self) -> str:
        return "Suspicious Process Execution & Command-Line Anomaly"

    @property
    def severity(self) -> EventSeverity:
        return EventSeverity.HIGH

    @property
    def category(self) -> str:
        return "EXECUTION"

    def evaluate(self, events: List[SecurityEvent]) -> List[DetectionFinding]:
        findings: List[DetectionFinding] = []

        for e in events:
            if e.event_type != EventType.PROCESS_EXECUTION:
                continue

            cmd = e.command_line or ""
            proc_name = e.process_name or ""
            combined_text = f"{proc_name} {cmd}".strip()

            for pattern, pattern_label, mitre_id, pattern_sev in SUSPICIOUS_PATTERNS:
                if pattern.search(combined_text):
                    indicators = [
                        f"Process name: '{proc_name or 'unspecified'}'.",
                        f"Command line invocation: '{cmd}'.",
                        f"Execution pattern match: {pattern_label}.",
                    ]
                    if e.user_id:
                        indicators.append(f"Executed under account: {e.user_id}.")
                    if e.host_id:
                        indicators.append(f"Executed on host: {e.host_id}.")

                    benign = [
                        "Authorized administrative software deployment, server provisioning (e.g. Terraform, cloud-init), or system configuration management.",
                        "System administrator performing routine maintenance or troubleshooting via terminal.",
                        "Automated build or test pipeline running packaged helper commands.",
                    ]

                    findings.append(
                        DetectionFinding(
                            finding_id=f"finding-exec-{e.event_id}",
                            rule_id=self.rule_id,
                            rule_name=f"{self.rule_name} ({pattern_label})",
                            severity=pattern_sev,
                            category=self.category,
                            mitre_attack_id=mitre_id,
                            summary=f"Suspicious command line execution detected: {pattern_label}",
                            observed_indicators=indicators,
                            benign_alternatives=benign,
                            supporting_event_ids=[e.event_id],
                            confidence_assessment="SUSPICIOUS_INDICATOR",
                            missing_telemetry_limitations=(
                                "Parent process tree lineage, execution environment variables, and shell history "
                                "are needed to conclusively distinguish interactive human malice from approved automated automation."
                            ),
                        )
                    )
                    break

        return findings
