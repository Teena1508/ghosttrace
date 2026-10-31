"""
Network Anomaly Detection Rules for GhostTrace.
Detects suspicious egress, non-standard outbound ports, and lateral SMB scanning.
"""

from __future__ import annotations

from typing import List, Optional

from investigation_engine.models import DetectionFinding, EventSeverity, EventType, SecurityEvent
from investigation_engine.detections.rule import BaseDetectionRule

SUSPICIOUS_PORTS = {
    4444: ("Metasploit / Reverse Shell Default Port", "T1071", EventSeverity.HIGH),
    1337: ("Hacker / CTF Conventional Port", "T1071", EventSeverity.HIGH),
    31337: ("Back Orifice / Legacy RAT Port", "T1071", EventSeverity.HIGH),
    8888: ("Alternate HTTP / Proxy Tunnel", "T1090", EventSeverity.MEDIUM),
    6667: ("IRC Default Port (Legacy Botnet C2)", "T1071.001", EventSeverity.HIGH),
}

LATERAL_PORTS = {445, 139, 3389}


class SuspiciousNetworkConnectionRule(BaseDetectionRule):
    """
    Detects network connections targeting suspicious non-standard ports or lateral movement protocols.
    """

    @property
    def rule_id(self) -> str:
        return "GT-NET-001"

    @property
    def rule_name(self) -> str:
        return "Suspicious Network Connection & Protocol Anomaly"

    @property
    def severity(self) -> EventSeverity:
        return EventSeverity.MEDIUM

    @property
    def category(self) -> str:
        return "COMMAND_AND_CONTROL"

    def evaluate(self, events: List[SecurityEvent]) -> List[DetectionFinding]:
        findings: List[DetectionFinding] = []

        for e in events:
            if e.event_type != EventType.NETWORK_CONNECTION:
                continue

            port = e.destination_port
            dst_ip = e.destination_ip or ""
            src_ip = e.source_ip or ""

            if not port:
                continue

            # Case 1: Known suspicious egress port
            if port in SUSPICIOUS_PORTS:
                desc, mitre_id, sev = SUSPICIOUS_PORTS[port]
                indicators = [
                    f"Destination IP: {dst_ip or 'unknown'}.",
                    f"Destination Port: {port} ({desc}).",
                ]
                if e.host_id:
                    indicators.append(f"Originating host: {e.host_id}.")
                if e.process_name:
                    indicators.append(f"Originating process: {e.process_name}.")

                benign = [
                    "Developer testing a custom web service or microservice listening on an alternate development port.",
                    "Internal non-standard proxy, debugging tunnel, or testing environment.",
                ]

                findings.append(
                    DetectionFinding(
                        finding_id=f"finding-net-port-{e.event_id}",
                        rule_id=self.rule_id,
                        rule_name=f"{self.rule_name} (Port {port})",
                        severity=sev,
                        category=self.category,
                        mitre_attack_id=mitre_id,
                        summary=f"Network connection to suspicious non-standard port {port} ({desc})",
                        observed_indicators=indicators,
                        benign_alternatives=benign,
                        supporting_event_ids=[e.event_id],
                        confidence_assessment="SUSPICIOUS_INDICATOR",
                        missing_telemetry_limitations=(
                            "Payload inspection (TLS handshake, PCAP, or HTTP headers) is needed to verify whether "
                            "this was interactive command and control traffic or benign application communication."
                        ),
                    )
                )

            # Case 2: Lateral SMB/RDP movement
            elif port in LATERAL_PORTS:
                # Internal lateral probe
                indicators = [
                    f"Connection to lateral port: {port} (SMB / RDP).",
                    f"Target host / destination IP: {dst_ip or 'internal target'}.",
                ]
                if e.host_id:
                    indicators.append(f"Originating host: {e.host_id}.")

                benign = [
                    "Routine administrative file share mounting or domain controller replication.",
                    "Internal systems management software (e.g. SCCM, Intune, Ansible Windows agent).",
                    "Network vulnerability scan or asset inventory audit.",
                ]

                findings.append(
                    DetectionFinding(
                        finding_id=f"finding-net-lateral-{e.event_id}",
                        rule_id="GT-NET-002",
                        rule_name="Internal Lateral Service Connection (SMB / RDP)",
                        severity=EventSeverity.LOW,
                        category="LATERAL_MOVEMENT",
                        mitre_attack_id="T1021.002" if port in (445, 139) else "T1021.001",
                        summary=f"Internal connection to lateral service port {port}",
                        observed_indicators=indicators,
                        benign_alternatives=benign,
                        supporting_event_ids=[e.event_id],
                        confidence_assessment="SUSPICIOUS_INDICATOR",
                        missing_telemetry_limitations=(
                            "Destination host security event logs (Security Event 4624 Type 3 logon or 5140 share access) "
                            "are required to determine if connection succeeded and what files were accessed."
                        ),
                    )
                )

        return findings
