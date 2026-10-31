"""
Authentication Detection Rules for GhostTrace.
Modular, explainable rules citing exact event IDs and presenting benign alternatives.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Dict, List, Optional

from investigation_engine.models import DetectionFinding, EventSeverity, EventType, SecurityEvent
from investigation_engine.detections.rule import BaseDetectionRule


class BruteForceAuthenticationRule(BaseDetectionRule):
    """
    Detects repeated failed authentication attempts originating from a single source IP
    or targeting a single account, optionally followed by a successful authentication.
    """

    @property
    def rule_id(self) -> str:
        return "GT-AUTH-001"

    @property
    def rule_name(self) -> str:
        return "Repeated Failed Authentication Attempts (Brute Force / Password Spray)"

    @property
    def severity(self) -> EventSeverity:
        return EventSeverity.HIGH

    @property
    def category(self) -> str:
        return "INITIAL_ACCESS"

    @property
    def mitre_attack_id(self) -> Optional[str]:
        return "T1110"

    def evaluate(self, events: List[SecurityEvent]) -> List[DetectionFinding]:
        findings: List[DetectionFinding] = []

        # Filter authentication events
        auth_events = [
            e for e in events
            if e.event_type == EventType.AUTHENTICATION
        ]
        if not auth_events:
            return findings

        # Group failed logons by source_ip and by user_id
        ip_failures: Dict[str, List[SecurityEvent]] = defaultdict(list)
        user_failures: Dict[str, List[SecurityEvent]] = defaultdict(list)

        for e in auth_events:
            action = (e.action or "").upper()
            is_failure = (
                "FAIL" in action
                or e.severity in (EventSeverity.MEDIUM, EventSeverity.HIGH, EventSeverity.CRITICAL)
                and "SUCCESS" not in action
            )
            if is_failure:
                if e.source_ip:
                    ip_failures[e.source_ip].append(e)
                if e.user_id:
                    user_failures[e.user_id].append(e)

        # Check IP failure threshold (>= 3 failures)
        for ip, fail_evts in ip_failures.items():
            if len(fail_evts) >= 3:
                fail_evts.sort(key=lambda x: x.timestamp)
                supporting_ids = [e.event_id for e in fail_evts]
                
                # Check if there is a subsequent success from same IP
                subsequent_success = [
                    e for e in auth_events
                    if e.source_ip == ip
                    and (e.action or "").upper() in ("LOGON_SUCCESS", "SUCCESS")
                    and e.timestamp >= fail_evts[0].timestamp
                ]
                has_success = len(subsequent_success) > 0
                if has_success:
                    supporting_ids.extend([e.event_id for e in subsequent_success])

                user_targets = sorted(list({e.user_id for e in fail_evts if e.user_id}))
                time_span_sec = (fail_evts[-1].timestamp - fail_evts[0].timestamp).total_seconds()

                indicators = [
                    f"Observed {len(fail_evts)} failed logon attempts from source IP {ip}.",
                    f"Target account(s): {', '.join(user_targets) if user_targets else 'unspecified accounts'}.",
                    f"Occurred over a duration of {time_span_sec:.1f} seconds.",
                ]
                if has_success:
                    succ_users = [e.user_id for e in subsequent_success if e.user_id]
                    indicators.append(
                        f"Subsequent successful logon observed for account(s): {', '.join(succ_users) if succ_users else 'account'}."
                    )

                benign = [
                    "User mistyped password or recently updated credentials while a client application cached stale credentials.",
                    "Automated integration script, cron job, or CI/CD runner executing with an expired service token.",
                    "Network connectivity hiccups or retry storms causing rapid re-transmission of authentication requests.",
                ]

                confidence = "CORROBORATED" if has_success else "SUSPICIOUS_INDICATOR"

                missing_limitations = (
                    "MFA challenge records and origin VPN session logs are required to verify whether this was "
                    "an external brute-force attempt or an internal misconfigured automation job."
                )

                findings.append(
                    DetectionFinding(
                        finding_id=f"finding-auth-bf-{ip.replace('.', '_')}",
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=EventSeverity.HIGH if has_success else EventSeverity.MEDIUM,
                        category=self.category,
                        mitre_attack_id=self.mitre_attack_id,
                        summary=(
                            f"Multiple failed logons ({len(fail_evts)}) detected from {ip}"
                            + (f" followed by successful logon" if has_success else "")
                        ),
                        observed_indicators=indicators,
                        benign_alternatives=benign,
                        supporting_event_ids=supporting_ids,
                        confidence_assessment=confidence,
                        missing_telemetry_limitations=missing_limitations,
                    )
                )

        return findings
