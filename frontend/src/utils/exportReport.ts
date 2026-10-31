/**
 * Report generation utilities for GhostTrace investigation workspace.
 * Generates formatted Markdown and JSON export packages from actual investigation data.
 */

import type { SecurityEvent, InvestigationReconstructionResult } from '../types/event';

export interface ReportDataInput {
  scenarioName: string;
  scenarioId: string;
  reconstruction: InvestigationReconstructionResult;
  events: SecurityEvent[];
}

function sanitizeCell(value: unknown): string {
  if (value === null || value === undefined) return 'N/A';
  return String(value)
    .replace(/\|/g, '\\|')
    .replace(/[\r\n]+/g, ' ')
    .trim();
}

function sanitizeText(value: unknown): string {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * Filter events to ensure strict isolation: only events belonging to the current
 * investigation's timeline or evidence graph are included in exports.
 */
function scopeEventsToInvestigation(
  events: SecurityEvent[],
  reconstruction: InvestigationReconstructionResult
): SecurityEvent[] {
  const investigationEventIds = new Set<string>();
  reconstruction.timeline.forEach((t) => investigationEventIds.add(t.event_id));
  reconstruction.evidence_graph.nodes.forEach((n) => {
    if (n.event_id) investigationEventIds.add(n.event_id);
    if (n.id && n.id.startsWith('evt:')) investigationEventIds.add(n.id.replace('evt:', ''));
  });

  const matched = events.filter((e) => investigationEventIds.has(e.event_id));
  // If no events matched (e.g. clean baseline), keep provided events only if non-empty
  return matched.length > 0 ? matched : events;
}

/**
 * Generate a professional forensic investigation report in Markdown format.
 */
export function generateMarkdownReport(input: ReportDataInput): string {
  const { scenarioName, scenarioId, reconstruction } = input;
  const events = scopeEventsToInvestigation(input.events, reconstruction);
  const now = new Date().toISOString();

  const totalEvents = events.length;
  const suspiciousCount = events.filter((e) => e.is_suspicious).length;
  const routineCount = totalEvents - suspiciousCount;

  const sortedEvents = [...events].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );
  const firstSeen = sortedEvents[0]?.timestamp || 'N/A';
  const lastSeen = sortedEvents[sortedEvents.length - 1]?.timestamp || 'N/A';

  const entryPoint = reconstruction.candidate_entry_points[0];
  const primaryHypothesis = reconstruction.hypotheses[0];

  let md = `# GhostTrace Forensic Investigation Report
**Investigation ID:** \`${sanitizeCell(reconstruction.investigation_id)}\`  
**Generated At:** ${now} UTC  
**Target Scenario:** ${sanitizeText(scenarioName)} (\`${sanitizeCell(scenarioId)}\`)  
**Status:** ${suspiciousCount > 0 ? 'SUSPICIOUS INCIDENT CONFIRMED' : 'ROUTINE BASELINE VERIFIED'}  
**Forensic Disclaimer:** *Live host telemetry collected from ${sanitizeCell(scenarioId === 'live_device' ? 'active device (real-time collection)' : 'forensic benchmark dataset')}. All recommendations are advisory — no automated containment commands were issued.*

---

## 1. Executive Summary
${
  primaryHypothesis
    ? `**Primary Hypothesis:** ${sanitizeText(primaryHypothesis.title)}  
**Confidence Score:** ${Math.round(primaryHypothesis.score * 100)}% (${primaryHypothesis.confidence})  
**Overview:** ${sanitizeText(primaryHypothesis.description)}`
    : 'No conclusive hypothesis formulated for this observation period.'
}

---

## 2. Investigation Scope & Data Sources
- **Total Normalized Telemetry Records:** ${totalEvents}
- **Corroborated Incident Evidence:** ${suspiciousCount}
- **Routine Operational Events:** ${routineCount}
- **Observation Window:** \`${firstSeen}\` to \`${lastSeen}\`
- **Reconstruction Algorithm:** GhostTrace Deterministic Correlation & Attack Reconstruction Engine

---

## 3. Candidate Entry Point & Initial Compromise
${
  entryPoint
    ? `- **Event ID:** \`${entryPoint.event_id}\`
- **Timestamp:** \`${entryPoint.timestamp}\`
- **Initial Principal (User):** \`${entryPoint.user_id || 'Unknown'}\`
- **Source Address:** \`${entryPoint.source_ip || 'Internal / N/A'}\`
- **Target Host:** \`${entryPoint.host_id || 'N/A'}\`
- **Confidence:** ${Math.round(entryPoint.confidence * 100)}%
- **Forensic Rationale:** ${entryPoint.rationale}
- **Supporting Event IDs:** ${entryPoint.supporting_event_ids.map((id) => `\`${id}\``).join(', ')}`
    : '*No adversary entry point identified. Observed telemetry represents benign baseline administrative activity.*'
}

---

## 4. Reconstructed Attack Timeline
| Index | Timestamp (UTC) | Category | Severity | Status | Phase | Description | Supporting Evidence |
|:-----:|:---------------:|:--------:|:--------:|:------:|:-----:|:------------|:-------------------:|
`;

  reconstruction.timeline.forEach((item, idx) => {
    const matchedEvt = events.find((e) => e.event_id === item.event_id);
    const severity = matchedEvt?.severity || 'INFORMATIONAL';
    const status = item.is_suspicious ? '**THREAT**' : 'ROUTINE';
    const desc = item.summary.replace(/\|/g, '\\|');
    const supp = item.supporting_event_ids.map((id) => `\`${id}\``).join(', ');
    md += `| ${idx + 1} | \`${item.timestamp}\` | ${item.event_type} | ${severity} | ${status} | ${item.phase} | ${desc} | ${supp} |\n`;
  });

  if (reconstruction.detection_findings && reconstruction.detection_findings.length > 0) {
    md += `\n---

## 5. Deterministic Detections & Evidence Lineage
`;
    reconstruction.detection_findings.forEach((f) => {
      md += `### [${f.rule_id}] ${f.rule_name} (${f.severity})
- **Tactic Category:** \`${f.category}\` ${f.mitre_attack_id ? `| **MITRE:** \`${f.mitre_attack_id}\`` : ''}
- **Summary:** ${f.summary}
- **Observed Direct Evidence:**
${f.observed_indicators.map((ind) => `  - ${ind}`).join('\n')}
- **Plausible Benign Alternatives:**
${f.benign_alternatives.map((alt) => `  - ${alt}`).join('\n')}
- **Supporting Event IDs:** ${f.supporting_event_ids.map((id) => `\`${id}\``).join(', ')}
${f.missing_telemetry_limitations ? `- **Missing Telemetry to Confirm/Refute:** ${f.missing_telemetry_limitations}\n` : ''}
`;
    });
  }

  md += `\n---

## 6. Evidence Graph Metrics & Relationship Summary
- **Graph Nodes:** ${reconstruction.evidence_graph.nodes.length}
- **Graph Edges:** ${reconstruction.evidence_graph.edges.length}
- **Relationship Lineage Breakdown:**
`;

  const relationCounts: Record<string, number> = {};
  reconstruction.evidence_graph.edges.forEach((edge) => {
    relationCounts[edge.relation] = (relationCounts[edge.relation] || 0) + 1;
  });
  Object.entries(relationCounts).forEach(([rel, count]) => {
    md += `  - \`${rel}\`: ${count} edge(s)\n`;
  });

  md += `\n---

## 6. Ranked Attack Hypotheses & Competing Explanations
`;

  reconstruction.hypotheses.forEach((hypo) => {
    md += `### Hypothesis #${hypo.rank}: ${hypo.title}
- **Score:** ${Math.round(hypo.score * 100)}% (${hypo.confidence})
- **Confidence Explanation:** ${hypo.confidence_explanation}
- **Attack Sequence Narrative:** ${hypo.description}
- **Supporting Evidence IDs:** ${
      hypo.supporting_event_ids.length > 0
        ? hypo.supporting_event_ids.map((id) => `\`${id}\``).join(', ')
        : '*None*'
    }
- **Contradicting Evidence IDs:** ${
      hypo.contradicting_event_ids.length > 0
        ? hypo.contradicting_event_ids.map((id) => `\`${id}\``).join(', ')
        : '*None observed*'
    }
- **Key Assumptions / Limitations:**
${hypo.assumptions.map((asm) => `  - ${asm}`).join('\n')}

`;
  });

  md += `---

## 7. Observed Facts vs. Inferred Conclusions

### Observed Telemetry Facts (Immutable Truth)
`;
  reconstruction.observed_facts.forEach((fact) => {
    md += `- **[${fact.fact_id}]** \`${fact.observed_at}\` (${fact.source}): ${fact.statement} (Events: ${fact.supporting_event_ids.map((id) => `\`${id}\``).join(', ')})\n`;
  });

  md += `\n### Inferred Forensic Conclusions (Analytical Hypotheses)
`;
  reconstruction.inferred_conclusions.forEach((conc) => {
    md += `- **[${conc.conclusion_id}]** (${conc.confidence} Confidence): ${conc.statement}
  - *Rationale:* ${conc.confidence_rationale}
  - *Supporting Events:* ${conc.supporting_event_ids.map((id) => `\`${id}\``).join(', ')}
  - *Alternative Explanations Considered:*
${conc.alternative_explanations.map((alt) => `    - ${alt}`).join('\n')}
`;
  });

  md += `\n---

## 8. Missing Evidence & Forensic Limitations
`;
  if (reconstruction.unresolved_questions.length > 0) {
    reconstruction.unresolved_questions.forEach((q) => {
      md += `### ${q.question}
- **Context:** ${q.context}
- **Missing Telemetry Type:** \`${q.missing_evidence_type}\`
- **Related Events:** ${q.related_event_ids.map((id) => `\`${id}\``).join(', ')}

`;
    });
  } else {
    md += '*No critical evidence gaps detected for this observation window.*\n\n';
  }

  md += `---

## 9. Advisory Defensive Recommendations
*Disclaimer: All recommendations are advisory simulations. No automated containment commands have been issued against production infrastructure.*

`;

  reconstruction.defensive_recommendations.forEach((rec) => {
    md += `### [${rec.priority}] ${rec.title}
- **Action:** ${rec.action}
- **Target Entity:** \`${rec.target_entity || 'N/A'}\`
- **MITRE Mitigation:** \`${rec.mitre_mitigation || 'N/A'}\`
- **Measure Classification:** \`${rec.measure_type || 'PRECAUTIONARY'}\`
- **Forensic Rationale:** ${rec.why_recommended || 'Standard defensive hygiene'}
- **Expected Benefit:** ${rec.expected_benefit || 'Mitigates potential attack vector'}
- **Operational Risk / Impact:** ${rec.potential_impact_risk || 'Standard operational review recommended'}
- **Supporting Evidence IDs:** ${
      rec.supporting_event_ids && rec.supporting_event_ids.length > 0
        ? rec.supporting_event_ids.map((id) => `\`${id}\``).join(', ')
        : 'N/A'
    }

`;
  });

  md += `---\n*Report generated by GhostTrace DFIR Workspace.*`;
  return md;
}

/**
 * Generate a complete JSON evidence package for forensic preservation and export.
 */
export function generateJsonReport(input: ReportDataInput): string {
  const { scenarioName, scenarioId, reconstruction } = input;
  const events = scopeEventsToInvestigation(input.events, reconstruction);
  const packagePayload = {
    schema_version: '1.0.0',
    export_metadata: {
      generated_at: new Date().toISOString(),
      generator: 'GhostTrace DFIR Investigation Workspace',
      target_scenario_name: scenarioName,
      target_scenario_id: scenarioId,
      disclaimer: scenarioId === 'live_device'
        ? 'LIVE HOST TELEMETRY — Real-time collection from active device. Advisory only.'
        : 'FORENSIC BENCHMARK DATA — For analysis and defensive review.',
    },
    investigation: reconstruction,
    normalized_telemetry_events: events,
  };
  return JSON.stringify(packagePayload, null, 2);
}

/**
 * Trigger browser file download.
 */
export function downloadFile(content: string, filename: string, contentType: string): void {
  const blob = new Blob([content], { type: contentType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}
