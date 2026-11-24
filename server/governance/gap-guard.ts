/**
 * Gap-coverage guard for governance reports.
 *
 * The evidence is structured, so whether every failing signal reached the Gaps
 * section does not have to be left to the model. In eval run mapping-depth-v1,
 * gpt-4o-mini dropped a warn-level metric (uniqueness 0.70) from Gaps in 1 of 3
 * repeats. After generation, this appends any missing signal to Gaps, worded
 * from the evidence, and reports what it added so the miss rate stays visible
 * in Langfuse.
 */

import type { GovernanceEvidence } from "./report-synthesis";

type Signal = { line: string; pattern: RegExp };

const METHOD: Record<string, { name: string; pattern: string }> = {
  kolmogorov_smirnov: { name: "KS drift", pattern: "\\bks\\b|kolmogorov|drift" },
  isolation_forest: { name: "Isolation Forest", pattern: "isolation forest" },
  local_outlier_factor: { name: "Local Outlier Factor (LOF)", pattern: "local outlier factor|\\blof\\b" },
};

export function failingSignals(evidence: GovernanceEvidence): Signal[] {
  const out: Signal[] = [];
  for (const row of evidence.quality ?? []) {
    if (row.status && /fail|warn|critical/i.test(row.status)) {
      out.push({ line: `${row.metricType} is ${row.status} at ${row.metricValue}.`, pattern: new RegExp(`\\b${row.metricType}\\b`, "i") });
    }
  }
  for (const row of evidence.drift ?? []) {
    if (row.status && /drift|watch/i.test(row.status)) {
      out.push({ line: `KS drift is ${row.status} at ${row.driftScore}.`, pattern: /\bdrift|\bks\b|kolmogorov/i });
    }
  }
  for (const row of evidence.anomalies ?? []) {
    if (row.severity && /high|critical/i.test(row.severity)) {
      const method = METHOD[row.detectionMethod ?? ""];
      out.push({
        line: `${method?.name ?? row.detectionMethod ?? "Anomaly detection"} flagged ${row.affectedRecords} ${row.severity}-severity records.`,
        pattern: new RegExp(`${method ? method.pattern + "|" : ""}anomal|outlier`, "i"),
      });
    }
  }
  for (const row of evidence.assessments ?? []) {
    if (row.status && /non[_ -]?compliant|fail|partial/i.test(row.status)) {
      out.push({ line: `Compliance assessment is ${row.status} (score ${row.score}).`, pattern: /assessment|non[- ]?compliant|finding/i });
    }
  }
  return out;
}

const HEADING = /^\s{0,3}#{1,6}\s+(.*)$/;

/** Returns the report with missing signals appended to Gaps, and the lines it added. */
export function ensureGapCoverage(markdown: string, evidence: GovernanceEvidence): { markdown: string; added: string[] } {
  const lines = markdown.split("\n");
  const gapsStart = lines.findIndex((line) => HEADING.test(line) && /\bgaps?\b/i.test(line));
  if (gapsStart < 0) return { markdown, added: [] };
  let gapsEnd = lines.length;
  for (let i = gapsStart + 1; i < lines.length; i++) {
    if (HEADING.test(lines[i])) {
      gapsEnd = i;
      break;
    }
  }
  // Remediation also counts: a signal named there has been surfaced.
  const surfaced = lines
    .filter((_, i) => i > gapsStart)
    .join("\n");
  const added = failingSignals(evidence)
    .filter((signal) => !signal.pattern.test(surfaced))
    .map((signal) => `- ${signal.line}`);
  if (!added.length) return { markdown, added };
  let insertAt = gapsEnd;
  while (insertAt > gapsStart + 1 && !lines[insertAt - 1].trim()) insertAt--;
  lines.splice(insertAt, 0, ...added);
  return { markdown: lines.join("\n"), added };
}
