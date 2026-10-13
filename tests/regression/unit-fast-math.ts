import fs from "fs";
import path from "path";
import {
  amountMatrix,
  amounts,
  isolationForestScores,
  ksDrift,
  localOutlierFactorScores,
  runFastMathMonitor,
  scoreQualityDimensions,
  type PipelineRow,
} from "../../server/analysis/fast-math";
import { assert, assertApprox, assertEqual, test } from "./harness";

function parseCsv(filePath: string): PipelineRow[] {
  const text = fs.readFileSync(filePath, "utf8").trim();
  const [header, ...lines] = text.split("\n");
  const columns = header.split(",");
  return lines.filter(Boolean).map((line) => {
    const cells = line.split(",");
    return Object.fromEntries(columns.map((column, index) => [column, cells[index] ?? ""])) as PipelineRow;
  });
}

export async function runUnitFastMath() {
  const fixtureRoot = path.resolve(process.cwd(), "fixtures/synthetic");
  const baseline = parseCsv(path.join(fixtureRoot, "ticket-training-set-baseline.csv"));
  const current = parseCsv(path.join(fixtureRoot, "ticket-training-set-current.csv"));
  const dirty = parseCsv(path.join(fixtureRoot, "ticket-training-set-dirty.csv"));

  await test("unit", "UNIT-QM-01", "Six quality dimensions score clean current extract near 1.0", () => {
    const quality = scoreQualityDimensions(current);
    assert(quality.completeness === 1, `completeness ${quality.completeness}`);
    assert(quality.accuracy === 1, `accuracy ${quality.accuracy}`);
    assert(quality.validity === 1, `validity ${quality.validity}`);
    assert(quality.uniqueness === 1, `uniqueness ${quality.uniqueness}`);
    assert(quality.freshness >= 0.8, `freshness ${quality.freshness}`);
    assert(quality.overall >= 0.9, `overall ${quality.overall}`);
  });

  await test("unit", "UNIT-QM-02", "Dirty extract fails completeness/uniqueness/validity", () => {
    const quality = scoreQualityDimensions(dirty);
    assert(quality.completeness < 1, "expected missing text");
    assert(quality.uniqueness < 1, "expected duplicates");
    assert(quality.validity < 1, "expected invalid labels");
  });

  await test("unit", "UNIT-KS-01", "KS drift detects baseline vs current amount shift", () => {
    const drift = ksDrift(amounts(baseline), amounts(current));
    assertEqual(drift.method, "kolmogorov_smirnov");
    assert(drift.ks > 0.2, `ks ${drift.ks}`);
    assertEqual(drift.status, "significant_drift");
  });

  await test("unit", "UNIT-IF-01", "Isolation Forest flags planted high-amount outliers", () => {
    const matrix = amountMatrix(current);
    const result = isolationForestScores(matrix, { trees: 40, contamination: 0.1, seed: 7 });
    assert(result.anomalousCount >= 5, `IF anomalies ${result.anomalousCount}`);
    assertEqual(result.method, "isolation_forest");
  });

  await test("unit", "UNIT-LOF-01", "Local Outlier Factor flags planted outliers", () => {
    const matrix = amountMatrix(current);
    const result = localOutlierFactorScores(matrix, { k: 8, contamination: 0.1 });
    assert(result.anomalousCount >= 5, `LOF anomalies ${result.anomalousCount}`);
    assertEqual(result.method, "local_outlier_factor");
  });

  await test("unit", "UNIT-FM-01", "Full fast-math monitor stays under 100ms budget", () => {
    const report = runFastMathMonitor({ baseline, current });
    assert(report.withinBudget, `elapsed ${report.elapsedMs}ms`);
    assert(report.elapsedMs < 100, `elapsed ${report.elapsedMs}ms`);
    assertEqual(report.engine, "practical_fast_math");
    assertEqual(report.drift.status, "significant_drift");
    assertApprox(report.quality.overall, 0.99, 0.05);
  });

  await test("unit", "UNIT-FM-02", "Realtime path module does not import OpenRouter", () => {
    const source = fs.readFileSync(path.resolve(process.cwd(), "server/analysis/fast-math.ts"), "utf8");
    assert(!/openrouter/i.test(source), "fast-math must not reference OpenRouter");
    assert(!/openai|anthropic|fetch\(/i.test(source), "fast-math must remain offline");
  });
}
