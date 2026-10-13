/**
 * Practical Fast Math — real-time monitoring path (<100ms target).
 *
 * Deliberately excludes LLMs. Uses classic statistical / ML methods:
 * - Six quality dimensions (completeness, accuracy, consistency, validity, uniqueness, freshness)
 * - Kolmogorov–Smirnov drift
 * - Isolation Forest anomalies
 * - Local Outlier Factor (LOF) anomalies
 */

export type QualityDimensions = {
  completeness: number;
  accuracy: number;
  consistency: number;
  validity: number;
  uniqueness: number;
  freshness: number;
  overall: number;
};

export type PipelineRow = {
  ticket_id?: string;
  text?: string;
  label?: string;
  amount?: number | string;
  timestamp?: string;
  [key: string]: string | number | undefined;
};

const ALLOWED_LABELS = new Set(["billing", "access", "shipping"]);

function clamp01(value: number) {
  return Math.min(1, Math.max(0, value));
}

function toNumber(value: string | number | undefined): number | null {
  if (value === undefined || value === "") return null;
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) ? n : null;
}

/** Six data-quality dimensions over a live extract. Scores are 0–1. */
export function scoreQualityDimensions(
  rows: PipelineRow[],
  options: { freshnessHours?: number } = {},
): QualityDimensions {
  const total = rows.length || 1;
  const freshnessMs = (options.freshnessHours ?? 24) * 60 * 60 * 1000;
  const now = Date.now();

  let missingText = 0;
  let invalidAmount = 0;
  let invalidLabel = 0;
  let inconsistent = 0;
  let fresh = 0;
  const ids = new Map<string, number>();

  for (const row of rows) {
    if (!row.text) missingText += 1;
    const amount = toNumber(row.amount);
    if (amount === null) invalidAmount += 1;
    if (!ALLOWED_LABELS.has(String(row.label ?? ""))) invalidLabel += 1;
    if (row.ticket_id) ids.set(String(row.ticket_id), (ids.get(String(row.ticket_id)) ?? 0) + 1);
    // Consistency: shipping labels should not have negative amounts
    if (row.label === "shipping" && amount !== null && amount < 0) inconsistent += 1;
    if (row.label === "billing" && amount !== null && amount === 0) inconsistent += 1;
    if (row.timestamp) {
      const ts = Date.parse(String(row.timestamp));
      if (Number.isFinite(ts) && now - ts <= freshnessMs) fresh += 1;
    }
  }

  let duplicate = 0;
  for (const count of Array.from(ids.values())) {
    if (count > 1) duplicate += count;
  }

  const completeness = clamp01(1 - missingText / total);
  const accuracy = clamp01(1 - invalidAmount / total);
  const consistency = clamp01(1 - inconsistent / total);
  const validity = clamp01(1 - invalidLabel / total);
  const uniqueness = clamp01(1 - duplicate / total);
  const freshness = rows.some((r) => r.timestamp) ? clamp01(fresh / total) : 1;

  const overall =
    completeness * 0.2 +
    accuracy * 0.2 +
    consistency * 0.15 +
    validity * 0.2 +
    uniqueness * 0.15 +
    freshness * 0.1;

  return {
    completeness: round4(completeness),
    accuracy: round4(accuracy),
    consistency: round4(consistency),
    validity: round4(validity),
    uniqueness: round4(uniqueness),
    freshness: round4(freshness),
    overall: round4(overall),
  };
}

function round4(value: number) {
  return Math.round(value * 10000) / 10000;
}

function kolmogorovSmirnov(left: number[], right: number[]) {
  const a = [...left].sort((x, y) => x - y);
  const b = [...right].sort((x, y) => x - y);
  let i = 0;
  let j = 0;
  let distance = 0;
  while (i < a.length && j < b.length) {
    if (a[i] <= b[j]) i += 1;
    else j += 1;
    distance = Math.max(distance, Math.abs(i / a.length - j / b.length));
  }
  return distance;
}

export function ksDrift(baseline: number[], current: number[], threshold = 0.2) {
  const ks = kolmogorovSmirnov(baseline, current);
  const mean = (values: number[]) => values.reduce((s, v) => s + v, 0) / (values.length || 1);
  return {
    method: "kolmogorov_smirnov" as const,
    feature: "amount",
    ks: round4(ks),
    baselineMean: round4(mean(baseline)),
    currentMean: round4(mean(current)),
    threshold,
    status: ks > threshold ? ("significant_drift" as const) : ("stable" as const),
  };
}

/** Isolation Forest path-length score for one point (higher = more anomalous). */
function isolationPathLength(
  point: number[],
  sample: number[][],
  depth: number,
  maxDepth: number,
): number {
  if (depth >= maxDepth || sample.length <= 1) return depth;
  const feature = Math.floor(Math.random() * point.length);
  const values = sample.map((row) => row[feature]);
  const min = Math.min(...values);
  const max = Math.max(...values);
  if (min === max) return depth;
  const split = min + Math.random() * (max - min);
  const left = sample.filter((row) => row[feature] < split);
  const right = sample.filter((row) => row[feature] >= split);
  const next = point[feature] < split ? left : right;
  return isolationPathLength(point, next.length ? next : sample, depth + 1, maxDepth);
}

function expectedPathLength(n: number) {
  if (n <= 1) return 0;
  return 2 * (Math.log(n - 1) + 0.5772156649) - (2 * (n - 1)) / n;
}

/**
 * Isolation Forest over a 1-D (or multi-D) feature matrix.
 * Returns per-row anomaly scores in [0,1] and flagged indices.
 */
export function isolationForestScores(
  matrix: number[][],
  options: { trees?: number; contamination?: number; seed?: number } = {},
) {
  const trees = options.trees ?? 50;
  const contamination = options.contamination ?? 0.1;
  const maxDepth = Math.ceil(Math.log2(Math.max(matrix.length, 2)));
  const c = expectedPathLength(matrix.length);

  // Deterministic-ish RNG for reproducible fixture runs
  let seed = options.seed ?? 42;
  const rand = () => {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    return seed / 0xffffffff;
  };
  const originalRandom = Math.random;
  Math.random = rand;

  try {
    const scores = matrix.map((point) => {
      let total = 0;
      for (let t = 0; t < trees; t += 1) {
        // subsample
        const size = Math.min(256, matrix.length);
        const sample: number[][] = [];
        for (let i = 0; i < size; i += 1) {
          sample.push(matrix[Math.floor(Math.random() * matrix.length)]);
        }
        total += isolationPathLength(point, sample, 0, maxDepth);
      }
      const avg = total / trees;
      return clamp01(Math.pow(2, -avg / (c || 1)));
    });

    const ranked = scores
      .map((score, index) => ({ score, index }))
      .sort((a, b) => b.score - a.score);
    const cut = Math.max(1, Math.floor(matrix.length * contamination));
    const threshold = ranked[cut - 1]?.score ?? 0.7;
    const flagged = ranked.filter((r) => r.score >= threshold).map((r) => r.index);

    return {
      method: "isolation_forest" as const,
      scores: scores.map(round4),
      threshold: round4(threshold),
      flaggedIndices: flagged,
      anomalousCount: flagged.length,
    };
  } finally {
    Math.random = originalRandom;
  }
}

function euclidean(a: number[], b: number[]) {
  let sum = 0;
  for (let i = 0; i < a.length; i += 1) {
    const d = a[i] - b[i];
    sum += d * d;
  }
  return Math.sqrt(sum);
}

/**
 * Local Outlier Factor. Higher LOF => more anomalous.
 * Scores are normalized to [0,1] for storage.
 */
export function localOutlierFactorScores(
  matrix: number[][],
  options: { k?: number; contamination?: number } = {},
) {
  const k = Math.min(options.k ?? 10, Math.max(1, matrix.length - 1));
  const contamination = options.contamination ?? 0.1;
  const n = matrix.length;

  const distances: number[][] = Array.from({ length: n }, () => Array(n).fill(0));
  for (let i = 0; i < n; i += 1) {
    for (let j = i + 1; j < n; j += 1) {
      const d = euclidean(matrix[i], matrix[j]);
      distances[i][j] = d;
      distances[j][i] = d;
    }
  }

  const neighbors: number[][] = [];
  const kDistance: number[] = [];
  for (let i = 0; i < n; i += 1) {
    const order = distances[i]
      .map((d, j) => ({ d, j }))
      .filter((x) => x.j !== i)
      .sort((a, b) => a.d - b.d)
      .slice(0, k);
    neighbors[i] = order.map((x) => x.j);
    kDistance[i] = order[order.length - 1]?.d ?? 0;
  }

  const reachDist = (i: number, j: number) => Math.max(kDistance[j], distances[i][j]);

  const lrd: number[] = [];
  for (let i = 0; i < n; i += 1) {
    const sum = neighbors[i].reduce((acc, j) => acc + reachDist(i, j), 0);
    lrd[i] = neighbors[i].length / Math.max(sum, 1e-9);
  }

  const rawLof = matrix.map((_, i) => {
    const sum = neighbors[i].reduce((acc, j) => acc + lrd[j] / lrd[i], 0);
    return sum / neighbors[i].length;
  });

  const maxLof = Math.max(...rawLof, 1);
  const scores = rawLof.map((v) => clamp01(v / maxLof));

  const ranked = scores
    .map((score, index) => ({ score, index }))
    .sort((a, b) => b.score - a.score);
  const cut = Math.max(1, Math.floor(n * contamination));
  const threshold = ranked[cut - 1]?.score ?? 0.7;
  const flagged = ranked.filter((r) => r.score >= threshold).map((r) => r.index);

  return {
    method: "local_outlier_factor" as const,
    scores: scores.map(round4),
    rawLof: rawLof.map(round4),
    threshold: round4(threshold),
    flaggedIndices: flagged,
    anomalousCount: flagged.length,
    k,
  };
}

export function amountMatrix(rows: PipelineRow[]): number[][] {
  return rows.map((row) => {
    const amount = toNumber(row.amount) ?? 0;
    return [amount];
  });
}

export function amounts(rows: PipelineRow[]): number[] {
  return rows.map((row) => toNumber(row.amount) ?? 0);
}

/** Full real-time monitoring pass. No network I/O. */
export function runFastMathMonitor(input: {
  current: PipelineRow[];
  baseline: PipelineRow[];
}) {
  const started = Date.now();
  const quality = scoreQualityDimensions(input.current);
  const drift = ksDrift(amounts(input.baseline), amounts(input.current));
  const matrix = amountMatrix(input.current);
  const isolation = isolationForestScores(matrix, { trees: 40, contamination: 0.1, seed: 7 });
  const lof = localOutlierFactorScores(matrix, { k: 8, contamination: 0.1 });
  const elapsedMs = Date.now() - started;

  return {
    quality,
    drift,
    isolationForest: isolation,
    localOutlierFactor: lof,
    elapsedMs,
    withinBudget: elapsedMs < 100,
    engine: "practical_fast_math" as const,
  };
}
