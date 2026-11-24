import { test } from "node:test";
import assert from "node:assert/strict";
import { InMemorySpanExporter, NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
import { setLangfuseTracerProvider } from "@langfuse/tracing";
import { LangfuseSpanProcessor } from "@langfuse/otel";

// Enable the Langfuse path without network: keys are dummies, and the real
// LangfuseSpanProcessor (which applies propagated attributes in onStart) exports
// to memory instead of the OTLP endpoint.
process.env.LANGFUSE_PUBLIC_KEY = "pk-lf-test";
process.env.LANGFUSE_SECRET_KEY = "sk-lf-test";
process.env.LANGFUSE_BASE_URL = "http://127.0.0.1:9";
delete process.env.HTTPS_PROXY;
delete process.env.https_proxy;

test("v4: trace-wide attributes reach the root and the cost-bearing generation", async () => {
  const { initLangfuse } = await import("../../server/observability/langfuse");
  const synthesis = await import("../../server/governance/report-synthesis");
  initLangfuse();
  const exporter = new InMemorySpanExporter();
  const processor = new LangfuseSpanProcessor({ exporter, flushAt: 1 });
  setLangfuseTracerProvider(new NodeTracerProvider({ spanProcessors: [processor] }));

  const result = await synthesis.generateGovernanceNarrative(
    {
      assetName: "ticket-training-set",
      frameworks: ["GDPR", "NIST AI RMF"],
      evidence: { quality: [{ metricType: "completeness", metricValue: 0.72, status: "fail" }] },
    },
    synthesis.offlineChat,
    { userId: 7, reportId: 42, assetId: 3 },
  );

  await processor.forceFlush();
  const spans = exporter.getFinishedSpans();
  const root = spans.find((s) => s.name === synthesis.GOVERNANCE_TRACE_NAME)!;
  const generation = spans.find((s) => s.name === "openrouter.governance_report")!;
  assert.ok(root && generation, "root chain and generation exported");
  assert.equal(generation.parentSpanContext?.spanId, root.spanContext().spanId, "generation is a child of the root");
  assert.equal(result.traceId, root.spanContext().traceId);

  for (const span of [root, generation]) {
    const a = span.attributes;
    assert.equal(a["langfuse.trace.name"], synthesis.GOVERNANCE_TRACE_NAME, span.name);
    assert.equal(a["user.id"] ?? a["langfuse.user.id"], "7", span.name);
    assert.equal(a["langfuse.version"], synthesis.GOVERNANCE_PROMPT_VERSION, span.name);
    assert.deepEqual(a["langfuse.trace.tags"], ["governance-report", "gdpr", "nist-ai-rmf"], span.name);
    // Metadata values are JSON-encoded on the wire; Langfuse decodes them.
    assert.equal(JSON.parse(String(a["langfuse.trace.metadata.reportId"])), "42", span.name);
    assert.equal(JSON.parse(String(a["langfuse.trace.metadata.assetId"])), "3", span.name);
  }
  // Overall input and output live on the root observation (no trace-level input/output).
  assert.ok(String(root.attributes["langfuse.observation.input"]).includes("ticket-training-set"));
  assert.ok(String(root.attributes["langfuse.observation.output"]).includes("Executive Summary"));
  assert.equal(root.attributes["langfuse.trace.input"], undefined);
  // The generation carries model, usage and cost.
  assert.equal(generation.attributes["langfuse.observation.type"], "generation");
  assert.ok(generation.attributes["langfuse.observation.model.name"]);
  assert.ok(generation.attributes["langfuse.observation.usage_details"]);
});

test.after(() => {
  // The in-memory provider has nothing to flush to the network; end the process cleanly.
  setTimeout(() => process.exit(process.exitCode ?? 0), 50).unref();
});
