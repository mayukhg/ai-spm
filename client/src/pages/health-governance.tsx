import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import Sidebar from "@/components/layout/sidebar";
import Header from "@/components/layout/header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { apiRequest } from "@/lib/queryClient";

interface HealthStatus {
  agent: {
    running: boolean;
    lastRunAt: string | null;
    lastElapsedMs: number | null;
    lastWithinBudget: boolean | null;
    nextRunAt: string | null;
    cyclesCompleted: number;
    intervalMinutes: number;
    methods: string[];
    llmOnRealtimePath: boolean;
  };
  openrouter: {
    configured: boolean;
    provider: string;
    model: string;
    realtimePathUsesLlm: boolean;
  };
}

interface MonitoringCycle {
  id: number;
  trigger: string;
  elapsedMs: number;
  withinBudget: boolean;
  qualityOverall: string;
  driftStatus: string;
  isolationAnomalies: number;
  lofAnomalies: number;
  createdAt: string;
}

interface GovernanceReport {
  id: number;
  title: string;
  status: string;
  summary?: string | null;
  bodyMarkdown?: string | null;
  model?: string | null;
  elapsedMs?: number | null;
  error?: string | null;
  frameworks: string[];
  createdAt: string;
  completedAt?: string | null;
}

export default function HealthGovernance() {
  const queryClient = useQueryClient();
  const reportsRef = useRef<HTMLDivElement | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [actionMessage, setActionMessage] = useState<{ tone: "ok" | "error"; text: string } | null>(null);

  const { data: status } = useQuery<HealthStatus>({ queryKey: ["/api/governance/health/status"] });
  const { data: cycles = [] } = useQuery<MonitoringCycle[]>({ queryKey: ["/api/governance/health/cycles"] });
  const { data: reports = [] } = useQuery<GovernanceReport[]>({
    queryKey: ["/api/governance/reports"],
    refetchInterval: (query) => {
      const rows = query.state.data as GovernanceReport[] | undefined;
      return rows?.some((report) => report.status === "running" || report.status === "pending") ? 2000 : 5000;
    },
  });

  const selectedReport = selectedId != null ? reports.find((report) => report.id === selectedId) ?? null : null;

  useEffect(() => {
    if (selectedId == null && reports[0]) setSelectedId(reports[0].id);
  }, [reports, selectedId]);

  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ["/api/governance/health/status"] });
    await queryClient.invalidateQueries({ queryKey: ["/api/governance/health/cycles"] });
    await queryClient.invalidateQueries({ queryKey: ["/api/governance/reports"] });
  };

  const runNow = async () => {
    setBusy("run");
    setActionMessage(null);
    try {
      await apiRequest("POST", "/api/governance/health/run-now");
      await refresh();
      setActionMessage({ tone: "ok", text: "Monitoring cycle finished. See Recent monitoring cycles below." });
    } catch (error) {
      setActionMessage({
        tone: "error",
        text: error instanceof Error ? error.message : "Monitoring cycle failed",
      });
    } finally {
      setBusy(null);
    }
  };

  const generateReport = async () => {
    setBusy("report");
    setActionMessage(null);
    try {
      const response = await fetch("/api/governance/reports", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ frameworks: ["GDPR", "NIST AI RMF"] }),
      });
      const payload = await response.json();
      if (!response.ok) {
        const message = payload.error || "Failed to start report";
        setActionMessage({
          tone: "error",
          text: payload.needsOpenRouterKey
            ? `${message} Add OPENROUTER_API_KEY to .env and restart the server.`
            : message,
        });
        return;
      }

      setSelectedId(payload.id);
      await refresh();
      setActionMessage({
        tone: "ok",
        text: `Report #${payload.id} queued (${payload.status}). Scroll to Governance reports — it refreshes while OpenRouter writes the markdown.`,
      });
      reportsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
      setActionMessage({
        tone: "error",
        text: error instanceof Error ? error.message : "Report failed",
      });
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="flex h-screen bg-background text-foreground">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden ml-64">
        <Header
          title="Health & Governance"
          subtitle="Fast-math resident monitoring plus async OpenRouter compliance synthesis"
          showSearch={false}
        />
        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between gap-3">
                <div>
                  <CardTitle>Resident agent</CardTitle>
                  <p className="text-sm text-muted-foreground mt-1">
                    Practical Fast Math only — Isolation Forest, LOF, KS, six quality dimensions
                  </p>
                </div>
                <Button onClick={runNow} disabled={busy === "run"}>
                  {busy === "run" ? "Running…" : "Run now"}
                </Button>
              </CardHeader>
              <CardContent className="space-y-3 text-sm">
                <p className="flex items-center gap-2">
                  Status{" "}
                  <Badge variant={status?.agent.running ? "default" : "secondary"}>
                    {status?.agent.running ? "running" : "stopped"}
                  </Badge>
                </p>
                <p>Interval: {status?.agent.intervalMinutes ?? 15} minutes</p>
                <p>Last run: {status?.agent.lastRunAt ? new Date(status.agent.lastRunAt).toLocaleString() : "—"}</p>
                <p>
                  Last elapsed:{" "}
                  {status?.agent.lastElapsedMs != null ? `${status.agent.lastElapsedMs} ms` : "—"}{" "}
                  {status?.agent.lastWithinBudget != null && (
                    <Badge variant={status.agent.lastWithinBudget ? "default" : "destructive"}>
                      {status.agent.lastWithinBudget ? "<100ms budget" : "over budget"}
                    </Badge>
                  )}
                </p>
                <p>LLM on realtime path: {status?.agent.llmOnRealtimePath ? "yes" : "no"}</p>
                <div className="flex flex-wrap gap-2">
                  {(status?.agent.methods ?? []).map((method) => (
                    <Badge key={method} variant="outline">{method.replaceAll("_", " ")}</Badge>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between gap-3">
                <div>
                  <CardTitle>Async governance</CardTitle>
                  <p className="text-sm text-muted-foreground mt-1">
                    OpenRouter natural-language synthesis for GDPR / NIST (not latency-critical)
                  </p>
                </div>
                <Button onClick={generateReport} disabled={busy === "report"}>
                  {busy === "report" ? "Queuing…" : "Generate GDPR / NIST report"}
                </Button>
              </CardHeader>
              <CardContent className="space-y-3 text-sm">
                <p className="flex items-center gap-2">
                  OpenRouter{" "}
                  <Badge variant={status?.openrouter.configured ? "default" : "secondary"}>
                    {status?.openrouter.configured ? "configured" : "key required"}
                  </Badge>
                </p>
                <p>Model: {status?.openrouter.model ?? "openai/gpt-4o-mini"}</p>
                <p>Realtime path uses LLM: {status?.openrouter.realtimePathUsesLlm ? "yes" : "no"}</p>
                {actionMessage && (
                  <div
                    className={
                      actionMessage.tone === "ok"
                        ? "rounded-md border border-emerald-500/40 bg-emerald-950/40 p-3 text-emerald-100"
                        : "rounded-md border border-orange-500/50 bg-orange-950/40 p-3 text-orange-100"
                    }
                  >
                    {actionMessage.text}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Recent monitoring cycles</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {cycles.length === 0 && <p className="text-sm text-muted-foreground">No cycles yet. Click Run now.</p>}
              {cycles.map((cycle) => (
                <div key={cycle.id} className="flex flex-wrap items-center gap-3 border border-border rounded-md p-3 text-sm">
                  <Badge variant="outline">{cycle.trigger}</Badge>
                  <span>{cycle.elapsedMs} ms</span>
                  <Badge variant={cycle.withinBudget ? "default" : "destructive"}>
                    {cycle.withinBudget ? "within budget" : "over budget"}
                  </Badge>
                  <span>quality {cycle.qualityOverall}</span>
                  <span>drift {cycle.driftStatus}</span>
                  <span>IF {cycle.isolationAnomalies}</span>
                  <span>LOF {cycle.lofAnomalies}</span>
                  <span className="text-muted-foreground ml-auto">{new Date(cycle.createdAt).toLocaleString()}</span>
                </div>
              ))}
            </CardContent>
          </Card>

          <Card ref={reportsRef}>
            <CardHeader>
              <CardTitle>Governance reports</CardTitle>
              <p className="text-sm text-muted-foreground">
                Click a report to open the markdown. Running reports refresh automatically.
              </p>
            </CardHeader>
            <CardContent className="space-y-3">
              {reports.length === 0 && (
                <p className="text-sm text-muted-foreground">No reports yet. Generate an async GDPR / NIST narrative.</p>
              )}
              {reports.map((report) => (
                <button
                  key={report.id}
                  type="button"
                  className={`w-full text-left border rounded-md p-3 space-y-2 hover:bg-zinc-900/60 ${
                    selectedId === report.id ? "border-primary" : "border-border"
                  }`}
                  onClick={() => setSelectedId(report.id)}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="font-medium">#{report.id} {report.title}</p>
                    <Badge variant={report.status === "completed" ? "default" : report.status === "failed" ? "destructive" : "secondary"}>
                      {report.status}
                    </Badge>
                    {report.model && <Badge variant="outline">{report.model}</Badge>}
                    {report.elapsedMs != null && <span className="text-xs text-muted-foreground">{report.elapsedMs} ms</span>}
                  </div>
                  {report.summary && <p className="text-sm text-muted-foreground line-clamp-2">{report.summary}</p>}
                  {report.error && <p className="text-sm text-red-400">{report.error}</p>}
                </button>
              ))}
              {selectedReport?.status === "running" && (
                <p className="text-sm text-muted-foreground">OpenRouter is writing report #{selectedReport.id}…</p>
              )}
              {selectedReport?.bodyMarkdown && (
                <div className="mt-4 rounded-md border border-border p-4 whitespace-pre-wrap text-sm leading-6 bg-zinc-950">
                  {selectedReport.bodyMarkdown}
                </div>
              )}
            </CardContent>
          </Card>
        </main>
      </div>
    </div>
  );
}
