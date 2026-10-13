import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import Sidebar from "@/components/layout/sidebar";
import Header from "@/components/layout/header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { apiRequest } from "@/lib/queryClient";

interface LlmToken {
  text: string;
  flagged: boolean;
  category: "prompt_injection" | "jailbreak" | null;
}

interface LlmResult {
  id: string;
  text: string;
  expected: string;
  label: string;
  score: number;
  decision: "allow" | "block";
  agreesWithExpected: boolean;
  title: string;
  summary: string;
  tokens: LlmToken[];
}

interface LlmReport {
  assetName: string;
  threshold: number;
  evaluated: number;
  blocked: number;
  allowed: number;
  results: LlmResult[];
}

function tokenClass(token: LlmToken) {
  if (!token.flagged) return "text-zinc-200";
  if (token.category === "jailbreak") return "bg-orange-500 text-black rounded px-1";
  return "bg-red-600 text-white rounded px-1";
}

export default function PromptChecks() {
  const queryClient = useQueryClient();
  const [running, setRunning] = useState(false);
  const { data, isLoading } = useQuery<LlmReport>({ queryKey: ["/api/llm/classifications"] });

  const runClassifier = async () => {
    setRunning(true);
    try {
      await apiRequest("POST", "/api/llm/classifications");
      await queryClient.invalidateQueries({ queryKey: ["/api/llm/classifications"] });
      await queryClient.invalidateQueries({ queryKey: ["/api/security-alerts/recent"] });
      await queryClient.invalidateQueries({ queryKey: ["/api/dashboard/metrics"] });
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="flex h-screen bg-background text-foreground">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden ml-64">
        <Header
          title="Prompt checks"
          subtitle="Prompt injection, jailbreak, and token-level scores for the support assistant"
          showSearch={false}
        />
        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle>Synthetic prompt evaluation</CardTitle>
                <p className="text-sm text-muted-foreground mt-1">
                  {data
                    ? `${data.assetName}: ${data.blocked} blocked, ${data.allowed} allowed, threshold ${data.threshold}`
                    : "Loading classifications"}
                </p>
              </div>
              <Button onClick={runClassifier} disabled={running || isLoading}>
                {running ? "Classifying" : "Classify and store alerts"}
              </Button>
            </CardHeader>
            <CardContent className="space-y-4">
              {data?.results.map((result) => (
                <div key={result.id} className="border border-border rounded-md p-4 space-y-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="font-medium">{result.title}</p>
                    <Badge variant={result.decision === "block" ? "destructive" : "secondary"}>
                      {result.decision}
                    </Badge>
                    <Badge variant="outline">{result.label.replaceAll("_", " ")}</Badge>
                    <span className="text-sm text-muted-foreground">score {result.score.toFixed(2)}</span>
                    {result.agreesWithExpected && (
                      <span className="text-sm text-green-400">matches expected label</span>
                    )}
                  </div>
                  <p className="leading-7">
                    {result.tokens.map((token, index) => (
                      <span key={`${result.id}-${token.text}-${index}`}>
                        {index > 0 ? " " : ""}
                        <span className={tokenClass(token)}>{token.text}</span>
                      </span>
                    ))}
                  </p>
                  <p className="text-sm text-muted-foreground">{result.summary}</p>
                </div>
              ))}
            </CardContent>
          </Card>
        </main>
      </div>
    </div>
  );
}
