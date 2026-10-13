import { useQuery } from "@tanstack/react-query";
import Sidebar from "@/components/layout/sidebar";
import Header from "@/components/layout/header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

interface SettingsStatus {
  authentication: string;
  syntheticFixtures: boolean;
  wiz: { configured: boolean };
  siem: { splunk: boolean; qradar: boolean; sentinel: boolean };
  services: Record<string, string>;
}

interface Policy {
  id: number;
  name: string;
  description?: string;
  isActive: boolean;
  category: string;
}

export default function SettingsPage() {
  const { data: status } = useQuery<SettingsStatus>({ queryKey: ["/api/settings/status"] });
  const { data: policies = [] } = useQuery<Policy[]>({ queryKey: ["/api/governance/policies"] });

  const connector = (enabled: boolean) => (
    <Badge variant={enabled ? "default" : "secondary"}>{enabled ? "configured" : "not configured"}</Badge>
  );

  return (
    <div className="flex h-screen bg-background text-foreground">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden ml-64">
        <Header title="Settings" subtitle="Authentication, connectors, and governance policies" showSearch={false} />
        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          <Card>
            <CardHeader><CardTitle>Platform</CardTitle></CardHeader>
            <CardContent className="space-y-2 text-sm">
              <p>Authentication: {status?.authentication}</p>
              <p>Synthetic fixtures: {status?.syntheticFixtures ? "enabled" : "disabled"}</p>
              <p className="flex items-center gap-2">Wiz {connector(Boolean(status?.wiz.configured))}</p>
              <p className="flex items-center gap-2">Splunk {connector(Boolean(status?.siem.splunk))}</p>
              <p className="flex items-center gap-2">QRadar {connector(Boolean(status?.siem.qradar))}</p>
              <p className="flex items-center gap-2">Sentinel {connector(Boolean(status?.siem.sentinel))}</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle>Governance policies</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              {policies.map((policy) => (
                <div key={policy.id} className="flex items-center justify-between border border-border rounded-md p-3">
                  <div>
                    <p className="font-medium">{policy.name}</p>
                    <p className="text-sm text-muted-foreground">{policy.description}</p>
                  </div>
                  <Badge variant={policy.isActive ? "default" : "secondary"}>
                    {policy.isActive ? "active" : "disabled"}
                  </Badge>
                </div>
              ))}
            </CardContent>
          </Card>
        </main>
      </div>
    </div>
  );
}
