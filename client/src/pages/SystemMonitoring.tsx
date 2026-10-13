import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useToast } from '@/hooks/use-toast';
import {
  Activity,
  Server,
  AlertTriangle,
  CheckCircle,
  Clock,
  Bell,
  Eye,
} from 'lucide-react';

interface ComponentHealth {
  name: string;
  status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  lastCheck: string;
  responseTime?: number;
  uptime?: number;
  details?: Record<string, unknown>;
  message?: string;
}

interface SystemHealth {
  overall: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  components: ComponentHealth[];
  summary: {
    total: number;
    healthy: number;
    degraded: number;
    unhealthy: number;
  };
}

interface MonitoringAlert {
  id: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  component: string;
  timestamp: string;
}

interface PerformanceSummary {
  uptime?: { seconds?: number; human?: string };
  memory?: {
    heapUsed?: string;
    heapTotal?: string;
    heapUsedPercent?: number;
    rss?: string;
  };
  process?: { pid?: number; version?: string };
}

function statusColor(status: string) {
  switch (status) {
    case 'healthy':
      return 'text-green-600 bg-green-100 dark:text-green-200 dark:bg-green-950';
    case 'degraded':
      return 'text-yellow-600 bg-yellow-100 dark:text-yellow-200 dark:bg-yellow-950';
    case 'unhealthy':
      return 'text-red-600 bg-red-100 dark:text-red-200 dark:bg-red-950';
    default:
      return 'text-gray-600 bg-gray-100 dark:text-gray-200 dark:bg-gray-900';
  }
}

function severityDot(severity: string) {
  switch (severity) {
    case 'critical':
      return 'bg-red-500';
    case 'high':
      return 'bg-orange-500';
    case 'medium':
      return 'bg-yellow-500';
    case 'low':
      return 'bg-blue-500';
    default:
      return 'bg-gray-500';
  }
}

export default function SystemMonitoring() {
  const [autoRefresh, setAutoRefresh] = useState(true);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const {
    data: health,
    isLoading,
    error,
    refetch,
  } = useQuery<SystemHealth>({
    queryKey: ['system-health'],
    queryFn: async () => {
      const response = await fetch('/api/monitoring/health', { credentials: 'include' });
      const result = await response.json().catch(() => null);
      if (!response.ok || !result?.health) {
        throw new Error(result?.message || 'Failed to fetch system health');
      }
      return result.health as SystemHealth;
    },
    refetchInterval: autoRefresh ? 30000 : false,
  });

  const { data: alerts = [] } = useQuery<MonitoringAlert[]>({
    queryKey: ['system-alerts'],
    queryFn: async () => {
      const response = await fetch('/api/monitoring/alerts', { credentials: 'include' });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) return [];
      return (result.alerts || []) as MonitoringAlert[];
    },
    refetchInterval: autoRefresh ? 30000 : false,
  });

  const { data: performance } = useQuery<PerformanceSummary>({
    queryKey: ['system-performance'],
    queryFn: async () => {
      const response = await fetch('/api/monitoring/performance', { credentials: 'include' });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) return {};
      return (result.performance || result) as PerformanceSummary;
    },
    refetchInterval: autoRefresh ? 30000 : false,
  });

  const acknowledgeAlert = async (alertId: string) => {
    try {
      const response = await fetch(`/api/monitoring/alerts/${alertId}/acknowledge`, {
        method: 'POST',
        credentials: 'include',
      });
      if (!response.ok) throw new Error('Acknowledge failed');
      toast({ title: 'Alert acknowledged', description: `Alert ${alertId} marked as acknowledged.` });
      await queryClient.invalidateQueries({ queryKey: ['system-alerts'] });
    } catch (err) {
      toast({
        title: 'Acknowledge failed',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    }
  };

  if (isLoading) {
    return (
      <div className="container mx-auto p-6">
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <Activity className="w-8 h-8 animate-spin mx-auto mb-4" />
            <p>Loading system health data...</p>
          </div>
        </div>
      </div>
    );
  }

  if (error || !health) {
    return (
      <div className="container mx-auto p-6">
        <Alert>
          <AlertTriangle className="w-4 h-4" />
          <AlertDescription>
            Failed to load system health data. Please check your connection and try again.
            <Button variant="outline" size="sm" className="ml-2" onClick={() => refetch()}>
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  const derivedAlerts =
    alerts.length > 0
      ? alerts
      : health.components
          .filter((c) => c.status === 'unhealthy' || c.status === 'degraded')
          .map((c) => ({
            id: `component-${c.name}`,
            name: `${c.name} ${c.status}`,
            description:
              typeof c.details?.error === 'string'
                ? c.details.error
                : typeof c.details?.status === 'string'
                  ? String(c.details.status)
                  : `${c.name} reported ${c.status}`,
            severity: (c.status === 'unhealthy' ? 'critical' : 'medium') as MonitoringAlert['severity'],
            component: c.name,
            timestamp: c.lastCheck,
          }));

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">System Monitoring</h1>
          <p className="text-muted-foreground">
            Real-time health monitoring and alerting for AI-SPM platform
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button
            variant={autoRefresh ? 'default' : 'outline'}
            size="sm"
            onClick={() => setAutoRefresh(!autoRefresh)}
          >
            <Activity className={`w-4 h-4 mr-2 ${autoRefresh ? 'animate-spin' : ''}`} />
            Auto Refresh
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              refetch();
              queryClient.invalidateQueries({ queryKey: ['system-alerts'] });
              queryClient.invalidateQueries({ queryKey: ['system-performance'] });
            }}
          >
            <Eye className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">System Status</CardTitle>
            <Server className="w-4 h-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="flex items-center space-x-2">
              <Badge className={statusColor(health.overall)}>{health.overall.toUpperCase()}</Badge>
              {health.overall === 'healthy' && <CheckCircle className="w-4 h-4 text-green-500" />}
              {health.overall !== 'healthy' && <AlertTriangle className="w-4 h-4 text-yellow-500" />}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Checked {new Date(health.timestamp).toLocaleTimeString()}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Uptime</CardTitle>
            <Clock className="w-4 h-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {performance?.uptime?.human ||
                `${Math.floor((processUptimeSeconds(health) / 3600) || 0)}h`}
            </div>
            <p className="text-xs text-muted-foreground">Process uptime</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Alerts</CardTitle>
            <Bell className="w-4 h-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{derivedAlerts.length}</div>
            <p className="text-xs text-muted-foreground">
              {health.summary.unhealthy} unhealthy / {health.summary.degraded} degraded
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Components</CardTitle>
            <Activity className="w-4 h-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {health.summary.healthy}/{health.summary.total}
            </div>
            <p className="text-xs text-muted-foreground">Healthy components</p>
          </CardContent>
        </Card>
      </div>

      {derivedAlerts.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Recent Alerts</CardTitle>
            <CardDescription>Latest system alerts requiring attention</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {derivedAlerts.slice(0, 8).map((alert) => (
                <div key={alert.id} className="flex items-center justify-between p-3 border rounded-lg">
                  <div className="flex items-center space-x-3">
                    <div className={`w-2 h-2 rounded-full ${severityDot(alert.severity)}`} />
                    <div>
                      <p className="font-medium">{alert.name}</p>
                      <p className="text-sm text-muted-foreground">{alert.description}</p>
                      <div className="flex items-center space-x-2 mt-1">
                        <Badge variant="outline" className="text-xs">
                          {alert.component}
                        </Badge>
                        <span className="text-xs text-muted-foreground">
                          {new Date(alert.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                    </div>
                  </div>
                  {!String(alert.id).startsWith('component-') && (
                    <Button variant="outline" size="sm" onClick={() => acknowledgeAlert(alert.id)}>
                      Acknowledge
                    </Button>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <Tabs defaultValue="components" className="space-y-6">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="components">Components</TabsTrigger>
          <TabsTrigger value="performance">Performance</TabsTrigger>
        </TabsList>

        <TabsContent value="components" className="space-y-6">
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {health.components.map((component) => (
              <Card key={component.name}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-lg capitalize">{component.name}</CardTitle>
                    <Badge variant="outline" className={statusColor(component.status)}>
                      {component.status}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <p className="text-sm text-muted-foreground">
                      {typeof component.details?.error === 'string'
                        ? component.details.error
                        : typeof component.details?.status === 'string'
                          ? String(component.details.status)
                          : component.message || 'OK'}
                    </p>
                    {typeof component.responseTime === 'number' && (
                      <div className="flex items-center justify-between text-sm">
                        <span>Response Time:</span>
                        <span className="font-medium">{component.responseTime}ms</span>
                      </div>
                    )}
                    <div className="flex items-center justify-between text-sm">
                      <span>Last Check:</span>
                      <span className="font-medium">
                        {new Date(component.lastCheck).toLocaleTimeString()}
                      </span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="performance" className="space-y-6">
          <div className="grid gap-6 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Memory</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span>Heap used</span>
                  <span className="font-medium">{performance?.memory?.heapUsed || '—'}</span>
                </div>
                <div className="flex justify-between">
                  <span>Heap total</span>
                  <span className="font-medium">{performance?.memory?.heapTotal || '—'}</span>
                </div>
                <div className="flex justify-between">
                  <span>RSS</span>
                  <span className="font-medium">{performance?.memory?.rss || '—'}</span>
                </div>
                <div className="flex justify-between">
                  <span>Heap %</span>
                  <span className="font-medium">
                    {performance?.memory?.heapUsedPercent != null
                      ? `${performance.memory.heapUsedPercent}%`
                      : '—'}
                  </span>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Process</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span>PID</span>
                  <span className="font-medium">{performance?.process?.pid ?? '—'}</span>
                </div>
                <div className="flex justify-between">
                  <span>Node</span>
                  <span className="font-medium">{performance?.process?.version || '—'}</span>
                </div>
                <div className="flex justify-between">
                  <span>Uptime</span>
                  <span className="font-medium">{performance?.uptime?.human || '—'}</span>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function processUptimeSeconds(health: SystemHealth) {
  const db = health.components.find((c) => c.name === 'database');
  return typeof db?.uptime === 'number' ? db.uptime : 0;
}
