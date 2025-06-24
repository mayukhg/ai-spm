import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Progress } from '@/components/ui/progress';
import { useQuery } from '@tanstack/react-query';
import { 
  Activity, 
  Server, 
  Database, 
  Shield, 
  AlertTriangle, 
  CheckCircle,
  Clock,
  Cpu,
  HardDrive,
  Memory,
  Network,
  Bell,
  Settings,
  Zap,
  Eye,
  TrendingUp,
  TrendingDown,
  Minus
} from 'lucide-react';

interface SystemHealth {
  status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  timestamp: string;
  uptime: number;
  version: string;
  components: {
    database: ComponentHealth;
    authentication: ComponentHealth;
    security: ComponentHealth;
    agentic: ComponentHealth;
    infrastructure: ComponentHealth;
    dependencies: ComponentHealth;
  };
  alerts: Alert[];
  metrics: SystemMetrics;
}

interface ComponentHealth {
  name: string;
  status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  lastCheck: string;
  responseTime?: number;
  message?: string;
  metrics?: Record<string, any>;
}

interface Alert {
  id: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  component: string;
  timestamp: string;
  currentValue?: number;
  threshold?: number;
  tags: string[];
}

interface SystemMetrics {
  application: {
    apiGateway: {
      responseTime: number;
      throughput: number;
      errorRate: number;
      activeConnections: number;
      requestsPerSecond: number;
    };
    authentication: {
      loginSuccessRate: number;
      authenticationLatency: number;
      activeUserSessions: number;
      failedLoginAttempts: number;
      ssoHealthStatus: string;
    };
    database: {
      connectionPoolSize: number;
      activeConnections: number;
      queryLatency: number;
      transactionRate: number;
      slowQueries: number;
    };
  };
  infrastructure: {
    compute: {
      cpuUsage: number;
      memoryUsage: number;
      diskUsage: number;
      loadAverage: number[];
      processCount: number;
    };
    network: {
      bytesIn: number;
      bytesOut: number;
      packetsIn: number;
      packetsOut: number;
      connectionErrors: number;
    };
  };
  security: {
    threatDetection: {
      activeThreats: number;
      detectionLatency: number;
      falsePositiveRate: number;
      threatScore: number;
    };
    compliance: {
      policyViolations: number;
      complianceScore: number;
      auditTrailIntegrity: boolean;
      privacyRequests: number;
    };
  };
  agentic: {
    agents: {
      activeAgents: number;
      healthyAgents: number;
      averageHealthScore: number;
      behavioralAnomalies: number;
    };
    workflows: {
      executionSuccessRate: number;
      averageExecutionTime: number;
      failedWorkflows: number;
      securityViolations: number;
    };
  };
}

export default function SystemMonitoring() {
  const [selectedTimeRange, setSelectedTimeRange] = useState('1h');
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Fetch system health data
  const { data: healthData, isLoading, error, refetch } = useQuery({
    queryKey: ['system-health'],
    queryFn: async () => {
      const response = await fetch('/api/monitoring/health');
      if (!response.ok) {
        throw new Error('Failed to fetch system health');
      }
      const result = await response.json();
      return result.health as SystemHealth;
    },
    refetchInterval: autoRefresh ? 30000 : false, // Refresh every 30 seconds if enabled
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'text-green-600 bg-green-100';
      case 'degraded': return 'text-yellow-600 bg-yellow-100';
      case 'unhealthy': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-blue-500';
      default: return 'bg-gray-500';
    }
  };

  const formatUptime = (uptimeMs: number) => {
    const seconds = Math.floor(uptimeMs / 1000);
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return `${days}d ${hours}h ${minutes}m`;
  };

  const formatBytes = (bytes: number) => {
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
  };

  const getTrendIcon = (value: number, threshold: number) => {
    if (value > threshold * 1.1) return <TrendingUp className="w-4 h-4 text-red-500" />;
    if (value < threshold * 0.9) return <TrendingDown className="w-4 h-4 text-green-500" />;
    return <Minus className="w-4 h-4 text-gray-500" />;
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

  if (error) {
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

  const health = healthData!;

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
            variant={autoRefresh ? "default" : "outline"}
            size="sm"
            onClick={() => setAutoRefresh(!autoRefresh)}
          >
            <Activity className={`w-4 h-4 mr-2 ${autoRefresh ? 'animate-spin' : ''}`} />
            Auto Refresh
          </Button>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <Eye className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* System Overview */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">System Status</CardTitle>
            <Server className="w-4 h-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="flex items-center space-x-2">
              <Badge className={getStatusColor(health.status)}>
                {health.status.toUpperCase()}
              </Badge>
              {health.status === 'healthy' && <CheckCircle className="w-4 h-4 text-green-500" />}
              {health.status === 'degraded' && <AlertTriangle className="w-4 h-4 text-yellow-500" />}
              {health.status === 'unhealthy' && <AlertTriangle className="w-4 h-4 text-red-500" />}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Version {health.version}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Uptime</CardTitle>
            <Clock className="w-4 h-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{formatUptime(health.uptime)}</div>
            <p className="text-xs text-muted-foreground">
              Since {new Date(Date.now() - health.uptime).toLocaleDateString()}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Alerts</CardTitle>
            <Bell className="w-4 h-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{health.alerts.length}</div>
            <p className="text-xs text-muted-foreground">
              {health.alerts.filter(a => a.severity === 'critical').length} critical
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Agents</CardTitle>
            <Zap className="w-4 h-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{health.metrics.agentic.agents.activeAgents}</div>
            <p className="text-xs text-muted-foreground">
              {health.metrics.agentic.agents.healthyAgents}/{health.metrics.agentic.agents.activeAgents} healthy
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Recent Alerts */}
      {health.alerts.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Recent Alerts</CardTitle>
            <CardDescription>Latest system alerts requiring attention</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {health.alerts.slice(0, 5).map((alert) => (
                <div key={alert.id} className="flex items-center justify-between p-3 border rounded-lg">
                  <div className="flex items-center space-x-3">
                    <div className={`w-2 h-2 rounded-full ${getSeverityColor(alert.severity)}`} />
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
                  <Button variant="outline" size="sm">
                    Acknowledge
                  </Button>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <Tabs defaultValue="components" className="space-y-6">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="components">Components</TabsTrigger>
          <TabsTrigger value="performance">Performance</TabsTrigger>
          <TabsTrigger value="infrastructure">Infrastructure</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
        </TabsList>

        {/* Components Tab */}
        <TabsContent value="components" className="space-y-6">
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {Object.entries(health.components).map(([name, component]) => (
              <Card key={name}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-lg capitalize">{name}</CardTitle>
                    <div className="flex items-center space-x-2">
                      <div className={`w-2 h-2 rounded-full ${getStatusColor(component.status).split(' ')[1]}`} />
                      <Badge variant="outline" className={getStatusColor(component.status)}>
                        {component.status}
                      </Badge>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <p className="text-sm text-muted-foreground">{component.message}</p>
                    {component.responseTime && (
                      <div className="flex items-center justify-between text-sm">
                        <span>Response Time:</span>
                        <span className="font-medium">{component.responseTime.toFixed(2)}ms</span>
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

        {/* Performance Tab */}
        <TabsContent value="performance" className="space-y-6">
          <div className="grid gap-6 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>API Gateway Performance</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <span>Response Time</span>
                  <div className="flex items-center space-x-2">
                    <span className="font-medium">{health.metrics.application.apiGateway.responseTime}ms</span>
                    {getTrendIcon(health.metrics.application.apiGateway.responseTime, 200)}
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <span>Throughput</span>
                  <span className="font-medium">{health.metrics.application.apiGateway.throughput} req/s</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Error Rate</span>
                  <span className="font-medium">{health.metrics.application.apiGateway.errorRate}%</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Active Connections</span>
                  <span className="font-medium">{health.metrics.application.apiGateway.activeConnections}</span>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Database Performance</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <span>Query Latency</span>
                  <div className="flex items-center space-x-2">
                    <span className="font-medium">{health.metrics.application.database.queryLatency}ms</span>
                    {getTrendIcon(health.metrics.application.database.queryLatency, 50)}
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <span>Transaction Rate</span>
                  <span className="font-medium">{health.metrics.application.database.transactionRate} tx/s</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Active Connections</span>
                  <span className="font-medium">
                    {health.metrics.application.database.activeConnections}/{health.metrics.application.database.connectionPoolSize}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Slow Queries</span>
                  <span className="font-medium">{health.metrics.application.database.slowQueries}</span>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Infrastructure Tab */}
        <TabsContent value="infrastructure" className="space-y-6">
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Cpu className="w-4 h-4 mr-2" />
                  CPU Usage
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span>Current</span>
                    <span className="font-medium">{health.metrics.infrastructure.compute.cpuUsage.toFixed(1)}%</span>
                  </div>
                  <Progress value={health.metrics.infrastructure.compute.cpuUsage} className="h-2" />
                  <div className="text-xs text-muted-foreground">
                    Load Average: {health.metrics.infrastructure.compute.loadAverage.map(l => l.toFixed(2)).join(', ')}
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Memory className="w-4 h-4 mr-2" />
                  Memory Usage
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span>Current</span>
                    <span className="font-medium">{health.metrics.infrastructure.compute.memoryUsage.toFixed(1)}%</span>
                  </div>
                  <Progress value={health.metrics.infrastructure.compute.memoryUsage} className="h-2" />
                  <div className="text-xs text-muted-foreground">
                    Processes: {health.metrics.infrastructure.compute.processCount}
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <HardDrive className="w-4 h-4 mr-2" />
                  Disk Usage
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span>Current</span>
                    <span className="font-medium">{health.metrics.infrastructure.compute.diskUsage.toFixed(1)}%</span>
                  </div>
                  <Progress value={health.metrics.infrastructure.compute.diskUsage} className="h-2" />
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Network className="w-4 h-4 mr-2" />
                Network Activity
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                <div className="text-center">
                  <p className="text-sm text-muted-foreground">Bytes In</p>
                  <p className="text-lg font-medium">{formatBytes(health.metrics.infrastructure.network.bytesIn)}</p>
                </div>
                <div className="text-center">
                  <p className="text-sm text-muted-foreground">Bytes Out</p>
                  <p className="text-lg font-medium">{formatBytes(health.metrics.infrastructure.network.bytesOut)}</p>
                </div>
                <div className="text-center">
                  <p className="text-sm text-muted-foreground">Packets In</p>
                  <p className="text-lg font-medium">{health.metrics.infrastructure.network.packetsIn}</p>
                </div>
                <div className="text-center">
                  <p className="text-sm text-muted-foreground">Connection Errors</p>
                  <p className="text-lg font-medium">{health.metrics.infrastructure.network.connectionErrors}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Security Tab */}
        <TabsContent value="security" className="space-y-6">
          <div className="grid gap-6 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Shield className="w-4 h-4 mr-2" />
                  Security Status
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <span>Active Threats</span>
                  <Badge variant={health.metrics.security.threatDetection.activeThreats > 0 ? "destructive" : "secondary"}>
                    {health.metrics.security.threatDetection.activeThreats}
                  </Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span>Threat Score</span>
                  <span className="font-medium">{health.metrics.security.threatDetection.threatScore}/100</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Detection Latency</span>
                  <span className="font-medium">{health.metrics.security.threatDetection.detectionLatency}s</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>False Positive Rate</span>
                  <span className="font-medium">{health.metrics.security.threatDetection.falsePositiveRate}%</span>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Compliance Status</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <span>Compliance Score</span>
                  <div className="flex items-center space-x-2">
                    <span className="font-medium">{health.metrics.security.compliance.complianceScore}%</span>
                    <Progress value={health.metrics.security.compliance.complianceScore} className="w-16 h-2" />
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <span>Policy Violations</span>
                  <Badge variant={health.metrics.security.compliance.policyViolations > 0 ? "destructive" : "secondary"}>
                    {health.metrics.security.compliance.policyViolations}
                  </Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span>Privacy Requests</span>
                  <span className="font-medium">{health.metrics.security.compliance.privacyRequests}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Audit Trail Integrity</span>
                  {health.metrics.security.compliance.auditTrailIntegrity ? 
                    <CheckCircle className="w-4 h-4 text-green-500" /> : 
                    <AlertTriangle className="w-4 h-4 text-red-500" />
                  }
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Agentic Workflows Security</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                <div className="text-center">
                  <p className="text-sm text-muted-foreground">Active Agents</p>
                  <p className="text-lg font-medium">{health.metrics.agentic.agents.activeAgents}</p>
                </div>
                <div className="text-center">
                  <p className="text-sm text-muted-foreground">Health Score</p>
                  <p className="text-lg font-medium">{health.metrics.agentic.agents.averageHealthScore}%</p>
                </div>
                <div className="text-center">
                  <p className="text-sm text-muted-foreground">Workflow Success Rate</p>
                  <p className="text-lg font-medium">{health.metrics.agentic.workflows.executionSuccessRate}%</p>
                </div>
                <div className="text-center">
                  <p className="text-sm text-muted-foreground">Security Violations</p>
                  <p className="text-lg font-medium">{health.metrics.agentic.workflows.securityViolations}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}