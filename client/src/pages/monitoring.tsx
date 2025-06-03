import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import Sidebar from "@/components/layout/sidebar";
import Header from "@/components/layout/header";
import SecurityTrendChart from "@/components/charts/security-trend-chart";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { 
  Eye, 
  Activity, 
  AlertTriangle, 
  TrendingUp, 
  Monitor,
  Play,
  Pause,
  Settings,
  RefreshCw,
  Clock,
  Shield
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { SecurityAlert } from "@shared/schema";
import { formatDistanceToNow } from "date-fns";

export default function Monitoring() {
  const [activeTab, setActiveTab] = useState("realtime");
  const [isMonitoring, setIsMonitoring] = useState(true);

  // Fetch real-time alerts
  const { data: alerts, isLoading: alertsLoading } = useQuery<SecurityAlert[]>({
    queryKey: ["/api/security-alerts", { limit: 50 }],
    refetchInterval: isMonitoring ? 5000 : false, // Refresh every 5 seconds when monitoring
  });

  // Fetch recent alerts for the feed
  const { data: recentAlerts, isLoading: recentLoading } = useQuery<SecurityAlert[]>({
    queryKey: ["/api/security-alerts/recent", { limit: 10 }],
    refetchInterval: isMonitoring ? 10000 : false, // Refresh every 10 seconds
  });

  const getAlertIcon = (type: string, severity: string) => {
    if (severity === "critical") {
      return <AlertTriangle className="h-5 w-5 text-red-500" />;
    }
    
    switch (type) {
      case "prompt_injection":
        return <AlertTriangle className="h-5 w-5 text-red-500" />;
      case "data_poisoning":
        return <Shield className="h-5 w-5 text-orange-500" />;
      case "anomalous_behavior":
        return <Activity className="h-5 w-5 text-yellow-500" />;
      default:
        return <Monitor className="h-5 w-5 text-blue-500" />;
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "critical":
        return <Badge variant="destructive">Critical</Badge>;
      case "high":
        return <Badge className="bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-200">High</Badge>;
      case "medium":
        return <Badge className="bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-200">Medium</Badge>;
      case "low":
        return <Badge variant="outline">Low</Badge>;
      default:
        return <Badge variant="secondary">Info</Badge>;
    }
  };

  const formatAlertType = (type: string) => {
    return type
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  };

  const toggleMonitoring = () => {
    setIsMonitoring(!isMonitoring);
  };

  return (
    <div className="flex h-screen bg-background">
      <Sidebar />
      
      <div className="flex-1 flex flex-col overflow-hidden ml-64">
        <Header 
          title="Real-time Monitoring" 
          subtitle="AI system behavior and threat detection"
          actions={
            <div className="flex items-center gap-2">
              <Button
                variant={isMonitoring ? "default" : "outline"}
                size="sm"
                onClick={toggleMonitoring}
                className="gap-2"
              >
                {isMonitoring ? (
                  <>
                    <Pause className="h-4 w-4" />
                    Pause
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4" />
                    Start
                  </>
                )}
              </Button>
              <Button variant="outline" size="sm" className="gap-2">
                <Settings className="h-4 w-4" />
                Configure
              </Button>
            </div>
          }
        />

        <main className="flex-1 overflow-y-auto p-6">
          <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="realtime">Real-time Activity</TabsTrigger>
              <TabsTrigger value="alerts">Alert Management</TabsTrigger>
              <TabsTrigger value="analytics">Analytics</TabsTrigger>
            </TabsList>

            {/* Real-time Activity Tab */}
            <TabsContent value="realtime" className="space-y-6">
              {/* Status Cards */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                <Card className="dashboard-card">
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium text-muted-foreground">
                      Monitoring Status
                    </CardTitle>
                    <div className={cn(
                      "h-2 w-2 rounded-full",
                      isMonitoring ? "bg-green-500" : "bg-red-500"
                    )} />
                  </CardHeader>
                  <CardContent>
                    <div className={cn(
                      "text-2xl font-bold",
                      isMonitoring ? "text-green-600" : "text-red-600"
                    )}>
                      {isMonitoring ? "ACTIVE" : "PAUSED"}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {isMonitoring ? "Real-time monitoring enabled" : "Monitoring is paused"}
                    </p>
                  </CardContent>
                </Card>

                <Card className="dashboard-card">
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium text-muted-foreground">
                      Assets Monitored
                    </CardTitle>
                    <Monitor className="h-5 w-5 text-primary" />
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold text-foreground">247</div>
                    <div className="flex items-center mt-1">
                      <TrendingUp className="h-3 w-3 text-green-500 mr-1" />
                      <span className="text-xs text-green-600">All systems operational</span>
                    </div>
                  </CardContent>
                </Card>

                <Card className="dashboard-card">
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium text-muted-foreground">
                      Active Alerts
                    </CardTitle>
                    <AlertTriangle className="h-5 w-5 text-orange-500" />
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold text-orange-600">
                      {alerts?.filter(a => a.status === "active").length || 0}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Requiring attention
                    </p>
                  </CardContent>
                </Card>

                <Card className="dashboard-card">
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium text-muted-foreground">
                      Response Time
                    </CardTitle>
                    <Activity className="h-5 w-5 text-green-500" />
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold text-green-600">1.2s</div>
                    <p className="text-xs text-muted-foreground">
                      Average detection time
                    </p>
                  </CardContent>
                </Card>
              </div>

              {/* Real-time Activity Chart */}
              <Card className="dashboard-card">
                <CardHeader className="flex flex-row items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Activity className="h-5 w-5 text-primary" />
                      System Activity Timeline
                    </CardTitle>
                    <p className="text-sm text-muted-foreground mt-1">
                      Real-time AI system metrics and events
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="flex items-center gap-1 text-sm text-muted-foreground">
                      <div className={cn(
                        "w-2 h-2 rounded-full",
                        isMonitoring ? "bg-green-500" : "bg-red-500"
                      )} />
                      {isMonitoring ? "Live" : "Paused"}
                    </div>
                    <Button variant="outline" size="sm">
                      <RefreshCw className="h-4 w-4" />
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  <SecurityTrendChart />
                </CardContent>
              </Card>

              {/* Recent Activity Feed */}
              <Card className="dashboard-card">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Clock className="h-5 w-5 text-primary" />
                    Recent Activity
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {recentLoading ? (
                      Array.from({ length: 5 }).map((_, i) => (
                        <div key={i} className="flex items-center gap-3 p-3 border rounded-lg">
                          <Skeleton className="h-5 w-5" />
                          <div className="flex-1 space-y-1">
                            <Skeleton className="h-4 w-3/4" />
                            <Skeleton className="h-3 w-1/2" />
                          </div>
                          <Skeleton className="h-6 w-16" />
                        </div>
                      ))
                    ) : recentAlerts && recentAlerts.length > 0 ? (
                      recentAlerts.map((alert) => (
                        <div key={alert.id} className="flex items-center gap-3 p-3 border rounded-lg hover:bg-muted/50 transition-colors">
                          {getAlertIcon(alert.type, alert.severity)}
                          <div className="flex-1">
                            <p className="text-sm font-medium text-foreground">
                              {alert.title}
                            </p>
                            <p className="text-xs text-muted-foreground">
                              {formatAlertType(alert.type)} • {formatDistanceToNow(new Date(alert.detectedAt), { addSuffix: true })}
                            </p>
                          </div>
                          {getSeverityBadge(alert.severity)}
                        </div>
                      ))
                    ) : (
                      <div className="text-center py-8">
                        <Activity className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                        <p className="text-muted-foreground">No recent activity</p>
                        <p className="text-sm text-muted-foreground mt-1">
                          System is running smoothly
                        </p>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* Alert Management Tab */}
            <TabsContent value="alerts" className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5 text-primary" />
                    Alert Management
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="rounded-md border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Alert</TableHead>
                          <TableHead>Type</TableHead>
                          <TableHead>Severity</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead>Asset</TableHead>
                          <TableHead>Detected</TableHead>
                          <TableHead className="text-right">Actions</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {alertsLoading ? (
                          Array.from({ length: 10 }).map((_, i) => (
                            <TableRow key={i}>
                              <TableCell>
                                <div className="flex items-center gap-3">
                                  <Skeleton className="h-5 w-5" />
                                  <Skeleton className="h-4 w-48" />
                                </div>
                              </TableCell>
                              <TableCell><Skeleton className="h-4 w-24" /></TableCell>
                              <TableCell><Skeleton className="h-6 w-16" /></TableCell>
                              <TableCell><Skeleton className="h-6 w-20" /></TableCell>
                              <TableCell><Skeleton className="h-4 w-12" /></TableCell>
                              <TableCell><Skeleton className="h-4 w-20" /></TableCell>
                              <TableCell>
                                <div className="flex justify-end">
                                  <Skeleton className="h-8 w-8" />
                                </div>
                              </TableCell>
                            </TableRow>
                          ))
                        ) : alerts && alerts.length > 0 ? (
                          alerts.map((alert) => (
                            <TableRow key={alert.id} className="hover:bg-muted/50">
                              <TableCell>
                                <div className="flex items-center gap-3">
                                  {getAlertIcon(alert.type, alert.severity)}
                                  <div>
                                    <div className="font-medium text-foreground">
                                      {alert.title}
                                    </div>
                                    <div className="text-sm text-muted-foreground line-clamp-1">
                                      {alert.description}
                                    </div>
                                  </div>
                                </div>
                              </TableCell>
                              <TableCell className="capitalize">
                                {formatAlertType(alert.type)}
                              </TableCell>
                              <TableCell>
                                {getSeverityBadge(alert.severity)}
                              </TableCell>
                              <TableCell>
                                <Badge 
                                  variant={alert.status === "active" ? "destructive" : "secondary"}
                                  className="capitalize"
                                >
                                  {alert.status}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-muted-foreground">
                                {alert.assetId ? `#${alert.assetId}` : "N/A"}
                              </TableCell>
                              <TableCell className="text-muted-foreground">
                                {formatDistanceToNow(new Date(alert.detectedAt), { addSuffix: true })}
                              </TableCell>
                              <TableCell className="text-right">
                                <Button variant="ghost" size="sm">
                                  <Eye className="h-4 w-4" />
                                </Button>
                              </TableCell>
                            </TableRow>
                          ))
                        ) : (
                          <TableRow>
                            <TableCell colSpan={7} className="text-center py-8">
                              <Shield className="h-12 w-12 text-green-500 mx-auto mb-4" />
                              <p className="text-muted-foreground">No alerts found</p>
                              <p className="text-sm text-muted-foreground mt-1">
                                Your AI systems are secure
                              </p>
                            </TableCell>
                          </TableRow>
                        )}
                      </TableBody>
                    </Table>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* Analytics Tab */}
            <TabsContent value="analytics" className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card className="dashboard-card">
                  <CardHeader>
                    <CardTitle>Detection Patterns</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="h-64 flex items-center justify-center text-muted-foreground">
                      <div className="text-center">
                        <TrendingUp className="h-12 w-12 mx-auto mb-4" />
                        <p>Analytics dashboard coming soon</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="dashboard-card">
                  <CardHeader>
                    <CardTitle>Threat Intelligence</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="h-64 flex items-center justify-center text-muted-foreground">
                      <div className="text-center">
                        <Shield className="h-12 w-12 mx-auto mb-4" />
                        <p>Threat intelligence feed coming soon</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>
        </main>
      </div>
    </div>
  );
}
