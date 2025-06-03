import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import Sidebar from "@/components/layout/sidebar";
import Header from "@/components/layout/header";
import MetricsCards from "@/components/dashboard/metrics-cards";
import AssetTable from "@/components/dashboard/asset-table";
import AlertFeed from "@/components/dashboard/alert-feed";
import ComplianceStatus from "@/components/dashboard/compliance-status";
import SecurityTrendChart from "@/components/charts/security-trend-chart";
import { Shield, TrendingUp, AlertTriangle, CheckCircle, 
         Search, FileText, ShieldCheck, Settings } from "lucide-react";
import type { DashboardMetrics, VulnerabilityStats } from "@/types";

export default function Dashboard() {
  // Fetch dashboard metrics
  const { data: metrics, isLoading: metricsLoading } = useQuery<DashboardMetrics>({
    queryKey: ["/api/dashboard/metrics"],
  });

  // Fetch vulnerability statistics
  const { data: vulnStats, isLoading: vulnStatsLoading } = useQuery<VulnerabilityStats>({
    queryKey: ["/api/vulnerabilities/stats"],
  });

  // Fetch recent security alerts
  const { data: recentAlerts, isLoading: alertsLoading } = useQuery({
    queryKey: ["/api/security-alerts/recent"],
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  // Fetch compliance overview
  const { data: complianceOverview, isLoading: complianceLoading } = useQuery({
    queryKey: ["/api/compliance/overview"],
  });

  return (
    <div className="flex h-screen bg-background">
      <Sidebar />
      
      <div className="flex-1 flex flex-col overflow-hidden ml-64">
        <Header 
          title="AI Security Dashboard" 
          subtitle="Real-time AI security posture management"
        />

        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Key Metrics Cards */}
          <MetricsCards 
            metrics={metrics} 
            vulnerabilityStats={vulnStats}
            isLoading={metricsLoading || vulnStatsLoading} 
          />

          {/* Main Dashboard Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Security Trend Chart - Takes 2 columns */}
            <div className="lg:col-span-2">
              <Card className="dashboard-card">
                <CardHeader className="flex flex-row items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <TrendingUp className="h-5 w-5 text-primary" />
                      Security Posture Trend
                    </CardTitle>
                    <p className="text-sm text-muted-foreground mt-1">
                      AI security metrics over time
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="flex items-center gap-1 text-sm text-muted-foreground">
                      <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                      Live
                    </div>
                    <Button variant="outline" size="sm">
                      View Details
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  <SecurityTrendChart />
                </CardContent>
              </Card>
            </div>

            {/* Recent Alerts */}
            <AlertFeed alerts={recentAlerts} isLoading={alertsLoading} />
          </div>

          {/* AI Asset Inventory and Quick Actions */}
          <div className="grid grid-cols-1 xl:grid-cols-4 gap-6">
            {/* Asset Inventory - Takes 3 columns */}
            <div className="xl:col-span-3">
              <AssetTable />
            </div>

            {/* Quick Actions Panel */}
            <div className="space-y-6">
              {/* Quick Actions */}
              <Card className="dashboard-card">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Settings className="h-5 w-5 text-primary" />
                    Quick Actions
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 gap-3">
                    <Button className="w-full justify-start" variant="outline">
                      <Search className="h-4 w-4 mr-2" />
                      Run Asset Scan
                    </Button>
                    <Button className="w-full justify-start" variant="outline">
                      <FileText className="h-4 w-4 mr-2" />
                      Generate Report
                    </Button>
                    <Button className="w-full justify-start" variant="outline">
                      <ShieldCheck className="h-4 w-4 mr-2" />
                      Security Audit
                    </Button>
                    <Button className="w-full justify-start" variant="outline">
                      <Settings className="h-4 w-4 mr-2" />
                      Configure Policies
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Compliance Status Summary */}
              <ComplianceStatus 
                overview={complianceOverview} 
                isLoading={complianceLoading}
              />
            </div>
          </div>

          {/* Vulnerability Summary */}
          {vulnStats && (
            <Card className="dashboard-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5 text-warning" />
                  Vulnerability Summary
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                  <div className="text-center p-4 bg-red-50 dark:bg-red-950/20 rounded-lg border border-red-200 dark:border-red-800">
                    <div className="text-2xl font-bold text-red-600 dark:text-red-400">
                      {vulnStats.critical}
                    </div>
                    <div className="text-sm text-red-800 dark:text-red-300">Critical</div>
                  </div>
                  <div className="text-center p-4 bg-orange-50 dark:bg-orange-950/20 rounded-lg border border-orange-200 dark:border-orange-800">
                    <div className="text-2xl font-bold text-orange-600 dark:text-orange-400">
                      {vulnStats.high}
                    </div>
                    <div className="text-sm text-orange-800 dark:text-orange-300">High</div>
                  </div>
                  <div className="text-center p-4 bg-yellow-50 dark:bg-yellow-950/20 rounded-lg border border-yellow-200 dark:border-yellow-800">
                    <div className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">
                      {vulnStats.medium}
                    </div>
                    <div className="text-sm text-yellow-800 dark:text-yellow-300">Medium</div>
                  </div>
                  <div className="text-center p-4 bg-green-50 dark:bg-green-950/20 rounded-lg border border-green-200 dark:border-green-800">
                    <div className="text-2xl font-bold text-green-600 dark:text-green-400">
                      {vulnStats.low}
                    </div>
                    <div className="text-sm text-green-800 dark:text-green-300">Low</div>
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                    <div className="flex items-center gap-3">
                      <AlertTriangle className="h-5 w-5 text-red-500" />
                      <span className="text-sm font-medium">Model Serialization Issues</span>
                    </div>
                    <Badge variant="destructive">Critical</Badge>
                  </div>
                  
                  <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                    <div className="flex items-center gap-3">
                      <Shield className="h-5 w-5 text-orange-500" />
                      <span className="text-sm font-medium">Insufficient Access Controls</span>
                    </div>
                    <Badge className="bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-200">
                      High
                    </Badge>
                  </div>
                  
                  <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                    <div className="flex items-center gap-3">
                      <CheckCircle className="h-5 w-5 text-blue-500" />
                      <span className="text-sm font-medium">Data Exposure Risk</span>
                    </div>
                    <Badge variant="secondary">Medium</Badge>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </main>
      </div>
    </div>
  );
}
