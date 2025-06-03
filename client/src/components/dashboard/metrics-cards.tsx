import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { 
  TrendingUp, 
  TrendingDown, 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Eye,
  Brain
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { DashboardMetrics, VulnerabilityStats } from "@/types";

interface MetricsCardsProps {
  metrics?: DashboardMetrics;
  vulnerabilityStats?: VulnerabilityStats;
  isLoading: boolean;
}

export default function MetricsCards({ metrics, vulnerabilityStats, isLoading }: MetricsCardsProps) {
  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {Array.from({ length: 4 }).map((_, i) => (
          <Card key={i} className="dashboard-card">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-5 w-5 rounded" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-8 w-16 mb-2" />
              <Skeleton className="h-4 w-32" />
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  if (!metrics || !vulnerabilityStats) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card className="dashboard-card">
          <CardContent className="pt-6">
            <div className="text-center text-muted-foreground">
              <Shield className="h-8 w-8 mx-auto mb-2" />
              <p>Unable to load metrics</p>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  const compliancePercentage = Math.round(metrics.complianceScore);
  const complianceStatus = compliancePercentage >= 90 ? "excellent" : 
                          compliancePercentage >= 75 ? "good" : 
                          compliancePercentage >= 60 ? "warning" : "critical";

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      {/* Total AI Assets */}
      <Card className="dashboard-card">
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">
            Total AI Assets
          </CardTitle>
          <Brain className="h-5 w-5 text-primary" />
        </CardHeader>
        <CardContent>
          <div className="text-3xl font-bold text-foreground">
            {metrics.totalAssets.toLocaleString()}
          </div>
          <div className="flex items-center mt-2">
            <TrendingUp className="h-4 w-4 text-green-500 mr-1" />
            <span className="text-sm text-green-600 font-medium">
              12% from last month
            </span>
          </div>
          <p className="text-xs text-muted-foreground mt-1">
            Across all environments
          </p>
        </CardContent>
      </Card>

      {/* Critical Vulnerabilities */}
      <Card className="dashboard-card">
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">
            Critical Vulnerabilities
          </CardTitle>
          <AlertTriangle className="h-5 w-5 text-red-500" />
        </CardHeader>
        <CardContent>
          <div className="text-3xl font-bold text-red-600">
            {metrics.criticalVulnerabilities}
          </div>
          <div className="flex items-center mt-2">
            <Badge 
              variant="destructive" 
              className="text-xs"
            >
              Requires Attention
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground mt-1">
            {vulnerabilityStats.total} total vulnerabilities
          </p>
        </CardContent>
      </Card>

      {/* Compliance Score */}
      <Card className="dashboard-card">
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">
            Compliance Score
          </CardTitle>
          <CheckCircle className={cn(
            "h-5 w-5",
            complianceStatus === "excellent" ? "text-green-500" :
            complianceStatus === "good" ? "text-blue-500" :
            complianceStatus === "warning" ? "text-yellow-500" : "text-red-500"
          )} />
        </CardHeader>
        <CardContent>
          <div className={cn(
            "text-3xl font-bold",
            complianceStatus === "excellent" ? "text-green-600" :
            complianceStatus === "good" ? "text-blue-600" :
            complianceStatus === "warning" ? "text-yellow-600" : "text-red-600"
          )}>
            {compliancePercentage}%
          </div>
          <div className="flex items-center mt-2">
            <TrendingUp className="h-4 w-4 text-green-500 mr-1" />
            <span className="text-sm text-green-600 font-medium">
              3% improvement
            </span>
          </div>
          <p className="text-xs text-muted-foreground mt-1">
            NIST AI RMF average
          </p>
        </CardContent>
      </Card>

      {/* Active Threats */}
      <Card className="dashboard-card">
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">
            Active Threats
          </CardTitle>
          <Eye className="h-5 w-5 text-orange-500" />
        </CardHeader>
        <CardContent>
          <div className="text-3xl font-bold text-orange-600">
            {metrics.activeThreats}
          </div>
          <div className="flex items-center mt-2">
            <Badge 
              variant="outline" 
              className="text-xs border-orange-200 text-orange-700"
            >
              Under Investigation
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground mt-1">
            Real-time monitoring active
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
