import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { 
  AlertTriangle, 
  Shield, 
  Info, 
  Eye, 
  ExternalLink,
  Clock
} from "lucide-react";
import { cn } from "@/lib/utils";
import { formatDistanceToNow } from "date-fns";
import type { SecurityAlert } from "@shared/schema";

interface AlertFeedProps {
  alerts?: SecurityAlert[];
  isLoading: boolean;
}

export default function AlertFeed({ alerts, isLoading }: AlertFeedProps) {
  const getAlertIcon = (type: string, severity: string) => {
    if (severity === "critical") {
      return <AlertTriangle className="h-5 w-5 text-red-500" />;
    }
    
    switch (type) {
      case "prompt_injection":
        return <AlertTriangle className="h-5 w-5 text-red-500" />;
      case "data_poisoning":
        return <Shield className="h-5 w-5 text-orange-500" />;
      case "model_theft":
        return <Shield className="h-5 w-5 text-purple-500" />;
      case "anomalous_behavior":
        return <Eye className="h-5 w-5 text-yellow-500" />;
      default:
        return <Info className="h-5 w-5 text-blue-500" />;
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "critical":
        return (
          <Badge variant="destructive" className="text-xs">
            Critical
          </Badge>
        );
      case "high":
        return (
          <Badge className="bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-200 text-xs">
            High
          </Badge>
        );
      case "medium":
        return (
          <Badge className="bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-200 text-xs">
            Medium
          </Badge>
        );
      case "low":
        return (
          <Badge variant="outline" className="text-xs">
            Low
          </Badge>
        );
      default:
        return (
          <Badge variant="secondary" className="text-xs">
            Info
          </Badge>
        );
    }
  };

  const getAlertBackground = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-red-50 dark:bg-red-950/20 border-red-200 dark:border-red-800";
      case "high":
        return "bg-orange-50 dark:bg-orange-950/20 border-orange-200 dark:border-orange-800";
      case "medium":
        return "bg-yellow-50 dark:bg-yellow-950/20 border-yellow-200 dark:border-yellow-800";
      case "low":
        return "bg-blue-50 dark:bg-blue-950/20 border-blue-200 dark:border-blue-800";
      default:
        return "bg-muted/50 border-border";
    }
  };

  const formatAlertType = (type: string) => {
    return type
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  };

  return (
    <Card className="dashboard-card">
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <div>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-orange-500" />
            Recent Threat Alerts
          </CardTitle>
          <p className="text-sm text-muted-foreground mt-1">
            Real-time security notifications
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 text-sm text-muted-foreground">
            <div className="w-2 h-2 bg-green-500 rounded-full"></div>
            Live
          </div>
          <Button variant="outline" size="sm">
            View All
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {isLoading ? (
            // Loading skeleton
            Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="flex items-start gap-3 p-3 border rounded-lg">
                <Skeleton className="h-5 w-5 rounded" />
                <div className="flex-1 space-y-2">
                  <Skeleton className="h-4 w-3/4" />
                  <Skeleton className="h-3 w-1/2" />
                  <Skeleton className="h-3 w-1/4" />
                </div>
                <Skeleton className="h-6 w-16" />
              </div>
            ))
          ) : alerts && alerts.length > 0 ? (
            alerts.slice(0, 5).map((alert) => (
              <div
                key={alert.id}
                className={cn(
                  "flex items-start gap-3 p-3 rounded-lg border transition-colors hover:shadow-sm",
                  getAlertBackground(alert.severity)
                )}
              >
                <div className="mt-0.5">
                  {getAlertIcon(alert.type, alert.severity)}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-start justify-between gap-2 mb-1">
                    <p className="text-sm font-medium text-foreground leading-tight">
                      {alert.title}
                    </p>
                    {getSeverityBadge(alert.severity)}
                  </div>
                  <p className="text-xs text-muted-foreground mb-2 line-clamp-2">
                    {alert.description}
                  </p>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      <span className="capitalize">{formatAlertType(alert.type)}</span>
                      {alert.assetId && (
                        <>
                          <span>•</span>
                          <span>Asset ID: {alert.assetId}</span>
                        </>
                      )}
                    </div>
                    <div className="flex items-center gap-1 text-xs text-muted-foreground">
                      <Clock className="h-3 w-3" />
                      {formatDistanceToNow(new Date(alert.detectedAt), { addSuffix: true })}
                    </div>
                  </div>
                </div>
                <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                  <ExternalLink className="h-4 w-4" />
                </Button>
              </div>
            ))
          ) : (
            <div className="text-center py-8">
              <Shield className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-muted-foreground">No recent alerts</p>
              <p className="text-sm text-muted-foreground mt-1">
                Your AI systems are secure
              </p>
            </div>
          )}
        </div>

        {alerts && alerts.length > 5 && (
          <div className="mt-4 pt-4 border-t">
            <Button variant="outline" className="w-full">
              View {alerts.length - 5} more alerts
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
