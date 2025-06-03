import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { CheckCircle, AlertCircle, Shield } from "lucide-react";
import { cn } from "@/lib/utils";
import type { ComplianceOverview } from "@/types";

interface ComplianceStatusProps {
  overview?: ComplianceOverview[];
  isLoading: boolean;
}

export default function ComplianceStatus({ overview, isLoading }: ComplianceStatusProps) {
  const getComplianceStatus = (score: number) => {
    if (score >= 90) return { status: "compliant", color: "text-green-600", bg: "bg-green-50 dark:bg-green-950/20 border-green-200 dark:border-green-800" };
    if (score >= 75) return { status: "good", color: "text-blue-600", bg: "bg-blue-50 dark:bg-blue-950/20 border-blue-200 dark:border-blue-800" };
    if (score >= 60) return { status: "partial", color: "text-yellow-600", bg: "bg-yellow-50 dark:bg-yellow-950/20 border-yellow-200 dark:border-yellow-800" };
    return { status: "non-compliant", color: "text-red-600", bg: "bg-red-50 dark:bg-red-950/20 border-red-200 dark:border-red-800" };
  };

  const getStatusIcon = (score: number) => {
    const { status } = getComplianceStatus(score);
    if (status === "compliant" || status === "good") {
      return <CheckCircle className="h-5 w-5 text-green-500" />;
    }
    return <AlertCircle className="h-5 w-5 text-yellow-500" />;
  };

  const getStatusBadge = (score: number) => {
    const { status } = getComplianceStatus(score);
    switch (status) {
      case "compliant":
        return <Badge className="bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-200">Compliant</Badge>;
      case "good":
        return <Badge className="bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-200">Good</Badge>;
      case "partial":
        return <Badge className="bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-200">Partial</Badge>;
      case "non-compliant":
        return <Badge variant="destructive">Non-Compliant</Badge>;
      default:
        return <Badge variant="outline">Unknown</Badge>;
    }
  };

  return (
    <Card className="dashboard-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-primary" />
          Compliance Status
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {isLoading ? (
            // Loading skeleton
            Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="p-4 border rounded-lg space-y-3">
                <div className="flex items-center justify-between">
                  <Skeleton className="h-4 w-24" />
                  <Skeleton className="h-6 w-16" />
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <Skeleton className="h-3 w-16" />
                    <Skeleton className="h-3 w-8" />
                  </div>
                  <Skeleton className="h-2 w-full" />
                </div>
                <Skeleton className="h-3 w-32" />
              </div>
            ))
          ) : overview && overview.length > 0 ? (
            overview.map((framework) => {
              const { color, bg } = getComplianceStatus(framework.averageScore);
              
              return (
                <div
                  key={framework.frameworkId}
                  className={cn(
                    "p-4 border rounded-lg transition-colors hover:shadow-sm",
                    bg
                  )}
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      {getStatusIcon(framework.averageScore)}
                      <span className="font-medium text-foreground">
                        {framework.frameworkName}
                      </span>
                    </div>
                    {getStatusBadge(framework.averageScore)}
                  </div>
                  
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Score</span>
                      <span className={cn("font-medium", color)}>
                        {framework.averageScore}%
                      </span>
                    </div>
                    <Progress 
                      value={framework.averageScore} 
                      className="h-2"
                    />
                    <p className="text-xs text-muted-foreground">
                      {framework.totalAssessments} assessments completed
                    </p>
                  </div>
                </div>
              );
            })
          ) : (
            <div className="text-center py-8">
              <Shield className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-muted-foreground">No compliance data available</p>
              <p className="text-sm text-muted-foreground mt-1">
                Run compliance assessments to see status
              </p>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
