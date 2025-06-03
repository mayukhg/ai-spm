import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import Sidebar from "@/components/layout/sidebar";
import Header from "@/components/layout/header";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { 
  AlertTriangle, 
  Shield, 
  Eye, 
  Edit, 
  Filter,
  TrendingDown,
  TrendingUp,
  CheckCircle
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { Vulnerability, VulnerabilityStats } from "@shared/schema";
import { formatDistanceToNow } from "date-fns";

export default function Vulnerabilities() {
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState("");

  // Fetch vulnerabilities with filters
  const { data: vulnerabilities, isLoading: vulnLoading, error } = useQuery<Vulnerability[]>({
    queryKey: [
      "/api/vulnerabilities",
      {
        severity: severityFilter || undefined,
        status: statusFilter || undefined,
      }
    ],
  });

  // Fetch vulnerability statistics
  const { data: stats, isLoading: statsLoading } = useQuery<VulnerabilityStats>({
    queryKey: ["/api/vulnerabilities/stats"],
  });

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case "critical":
        return <AlertTriangle className="h-5 w-5 text-red-500" />;
      case "high":
        return <AlertTriangle className="h-5 w-5 text-orange-500" />;
      case "medium":
        return <Shield className="h-5 w-5 text-yellow-500" />;
      case "low":
        return <CheckCircle className="h-5 w-5 text-green-500" />;
      default:
        return <Shield className="h-5 w-5 text-gray-500" />;
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
        return <Badge className="bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-200">Low</Badge>;
      default:
        return <Badge variant="outline">Unknown</Badge>;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "open":
        return <Badge variant="destructive">Open</Badge>;
      case "investigating":
        return <Badge className="bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-200">Investigating</Badge>;
      case "resolved":
        return <Badge className="bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-200">Resolved</Badge>;
      case "false_positive":
        return <Badge variant="outline">False Positive</Badge>;
      default:
        return <Badge variant="outline">Unknown</Badge>;
    }
  };

  return (
    <div className="flex h-screen bg-background">
      <Sidebar />
      
      <div className="flex-1 flex flex-col overflow-hidden ml-64">
        <Header 
          title="Vulnerability Management" 
          subtitle="Monitor and manage AI security vulnerabilities"
          onSearch={setSearchQuery}
        />

        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Statistics Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            {statsLoading ? (
              Array.from({ length: 4 }).map((_, i) => (
                <Card key={i} className="dashboard-card">
                  <CardHeader className="pb-2">
                    <Skeleton className="h-4 w-20" />
                  </CardHeader>
                  <CardContent>
                    <Skeleton className="h-8 w-12 mb-2" />
                    <Skeleton className="h-4 w-24" />
                  </CardContent>
                </Card>
              ))
            ) : stats ? (
              <>
                <Card className="dashboard-card">
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium text-muted-foreground">
                      Critical
                    </CardTitle>
                    <AlertTriangle className="h-5 w-5 text-red-500" />
                  </CardHeader>
                  <CardContent>
                    <div className="text-3xl font-bold text-red-600">
                      {stats.critical}
                    </div>
                    <div className="flex items-center mt-2">
                      <TrendingDown className="h-4 w-4 text-green-500 mr-1" />
                      <span className="text-sm text-green-600 font-medium">
                        -2 from last week
                      </span>
                    </div>
                  </CardContent>
                </Card>

                <Card className="dashboard-card">
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium text-muted-foreground">
                      High
                    </CardTitle>
                    <AlertTriangle className="h-5 w-5 text-orange-500" />
                  </CardHeader>
                  <CardContent>
                    <div className="text-3xl font-bold text-orange-600">
                      {stats.high}
                    </div>
                    <div className="flex items-center mt-2">
                      <TrendingUp className="h-4 w-4 text-red-500 mr-1" />
                      <span className="text-sm text-red-600 font-medium">
                        +3 from last week
                      </span>
                    </div>
                  </CardContent>
                </Card>

                <Card className="dashboard-card">
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium text-muted-foreground">
                      Medium
                    </CardTitle>
                    <Shield className="h-5 w-5 text-yellow-500" />
                  </CardHeader>
                  <CardContent>
                    <div className="text-3xl font-bold text-yellow-600">
                      {stats.medium}
                    </div>
                    <div className="flex items-center mt-2">
                      <TrendingDown className="h-4 w-4 text-green-500 mr-1" />
                      <span className="text-sm text-green-600 font-medium">
                        -1 from last week
                      </span>
                    </div>
                  </CardContent>
                </Card>

                <Card className="dashboard-card">
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium text-muted-foreground">
                      Total Open
                    </CardTitle>
                    <Shield className="h-5 w-5 text-primary" />
                  </CardHeader>
                  <CardContent>
                    <div className="text-3xl font-bold text-foreground">
                      {stats.total}
                    </div>
                    <div className="flex items-center mt-2">
                      <span className="text-sm text-muted-foreground">
                        Across all assets
                      </span>
                    </div>
                  </CardContent>
                </Card>
              </>
            ) : null}
          </div>

          {/* Vulnerabilities Table */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-primary" />
                Vulnerability Registry
              </CardTitle>
            </CardHeader>
            <CardContent>
              {/* Filters */}
              <div className="flex items-center gap-4 mb-6">
                <div className="flex items-center gap-2">
                  <Filter className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm font-medium">Filters:</span>
                </div>
                
                <Select value={severityFilter} onValueChange={setSeverityFilter}>
                  <SelectTrigger className="w-40">
                    <SelectValue placeholder="All Severities" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Severities</SelectItem>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                  </SelectContent>
                </Select>

                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="w-40">
                    <SelectValue placeholder="All Statuses" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Statuses</SelectItem>
                    <SelectItem value="open">Open</SelectItem>
                    <SelectItem value="investigating">Investigating</SelectItem>
                    <SelectItem value="resolved">Resolved</SelectItem>
                    <SelectItem value="false_positive">False Positive</SelectItem>
                  </SelectContent>
                </Select>

                {(severityFilter || statusFilter) && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setSeverityFilter("");
                      setStatusFilter("");
                    }}
                  >
                    Clear Filters
                  </Button>
                )}
              </div>

              {/* Results summary */}
              {vulnerabilities && (
                <div className="mb-4">
                  <p className="text-sm text-muted-foreground">
                    Showing {vulnerabilities.length} vulnerabilities
                    {(searchQuery || severityFilter || statusFilter) && " matching your criteria"}
                  </p>
                </div>
              )}

              {/* Table */}
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Vulnerability</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Category</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Asset ID</TableHead>
                      <TableHead>Detected</TableHead>
                      <TableHead>Assigned To</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {vulnLoading ? (
                      // Loading skeleton
                      Array.from({ length: 10 }).map((_, i) => (
                        <TableRow key={i}>
                          <TableCell>
                            <div className="flex items-center gap-3">
                              <Skeleton className="h-5 w-5" />
                              <div>
                                <Skeleton className="h-4 w-48 mb-1" />
                                <Skeleton className="h-3 w-32" />
                              </div>
                            </div>
                          </TableCell>
                          <TableCell><Skeleton className="h-6 w-16" /></TableCell>
                          <TableCell><Skeleton className="h-4 w-24" /></TableCell>
                          <TableCell><Skeleton className="h-6 w-20" /></TableCell>
                          <TableCell><Skeleton className="h-4 w-12" /></TableCell>
                          <TableCell><Skeleton className="h-4 w-20" /></TableCell>
                          <TableCell><Skeleton className="h-4 w-16" /></TableCell>
                          <TableCell>
                            <div className="flex justify-end gap-2">
                              <Skeleton className="h-8 w-8" />
                              <Skeleton className="h-8 w-8" />
                            </div>
                          </TableCell>
                        </TableRow>
                      ))
                    ) : error ? (
                      <TableRow>
                        <TableCell colSpan={8} className="text-center py-8">
                          <AlertTriangle className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                          <p className="text-muted-foreground">Failed to load vulnerabilities</p>
                          <p className="text-sm text-muted-foreground mt-1">
                            {error instanceof Error ? error.message : "Unknown error"}
                          </p>
                        </TableCell>
                      </TableRow>
                    ) : vulnerabilities && vulnerabilities.length > 0 ? (
                      vulnerabilities.map((vulnerability) => (
                        <TableRow key={vulnerability.id} className="hover:bg-muted/50">
                          <TableCell>
                            <div className="flex items-center gap-3">
                              {getSeverityIcon(vulnerability.severity)}
                              <div>
                                <div className="font-medium text-foreground">
                                  {vulnerability.title}
                                </div>
                                <div className="text-sm text-muted-foreground line-clamp-1">
                                  {vulnerability.description}
                                </div>
                              </div>
                            </div>
                          </TableCell>
                          <TableCell>
                            {getSeverityBadge(vulnerability.severity)}
                          </TableCell>
                          <TableCell className="capitalize">
                            {vulnerability.category.replace('_', ' ')}
                          </TableCell>
                          <TableCell>
                            {getStatusBadge(vulnerability.status)}
                          </TableCell>
                          <TableCell className="text-muted-foreground">
                            #{vulnerability.assetId}
                          </TableCell>
                          <TableCell className="text-muted-foreground">
                            {formatDistanceToNow(new Date(vulnerability.detectedAt), { addSuffix: true })}
                          </TableCell>
                          <TableCell className="text-muted-foreground">
                            {vulnerability.assignedTo ? `User #${vulnerability.assignedTo}` : "Unassigned"}
                          </TableCell>
                          <TableCell className="text-right">
                            <div className="flex justify-end gap-2">
                              <Button variant="ghost" size="sm">
                                <Eye className="h-4 w-4" />
                              </Button>
                              <Button variant="ghost" size="sm">
                                <Edit className="h-4 w-4" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))
                    ) : (
                      <TableRow>
                        <TableCell colSpan={8} className="text-center py-8">
                          <CheckCircle className="h-12 w-12 text-green-500 mx-auto mb-4" />
                          <p className="text-muted-foreground">No vulnerabilities found</p>
                          <p className="text-sm text-muted-foreground mt-1">
                            {searchQuery || severityFilter || statusFilter 
                              ? "Try adjusting your filters" 
                              : "Your AI systems are secure!"
                            }
                          </p>
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </main>
      </div>
    </div>
  );
}
