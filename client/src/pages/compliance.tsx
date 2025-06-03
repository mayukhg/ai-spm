import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/use-auth";
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
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { 
  ClipboardCheck, 
  Shield, 
  CheckCircle, 
  AlertTriangle, 
  FileText, 
  Plus,
  Eye,
  Edit,
  Download,
  TrendingUp,
  TrendingDown,
  BarChart3,
  Calendar,
  Filter
} from "lucide-react";
import { cn } from "@/lib/utils";
import { apiRequest } from "@/lib/queryClient";
import type { 
  ComplianceFramework, 
  ComplianceAssessment, 
  InsertComplianceFramework,
  InsertComplianceAssessment,
  AiAsset 
} from "@shared/schema";
import type { ComplianceOverview } from "@/types";
import { formatDistanceToNow } from "date-fns";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { insertComplianceFrameworkSchema, insertComplianceAssessmentSchema } from "@shared/schema";

export default function Compliance() {
  const [activeTab, setActiveTab] = useState("overview");
  const [isAddFrameworkOpen, setIsAddFrameworkOpen] = useState(false);
  const [isAddAssessmentOpen, setIsAddAssessmentOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  
  const { toast } = useToast();
  const { user } = useAuth();
  const queryClient = useQueryClient();

  // Check if user has compliance management permissions
  const canManageCompliance = user?.role === "ciso" || user?.role === "compliance_officer";

  // Fetch compliance overview
  const { data: overview, isLoading: overviewLoading } = useQuery<ComplianceOverview[]>({
    queryKey: ["/api/compliance/overview"],
  });

  // Fetch compliance frameworks
  const { data: frameworks, isLoading: frameworksLoading } = useQuery<ComplianceFramework[]>({
    queryKey: ["/api/compliance/frameworks"],
  });

  // Fetch AI assets for assessment creation
  const { data: assets } = useQuery<AiAsset[]>({
    queryKey: ["/api/ai-assets"],
  });

  // Framework form
  const frameworkForm = useForm<InsertComplianceFramework>({
    resolver: zodResolver(insertComplianceFrameworkSchema),
    defaultValues: {
      name: "",
      version: "",
      description: "",
      category: "ai_specific",
      isActive: true,
    },
  });

  // Assessment form
  const assessmentForm = useForm<InsertComplianceAssessment>({
    resolver: zodResolver(insertComplianceAssessmentSchema),
    defaultValues: {
      assetId: 0,
      frameworkId: 0,
      score: 0,
      status: "partially_compliant",
      findings: {},
      recommendations: "",
    },
  });

  // Create framework mutation
  const createFrameworkMutation = useMutation({
    mutationFn: async (data: InsertComplianceFramework) => {
      const response = await apiRequest("POST", "/api/compliance/frameworks", data);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/compliance/frameworks"] });
      queryClient.invalidateQueries({ queryKey: ["/api/compliance/overview"] });
      setIsAddFrameworkOpen(false);
      frameworkForm.reset();
      toast({
        title: "Framework created successfully",
        description: "The compliance framework has been added.",
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Failed to create framework",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  // Create assessment mutation
  const createAssessmentMutation = useMutation({
    mutationFn: async (data: InsertComplianceAssessment) => {
      const response = await apiRequest("POST", "/api/compliance/assessments", data);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/compliance/overview"] });
      setIsAddAssessmentOpen(false);
      assessmentForm.reset();
      toast({
        title: "Assessment created successfully",
        description: "The compliance assessment has been recorded.",
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Failed to create assessment",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleCreateFramework = (data: InsertComplianceFramework) => {
    createFrameworkMutation.mutate(data);
  };

  const handleCreateAssessment = (data: InsertComplianceAssessment) => {
    createAssessmentMutation.mutate(data);
  };

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
    return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
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

  const calculateOverallScore = () => {
    if (!overview || overview.length === 0) return 0;
    const totalScore = overview.reduce((sum, item) => sum + item.averageScore, 0);
    return Math.round(totalScore / overview.length);
  };

  return (
    <div className="flex h-screen bg-background">
      <Sidebar />
      
      <div className="flex-1 flex flex-col overflow-hidden ml-64">
        <Header 
          title="Compliance Management" 
          subtitle="Monitor regulatory compliance and governance"
          onSearch={setSearchQuery}
          actions={
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" className="gap-2">
                <Download className="h-4 w-4" />
                Export Report
              </Button>
              {canManageCompliance && (
                <Dialog open={isAddFrameworkOpen} onOpenChange={setIsAddFrameworkOpen}>
                  <DialogTrigger asChild>
                    <Button className="gap-2">
                      <Plus className="h-4 w-4" />
                      Add Framework
                    </Button>
                  </DialogTrigger>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>Add Compliance Framework</DialogTitle>
                    </DialogHeader>
                    <form onSubmit={frameworkForm.handleSubmit(handleCreateFramework)} className="space-y-4">
                      <div className="space-y-2">
                        <Label htmlFor="framework-name">Framework Name</Label>
                        <Input
                          id="framework-name"
                          placeholder="e.g., NIST AI RMF 1.0"
                          {...frameworkForm.register("name")}
                        />
                        {frameworkForm.formState.errors.name && (
                          <p className="text-sm text-red-600">
                            {frameworkForm.formState.errors.name.message}
                          </p>
                        )}
                      </div>

                      <div className="grid grid-cols-2 gap-4">
                        <div className="space-y-2">
                          <Label htmlFor="framework-version">Version</Label>
                          <Input
                            id="framework-version"
                            placeholder="e.g., 1.0"
                            {...frameworkForm.register("version")}
                          />
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor="framework-category">Category</Label>
                          <Select
                            value={frameworkForm.watch("category") || "ai_specific"}
                            onValueChange={(value) => frameworkForm.setValue("category", value)}
                          >
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="ai_specific">AI Specific</SelectItem>
                              <SelectItem value="data_privacy">Data Privacy</SelectItem>
                              <SelectItem value="security">Security</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                      </div>

                      <div className="space-y-2">
                        <Label htmlFor="framework-description">Description</Label>
                        <Textarea
                          id="framework-description"
                          placeholder="Brief description of the framework"
                          {...frameworkForm.register("description")}
                        />
                      </div>

                      <div className="flex justify-end gap-2 pt-4">
                        <Button
                          type="button"
                          variant="outline"
                          onClick={() => setIsAddFrameworkOpen(false)}
                        >
                          Cancel
                        </Button>
                        <Button
                          type="submit"
                          disabled={createFrameworkMutation.isPending}
                        >
                          {createFrameworkMutation.isPending ? "Creating..." : "Create Framework"}
                        </Button>
                      </div>
                    </form>
                  </DialogContent>
                </Dialog>
              )}
            </div>
          }
        />

        <main className="flex-1 overflow-y-auto p-6">
          <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="overview">Compliance Overview</TabsTrigger>
              <TabsTrigger value="frameworks">Frameworks</TabsTrigger>
              <TabsTrigger value="assessments">Assessments</TabsTrigger>
            </TabsList>

            {/* Compliance Overview Tab */}
            <TabsContent value="overview" className="space-y-6">
              {/* Overall Compliance Score */}
              <Card className="dashboard-card">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <BarChart3 className="h-5 w-5 text-primary" />
                    Overall Compliance Score
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-4xl font-bold text-foreground mb-2">
                        {calculateOverallScore()}%
                      </div>
                      <div className="flex items-center gap-2">
                        <TrendingUp className="h-4 w-4 text-green-500" />
                        <span className="text-sm text-green-600 font-medium">
                          +3% from last month
                        </span>
                      </div>
                    </div>
                    <div className="w-32 h-32">
                      <div className="relative w-full h-full">
                        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                          <circle
                            cx="50"
                            cy="50"
                            r="40"
                            fill="none"
                            stroke="currentColor"
                            strokeWidth="8"
                            className="text-muted opacity-20"
                          />
                          <circle
                            cx="50"
                            cy="50"
                            r="40"
                            fill="none"
                            stroke="currentColor"
                            strokeWidth="8"
                            strokeDasharray={`${calculateOverallScore() * 2.51} 251`}
                            className={cn(
                              calculateOverallScore() >= 90 ? "text-green-500" :
                              calculateOverallScore() >= 75 ? "text-blue-500" :
                              calculateOverallScore() >= 60 ? "text-yellow-500" : "text-red-500"
                            )}
                          />
                        </svg>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Framework Compliance Status */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card className="dashboard-card">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <ClipboardCheck className="h-5 w-5 text-primary" />
                      Framework Compliance
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {overviewLoading ? (
                        Array.from({ length: 3 }).map((_, i) => (
                          <div key={i} className="p-4 border rounded-lg space-y-3">
                            <div className="flex items-center justify-between">
                              <Skeleton className="h-4 w-32" />
                              <Skeleton className="h-6 w-20" />
                            </div>
                            <Skeleton className="h-2 w-full" />
                            <Skeleton className="h-3 w-24" />
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
                                  <span className="text-muted-foreground">Compliance Score</span>
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
                          <ClipboardCheck className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                          <p className="text-muted-foreground">No compliance data available</p>
                          <p className="text-sm text-muted-foreground mt-1">
                            Create frameworks and run assessments to see compliance status
                          </p>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>

                {/* Quick Actions */}
                <Card className="dashboard-card">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Shield className="h-5 w-5 text-primary" />
                      Quick Actions
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      <Dialog open={isAddAssessmentOpen} onOpenChange={setIsAddAssessmentOpen}>
                        <DialogTrigger asChild>
                          <Button className="w-full justify-start gap-2" variant="outline">
                            <ClipboardCheck className="h-4 w-4" />
                            Run New Assessment
                          </Button>
                        </DialogTrigger>
                        <DialogContent>
                          <DialogHeader>
                            <DialogTitle>Create Compliance Assessment</DialogTitle>
                          </DialogHeader>
                          <form onSubmit={assessmentForm.handleSubmit(handleCreateAssessment)} className="space-y-4">
                            <div className="grid grid-cols-2 gap-4">
                              <div className="space-y-2">
                                <Label htmlFor="assessment-asset">AI Asset</Label>
                                <Select
                                  value={assessmentForm.watch("assetId")?.toString() || ""}
                                  onValueChange={(value) => assessmentForm.setValue("assetId", parseInt(value))}
                                >
                                  <SelectTrigger>
                                    <SelectValue placeholder="Select asset" />
                                  </SelectTrigger>
                                  <SelectContent>
                                    {assets?.map((asset) => (
                                      <SelectItem key={asset.id} value={asset.id.toString()}>
                                        {asset.name}
                                      </SelectItem>
                                    ))}
                                  </SelectContent>
                                </Select>
                              </div>
                              <div className="space-y-2">
                                <Label htmlFor="assessment-framework">Framework</Label>
                                <Select
                                  value={assessmentForm.watch("frameworkId")?.toString() || ""}
                                  onValueChange={(value) => assessmentForm.setValue("frameworkId", parseInt(value))}
                                >
                                  <SelectTrigger>
                                    <SelectValue placeholder="Select framework" />
                                  </SelectTrigger>
                                  <SelectContent>
                                    {frameworks?.map((framework) => (
                                      <SelectItem key={framework.id} value={framework.id.toString()}>
                                        {framework.name}
                                      </SelectItem>
                                    ))}
                                  </SelectContent>
                                </Select>
                              </div>
                            </div>

                            <div className="grid grid-cols-2 gap-4">
                              <div className="space-y-2">
                                <Label htmlFor="assessment-score">Compliance Score (%)</Label>
                                <Input
                                  id="assessment-score"
                                  type="number"
                                  min="0"
                                  max="100"
                                  placeholder="85"
                                  {...assessmentForm.register("score", { valueAsNumber: true })}
                                />
                              </div>
                              <div className="space-y-2">
                                <Label htmlFor="assessment-status">Status</Label>
                                <Select
                                  value={assessmentForm.watch("status")}
                                  onValueChange={(value) => assessmentForm.setValue("status", value as any)}
                                >
                                  <SelectTrigger>
                                    <SelectValue />
                                  </SelectTrigger>
                                  <SelectContent>
                                    <SelectItem value="compliant">Compliant</SelectItem>
                                    <SelectItem value="non_compliant">Non-Compliant</SelectItem>
                                    <SelectItem value="partially_compliant">Partially Compliant</SelectItem>
                                  </SelectContent>
                                </Select>
                              </div>
                            </div>

                            <div className="space-y-2">
                              <Label htmlFor="assessment-recommendations">Recommendations</Label>
                              <Textarea
                                id="assessment-recommendations"
                                placeholder="Recommendations for improving compliance..."
                                {...assessmentForm.register("recommendations")}
                              />
                            </div>

                            <div className="flex justify-end gap-2 pt-4">
                              <Button
                                type="button"
                                variant="outline"
                                onClick={() => setIsAddAssessmentOpen(false)}
                              >
                                Cancel
                              </Button>
                              <Button
                                type="submit"
                                disabled={createAssessmentMutation.isPending}
                              >
                                {createAssessmentMutation.isPending ? "Creating..." : "Create Assessment"}
                              </Button>
                            </div>
                          </form>
                        </DialogContent>
                      </Dialog>

                      <Button className="w-full justify-start gap-2" variant="outline">
                        <FileText className="h-4 w-4" />
                        Generate Compliance Report
                      </Button>
                      
                      <Button className="w-full justify-start gap-2" variant="outline">
                        <Calendar className="h-4 w-4" />
                        Schedule Assessment
                      </Button>
                      
                      <Button className="w-full justify-start gap-2" variant="outline">
                        <Shield className="h-4 w-4" />
                        Policy Management
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Recent Assessments */}
              <Card className="dashboard-card">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Calendar className="h-5 w-5 text-primary" />
                    Recent Assessment Activity
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-center py-8">
                    <ClipboardCheck className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                    <p className="text-muted-foreground">No recent assessments</p>
                    <p className="text-sm text-muted-foreground mt-1">
                      Assessment history will appear here
                    </p>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* Frameworks Tab */}
            <TabsContent value="frameworks" className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <FileText className="h-5 w-5 text-primary" />
                    Compliance Frameworks
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="rounded-md border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Framework Name</TableHead>
                          <TableHead>Version</TableHead>
                          <TableHead>Category</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead>Assessments</TableHead>
                          <TableHead className="text-right">Actions</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {frameworksLoading ? (
                          Array.from({ length: 5 }).map((_, i) => (
                            <TableRow key={i}>
                              <TableCell><Skeleton className="h-4 w-48" /></TableCell>
                              <TableCell><Skeleton className="h-4 w-16" /></TableCell>
                              <TableCell><Skeleton className="h-4 w-24" /></TableCell>
                              <TableCell><Skeleton className="h-6 w-16" /></TableCell>
                              <TableCell><Skeleton className="h-4 w-12" /></TableCell>
                              <TableCell>
                                <div className="flex justify-end gap-2">
                                  <Skeleton className="h-8 w-8" />
                                  <Skeleton className="h-8 w-8" />
                                </div>
                              </TableCell>
                            </TableRow>
                          ))
                        ) : frameworks && frameworks.length > 0 ? (
                          frameworks.map((framework) => (
                            <TableRow key={framework.id} className="hover:bg-muted/50">
                              <TableCell>
                                <div>
                                  <div className="font-medium text-foreground">
                                    {framework.name}
                                  </div>
                                  <div className="text-sm text-muted-foreground">
                                    {framework.description}
                                  </div>
                                </div>
                              </TableCell>
                              <TableCell className="text-muted-foreground">
                                {framework.version || "N/A"}
                              </TableCell>
                              <TableCell>
                                <Badge variant="outline" className="capitalize">
                                  {framework.category?.replace('_', ' ')}
                                </Badge>
                              </TableCell>
                              <TableCell>
                                <Badge 
                                  variant={framework.isActive ? "default" : "secondary"}
                                >
                                  {framework.isActive ? "Active" : "Inactive"}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-muted-foreground">
                                {overview?.find(o => o.frameworkId === framework.id)?.totalAssessments || 0}
                              </TableCell>
                              <TableCell className="text-right">
                                <div className="flex justify-end gap-2">
                                  <Button variant="ghost" size="sm">
                                    <Eye className="h-4 w-4" />
                                  </Button>
                                  {canManageCompliance && (
                                    <Button variant="ghost" size="sm">
                                      <Edit className="h-4 w-4" />
                                    </Button>
                                  )}
                                </div>
                              </TableCell>
                            </TableRow>
                          ))
                        ) : (
                          <TableRow>
                            <TableCell colSpan={6} className="text-center py-8">
                              <FileText className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                              <p className="text-muted-foreground">No compliance frameworks found</p>
                              <p className="text-sm text-muted-foreground mt-1">
                                Add frameworks to start compliance monitoring
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

            {/* Assessments Tab */}
            <TabsContent value="assessments" className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <ClipboardCheck className="h-5 w-5 text-primary" />
                    Compliance Assessments
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-center py-12">
                    <ClipboardCheck className="h-16 w-16 text-muted-foreground mx-auto mb-4" />
                    <h3 className="text-lg font-semibold text-foreground mb-2">
                      Assessment Management
                    </h3>
                    <p className="text-muted-foreground mb-4">
                      Detailed assessment tracking and management will be available here
                    </p>
                    <Button className="gap-2">
                      <Plus className="h-4 w-4" />
                      Create Assessment
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </main>
      </div>
    </div>
  );
}
