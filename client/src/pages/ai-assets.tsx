import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
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
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { 
  Search,
  Plus,
  Eye,
  Edit,
  Trash2,
  Brain,
  Database,
  Zap,
  Shield,
  Filter,
  MoreHorizontal
} from "lucide-react";
import { cn } from "@/lib/utils";
import { apiRequest } from "@/lib/queryClient";
import type { AiAsset, InsertAiAsset } from "@shared/schema";
import { formatDistanceToNow } from "date-fns";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { insertAiAssetSchema } from "@shared/schema";

export default function AiAssets() {
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("");
  const [environmentFilter, setEnvironmentFilter] = useState<string>("");
  const [riskFilter, setRiskFilter] = useState<string>("");
  const [isAddDialogOpen, setIsAddDialogOpen] = useState(false);
  
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Fetch AI assets with filters
  const { data: assets, isLoading, error } = useQuery<AiAsset[]>({
    queryKey: [
      "/api/ai-assets",
      {
        search: searchQuery || undefined,
        type: typeFilter || undefined,
        environment: environmentFilter || undefined,
        riskLevel: riskFilter || undefined,
      }
    ],
  });

  // Add asset form
  const form = useForm<InsertAiAsset>({
    resolver: zodResolver(insertAiAssetSchema),
    defaultValues: {
      name: "",
      type: "model",
      description: "",
      environment: "development",
      status: "active",
      riskLevel: "medium",
      version: "",
      framework: "",
      modelType: "",
      dataClassification: "internal",
      owner: "",
      contactEmail: "",
      location: "",
    },
  });

  // Create asset mutation
  const createAssetMutation = useMutation({
    mutationFn: async (data: InsertAiAsset) => {
      const response = await apiRequest("POST", "/api/ai-assets", data);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ai-assets"] });
      setIsAddDialogOpen(false);
      form.reset();
      toast({
        title: "Asset created successfully",
        description: "The AI asset has been added to your inventory.",
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Failed to create asset",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleAddAsset = (data: InsertAiAsset) => {
    createAssetMutation.mutate(data);
  };

  const getAssetIcon = (type: string) => {
    switch (type) {
      case "model":
        return <Brain className="h-5 w-5 text-blue-500" />;
      case "dataset":
        return <Database className="h-5 w-5 text-purple-500" />;
      case "api":
        return <Zap className="h-5 w-5 text-green-500" />;
      default:
        return <Shield className="h-5 w-5 text-gray-500" />;
    }
  };

  const getRiskBadgeVariant = (riskLevel: string) => {
    switch (riskLevel) {
      case "critical":
        return "destructive";
      case "high":
        return "destructive";
      case "medium":
        return "secondary";
      case "low":
        return "outline";
      default:
        return "outline";
    }
  };

  const getRiskColor = (riskLevel: string) => {
    switch (riskLevel) {
      case "critical":
        return "text-red-600";
      case "high":
        return "text-orange-600";
      case "medium":
        return "text-yellow-600";
      case "low":
        return "text-green-600";
      default:
        return "text-gray-600";
    }
  };

  return (
    <div className="flex h-screen bg-background">
      <Sidebar />
      
      <div className="flex-1 flex flex-col overflow-hidden ml-64">
        <Header 
          title="AI Asset Discovery" 
          subtitle="Manage your AI/ML models, datasets, and APIs"
          onSearch={setSearchQuery}
          actions={
            <Dialog open={isAddDialogOpen} onOpenChange={setIsAddDialogOpen}>
              <DialogTrigger asChild>
                <Button className="gap-2">
                  <Plus className="h-4 w-4" />
                  Add Asset
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl">
                <DialogHeader>
                  <DialogTitle>Add New AI Asset</DialogTitle>
                </DialogHeader>
                <form onSubmit={form.handleSubmit(handleAddAsset)} className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="name">Asset Name</Label>
                      <Input
                        id="name"
                        placeholder="e.g., GPT-4-Customer-Service"
                        {...form.register("name")}
                      />
                      {form.formState.errors.name && (
                        <p className="text-sm text-red-600">
                          {form.formState.errors.name.message}
                        </p>
                      )}
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="type">Type</Label>
                      <Select
                        value={form.watch("type")}
                        onValueChange={(value) => form.setValue("type", value as any)}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="model">Model</SelectItem>
                          <SelectItem value="dataset">Dataset</SelectItem>
                          <SelectItem value="api">API</SelectItem>
                          <SelectItem value="pipeline">Pipeline</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="description">Description</Label>
                    <Textarea
                      id="description"
                      placeholder="Brief description of the AI asset"
                      {...form.register("description")}
                    />
                  </div>

                  <div className="grid grid-cols-3 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="environment">Environment</Label>
                      <Select
                        value={form.watch("environment")}
                        onValueChange={(value) => form.setValue("environment", value)}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="production">Production</SelectItem>
                          <SelectItem value="staging">Staging</SelectItem>
                          <SelectItem value="development">Development</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="riskLevel">Risk Level</Label>
                      <Select
                        value={form.watch("riskLevel")}
                        onValueChange={(value) => form.setValue("riskLevel", value as any)}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="critical">Critical</SelectItem>
                          <SelectItem value="high">High</SelectItem>
                          <SelectItem value="medium">Medium</SelectItem>
                          <SelectItem value="low">Low</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="dataClassification">Data Classification</Label>
                      <Select
                        value={form.watch("dataClassification") || "internal"}
                        onValueChange={(value) => form.setValue("dataClassification", value)}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="public">Public</SelectItem>
                          <SelectItem value="internal">Internal</SelectItem>
                          <SelectItem value="confidential">Confidential</SelectItem>
                          <SelectItem value="restricted">Restricted</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="owner">Owner</Label>
                      <Input
                        id="owner"
                        placeholder="Asset owner name"
                        {...form.register("owner")}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="contactEmail">Contact Email</Label>
                      <Input
                        id="contactEmail"
                        type="email"
                        placeholder="owner@company.com"
                        {...form.register("contactEmail")}
                      />
                    </div>
                  </div>

                  <div className="flex justify-end gap-2 pt-4">
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => setIsAddDialogOpen(false)}
                    >
                      Cancel
                    </Button>
                    <Button
                      type="submit"
                      disabled={createAssetMutation.isPending}
                    >
                      {createAssetMutation.isPending ? "Creating..." : "Create Asset"}
                    </Button>
                  </div>
                </form>
              </DialogContent>
            </Dialog>
          }
        />

        <main className="flex-1 overflow-y-auto p-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-primary" />
                AI Asset Inventory
              </CardTitle>
            </CardHeader>
            <CardContent>
              {/* Filters */}
              <div className="flex items-center gap-4 mb-6">
                <div className="flex items-center gap-2">
                  <Filter className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm font-medium">Filters:</span>
                </div>
                
                <Select value={typeFilter} onValueChange={setTypeFilter}>
                  <SelectTrigger className="w-32">
                    <SelectValue placeholder="Type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="">All Types</SelectItem>
                    <SelectItem value="model">Models</SelectItem>
                    <SelectItem value="dataset">Datasets</SelectItem>
                    <SelectItem value="api">APIs</SelectItem>
                    <SelectItem value="pipeline">Pipelines</SelectItem>
                  </SelectContent>
                </Select>

                <Select value={environmentFilter} onValueChange={setEnvironmentFilter}>
                  <SelectTrigger className="w-40">
                    <SelectValue placeholder="Environment" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="">All Environments</SelectItem>
                    <SelectItem value="production">Production</SelectItem>
                    <SelectItem value="staging">Staging</SelectItem>
                    <SelectItem value="development">Development</SelectItem>
                  </SelectContent>
                </Select>

                <Select value={riskFilter} onValueChange={setRiskFilter}>
                  <SelectTrigger className="w-32">
                    <SelectValue placeholder="Risk" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="">All Risk Levels</SelectItem>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                  </SelectContent>
                </Select>

                {(typeFilter || environmentFilter || riskFilter) && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setTypeFilter("");
                      setEnvironmentFilter("");
                      setRiskFilter("");
                    }}
                  >
                    Clear Filters
                  </Button>
                )}
              </div>

              {/* Results summary */}
              {assets && (
                <div className="mb-4">
                  <p className="text-sm text-muted-foreground">
                    Showing {assets.length} assets
                    {(searchQuery || typeFilter || environmentFilter || riskFilter) && " matching your criteria"}
                  </p>
                </div>
              )}

              {/* Table */}
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Asset Name</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Environment</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Risk Level</TableHead>
                      <TableHead>Owner</TableHead>
                      <TableHead>Last Scanned</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {isLoading ? (
                      // Loading skeleton
                      Array.from({ length: 10 }).map((_, i) => (
                        <TableRow key={i}>
                          <TableCell>
                            <div className="flex items-center gap-3">
                              <Skeleton className="h-8 w-8 rounded" />
                              <div>
                                <Skeleton className="h-4 w-32 mb-1" />
                                <Skeleton className="h-3 w-24" />
                              </div>
                            </div>
                          </TableCell>
                          <TableCell><Skeleton className="h-6 w-16" /></TableCell>
                          <TableCell><Skeleton className="h-4 w-20" /></TableCell>
                          <TableCell><Skeleton className="h-6 w-16" /></TableCell>
                          <TableCell><Skeleton className="h-6 w-16" /></TableCell>
                          <TableCell><Skeleton className="h-4 w-20" /></TableCell>
                          <TableCell><Skeleton className="h-4 w-20" /></TableCell>
                          <TableCell>
                            <div className="flex justify-end gap-2">
                              <Skeleton className="h-8 w-8" />
                              <Skeleton className="h-8 w-8" />
                              <Skeleton className="h-8 w-8" />
                            </div>
                          </TableCell>
                        </TableRow>
                      ))
                    ) : error ? (
                      <TableRow>
                        <TableCell colSpan={8} className="text-center py-8">
                          <Shield className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                          <p className="text-muted-foreground">Failed to load assets</p>
                          <p className="text-sm text-muted-foreground mt-1">
                            {error instanceof Error ? error.message : "Unknown error"}
                          </p>
                        </TableCell>
                      </TableRow>
                    ) : assets && assets.length > 0 ? (
                      assets.map((asset) => (
                        <TableRow key={asset.id} className="hover:bg-muted/50">
                          <TableCell>
                            <div className="flex items-center gap-3">
                              <div className="w-8 h-8 bg-muted rounded-lg flex items-center justify-center">
                                {getAssetIcon(asset.type)}
                              </div>
                              <div>
                                <div className="font-medium text-foreground">{asset.name}</div>
                                <div className="text-sm text-muted-foreground">
                                  {asset.description || `${asset.modelType || asset.type}`}
                                </div>
                              </div>
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className="capitalize">
                              {asset.type}
                            </Badge>
                          </TableCell>
                          <TableCell className="capitalize">
                            {asset.environment}
                          </TableCell>
                          <TableCell>
                            <Badge 
                              variant={asset.status === "active" ? "default" : "secondary"} 
                              className="capitalize"
                            >
                              {asset.status}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Badge 
                              variant={getRiskBadgeVariant(asset.riskLevel)}
                              className={cn("capitalize", getRiskColor(asset.riskLevel))}
                            >
                              {asset.riskLevel}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-muted-foreground">
                            {asset.owner}
                          </TableCell>
                          <TableCell className="text-muted-foreground">
                            {asset.lastScannedAt 
                              ? formatDistanceToNow(new Date(asset.lastScannedAt), { addSuffix: true })
                              : "Never"
                            }
                          </TableCell>
                          <TableCell className="text-right">
                            <div className="flex justify-end gap-2">
                              <Button variant="ghost" size="sm">
                                <Eye className="h-4 w-4" />
                              </Button>
                              <Button variant="ghost" size="sm">
                                <Edit className="h-4 w-4" />
                              </Button>
                              <Button variant="ghost" size="sm">
                                <MoreHorizontal className="h-4 w-4" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))
                    ) : (
                      <TableRow>
                        <TableCell colSpan={8} className="text-center py-8">
                          <Shield className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                          <p className="text-muted-foreground">No AI assets found</p>
                          <p className="text-sm text-muted-foreground mt-1">
                            {searchQuery || typeFilter || environmentFilter || riskFilter 
                              ? "Try adjusting your filters" 
                              : "Get started by adding your first AI asset"
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
