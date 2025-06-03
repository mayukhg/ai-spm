import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
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
  Search, 
  Plus, 
  Eye, 
  Settings, 
  Brain, 
  Database, 
  Zap,
  Shield
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { AiAsset } from "@shared/schema";
import { formatDistanceToNow } from "date-fns";

export default function AssetTable() {
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("");
  const [environmentFilter, setEnvironmentFilter] = useState<string>("");

  // Fetch AI assets with filters
  const { data: assets, isLoading, error } = useQuery<AiAsset[]>({
    queryKey: [
      "/api/ai-assets", 
      { 
        search: searchQuery || undefined, 
        type: typeFilter || undefined,
        environment: environmentFilter || undefined
      }
    ],
    refetchInterval: 30000, // Refresh every 30 seconds
  });

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

  const getStatusBadgeVariant = (status: string) => {
    switch (status) {
      case "active":
        return "default";
      case "inactive":
        return "secondary";
      case "deprecated":
        return "destructive";
      default:
        return "outline";
    }
  };

  if (error) {
    return (
      <Card className="dashboard-card">
        <CardHeader>
          <CardTitle>AI Asset Inventory</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center py-8">
            <Shield className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-muted-foreground">Failed to load assets</p>
            <p className="text-sm text-muted-foreground mt-1">
              {error instanceof Error ? error.message : "Unknown error"}
            </p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="dashboard-card">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary" />
            AI Asset Inventory
          </CardTitle>
          <Button className="gap-2">
            <Plus className="h-4 w-4" />
            Add Asset
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {/* Filters */}
        <div className="flex items-center gap-4 mb-6">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
            <Input
              placeholder="Search assets..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10"
            />
          </div>
          <Select value={typeFilter} onValueChange={setTypeFilter}>
            <SelectTrigger className="w-40">
              <SelectValue placeholder="All Types" />
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
              <SelectValue placeholder="All Environments" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="">All Environments</SelectItem>
              <SelectItem value="production">Production</SelectItem>
              <SelectItem value="staging">Staging</SelectItem>
              <SelectItem value="development">Development</SelectItem>
            </SelectContent>
          </Select>
        </div>

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
                <TableHead>Last Scanned</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                // Loading skeleton
                Array.from({ length: 5 }).map((_, i) => (
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
                    <TableCell>
                      <div className="flex justify-end gap-2">
                        <Skeleton className="h-8 w-8" />
                        <Skeleton className="h-8 w-8" />
                      </div>
                    </TableCell>
                  </TableRow>
                ))
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
                      <Badge variant={getStatusBadgeVariant(asset.status)} className="capitalize">
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
                          <Settings className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8">
                    <Shield className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                    <p className="text-muted-foreground">No AI assets found</p>
                    <p className="text-sm text-muted-foreground mt-1">
                      {searchQuery || typeFilter || environmentFilter 
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

        {/* Pagination */}
        {assets && assets.length > 0 && (
          <div className="flex items-center justify-between mt-6">
            <div className="text-sm text-muted-foreground">
              Showing <span className="font-medium">1</span> to{" "}
              <span className="font-medium">{Math.min(10, assets.length)}</span> of{" "}
              <span className="font-medium">{assets.length}</span> results
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" disabled>
                Previous
              </Button>
              <Button variant="default" size="sm">
                1
              </Button>
              <Button variant="outline" size="sm">
                2
              </Button>
              <Button variant="outline" size="sm">
                3
              </Button>
              <Button variant="outline" size="sm">
                Next
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
