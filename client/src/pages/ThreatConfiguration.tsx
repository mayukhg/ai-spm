import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useToast } from '@/hooks/use-toast';
import { 
  Shield, 
  Settings, 
  AlertTriangle, 
  CheckCircle,
  Eye,
  Brain,
  Lock,
  Zap,
  TrendingUp,
  Save,
  RotateCcw,
  Plus
} from 'lucide-react';

interface ThreatConfig {
  enabled: boolean;
  severity: 'critical' | 'high' | 'medium' | 'low';
  detectionMethods: string[];
  thresholds: Record<string, number>;
  responseActions: string[];
}

interface ThreatConfigData {
  aiSpecificThreats: Record<string, ThreatConfig>;
  detectionSettings: {
    scanInterval: number;
    retentionPeriod: number;
    alertCooldown: number;
    batchSize: number;
  };
  integrations: {
    siemForwarding: boolean;
    slackNotifications: boolean;
    emailAlerts: boolean;
    webhookEndpoints: string[];
  };
  riskScoring: {
    baseScore: number;
    multipliers: Record<string, number>;
    decayFactor: number;
  };
}

interface ThreatStats {
  totalThreats: number;
  enabledThreats: number;
  disabledThreats: number;
  detectedIncidents: {
    last24Hours: number;
    lastWeek: number;
    lastMonth: number;
  };
  threatBreakdown: Record<string, { detected: number; severity: string }>;
}

export default function ThreatConfiguration() {
  const [unsavedChanges, setUnsavedChanges] = useState(false);
  const [localConfig, setLocalConfig] = useState<ThreatConfigData | null>(null);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Fetch threat configuration
  const { data: configData, isLoading: configLoading, error: configError } = useQuery({
    queryKey: ['threat-config'],
    queryFn: async () => {
      const response = await fetch('/api/threat-config/threat-config');
      if (!response.ok) {
        throw new Error('Failed to fetch threat configuration');
      }
      const result = await response.json();
      return result.config as ThreatConfigData;
    },
  });

  // Fetch threat statistics
  const { data: statsData, isLoading: statsLoading } = useQuery({
    queryKey: ['threat-stats'],
    queryFn: async () => {
      const response = await fetch('/api/threat-config/threat-stats');
      if (!response.ok) {
        throw new Error('Failed to fetch threat statistics');
      }
      const result = await response.json();
      return result.stats as ThreatStats;
    },
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  // Update threat status mutation
  const updateThreatStatusMutation = useMutation({
    mutationFn: async ({ threatName, enabled }: { threatName: string; enabled: boolean }) => {
      const response = await fetch(`/api/threat-config/threat-config/${threatName}/status`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ enabled }),
      });
      if (!response.ok) {
        throw new Error('Failed to update threat status');
      }
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-config'] });
      queryClient.invalidateQueries({ queryKey: ['threat-stats'] });
      toast({
        title: "Success",
        description: "Threat configuration updated successfully",
      });
    },
    onError: (error) => {
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to update threat configuration",
        variant: "destructive",
      });
    },
  });

  // Update threat thresholds mutation
  const updateThresholdsMutation = useMutation({
    mutationFn: async ({ threatName, thresholds }: { threatName: string; thresholds: Record<string, number> }) => {
      const response = await fetch(`/api/threat-config/threat-config/${threatName}/thresholds`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ thresholds }),
      });
      if (!response.ok) {
        throw new Error('Failed to update threat thresholds');
      }
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-config'] });
      setUnsavedChanges(false);
      toast({
        title: "Success",
        description: "Threat thresholds updated successfully",
      });
    },
    onError: (error) => {
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to update thresholds",
        variant: "destructive",
      });
    },
  });

  // Reload configuration mutation
  const reloadConfigMutation = useMutation({
    mutationFn: async () => {
      const response = await fetch('/api/threat-config/reload-config', {
        method: 'POST',
      });
      if (!response.ok) {
        throw new Error('Failed to reload configuration');
      }
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-config'] });
      toast({
        title: "Success",
        description: "Configuration reloaded across all services",
      });
    },
    onError: (error) => {
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to reload configuration",
        variant: "destructive",
      });
    },
  });

  // Initialize local config when data loads
  useEffect(() => {
    if (configData && !localConfig) {
      setLocalConfig(configData);
    }
  }, [configData, localConfig]);

  const handleThreatToggle = (threatName: string, enabled: boolean) => {
    updateThreatStatusMutation.mutate({ threatName, enabled });
  };

  const handleThresholdChange = (threatName: string, thresholdName: string, value: number) => {
    if (!localConfig) return;
    
    setLocalConfig(prev => ({
      ...prev!,
      aiSpecificThreats: {
        ...prev!.aiSpecificThreats,
        [threatName]: {
          ...prev!.aiSpecificThreats[threatName],
          thresholds: {
            ...prev!.aiSpecificThreats[threatName].thresholds,
            [thresholdName]: value
          }
        }
      }
    }));
    setUnsavedChanges(true);
  };

  const handleSaveThresholds = (threatName: string) => {
    if (!localConfig) return;
    
    const thresholds = localConfig.aiSpecificThreats[threatName].thresholds;
    updateThresholdsMutation.mutate({ threatName, thresholds });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  const getThreatIcon = (threatName: string) => {
    switch (threatName) {
      case 'modelInversionAttacks': return <Brain className="w-5 h-5" />;
      case 'adversarialInputs': return <Zap className="w-5 h-5" />;
      case 'dataExtraction': return <Eye className="w-5 h-5" />;
      case 'modelStealing': return <Lock className="w-5 h-5" />;
      default: return <Shield className="w-5 h-5" />;
    }
  };

  const formatThreatName = (threatName: string) => {
    return threatName
      .replace(/([A-Z])/g, ' $1')
      .replace(/^./, str => str.toUpperCase());
  };

  if (configLoading) {
    return (
      <div className="container mx-auto p-6">
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <Settings className="w-8 h-8 animate-spin mx-auto mb-4" />
            <p>Loading threat configuration...</p>
          </div>
        </div>
      </div>
    );
  }

  if (configError) {
    return (
      <div className="container mx-auto p-6">
        <Alert>
          <AlertTriangle className="w-4 h-4" />
          <AlertDescription>
            Failed to load threat configuration. Please check your connection and try again.
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">AI Threat Configuration</h1>
          <p className="text-muted-foreground">
            Configure AI-specific threat detection rules and response policies
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button
            variant="outline"
            onClick={() => reloadConfigMutation.mutate()}
            disabled={reloadConfigMutation.isPending}
          >
            <RotateCcw className={`w-4 h-4 mr-2 ${reloadConfigMutation.isPending ? 'animate-spin' : ''}`} />
            Reload Config
          </Button>
        </div>
      </div>

      {/* Statistics Overview */}
      {statsData && (
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Threats</CardTitle>
              <Shield className="w-4 h-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{statsData.totalThreats}</div>
              <p className="text-xs text-muted-foreground">
                {statsData.enabledThreats} enabled, {statsData.disabledThreats} disabled
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Last 24 Hours</CardTitle>
              <AlertTriangle className="w-4 h-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{statsData.detectedIncidents.last24Hours}</div>
              <p className="text-xs text-muted-foreground">incidents detected</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Last Week</CardTitle>
              <TrendingUp className="w-4 h-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{statsData.detectedIncidents.lastWeek}</div>
              <p className="text-xs text-muted-foreground">total incidents</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Last Month</CardTitle>
              <TrendingUp className="w-4 h-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{statsData.detectedIncidents.lastMonth}</div>
              <p className="text-xs text-muted-foreground">total incidents</p>
            </CardContent>
          </Card>
        </div>
      )}

      <Tabs defaultValue="threats" className="space-y-6">
        <TabsList>
          <TabsTrigger value="threats">Threat Rules</TabsTrigger>
          <TabsTrigger value="settings">Detection Settings</TabsTrigger>
          <TabsTrigger value="integrations">Integrations</TabsTrigger>
        </TabsList>

        <TabsContent value="threats" className="space-y-6">
          {localConfig && (
            <div className="grid gap-6">
              {Object.entries(localConfig.aiSpecificThreats).map(([threatName, config]) => (
                <Card key={threatName}>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        {getThreatIcon(threatName)}
                        <div>
                          <CardTitle>{formatThreatName(threatName)}</CardTitle>
                          <CardDescription>
                            Detection methods: {config.detectionMethods.join(', ')}
                          </CardDescription>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Badge className={`${getSeverityColor(config.severity)} text-white`}>
                          {config.severity}
                        </Badge>
                        <Switch
                          checked={config.enabled}
                          onCheckedChange={(enabled) => handleThreatToggle(threatName, enabled)}
                          disabled={updateThreatStatusMutation.isPending}
                        />
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {/* Thresholds */}
                      <div>
                        <h4 className="text-sm font-medium mb-3">Detection Thresholds</h4>
                        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
                          {Object.entries(config.thresholds).map(([thresholdName, value]) => (
                            <div key={thresholdName} className="space-y-1">
                              <Label htmlFor={`${threatName}-${thresholdName}`} className="text-xs">
                                {thresholdName.replace(/([A-Z])/g, ' $1').toLowerCase()}
                              </Label>
                              <Input
                                id={`${threatName}-${thresholdName}`}
                                type="number"
                                value={value}
                                onChange={(e) => handleThresholdChange(
                                  threatName, 
                                  thresholdName, 
                                  parseFloat(e.target.value) || 0
                                )}
                                className="text-sm"
                              />
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Response Actions */}
                      <div>
                        <h4 className="text-sm font-medium mb-2">Response Actions</h4>
                        <div className="flex flex-wrap gap-1">
                          {config.responseActions.map((action) => (
                            <Badge key={action} variant="outline" className="text-xs">
                              {action.replace(/_/g, ' ')}
                            </Badge>
                          ))}
                        </div>
                      </div>

                      {/* Save Button */}
                      {unsavedChanges && (
                        <div className="flex items-center justify-between pt-3 border-t">
                          <p className="text-sm text-muted-foreground">Unsaved changes</p>
                          <Button
                            size="sm"
                            onClick={() => handleSaveThresholds(threatName)}
                            disabled={updateThresholdsMutation.isPending}
                          >
                            <Save className="w-3 h-3 mr-1" />
                            Save Changes
                          </Button>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="settings" className="space-y-6">
          {localConfig && (
            <Card>
              <CardHeader>
                <CardTitle>Detection Settings</CardTitle>
                <CardDescription>
                  Global configuration for threat detection system
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <Label>Scan Interval (seconds)</Label>
                    <Input
                      type="number"
                      value={localConfig.detectionSettings.scanInterval}
                      readOnly
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Retention Period (seconds)</Label>
                    <Input
                      type="number"
                      value={localConfig.detectionSettings.retentionPeriod}
                      readOnly
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Alert Cooldown (seconds)</Label>
                    <Input
                      type="number"
                      value={localConfig.detectionSettings.alertCooldown}
                      readOnly
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Batch Size</Label>
                    <Input
                      type="number"
                      value={localConfig.detectionSettings.batchSize}
                      readOnly
                    />
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="integrations" className="space-y-6">
          {localConfig && (
            <Card>
              <CardHeader>
                <CardTitle>External Integrations</CardTitle>
                <CardDescription>
                  Configuration for external security platform integrations
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-medium">SIEM Forwarding</h4>
                      <p className="text-sm text-muted-foreground">Forward alerts to SIEM platforms</p>
                    </div>
                    <Switch checked={localConfig.integrations.siemForwarding} readOnly />
                  </div>
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-medium">Slack Notifications</h4>
                      <p className="text-sm text-muted-foreground">Send alerts to Slack channels</p>
                    </div>
                    <Switch checked={localConfig.integrations.slackNotifications} readOnly />
                  </div>
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-medium">Email Alerts</h4>
                      <p className="text-sm text-muted-foreground">Send email notifications</p>
                    </div>
                    <Switch checked={localConfig.integrations.emailAlerts} readOnly />
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}