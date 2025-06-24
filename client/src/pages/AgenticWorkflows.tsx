import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { useQuery } from '@tanstack/react-query';
import { 
  Bot, 
  Play, 
  Pause, 
  Shield, 
  AlertTriangle, 
  CheckCircle,
  Settings,
  Activity,
  Brain,
  Lock,
  Users,
  FileText,
  Eye,
  Zap
} from 'lucide-react';

interface Agent {
  id: string;
  name: string;
  agentType: 'autonomous' | 'supervised' | 'collaborative';
  status: 'inactive' | 'starting' | 'active' | 'suspended' | 'terminated';
  securityLevel: 'low' | 'medium' | 'high' | 'critical';
  capabilities: string[];
  metrics: {
    securityScore: number;
    complianceScore: number;
    tasksCompleted: number;
    errorRate: number;
  };
  lastActivity: string;
}

interface WorkflowExecution {
  id: string;
  workflowId: string;
  status: 'running' | 'completed' | 'failed' | 'suspended';
  startTime: string;
  endTime?: string;
  securityEvents: any[];
  complianceChecks: any[];
}

interface MCPContext {
  id: string;
  type: 'conversation' | 'document' | 'data' | 'model_state' | 'tool_result';
  sensitivityLevel: 'public' | 'internal' | 'confidential' | 'restricted';
  createdAt: string;
  accessCount: number;
}

export default function AgenticWorkflows() {
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);

  // Mock data for demonstration
  const agents: Agent[] = [
    {
      id: '1',
      name: 'Data Processing Agent',
      agentType: 'autonomous',
      status: 'active',
      securityLevel: 'high',
      capabilities: ['data-analysis', 'report-generation', 'compliance-check'],
      metrics: {
        securityScore: 95,
        complianceScore: 98,
        tasksCompleted: 247,
        errorRate: 0.02
      },
      lastActivity: '2025-06-24T09:15:00Z'
    },
    {
      id: '2',
      name: 'Security Monitor Agent',
      agentType: 'supervised',
      status: 'active',
      securityLevel: 'critical',
      capabilities: ['threat-detection', 'incident-response', 'vulnerability-scan'],
      metrics: {
        securityScore: 99,
        complianceScore: 97,
        tasksCompleted: 156,
        errorRate: 0.01
      },
      lastActivity: '2025-06-24T09:20:00Z'
    },
    {
      id: '3',
      name: 'Compliance Assistant',
      agentType: 'collaborative',
      status: 'suspended',
      securityLevel: 'medium',
      capabilities: ['policy-check', 'audit-support', 'risk-assessment'],
      metrics: {
        securityScore: 87,
        complianceScore: 94,
        tasksCompleted: 89,
        errorRate: 0.05
      },
      lastActivity: '2025-06-24T08:45:00Z'
    }
  ];

  const workflowExecutions: WorkflowExecution[] = [
    {
      id: 'exec-1',
      workflowId: 'wf-1',
      status: 'running',
      startTime: '2025-06-24T09:00:00Z',
      securityEvents: [],
      complianceChecks: [
        { framework: 'GDPR', status: 'compliant' },
        { framework: 'AI-Act', status: 'compliant' }
      ]
    },
    {
      id: 'exec-2',
      workflowId: 'wf-2',
      status: 'completed',
      startTime: '2025-06-24T08:30:00Z',
      endTime: '2025-06-24T08:45:00Z',
      securityEvents: [],
      complianceChecks: [
        { framework: 'GDPR', status: 'compliant' },
        { framework: 'SOC-2', status: 'compliant' }
      ]
    }
  ];

  const mcpContexts: MCPContext[] = [
    {
      id: 'ctx-1',
      type: 'conversation',
      sensitivityLevel: 'internal',
      createdAt: '2025-06-24T09:00:00Z',
      accessCount: 5
    },
    {
      id: 'ctx-2',
      type: 'data',
      sensitivityLevel: 'confidential',
      createdAt: '2025-06-24T08:30:00Z',
      accessCount: 2
    }
  ];

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'bg-green-500';
      case 'running': return 'bg-blue-500';
      case 'completed': return 'bg-green-500';
      case 'suspended': return 'bg-yellow-500';
      case 'failed': return 'bg-red-500';
      default: return 'bg-gray-500';
    }
  };

  const getSecurityLevelColor = (level: string) => {
    switch (level) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  const getSensitivityColor = (level: string) => {
    switch (level) {
      case 'restricted': return 'bg-red-500';
      case 'confidential': return 'bg-orange-500';
      case 'internal': return 'bg-yellow-500';
      case 'public': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Agentic Workflows</h1>
          <p className="text-muted-foreground">
            Manage agent-based workflows with comprehensive security controls and MCP integration
          </p>
        </div>
        <Button>
          <Bot className="w-4 h-4 mr-2" />
          Create Agent
        </Button>
      </div>

      {/* Security Status Alert */}
      <Alert>
        <Shield className="w-4 h-4" />
        <AlertDescription>
          All agents operating under zero-trust security framework with Model Context Protocol encryption.
          Current security posture: <Badge variant="outline" className="ml-1">High</Badge>
        </AlertDescription>
      </Alert>

      <Tabs defaultValue="agents" className="space-y-6">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="agents">Agents</TabsTrigger>
          <TabsTrigger value="workflows">Workflows</TabsTrigger>
          <TabsTrigger value="contexts">MCP Contexts</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
        </TabsList>

        {/* Agents Tab */}
        <TabsContent value="agents" className="space-y-6">
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {agents.map((agent) => (
              <Card key={agent.id} className="cursor-pointer hover:shadow-lg transition-shadow">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <Bot className="w-5 h-5" />
                      <CardTitle className="text-lg">{agent.name}</CardTitle>
                    </div>
                    <div className="flex items-center space-x-1">
                      <div className={`w-2 h-2 rounded-full ${getStatusColor(agent.status)}`} />
                      <Badge variant="outline" className={`text-xs ${getSecurityLevelColor(agent.securityLevel)} text-white`}>
                        {agent.securityLevel}
                      </Badge>
                    </div>
                  </div>
                  <CardDescription>{agent.agentType} agent</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {/* Capabilities */}
                    <div>
                      <h4 className="text-sm font-medium mb-2">Capabilities</h4>
                      <div className="flex flex-wrap gap-1">
                        {agent.capabilities.map((capability) => (
                          <Badge key={capability} variant="secondary" className="text-xs">
                            {capability}
                          </Badge>
                        ))}
                      </div>
                    </div>

                    {/* Metrics */}
                    <div className="grid grid-cols-2 gap-2 text-sm">
                      <div>
                        <span className="text-muted-foreground">Security:</span>
                        <span className="ml-1 font-medium">{agent.metrics.securityScore}%</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Compliance:</span>
                        <span className="ml-1 font-medium">{agent.metrics.complianceScore}%</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Tasks:</span>
                        <span className="ml-1 font-medium">{agent.metrics.tasksCompleted}</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Error Rate:</span>
                        <span className="ml-1 font-medium">{(agent.metrics.errorRate * 100).toFixed(1)}%</span>
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex space-x-2">
                      <Button size="sm" variant="outline">
                        <Settings className="w-3 h-3 mr-1" />
                        Configure
                      </Button>
                      <Button size="sm" variant="outline">
                        <Activity className="w-3 h-3 mr-1" />
                        Monitor
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Workflows Tab */}
        <TabsContent value="workflows" className="space-y-6">
          <div className="space-y-4">
            {workflowExecutions.map((execution) => (
              <Card key={execution.id}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <Zap className="w-5 h-5" />
                      <CardTitle>Workflow Execution {execution.id}</CardTitle>
                    </div>
                    <div className="flex items-center space-x-2">
                      <div className={`w-2 h-2 rounded-full ${getStatusColor(execution.status)}`} />
                      <Badge variant="outline">{execution.status}</Badge>
                    </div>
                  </div>
                  <CardDescription>
                    Started: {new Date(execution.startTime).toLocaleString()}
                    {execution.endTime && ` • Completed: ${new Date(execution.endTime).toLocaleString()}`}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Security Events */}
                    <div>
                      <h4 className="text-sm font-medium mb-2 flex items-center">
                        <Shield className="w-4 h-4 mr-1" />
                        Security Events
                      </h4>
                      {execution.securityEvents.length === 0 ? (
                        <p className="text-sm text-muted-foreground flex items-center">
                          <CheckCircle className="w-3 h-3 mr-1 text-green-500" />
                          No security events detected
                        </p>
                      ) : (
                        <div className="space-y-1">
                          {execution.securityEvents.map((event, index) => (
                            <div key={index} className="text-sm">
                              <Badge variant="destructive">{event.type}</Badge>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Compliance Checks */}
                    <div>
                      <h4 className="text-sm font-medium mb-2 flex items-center">
                        <FileText className="w-4 h-4 mr-1" />
                        Compliance Checks
                      </h4>
                      <div className="space-y-1">
                        {execution.complianceChecks.map((check, index) => (
                          <div key={index} className="flex items-center justify-between text-sm">
                            <span>{check.framework}</span>
                            <Badge variant={check.status === 'compliant' ? 'default' : 'destructive'}>
                              {check.status}
                            </Badge>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* MCP Contexts Tab */}
        <TabsContent value="contexts" className="space-y-6">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {mcpContexts.map((context) => (
              <Card key={context.id}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <Brain className="w-5 h-5" />
                      <CardTitle className="text-lg">Context {context.id}</CardTitle>
                    </div>
                    <Badge variant="outline" className={`${getSensitivityColor(context.sensitivityLevel)} text-white`}>
                      {context.sensitivityLevel}
                    </Badge>
                  </div>
                  <CardDescription>{context.type} context</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">Created:</span>
                      <span>{new Date(context.createdAt).toLocaleDateString()}</span>
                    </div>
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">Access Count:</span>
                      <span>{context.accessCount}</span>
                    </div>
                    <div className="flex space-x-2">
                      <Button size="sm" variant="outline">
                        <Eye className="w-3 h-3 mr-1" />
                        View
                      </Button>
                      <Button size="sm" variant="outline">
                        <Users className="w-3 h-3 mr-1" />
                        Share
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Security Tab */}
        <TabsContent value="security" className="space-y-6">
          <div className="grid gap-6 md:grid-cols-2">
            {/* Security Overview */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Shield className="w-5 h-5 mr-2" />
                  Security Overview
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span>Active Agents</span>
                    <Badge variant="outline">{agents.filter(a => a.status === 'active').length}</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Security Score</span>
                    <Badge variant="outline">96%</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Compliance Score</span>
                    <Badge variant="outline">97%</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Encrypted Contexts</span>
                    <Badge variant="outline">100%</Badge>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Recent Security Events */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <AlertTriangle className="w-5 h-5 mr-2" />
                  Recent Security Events
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-sm">
                    <span>No security events in last 24h</span>
                    <CheckCircle className="w-4 h-4 text-green-500" />
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span>All agents authenticated</span>
                    <CheckCircle className="w-4 h-4 text-green-500" />
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span>MCP integrity verified</span>
                    <CheckCircle className="w-4 h-4 text-green-500" />
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span>Zero-trust policies active</span>
                    <CheckCircle className="w-4 h-4 text-green-500" />
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Compliance Frameworks */}
          <Card>
            <CardHeader>
              <CardTitle>Compliance Frameworks</CardTitle>
              <CardDescription>
                Current compliance status across supported regulatory frameworks
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-3">
                <div className="text-center">
                  <h4 className="font-medium">GDPR</h4>
                  <div className="text-2xl font-bold text-green-600">98%</div>
                  <p className="text-sm text-muted-foreground">Compliant</p>
                </div>
                <div className="text-center">
                  <h4 className="font-medium">AI Act</h4>
                  <div className="text-2xl font-bold text-green-600">97%</div>
                  <p className="text-sm text-muted-foreground">Compliant</p>
                </div>
                <div className="text-center">
                  <h4 className="font-medium">SOC 2</h4>
                  <div className="text-2xl font-bold text-green-600">96%</div>
                  <p className="text-sm text-muted-foreground">Compliant</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}