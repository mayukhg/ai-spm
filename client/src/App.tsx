import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AuthProvider } from "@/hooks/use-auth";
import { ProtectedRoute } from "./lib/protected-route";
import Dashboard from "@/pages/dashboard";
import AuthPage from "@/pages/auth-page";
import AiAssets from "@/pages/ai-assets";
import Vulnerabilities from "@/pages/vulnerabilities";
import Monitoring from "@/pages/monitoring";
import Compliance from "@/pages/compliance";
import Users from "@/pages/users";
import SettingsPage from "@/pages/settings";
import AgenticWorkflows from "@/pages/AgenticWorkflows";
import SystemMonitoring from "@/pages/SystemMonitoring";
import ThreatConfiguration from "@/pages/ThreatConfiguration";
import PromptChecks from "@/pages/prompt-checks";
import HealthGovernance from "@/pages/health-governance";
import NotFound from "@/pages/not-found";

function Router() {
  return (
    <Switch>
      {/* Public routes */}
      <Route path="/auth" component={AuthPage} />
      
      {/* Protected routes */}
      <ProtectedRoute path="/" component={Dashboard} />
      <ProtectedRoute path="/ai-assets" component={AiAssets} />
      <ProtectedRoute path="/vulnerabilities" component={Vulnerabilities} />
      <ProtectedRoute path="/monitoring" component={Monitoring} />
      <ProtectedRoute path="/prompt-checks" component={PromptChecks} />
      <ProtectedRoute path="/health-governance" component={HealthGovernance} />
      <ProtectedRoute path="/compliance" component={Compliance} />
      <ProtectedRoute path="/agentic" component={AgenticWorkflows} />
      <ProtectedRoute path="/system-monitoring" component={SystemMonitoring} />
      <ProtectedRoute path="/threat-config" component={ThreatConfiguration} requiredRoles={["ciso"]} />
      <ProtectedRoute path="/users" component={Users} requiredRoles={["ciso"]} />
      <ProtectedRoute path="/settings" component={SettingsPage} />
      
      {/* Fallback to 404 */}
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <AuthProvider>
          <Toaster />
          <Router />
        </AuthProvider>
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
