import { useEffect } from "react";
import { Switch, Route, useLocation } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AuthProvider, useAuth } from "@/hooks/use-auth";
import { ProtectedRoute } from "./lib/protected-route";
import { identifyUser, sectionFromPath, trackEvent } from "@/lib/mixpanel";
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

function AnalyticsRouter() {
  const [location] = useLocation();
  const { user } = useAuth();

  useEffect(() => {
    if (user) {
      identifyUser(String(user.id), {
        $email: user.email,
        $name: user.fullName,
        role: user.role,
        $created: user.createdAt,
        department: user.department ?? undefined,
        username: user.username,
      });
    }
  }, [user?.id]);

  useEffect(() => {
    if (location.startsWith("/auth")) return;
    trackEvent("dashboard_viewed", {
      section: sectionFromPath(location),
      path: location,
    });
  }, [location]);

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
          <AnalyticsRouter />
        </AuthProvider>
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
