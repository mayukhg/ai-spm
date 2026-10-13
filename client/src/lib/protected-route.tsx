import { useAuth } from "@/hooks/use-auth";
import { Loader2 } from "lucide-react";
import { Redirect, Route } from "wouter";

interface ProtectedRouteProps {
  path: string;
  component: () => React.JSX.Element;
  requiredRoles?: string[];
}

export function ProtectedRoute({
  path,
  component: Component,
  requiredRoles = [],
}: ProtectedRouteProps) {
  const { user, isLoading } = useAuth();

  if (isLoading) {
    return (
      <Route path={path}>
        <div className="flex items-center justify-center min-h-screen bg-black text-zinc-100">
          <div className="text-center">
            <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto mb-4" />
            <p className="text-gray-600">Loading...</p>
          </div>
        </div>
      </Route>
    );
  }

  if (!user) {
    return (
      <Route path={path}>
        <Redirect to="/auth" />
      </Route>
    );
  }

  // Check role-based access if required roles are specified
  if (requiredRoles.length > 0 && !requiredRoles.includes(user.role)) {
    return (
      <Route path={path}>
        <div className="flex items-center justify-center min-h-screen bg-black text-zinc-100">
          <div className="max-w-md mx-auto text-center">
            <div className="bg-zinc-950 rounded-lg shadow-sm border border-zinc-700 p-6">
              <div className="w-12 h-12 bg-red-950 rounded-full flex items-center justify-center mx-auto mb-4">
                <i className="fas fa-ban text-red-400 text-xl"></i>
              </div>
              <h2 className="text-xl font-semibold text-zinc-100 mb-2">Access Denied</h2>
              <p className="text-zinc-300 mb-4">
                You don't have the required permissions to access this page.
              </p>
              <p className="text-sm text-gray-500">
                Required roles: {requiredRoles.join(", ")}
              </p>
            </div>
          </div>
        </div>
      </Route>
    );
  }

  return <Route path={path} component={Component} />;
}
