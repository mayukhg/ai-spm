import { useState } from "react";
import { Link, useLocation } from "wouter";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { useAuth } from "@/hooks/use-auth";
import { 
  Shield, 
  LayoutDashboard, 
  Search, 
  Database, 
  Bug, 
  Eye, 
  Settings, 
  ClipboardCheck, 
  Users,
  LogOut,
  ChevronLeft,
  ChevronRight
} from "lucide-react";

const navigationItems = [
  {
    title: "Dashboard",
    href: "/",
    icon: LayoutDashboard,
    roles: ["ciso", "analyst", "engineer", "compliance_officer"]
  },
  {
    title: "AI Assets",
    href: "/ai-assets",
    icon: Search,
    roles: ["ciso", "analyst", "engineer", "compliance_officer"]
  },
  {
    title: "Vulnerabilities",
    href: "/vulnerabilities", 
    icon: Bug,
    roles: ["ciso", "analyst", "engineer", "compliance_officer"]
  },
  {
    title: "Monitoring",
    href: "/monitoring",
    icon: Eye,
    roles: ["ciso", "analyst", "engineer", "compliance_officer"]
  },
  {
    title: "Compliance",
    href: "/compliance",
    icon: ClipboardCheck,
    roles: ["ciso", "analyst", "compliance_officer"]
  }
];

const managementItems = [
  {
    title: "User Management",
    href: "/users",
    icon: Users,
    roles: ["ciso"]
  },
  {
    title: "Settings",
    href: "/settings",
    icon: Settings,
    roles: ["ciso", "analyst", "engineer", "compliance_officer"]
  }
];

export default function Sidebar() {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [location] = useLocation();
  const { user, logoutMutation } = useAuth();

  if (!user) return null;

  const hasAccess = (roles: string[]) => {
    return roles.includes(user.role);
  };

  const handleLogout = () => {
    logoutMutation.mutate();
  };

  return (
    <div 
      className={cn(
        "fixed inset-y-0 left-0 z-50 bg-sidebar border-r border-sidebar-border transition-all duration-300",
        isCollapsed ? "w-16" : "w-64"
      )}
    >
      <div className="flex h-full flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-sidebar-border">
          <div className={cn("flex items-center gap-3", isCollapsed && "justify-center")}>
            <div className="w-8 h-8 bg-sidebar-primary rounded-lg flex items-center justify-center">
              <Shield className="h-5 w-5 text-sidebar-primary-foreground" />
            </div>
            {!isCollapsed && (
              <div>
                <h1 className="text-lg font-bold text-sidebar-foreground">AI-SPM</h1>
                <p className="text-xs text-sidebar-foreground/60">Security Platform</p>
              </div>
            )}
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setIsCollapsed(!isCollapsed)}
            className="h-8 w-8 p-0 text-sidebar-foreground/60 hover:text-sidebar-foreground hover:bg-sidebar-accent"
          >
            {isCollapsed ? (
              <ChevronRight className="h-4 w-4" />
            ) : (
              <ChevronLeft className="h-4 w-4" />
            )}
          </Button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4 space-y-2">
          {/* Main Navigation */}
          <div className="space-y-2">
            {navigationItems.map((item) => {
              if (!hasAccess(item.roles)) return null;
              
              const isActive = location === item.href;
              const Icon = item.icon;

              return (
                <Link key={item.href} href={item.href}>
                  <Button
                    variant={isActive ? "default" : "ghost"}
                    className={cn(
                      "w-full justify-start gap-3 text-sidebar-foreground",
                      isActive && "bg-sidebar-primary text-sidebar-primary-foreground hover:bg-sidebar-primary/90",
                      !isActive && "hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
                      isCollapsed && "justify-center px-2"
                    )}
                  >
                    <Icon className="h-5 w-5 flex-shrink-0" />
                    {!isCollapsed && <span>{item.title}</span>}
                  </Button>
                </Link>
              );
            })}
          </div>

          {/* Management Section */}
          {managementItems.some(item => hasAccess(item.roles)) && (
            <>
              <Separator className="my-4 bg-sidebar-border" />
              {!isCollapsed && (
                <h3 className="px-3 text-xs font-semibold text-sidebar-foreground/60 uppercase tracking-wider mb-2">
                  Management
                </h3>
              )}
              <div className="space-y-2">
                {managementItems.map((item) => {
                  if (!hasAccess(item.roles)) return null;
                  
                  const isActive = location === item.href;
                  const Icon = item.icon;

                  return (
                    <Link key={item.href} href={item.href}>
                      <Button
                        variant={isActive ? "default" : "ghost"}
                        className={cn(
                          "w-full justify-start gap-3 text-sidebar-foreground",
                          isActive && "bg-sidebar-primary text-sidebar-primary-foreground hover:bg-sidebar-primary/90",
                          !isActive && "hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
                          isCollapsed && "justify-center px-2"
                        )}
                      >
                        <Icon className="h-5 w-5 flex-shrink-0" />
                        {!isCollapsed && <span>{item.title}</span>}
                      </Button>
                    </Link>
                  );
                })}
              </div>
            </>
          )}
        </nav>

        {/* User Profile */}
        <div className="p-4 border-t border-sidebar-border">
          <div className={cn("flex items-center gap-3", isCollapsed && "justify-center")}>
            <div className="w-8 h-8 bg-sidebar-primary rounded-full flex items-center justify-center">
              <span className="text-sidebar-primary-foreground text-sm font-medium">
                {user.fullName.split(' ').map(n => n[0]).join('').toUpperCase()}
              </span>
            </div>
            {!isCollapsed && (
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-sidebar-foreground truncate">
                  {user.fullName}
                </p>
                <p className="text-xs text-sidebar-foreground/60 truncate">
                  {user.role.replace('_', ' ').toUpperCase()}
                </p>
              </div>
            )}
            <Button
              variant="ghost"
              size="sm"
              onClick={handleLogout}
              disabled={logoutMutation.isPending}
              className={cn(
                "h-8 w-8 p-0 text-sidebar-foreground/60 hover:text-sidebar-foreground hover:bg-sidebar-accent",
                isCollapsed && "ml-0"
              )}
            >
              <LogOut className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
