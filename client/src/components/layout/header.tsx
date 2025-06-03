import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { 
  Search, 
  Bell, 
  Settings, 
  Moon, 
  Sun,
  Filter,
  Download
} from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";

interface HeaderProps {
  title: string;
  subtitle?: string;
  showSearch?: boolean;
  showNotifications?: boolean;
  onSearch?: (query: string) => void;
  actions?: React.ReactNode;
}

export default function Header({ 
  title, 
  subtitle, 
  showSearch = true, 
  showNotifications = true,
  onSearch,
  actions 
}: HeaderProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [theme, setTheme] = useState<"light" | "dark">("light");

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const query = e.target.value;
    setSearchQuery(query);
    onSearch?.(query);
  };

  const toggleTheme = () => {
    const newTheme = theme === "light" ? "dark" : "light";
    setTheme(newTheme);
    document.documentElement.classList.toggle("dark", newTheme === "dark");
  };

  return (
    <header className="bg-card shadow-sm border-b border-border px-6 py-4">
      <div className="flex items-center justify-between">
        {/* Title Section */}
        <div className="flex-1">
          <h1 className="text-2xl font-bold text-foreground">{title}</h1>
          {subtitle && (
            <p className="text-sm text-muted-foreground mt-1">{subtitle}</p>
          )}
        </div>

        {/* Actions Section */}
        <div className="flex items-center gap-4">
          {/* Search */}
          {showSearch && (
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
              <Input
                type="text"
                placeholder="Search assets, vulnerabilities..."
                value={searchQuery}
                onChange={handleSearchChange}
                className="w-80 pl-10 pr-4 h-10 bg-background border-input"
              />
            </div>
          )}

          {/* Custom Actions */}
          {actions}

          {/* Quick Action Buttons */}
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" className="gap-2">
              <Filter className="h-4 w-4" />
              Filter
            </Button>
            <Button variant="outline" size="sm" className="gap-2">
              <Download className="h-4 w-4" />
              Export
            </Button>
          </div>

          {/* Notifications */}
          {showNotifications && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="sm" className="relative h-10 w-10 p-0">
                  <Bell className="h-5 w-5" />
                  <Badge 
                    variant="destructive" 
                    className="absolute -top-1 -right-1 h-5 w-5 p-0 flex items-center justify-center text-xs"
                  >
                    3
                  </Badge>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-80">
                <div className="flex items-center justify-between p-3 border-b">
                  <h3 className="font-semibold">Notifications</h3>
                  <Button variant="ghost" size="sm" className="text-xs">
                    Mark all read
                  </Button>
                </div>
                
                <div className="max-h-80 overflow-y-auto">
                  <DropdownMenuItem className="p-3 flex flex-col items-start gap-1">
                    <div className="flex w-full items-start justify-between">
                      <p className="text-sm font-medium">Critical vulnerability detected</p>
                      <span className="text-xs text-muted-foreground">2m ago</span>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      High-risk prompt injection in GPT-4-Customer-Service
                    </p>
                  </DropdownMenuItem>
                  
                  <DropdownMenuItem className="p-3 flex flex-col items-start gap-1">
                    <div className="flex w-full items-start justify-between">
                      <p className="text-sm font-medium">Compliance check failed</p>
                      <span className="text-xs text-muted-foreground">15m ago</span>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      GDPR compliance score dropped below threshold
                    </p>
                  </DropdownMenuItem>
                  
                  <DropdownMenuItem className="p-3 flex flex-col items-start gap-1">
                    <div className="flex w-full items-start justify-between">
                      <p className="text-sm font-medium">New AI asset discovered</p>
                      <span className="text-xs text-muted-foreground">1h ago</span>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      recommendation-engine-staging automatically detected
                    </p>
                  </DropdownMenuItem>
                </div>
                
                <DropdownMenuSeparator />
                <DropdownMenuItem className="p-3 text-center">
                  <Button variant="ghost" size="sm" className="w-full">
                    View all notifications
                  </Button>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          )}

          {/* Theme Toggle */}
          <Button 
            variant="ghost" 
            size="sm" 
            onClick={toggleTheme}
            className="h-10 w-10 p-0"
          >
            {theme === "light" ? (
              <Moon className="h-5 w-5" />
            ) : (
              <Sun className="h-5 w-5" />
            )}
          </Button>

          {/* Settings */}
          <Button variant="ghost" size="sm" className="h-10 w-10 p-0">
            <Settings className="h-5 w-5" />
          </Button>
        </div>
      </div>
    </header>
  );
}
