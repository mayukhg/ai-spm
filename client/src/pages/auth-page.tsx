import { useState } from "react";
import { useAuth } from "@/hooks/use-auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Loader2, Shield, Brain, Lock, Users, ChartBar, Eye } from "lucide-react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { insertUserSchema } from "@shared/schema";
import { Redirect } from "wouter";

// Login form schema
const loginSchema = z.object({
  username: z.string().min(1, "Username or email is required"),
  password: z.string().min(1, "Password is required"),
});

// Registration form schema - extends the base schema with additional validation
const registerSchema = insertUserSchema.extend({
  confirmPassword: z.string().min(1, "Please confirm your password"),
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
});

type LoginFormData = z.infer<typeof loginSchema>;
type RegisterFormData = z.infer<typeof registerSchema>;

export default function AuthPage() {
  const { user, loginMutation, registerMutation } = useAuth();
  const [activeTab, setActiveTab] = useState("login");

  // Redirect if already authenticated
  if (user) {
    return <Redirect to="/" />;
  }

  // Login form
  const loginForm = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      username: "",
      password: "",
    },
  });

  // Registration form
  const registerForm = useForm<RegisterFormData>({
    resolver: zodResolver(registerSchema),
    defaultValues: {
      username: "",
      email: "",
      password: "",
      confirmPassword: "",
      fullName: "",
      role: "analyst",
      department: "",
    },
  });

  const handleLogin = (data: LoginFormData) => {
    loginMutation.mutate(data);
  };

  const handleRegister = (data: RegisterFormData) => {
    const { confirmPassword, ...userData } = data;
    registerMutation.mutate(userData);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-blue-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900 flex">
      {/* Left side - Hero section */}
      <div className="hidden lg:flex lg:w-1/2 xl:w-2/3 bg-gradient-to-br from-primary/10 via-primary/5 to-transparent relative overflow-hidden">
        <div className="absolute inset-0 bg-grid-pattern opacity-5"></div>
        <div className="relative z-10 flex flex-col justify-center px-12 xl:px-16">
          {/* Logo and title */}
          <div className="mb-8">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-12 h-12 bg-primary rounded-xl flex items-center justify-center">
                <Shield className="h-7 w-7 text-white" />
              </div>
              <div>
                <h1 className="text-3xl font-bold text-gray-900 dark:text-white">AI-SPM</h1>
                <p className="text-sm text-gray-600 dark:text-gray-400">Security Posture Management</p>
              </div>
            </div>
            <h2 className="text-4xl xl:text-5xl font-bold text-gray-900 dark:text-white mb-4">
              Secure Your AI
              <span className="block text-primary">Infrastructure</span>
            </h2>
            <p className="text-xl text-gray-600 dark:text-gray-300 max-w-lg">
              Comprehensive AI security posture management platform designed for enterprise environments.
            </p>
          </div>

          {/* Feature highlights */}
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 mb-8">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 bg-blue-100 dark:bg-blue-900/30 rounded-lg flex items-center justify-center">
                <Brain className="h-5 w-5 text-blue-600 dark:text-blue-400" />
              </div>
              <div>
                <h3 className="font-semibold text-gray-900 dark:text-white mb-1">AI Asset Discovery</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Automatically discover and inventory all AI assets across your organization
                </p>
              </div>
            </div>

            <div className="flex items-start gap-3">
              <div className="w-10 h-10 bg-green-100 dark:bg-green-900/30 rounded-lg flex items-center justify-center">
                <Lock className="h-5 w-5 text-green-600 dark:text-green-400" />
              </div>
              <div>
                <h3 className="font-semibold text-gray-900 dark:text-white mb-1">Vulnerability Scanning</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Continuous security scanning and threat detection for AI models
                </p>
              </div>
            </div>

            <div className="flex items-start gap-3">
              <div className="w-10 h-10 bg-purple-100 dark:bg-purple-900/30 rounded-lg flex items-center justify-center">
                <ChartBar className="h-5 w-5 text-purple-600 dark:text-purple-400" />
              </div>
              <div>
                <h3 className="font-semibold text-gray-900 dark:text-white mb-1">Compliance Reporting</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Automated compliance monitoring for NIST AI RMF, GDPR, and more
                </p>
              </div>
            </div>

            <div className="flex items-start gap-3">
              <div className="w-10 h-10 bg-orange-100 dark:bg-orange-900/30 rounded-lg flex items-center justify-center">
                <Eye className="h-5 w-5 text-orange-600 dark:text-orange-400" />
              </div>
              <div>
                <h3 className="font-semibold text-gray-900 dark:text-white mb-1">Real-time Monitoring</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  24/7 monitoring of AI system behavior and anomaly detection
                </p>
              </div>
            </div>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-3 gap-8">
            <div className="text-center">
              <div className="text-3xl font-bold text-primary mb-1">247</div>
              <div className="text-sm text-gray-600 dark:text-gray-400">AI Assets Protected</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-green-600 mb-1">99.9%</div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Uptime</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-purple-600 mb-1">87%</div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Compliance Score</div>
            </div>
          </div>
        </div>
      </div>

      {/* Right side - Authentication forms */}
      <div className="w-full lg:w-1/2 xl:w-1/3 flex items-center justify-center p-8">
        <div className="w-full max-w-md">
          <Card className="shadow-xl border-0 bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm">
            <CardHeader className="text-center pb-4">
              <div className="lg:hidden flex items-center justify-center gap-2 mb-4">
                <div className="w-10 h-10 bg-primary rounded-lg flex items-center justify-center">
                  <Shield className="h-6 w-6 text-white" />
                </div>
                <div>
                  <h1 className="text-xl font-bold text-gray-900 dark:text-white">AI-SPM</h1>
                </div>
              </div>
              <CardTitle className="text-2xl font-bold text-gray-900 dark:text-white">
                Welcome Back
              </CardTitle>
              <p className="text-sm text-gray-600 dark:text-gray-400 mt-2">
                Sign in to your AI Security Platform
              </p>
            </CardHeader>
            <CardContent>
              <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
                <TabsList className="grid w-full grid-cols-2">
                  <TabsTrigger value="login">Sign In</TabsTrigger>
                  <TabsTrigger value="register">Create Account</TabsTrigger>
                </TabsList>

                {/* Login Tab */}
                <TabsContent value="login" className="space-y-4 mt-6">
                  <form onSubmit={loginForm.handleSubmit(handleLogin)} className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="login-username">Username or Email</Label>
                      <Input
                        id="login-username"
                        type="text"
                        placeholder="Enter username or email"
                        {...loginForm.register("username")}
                        className="h-11"
                      />
                      {loginForm.formState.errors.username && (
                        <p className="text-sm text-red-600">
                          {loginForm.formState.errors.username.message}
                        </p>
                      )}
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="login-password">Password</Label>
                      <Input
                        id="login-password"
                        type="password"
                        placeholder="Enter password"
                        {...loginForm.register("password")}
                        className="h-11"
                      />
                      {loginForm.formState.errors.password && (
                        <p className="text-sm text-red-600">
                          {loginForm.formState.errors.password.message}
                        </p>
                      )}
                    </div>

                    {loginMutation.error && (
                      <Alert className="border-red-200 bg-red-50 dark:bg-red-950/20">
                        <AlertDescription className="text-red-800 dark:text-red-200">
                          {loginMutation.error.message}
                        </AlertDescription>
                      </Alert>
                    )}

                    <Button 
                      type="submit" 
                      className="w-full h-11 text-base"
                      disabled={loginMutation.isPending}
                    >
                      {loginMutation.isPending ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          Signing In...
                        </>
                      ) : (
                        "Sign In"
                      )}
                    </Button>
                  </form>
                </TabsContent>

                {/* Register Tab */}
                <TabsContent value="register" className="space-y-4 mt-6">
                  <form onSubmit={registerForm.handleSubmit(handleRegister)} className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label htmlFor="register-username">Username</Label>
                        <Input
                          id="register-username"
                          type="text"
                          placeholder="Choose username"
                          {...registerForm.register("username")}
                          className="h-11"
                        />
                        {registerForm.formState.errors.username && (
                          <p className="text-sm text-red-600">
                            {registerForm.formState.errors.username.message}
                          </p>
                        )}
                      </div>

                      <div className="space-y-2">
                        <Label htmlFor="register-fullname">Full Name</Label>
                        <Input
                          id="register-fullname"
                          type="text"
                          placeholder="Your full name"
                          {...registerForm.register("fullName")}
                          className="h-11"
                        />
                        {registerForm.formState.errors.fullName && (
                          <p className="text-sm text-red-600">
                            {registerForm.formState.errors.fullName.message}
                          </p>
                        )}
                      </div>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="register-email">Email</Label>
                      <Input
                        id="register-email"
                        type="email"
                        placeholder="your.email@company.com"
                        {...registerForm.register("email")}
                        className="h-11"
                      />
                      {registerForm.formState.errors.email && (
                        <p className="text-sm text-red-600">
                          {registerForm.formState.errors.email.message}
                        </p>
                      )}
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label htmlFor="register-role">Role</Label>
                        <select
                          id="register-role"
                          {...registerForm.register("role")}
                          className="h-11 w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                        >
                          <option value="analyst">Security Analyst</option>
                          <option value="engineer">AI/ML Engineer</option>
                          <option value="compliance_officer">Compliance Officer</option>
                          <option value="ciso">CISO</option>
                        </select>
                        {registerForm.formState.errors.role && (
                          <p className="text-sm text-red-600">
                            {registerForm.formState.errors.role.message}
                          </p>
                        )}
                      </div>

                      <div className="space-y-2">
                        <Label htmlFor="register-department">Department</Label>
                        <Input
                          id="register-department"
                          type="text"
                          placeholder="Security, IT, etc."
                          {...registerForm.register("department")}
                          className="h-11"
                        />
                        {registerForm.formState.errors.department && (
                          <p className="text-sm text-red-600">
                            {registerForm.formState.errors.department.message}
                          </p>
                        )}
                      </div>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="register-password">Password</Label>
                      <Input
                        id="register-password"
                        type="password"
                        placeholder="Create strong password"
                        {...registerForm.register("password")}
                        className="h-11"
                      />
                      {registerForm.formState.errors.password && (
                        <p className="text-sm text-red-600">
                          {registerForm.formState.errors.password.message}
                        </p>
                      )}
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="register-confirm-password">Confirm Password</Label>
                      <Input
                        id="register-confirm-password"
                        type="password"
                        placeholder="Confirm your password"
                        {...registerForm.register("confirmPassword")}
                        className="h-11"
                      />
                      {registerForm.formState.errors.confirmPassword && (
                        <p className="text-sm text-red-600">
                          {registerForm.formState.errors.confirmPassword.message}
                        </p>
                      )}
                    </div>

                    {registerMutation.error && (
                      <Alert className="border-red-200 bg-red-50 dark:bg-red-950/20">
                        <AlertDescription className="text-red-800 dark:text-red-200">
                          {registerMutation.error.message}
                        </AlertDescription>
                      </Alert>
                    )}

                    <Button 
                      type="submit" 
                      className="w-full h-11 text-base"
                      disabled={registerMutation.isPending}
                    >
                      {registerMutation.isPending ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          Creating Account...
                        </>
                      ) : (
                        "Create Account"
                      )}
                    </Button>
                  </form>
                </TabsContent>
              </Tabs>

              <div className="mt-6 text-center">
                <p className="text-xs text-gray-600 dark:text-gray-400">
                  By signing in, you agree to our Terms of Service and Privacy Policy
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
