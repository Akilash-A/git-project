"use client";

import { useState, useEffect } from "react";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { 
  Shield, 
  Ban, 
  Clock, 
  Trash2, 
  PlusCircle,
  AlertTriangle,
  Timer,
  Network
} from "lucide-react";

import { DashboardLayout } from "@/components/layout/dashboard-layout";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { useToast } from "@/hooks/use-toast";
import databaseService from "@/lib/database-service";

const ipSchema = z.object({
  ip: z.string().ip({ version: "v4", message: "Invalid IPv4 address" }),
  action: z.enum(["block", "throttle"]),
  delay: z.number().min(100).max(10000).optional(),
});

type TrafficRule = {
  id: string;
  ip: string;
  action: "block" | "throttle";
  delay?: number;
  createdAt: string;
  status: "active" | "inactive";
};

const initialRules: TrafficRule[] = [
  {
    id: "1",
    ip: "192.168.1.100",
    action: "block",
    createdAt: new Date().toISOString(),
    status: "active"
  },
  {
    id: "2", 
    ip: "10.0.0.50",
    action: "throttle",
    delay: 2000,
    createdAt: new Date().toISOString(),
    status: "active"
  }
];

export default function TrafficControlPage() {
  const { toast } = useToast();
  const [trafficRules, setTrafficRules] = useState<TrafficRule[]>([]);
  const [isClient, setIsClient] = useState(false);

  // Load traffic rules from database
  const loadTrafficRules = async () => {
    try {
      const rules = await databaseService.getTrafficRules();
      setTrafficRules(rules.map(rule => ({
        id: rule.id,
        ip: rule.ip,
        action: rule.action as "block" | "throttle",
        delay: rule.delay,
        createdAt: rule.created_at,
        status: rule.status as "active" | "inactive"
      })));
    } catch (error) {
      console.error('Failed to load traffic rules:', error);
      toast({
        title: "Error",
        description: "Failed to load traffic rules from server.",
        variant: "destructive",
      });
    }
  };

  useEffect(() => {
    setIsClient(true);
    loadTrafficRules();
  }, []);

  // Listen for traffic rules updates from other clients
  useEffect(() => {
    // TODO: Add real-time updates listener
    // For now, we'll poll for updates when the page gains focus
    const handleFocus = () => {
      loadTrafficRules();
    };

    window.addEventListener('focus', handleFocus);
    return () => {
      window.removeEventListener('focus', handleFocus);
    };
  }, []);

  const form = useForm<z.infer<typeof ipSchema>>({
    resolver: zodResolver(ipSchema),
    defaultValues: {
      ip: "",
      action: "block",
      delay: 1000,
    },
  });

  const watchAction = form.watch("action");

  async function onSubmit(values: z.infer<typeof ipSchema>) {
    // Check if IP already exists
    if (trafficRules.some(rule => rule.ip === values.ip)) {
      form.setError("ip", {
        type: "manual",
        message: "IP address already has a traffic rule.",
      });
      return;
    }

    const newRule = {
      id: Date.now().toString(),
      ip: values.ip,
      action: values.action,
      delay: values.action === "throttle" ? values.delay : undefined,
      status: "active"
    };

    try {
      const result = await databaseService.addTrafficRule(newRule);
      
      if (result.success) {
        // Reload rules from database to get the latest state
        await loadTrafficRules();
        form.reset();
        
        toast({
          title: "Traffic Rule Added",
          description: `${values.action === "block" ? "Blocked" : "Throttled"} IP: ${values.ip}`,
        });
      } else {
        toast({
          title: "Error",
          description: "Failed to add traffic rule.",
          variant: "destructive",
        });
      }
    } catch (error) {
      console.error('Failed to add traffic rule:', error);
      toast({
        title: "Error",
        description: "Failed to add traffic rule to server.",
        variant: "destructive",
      });
    }
  }

  async function removeRule(ruleId: string) {
    const rule = trafficRules.find(r => r.id === ruleId);
    
    try {
      const success = await databaseService.removeTrafficRule(ruleId);
      
      if (success) {
        // Reload rules from database
        await loadTrafficRules();
        
        if (rule) {
          toast({
            title: "Rule Removed",
            description: `Removed ${rule.action} rule for IP: ${rule.ip}`,
          });
        }
      } else {
        toast({
          title: "Error",
          description: "Failed to remove traffic rule.",
          variant: "destructive",
        });
      }
    } catch (error) {
      console.error('Failed to remove traffic rule:', error);
      toast({
        title: "Error",
        description: "Failed to remove traffic rule from server.",
        variant: "destructive",
      });
    }
  }

  async function toggleRuleStatus(ruleId: string) {
    const rule = trafficRules.find(r => r.id === ruleId);
    if (!rule) return;
    
    const newStatus = rule.status === "active" ? "inactive" : "active";
    
    try {
      const success = await databaseService.updateTrafficRuleStatus(ruleId, newStatus);
      
      if (success) {
        // Reload rules from database
        await loadTrafficRules();
        
        toast({
          title: "Rule Updated",
          description: `${rule.action} rule for ${rule.ip} is now ${newStatus}`,
        });
      } else {
        toast({
          title: "Error",
          description: "Failed to update traffic rule status.",
          variant: "destructive",
        });
      }
    } catch (error) {
      console.error('Failed to update traffic rule status:', error);
      toast({
        title: "Error",
        description: "Failed to update traffic rule status on server.",
        variant: "destructive",
      });
    }
  }

  if (!isClient) {
    return null;
  }

  const blockedCount = trafficRules.filter(r => r.action === "block" && r.status === "active").length;
  const throttledCount = trafficRules.filter(r => r.action === "throttle" && r.status === "active").length;

  return (
    <DashboardLayout>
      <main className="flex flex-1 flex-col gap-4 p-4 md:gap-8 md:p-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="font-headline text-lg font-semibold md:text-2xl flex items-center gap-2">
              <Network className="h-6 w-6" />
              Traffic Control
            </h1>
            <p className="text-muted-foreground">
              Manage IP blocking and response throttling for network traffic control.
            </p>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid gap-4 md:grid-cols-3 lg:grid-cols-3">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Blocked IPs</CardTitle>
              <Ban className="h-4 w-4 text-destructive" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-destructive">{blockedCount}</div>
              <p className="text-xs text-muted-foreground">
                Active blocking rules
              </p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Throttled IPs</CardTitle>
              <Timer className="h-4 w-4 text-orange-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-orange-500">{throttledCount}</div>
              <p className="text-xs text-muted-foreground">
                Active throttling rules
              </p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Rules</CardTitle>
              <Shield className="h-4 w-4 text-blue-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{trafficRules.length}</div>
              <p className="text-xs text-muted-foreground">
                All traffic control rules
              </p>
            </CardContent>
          </Card>
        </div>

        <div className="grid gap-4 md:grid-cols-2 md:gap-8">
          {/* Add New Rule */}
          <Card>
            <CardHeader>
              <CardTitle>Add Traffic Control Rule</CardTitle>
              <CardDescription>
                Block an IP address or throttle its response time. Blocked IPs are prevented from accessing your network at both application and system levels.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Form {...form}>
                <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                  <FormField
                    control={form.control}
                    name="ip"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>IP Address</FormLabel>
                        <FormControl>
                          <Input 
                            placeholder="e.g., 192.168.1.100" 
                            {...field} 
                            className="border-[hsl(267.1,37.5%,22%)]"
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  
                  <FormField
                    control={form.control}
                    name="action"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Action</FormLabel>
                        <Select onValueChange={field.onChange} defaultValue={field.value}>
                          <FormControl>
                            <SelectTrigger className="border-[hsl(267.1,37.5%,22%)]">
                              <SelectValue placeholder="Select action" />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            <SelectItem value="block">
                              <div className="flex items-center gap-2">
                                <Ban className="h-4 w-4 text-destructive" />
                                Block IP
                              </div>
                            </SelectItem>
                            <SelectItem value="throttle">
                              <div className="flex items-center gap-2">
                                <Clock className="h-4 w-4 text-orange-500" />
                                Throttle Response
                              </div>
                            </SelectItem>
                          </SelectContent>
                        </Select>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  {watchAction === "throttle" && (
                    <FormField
                      control={form.control}
                      name="delay"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Response Delay (ms)</FormLabel>
                          <Select 
                            onValueChange={(value) => field.onChange(parseInt(value))} 
                            defaultValue={field.value?.toString()}
                          >
                            <FormControl>
                              <SelectTrigger className="border-[hsl(267.1,37.5%,22%)]">
                                <SelectValue placeholder="Select delay" />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              <SelectItem value="500">500ms (0.5 second)</SelectItem>
                              <SelectItem value="1000">1000ms (1 second)</SelectItem>
                              <SelectItem value="2000">2000ms (2 seconds)</SelectItem>
                              <SelectItem value="3000">3000ms (3 seconds)</SelectItem>
                              <SelectItem value="5000">5000ms (5 seconds)</SelectItem>
                              <SelectItem value="10000">10000ms (10 seconds)</SelectItem>
                            </SelectContent>
                          </Select>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  )}

                  <Button type="submit" className="w-full sm:w-auto">
                    <PlusCircle className="mr-2 h-4 w-4" />
                    Add Rule
                  </Button>
                </form>
              </Form>
            </CardContent>
          </Card>

          {/* Active Rules */}
          <Card>
            <CardHeader>
              <CardTitle>Active Traffic Rules</CardTitle>
              <CardDescription>
                Current IP blocking and throttling rules.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border">
                {trafficRules.length > 0 ? (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>IP Address</TableHead>
                        <TableHead>Action</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead></TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {trafficRules.map((rule) => (
                        <TableRow key={rule.id}>
                          <TableCell className="font-mono">{rule.ip}</TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              {rule.action === "block" ? (
                                <>
                                  <Ban className="h-4 w-4 text-destructive" />
                                  <span>Block</span>
                                </>
                              ) : (
                                <>
                                  <Clock className="h-4 w-4 text-orange-500" />
                                  <span>Throttle ({rule.delay}ms)</span>
                                </>
                              )}
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge 
                              variant={rule.status === "active" ? "default" : "secondary"}
                              className="cursor-pointer"
                              onClick={() => toggleRuleStatus(rule.id)}
                            >
                              {rule.status}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => removeRule(rule.id)}
                              className="text-destructive hover:text-destructive"
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                ) : (
                  <div className="flex h-32 flex-col items-center justify-center gap-2 text-center p-4">
                    <AlertTriangle className="h-8 w-8 text-muted-foreground" />
                    <p className="text-sm text-muted-foreground">No traffic rules configured.</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      </main>
    </DashboardLayout>
  );
}