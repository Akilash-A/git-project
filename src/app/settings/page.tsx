"use client";

import { useState, useEffect } from "react";
import { Trash2, Database, Settings as SettingsIcon, AlertTriangle, Shield, BarChart3, Download, Upload, Eye, Calendar, Clock } from "lucide-react";

import { DashboardLayout } from "@/components/layout/dashboard-layout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import databaseService from "@/lib/database-service";
import type { Packet } from "@/lib/types";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";

interface DatabaseStats {
  totalPackets: number;
  totalAlerts: number;
  whitelistedIPs: number;
  securityAnalyses: number;
  packetsLastHour: number;
  uniqueIPs: number;
}

export default function SettingsPage() {
  const [stats, setStats] = useState<DatabaseStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  
  // Packets viewing state
  const [packets, setPackets] = useState<Packet[]>([]);
  const [packetsLoading, setPacketsLoading] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [packetsPerPage] = useState(50);
  const [totalPacketsCount, setTotalPacketsCount] = useState(0);
  
  // Settings state
  const [autoCleanup, setAutoCleanup] = useState(true);
  const [cleanupDays, setCleanupDays] = useState(30);
  const [alertRetentionDays, setAlertRetentionDays] = useState(7);

  useEffect(() => {
    loadStatistics();
    loadSettings();
  }, []);

  const loadStatistics = async () => {
    try {
      const stats = await databaseService.getStatistics();
      setStats(stats);
    } catch (error) {
      console.error('Failed to load statistics:', error);
      // Fallback to mock data if service is not available
      setStats({
        totalPackets: 0,
        totalAlerts: 0,
        whitelistedIPs: 0,
        securityAnalyses: 0,
        packetsLastHour: 0,
        uniqueIPs: 0
      });
    }
  };

  const loadSettings = () => {
    // Load settings from localStorage or API
    const savedAutoCleanup = localStorage.getItem('autoCleanup');
    const savedCleanupDays = localStorage.getItem('cleanupDays');
    const savedAlertRetentionDays = localStorage.getItem('alertRetentionDays');
    
    if (savedAutoCleanup !== null) setAutoCleanup(JSON.parse(savedAutoCleanup));
    if (savedCleanupDays) setCleanupDays(parseInt(savedCleanupDays));
    if (savedAlertRetentionDays) setAlertRetentionDays(parseInt(savedAlertRetentionDays));
  };

  const saveSettings = () => {
    localStorage.setItem('autoCleanup', JSON.stringify(autoCleanup));
    localStorage.setItem('cleanupDays', cleanupDays.toString());
    localStorage.setItem('alertRetentionDays', alertRetentionDays.toString());
    
    setMessage({ type: 'success', text: 'Settings saved successfully!' });
    setTimeout(() => setMessage(null), 3000);
  };

  const clearData = async (table: string, daysOld?: number) => {
    setLoading(true);
    
    try {
      const result = await databaseService.clearData({ table, daysOld });
      
      if (result.success) {
        setMessage({ 
          type: 'success', 
          text: result.message || `Successfully cleared ${table === 'all' ? 'all data' : table}` 
        });
        
        // Reload statistics
        loadStatistics();
      } else {
        setMessage({ 
          type: 'error', 
          text: result.message || `Failed to clear ${table}` 
        });
      }
    } catch (error) {
      setMessage({ 
        type: 'error', 
        text: `Failed to clear ${table}: ${error}` 
      });
    } finally {
      setLoading(false);
      setTimeout(() => setMessage(null), 5000);
    }
  };

  const formatNumber = (num: number) => {
    return new Intl.NumberFormat().format(num);
  };

  const loadPackets = async (page: number = 1) => {
    setPacketsLoading(true);
    try {
      const offset = (page - 1) * packetsPerPage;
      const packets = await databaseService.getPackets({ 
        limit: packetsPerPage, 
        offset 
      });
      
      setPackets(packets);
      setCurrentPage(page);
      
      // Update total count from stats
      if (stats) {
        setTotalPacketsCount(stats.totalPackets);
      }
    } catch (error) {
      console.error('Failed to load packets:', error);
      setMessage({ 
        type: 'error', 
        text: 'Failed to load packets from database' 
      });
    } finally {
      setPacketsLoading(false);
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const getAttackTypeBadge = (attackType: string | null) => {
    if (!attackType) return null;
    
    const badgeVariant = attackType.toLowerCase().includes('critical') ? 'destructive' : 'secondary';
    return <Badge variant={badgeVariant}>{attackType}</Badge>;
  };

  return (
    <DashboardLayout>
      <div className="flex flex-1 flex-col gap-4 p-4 md:gap-8 md:p-8">
        <div className="flex items-center">
          <h1 className="font-headline text-lg font-semibold md:text-2xl">
            Settings
          </h1>
        </div>

        {message && (
          <Alert className={message.type === 'error' ? 'border-red-500' : 'border-green-500'}>
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>{message.text}</AlertDescription>
          </Alert>
        )}

        <Tabs defaultValue="database" className="w-full">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="database">Database Management</TabsTrigger>
            <TabsTrigger value="packets">View Packets</TabsTrigger>
            <TabsTrigger value="cleanup">Auto Cleanup</TabsTrigger>
            <TabsTrigger value="export">Import/Export</TabsTrigger>
          </TabsList>

          <TabsContent value="database" className="space-y-6">
            {/* Database Statistics */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <BarChart3 className="h-5 w-5" />
                  Database Statistics
                </CardTitle>
                <CardDescription>
                  Overview of all stored data in the system
                </CardDescription>
              </CardHeader>
              <CardContent>
                {stats ? (
                  <div className="grid gap-4 md:grid-cols-3">
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">Total Packets</span>
                        <Badge variant="outline">{formatNumber(stats.totalPackets)}</Badge>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">Packets (Last Hour)</span>
                        <Badge variant="secondary">{formatNumber(stats.packetsLastHour)}</Badge>
                      </div>
                    </div>
                    
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">Total Alerts</span>
                        <Badge variant="destructive">{formatNumber(stats.totalAlerts)}</Badge>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">Security Analyses</span>
                        <Badge variant="outline">{formatNumber(stats.securityAnalyses)}</Badge>
                      </div>
                    </div>
                    
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">Whitelisted IPs</span>
                        <Badge variant="default">{formatNumber(stats.whitelistedIPs)}</Badge>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">Unique IPs</span>
                        <Badge variant="outline">{formatNumber(stats.uniqueIPs)}</Badge>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-4">Loading statistics...</div>
                )}
              </CardContent>
            </Card>

            {/* Data Management */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Database className="h-5 w-5" />
                  Data Management
                </CardTitle>
                <CardDescription>
                  Clear specific data types or all data from the database
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-4">
                    <AlertDialog>
                      <AlertDialogTrigger asChild>
                        <Button variant="outline" className="w-full border-2 dark:border-gray-600 dark:hover:border-gray-500" disabled={loading}>
                          <Trash2 className="mr-2 h-4 w-4" />
                          Clear Packets
                        </Button>
                      </AlertDialogTrigger>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>Clear Packet Data</AlertDialogTitle>
                          <AlertDialogDescription>
                            This will permanently delete all packet data from the database. This action cannot be undone.
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel>Cancel</AlertDialogCancel>
                          <AlertDialogAction 
                            onClick={() => clearData('packets')}
                            className="bg-red-600 hover:bg-red-700"
                          >
                            Clear Packets
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>

                    <AlertDialog>
                      <AlertDialogTrigger asChild>
                        <Button variant="outline" className="w-full border-2 dark:border-gray-600 dark:hover:border-gray-500" disabled={loading}>
                          <Trash2 className="mr-2 h-4 w-4" />
                          Clear Alerts
                        </Button>
                      </AlertDialogTrigger>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>Clear Alert Data</AlertDialogTitle>
                          <AlertDialogDescription>
                            This will permanently delete all alert data from the database. This action cannot be undone.
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel>Cancel</AlertDialogCancel>
                          <AlertDialogAction 
                            onClick={() => clearData('alerts')}
                            className="bg-red-600 hover:bg-red-700"
                          >
                            Clear Alerts
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>
                  </div>

                  <div className="space-y-4">
                    <AlertDialog>
                      <AlertDialogTrigger asChild>
                        <Button variant="outline" className="w-full border-2 dark:border-gray-600 dark:hover:border-gray-500" disabled={loading}>
                          <Trash2 className="mr-2 h-4 w-4" />
                          Clear Security Analysis
                        </Button>
                      </AlertDialogTrigger>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>Clear Security Analysis Data</AlertDialogTitle>
                          <AlertDialogDescription>
                            This will permanently delete all security analysis data from the database. This action cannot be undone.
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel>Cancel</AlertDialogCancel>
                          <AlertDialogAction 
                            onClick={() => clearData('security_analysis')}
                            className="bg-red-600 hover:bg-red-700"
                          >
                            Clear Analysis Data
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>

                    <AlertDialog>
                      <AlertDialogTrigger asChild>
                        <Button variant="destructive" className="w-full" disabled={loading}>
                          <Trash2 className="mr-2 h-4 w-4" />
                          Clear All Data
                        </Button>
                      </AlertDialogTrigger>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>Clear All Data</AlertDialogTitle>
                          <AlertDialogDescription>
                            This will permanently delete ALL data from the database including packets, alerts, and security analyses. Whitelist data will be preserved. This action cannot be undone.
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel>Cancel</AlertDialogCancel>
                          <AlertDialogAction 
                            onClick={() => clearData('all')}
                            className="bg-red-600 hover:bg-red-700"
                          >
                            Clear All Data
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="packets" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Eye className="h-5 w-5" />
                  View All Packets
                </CardTitle>
                <CardDescription>
                  Browse all packets stored in the database with pagination
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-muted-foreground">
                        Total Packets: {formatNumber(totalPacketsCount)}
                      </span>
                      {stats && (
                        <Badge variant="outline">
                          Showing {Math.min(packetsPerPage, packets.length)} of {formatNumber(stats.totalPackets)}
                        </Badge>
                      )}
                    </div>
                    <Button 
                      onClick={() => loadPackets(1)} 
                      disabled={packetsLoading}
                      className="border-2 dark:border-gray-600"
                    >
                      {packetsLoading ? "Loading..." : "Load Packets"}
                    </Button>
                  </div>

                  {packets.length > 0 && (
                    <>
                      <ScrollArea className="h-[500px] w-full rounded-md border">
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>Timestamp</TableHead>
                              <TableHead>Source IP</TableHead>
                              <TableHead>Destination IP</TableHead>
                              <TableHead>Protocol</TableHead>
                              <TableHead>Port</TableHead>
                              <TableHead>Size</TableHead>
                              <TableHead>Attack Type</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {packets.map((packet) => (
                              <TableRow key={packet.id}>
                                <TableCell className="font-mono text-xs">
                                  <div className="flex items-center gap-1">
                                    <Clock className="h-3 w-3" />
                                    {formatTimestamp(packet.timestamp)}
                                  </div>
                                </TableCell>
                                <TableCell className="font-mono">
                                  {packet.sourceIp}
                                </TableCell>
                                <TableCell className="font-mono">
                                  {packet.destinationIp}
                                </TableCell>
                                <TableCell>
                                  <Badge variant="outline">{packet.protocol}</Badge>
                                </TableCell>
                                <TableCell>{packet.port}</TableCell>
                                <TableCell>{packet.size ? `${packet.size} bytes` : 'N/A'}</TableCell>
                                <TableCell>
                                  {getAttackTypeBadge(packet.attackType)}
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </ScrollArea>

                      {/* Pagination Controls */}
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => loadPackets(currentPage - 1)}
                            disabled={currentPage <= 1 || packetsLoading}
                            className="border-2 dark:border-gray-600 dark:hover:border-gray-500"
                          >
                            Previous
                          </Button>
                          <span className="text-sm text-muted-foreground">
                            Page {currentPage} of {Math.ceil(totalPacketsCount / packetsPerPage)}
                          </span>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => loadPackets(currentPage + 1)}
                            disabled={currentPage >= Math.ceil(totalPacketsCount / packetsPerPage) || packetsLoading}
                            className="border-2 dark:border-gray-600 dark:hover:border-gray-500"
                          >
                            Next
                          </Button>
                        </div>
                        
                        <div className="text-sm text-muted-foreground">
                          Showing {(currentPage - 1) * packetsPerPage + 1}-{Math.min(currentPage * packetsPerPage, totalPacketsCount)} 
                          of {formatNumber(totalPacketsCount)} packets
                        </div>
                      </div>
                    </>
                  )}

                  {packets.length === 0 && !packetsLoading && (
                    <div className="text-center py-8 text-muted-foreground">
                      <Database className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No packets found in database</p>
                      <p className="text-sm">Click "Load Packets" to fetch data from the database</p>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="cleanup" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <SettingsIcon className="h-5 w-5" />
                  Automatic Cleanup Settings
                </CardTitle>
                <CardDescription>
                  Configure automatic data cleanup to manage database size
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="flex items-center space-x-2">
                  <Switch
                    id="auto-cleanup"
                    checked={autoCleanup}
                    onCheckedChange={setAutoCleanup}
                  />
                  <Label htmlFor="auto-cleanup">Enable automatic cleanup</Label>
                </div>

                <Separator />

                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="cleanup-days">Packet retention (days)</Label>
                    <Input
                      id="cleanup-days"
                      type="number"
                      value={cleanupDays}
                      onChange={(e) => setCleanupDays(parseInt(e.target.value) || 30)}
                      min="1"
                      max="365"
                      disabled={!autoCleanup}
                    />
                    <p className="text-sm text-muted-foreground">
                      Packets older than this will be automatically deleted
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="alert-retention-days">Alert retention (days)</Label>
                    <Input
                      id="alert-retention-days"
                      type="number"
                      value={alertRetentionDays}
                      onChange={(e) => setAlertRetentionDays(parseInt(e.target.value) || 7)}
                      min="1"
                      max="90"
                      disabled={!autoCleanup}
                    />
                    <p className="text-sm text-muted-foreground">
                      Alerts older than this will be automatically deleted
                    </p>
                  </div>
                </div>

                <Button onClick={saveSettings} className="w-full border-2 dark:border-gray-600">
                  Save Cleanup Settings
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="export" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Database className="h-5 w-5" />
                  Import/Export Data
                </CardTitle>
                <CardDescription>
                  Backup and restore your network monitoring data
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <Button variant="outline" className="w-full border-2 dark:border-gray-600 dark:hover:border-gray-500" disabled={loading}>
                    <Download className="mr-2 h-4 w-4" />
                    Export Database
                  </Button>
                  <Button variant="outline" className="w-full border-2 dark:border-gray-600 dark:hover:border-gray-500" disabled={loading}>
                    <Upload className="mr-2 h-4 w-4" />
                    Import Database
                  </Button>
                </div>
                
                <div className="space-y-2">
                  <h4 className="text-sm font-medium">Export Options:</h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    <li>• Export as SQLite database file</li>
                    <li>• Export as JSON for analysis</li>
                    <li>• Export specific date ranges</li>
                    <li>• Export filtered data (by IP, attack type, etc.)</li>
                  </ul>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </DashboardLayout>
  );
}