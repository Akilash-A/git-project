"use client";

import { useState, useEffect, useCallback } from "react";
import { 
  Search, 
  Brain, 
  TrendingUp, 
  Shield, 
  AlertTriangle, 
  Eye, 
  Activity, 
  MapPin,
  Clock,
  Zap,
  BarChart3,
  PieChart,
  Globe,
  Target,
  RefreshCw
} from "lucide-react";

import { DashboardLayout } from "@/components/layout/dashboard-layout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";
import databaseService from "@/lib/database-service";
import { getIpSecurityScore } from "@/app/actions";
import type { Packet } from "@/lib/types";
import type { IpAddressSecurityScoringOutput } from "@/ai/flows/ip-address-security-scoring";

interface IpStats {
  totalPackets: number;
  incomingPackets: number;
  outgoingPackets: number;
  uniquePorts: number;
  firstSeen: Date;
  lastSeen: Date;
  topPorts: { port: number; count: number }[];
  protocols: { protocol: string; count: number }[];
  hourlyActivity: { hour: number; count: number }[];
}

interface IpAnalysis {
  ipAddress: string;
  stats: IpStats;
  dangerScore: IpAddressSecurityScoringOutput | null;
  packets: Packet[];
}

export default function IpIntelligencePage() {
  const { toast } = useToast();
  
  const [searchIp, setSearchIp] = useState("");
  const [loading, setLoading] = useState(false);
  const [analysis, setAnalysis] = useState<IpAnalysis | null>(null);
  const [topIPs, setTopIPs] = useState<{ ip: string; count: number }[]>([]);
  const [recentAnalyses, setRecentAnalyses] = useState<string[]>([]);

  // Load top IPs on component mount
  useEffect(() => {
    loadTopIPs();
    loadRecentAnalyses();
  }, []);

  const loadTopIPs = async () => {
    try {
      // Get ALL packets without limit to get complete IP statistics
      const packets: Packet[] = await databaseService.getPackets({ limit: 999999 });
      const ipCounts: Record<string, number> = {};
      
      packets.forEach((packet: Packet) => {
        ipCounts[packet.sourceIp] = (ipCounts[packet.sourceIp] || 0) + 1;
        ipCounts[packet.destinationIp] = (ipCounts[packet.destinationIp] || 0) + 1;
      });
      
      const sortedIPs = Object.entries(ipCounts)
        .map(([ip, count]) => ({ ip, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10);
      
      setTopIPs(sortedIPs);
    } catch (error) {
      console.error("Error loading top IPs:", error);
    }
  };

  const loadRecentAnalyses = () => {
    const recent = localStorage.getItem('recentIpAnalyses');
    if (recent) {
      setRecentAnalyses(JSON.parse(recent));
    }
  };

  const saveToRecentAnalyses = (ip: string) => {
    const recent = recentAnalyses.filter(r => r !== ip);
    recent.unshift(ip);
    const updated = recent.slice(0, 5);
    setRecentAnalyses(updated);
    localStorage.setItem('recentIpAnalyses', JSON.stringify(updated));
  };

  const analyzeIP = async (ipAddress: string) => {
    if (!ipAddress || !isValidIP(ipAddress)) {
      toast({
        title: "Invalid IP Address",
        description: "Please enter a valid IP address",
        variant: "destructive",
      });
      return;
    }

    setLoading(true);
    try {
      // Get IP statistics from database
      const stats = await getIpStatistics(ipAddress);
      
      // Get ALL packets for this IP without any limit for complete analysis
      let ipPackets: Packet[] = [];
      
      try {
        // First try to get packets filtered by the specific IP for better performance
        const ipFilteredPackets = await databaseService.getPackets({ 
          limit: 999999,
          ip: ipAddress 
        });
        
        if (ipFilteredPackets.length > 0) {
          ipPackets = ipFilteredPackets.slice(0, 100); // Only slice for display
        } else {
          // Fallback: get all packets and filter manually
          const allPackets: Packet[] = await databaseService.getPackets({ limit: 999999 });
          ipPackets = allPackets.filter((p: Packet) => 
            p.sourceIp === ipAddress || p.destinationIp === ipAddress
          ).slice(0, 100); // Only slice for display
        }
      } catch (error) {
        console.error("Error fetching packets for display:", error);
        ipPackets = [];
      }

      // Get AI danger score
      let dangerScore: IpAddressSecurityScoringOutput | null = null;
      try {
        dangerScore = await getIpSecurityScore({ ipAddress });
      } catch (error) {
        console.error("Error getting danger score:", error);
      }

      const analysis: IpAnalysis = {
        ipAddress,
        stats,
        dangerScore,
        packets: ipPackets
      };

      setAnalysis(analysis);
      saveToRecentAnalyses(ipAddress);
      
      if (stats.totalPackets === 0) {
        toast({
          title: "No Data Found",
          description: `No packets found for ${ipAddress} in the database`,
          variant: "destructive",
        });
      } else {
        toast({
          title: "Analysis Complete",
          description: `Successfully analyzed ${ipAddress} - Found ${stats.totalPackets} packets`,
        });
      }
    } catch (error) {
      console.error("Error analyzing IP:", error);
      toast({
        title: "Analysis Failed",
        description: "Failed to analyze IP address. Please try again.",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const getIpStatistics = async (ipAddress: string): Promise<IpStats> => {
    // Get ALL packets from database without any limit for complete statistics
    // Also try to get packets specifically filtered by IP for better performance
    let allPackets: Packet[] = [];
    
    try {
      // First try to get packets filtered by the specific IP
      const ipFilteredPackets = await databaseService.getPackets({ 
        limit: 999999,
        ip: ipAddress 
      });
      
      if (ipFilteredPackets.length > 0) {
        allPackets = ipFilteredPackets;
      } else {
        // Fallback: get all packets and filter manually
        const allDbPackets = await databaseService.getPackets({ limit: 999999 });
        allPackets = allDbPackets.filter((p: Packet) => 
          p.sourceIp === ipAddress || p.destinationIp === ipAddress
        );
      }
    } catch (error) {
      console.error("Error fetching packets:", error);
      // Fallback: get all packets and filter manually
      const allDbPackets = await databaseService.getPackets({ limit: 999999 });
      allPackets = allDbPackets.filter((p: Packet) => 
        p.sourceIp === ipAddress || p.destinationIp === ipAddress
      );
    }

    const ipPackets = allPackets;

    const incomingPackets = ipPackets.filter((p: Packet) => p.destinationIp === ipAddress);
    const outgoingPackets = ipPackets.filter((p: Packet) => p.sourceIp === ipAddress);
    
    const ports = new Set(ipPackets.map((p: Packet) => p.port).filter(Boolean));
    const protocols = ipPackets.reduce((acc: Record<string, number>, p: Packet) => {
      acc[p.protocol] = (acc[p.protocol] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const portCounts = ipPackets.reduce((acc: Record<number, number>, p: Packet) => {
      if (p.port) {
        acc[p.port] = (acc[p.port] || 0) + 1;
      }
      return acc;
    }, {} as Record<number, number>);

    const hourlyActivity = Array.from({ length: 24 }, (_, hour) => {
      const count = ipPackets.filter((p: Packet) => 
        new Date(p.timestamp).getHours() === hour
      ).length;
      return { hour, count };
    });

    const timestamps = ipPackets.map((p: Packet) => new Date(p.timestamp));
    
    return {
      totalPackets: ipPackets.length,
      incomingPackets: incomingPackets.length,
      outgoingPackets: outgoingPackets.length,
      uniquePorts: ports.size,
      firstSeen: timestamps.length > 0 ? new Date(Math.min(...timestamps.map((d: Date) => d.getTime()))) : new Date(),
      lastSeen: timestamps.length > 0 ? new Date(Math.max(...timestamps.map((d: Date) => d.getTime()))) : new Date(),
      topPorts: Object.entries(portCounts)
        .map(([port, count]) => ({ port: parseInt(port), count: count as number }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 5),
      protocols: Object.entries(protocols)
        .map(([protocol, count]) => ({ protocol, count: count as number }))
        .sort((a, b) => b.count - a.count),
      hourlyActivity
    };
  };

  const isValidIP = (ip: string): boolean => {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipRegex.test(ip);
  };

  const formatTimestamp = (timestamp: string | number | Date) => {
    return new Date(timestamp).toLocaleString();
  };

  const getDangerLevel = (score?: number): { level: string; color: string; bgColor: string } => {
    if (!score) return { level: "Unknown", color: "text-gray-500", bgColor: "bg-gray-100" };
    
    if (score >= 80) return { level: "Critical", color: "text-red-600", bgColor: "bg-red-100" };
    if (score >= 60) return { level: "High", color: "text-orange-600", bgColor: "bg-orange-100" };
    if (score >= 40) return { level: "Medium", color: "text-yellow-600", bgColor: "bg-yellow-100" };
    if (score >= 20) return { level: "Low", color: "text-blue-600", bgColor: "bg-blue-100" };
    return { level: "Safe", color: "text-green-600", bgColor: "bg-green-100" };
  };

  return (
    <DashboardLayout>
      <div className="flex flex-1 flex-col gap-4 p-4 md:gap-8 md:p-8">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="font-headline text-lg font-semibold md:text-2xl flex items-center gap-2">
              <Brain className="h-6 w-6" />
              IP Intelligence
            </h1>
            <p className="text-muted-foreground">
              AI-powered IP address analysis and threat intelligence
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" onClick={loadTopIPs}>
              <RefreshCw className="h-4 w-4 mr-2" />
              Refresh Data
            </Button>
          </div>
        </div>

        {/* Search Section */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Search className="h-5 w-5" />
              IP Address Analysis
            </CardTitle>
            <CardDescription>
              Enter an IP address to get comprehensive analysis including packet statistics and AI-powered threat assessment
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-2">
              <Input
                placeholder="Enter IP address (e.g., 192.168.1.1)"
                value={searchIp}
                onChange={(e) => setSearchIp(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && analyzeIP(searchIp)}
                className="flex-1"
              />
              <Button 
                onClick={() => analyzeIP(searchIp)}
                disabled={loading || !searchIp}
              >
                {loading ? (
                  <>
                    <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Brain className="h-4 w-4 mr-2" />
                    Analyze IP
                  </>
                )}
              </Button>
            </div>

            {/* Quick Access */}
            <div className="space-y-2">
              {recentAnalyses.length > 0 && (
                <div>
                  <p className="text-sm font-medium mb-2">Recent Analyses:</p>
                  <div className="flex flex-wrap gap-2">
                    {recentAnalyses.map((ip) => (
                      <Button
                        key={ip}
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          setSearchIp(ip);
                          analyzeIP(ip);
                        }}
                      >
                        {ip}
                      </Button>
                    ))}
                  </div>
                </div>
              )}
              
              {topIPs.length > 0 && (
                <div>
                  <p className="text-sm font-medium mb-2">Top Active IPs:</p>
                  <div className="flex flex-wrap gap-2">
                    {topIPs.slice(0, 5).map((item) => (
                      <Button
                        key={item.ip}
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          setSearchIp(item.ip);
                          analyzeIP(item.ip);
                        }}
                      >
                        {item.ip} ({item.count})
                      </Button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Analysis Results */}
        {analysis && (
          <div className="space-y-6">
            {/* Overview Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">Total Packets</p>
                      <p className="text-2xl font-bold">{analysis.stats.totalPackets.toLocaleString()}</p>
                    </div>
                    <Activity className="h-8 w-8 text-blue-500" />
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">Incoming</p>
                      <p className="text-2xl font-bold text-orange-600">{analysis.stats.incomingPackets.toLocaleString()}</p>
                    </div>
                    <TrendingUp className="h-8 w-8 text-orange-500" />
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">Outgoing</p>
                      <p className="text-2xl font-bold text-green-600">{analysis.stats.outgoingPackets.toLocaleString()}</p>
                    </div>
                    <Target className="h-8 w-8 text-green-500" />
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">Unique Ports</p>
                      <p className="text-2xl font-bold">{analysis.stats.uniquePorts}</p>
                    </div>
                    <Globe className="h-8 w-8 text-purple-500" />
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* AI Danger Score */}
            {analysis.dangerScore && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Brain className="h-5 w-5" />
                    AI Security Assessment
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className="text-center">
                        <p className="text-3xl font-bold">{analysis.dangerScore.dangerScore}/100</p>
                        <p className="text-sm text-muted-foreground">Danger Score</p>
                      </div>
                      <div>
                        <Badge className={`${getDangerLevel(analysis.dangerScore.dangerScore).bgColor} ${getDangerLevel(analysis.dangerScore.dangerScore).color}`}>
                          {getDangerLevel(analysis.dangerScore.dangerScore).level}
                        </Badge>
                      </div>
                    </div>
                    <div className="flex-1 max-w-md">
                      <Progress value={analysis.dangerScore.dangerScore} className="h-3" />
                    </div>
                  </div>
                  
                  {analysis.dangerScore.analysisDetails && (
                    <div className="space-y-2">
                      <p className="font-medium">AI Analysis:</p>
                      <p className="text-sm text-muted-foreground">{analysis.dangerScore.analysisDetails}</p>
                    </div>
                  )}
                  
                  {analysis.dangerScore.securityScore && (
                    <div className="space-y-2">
                      <p className="font-medium">Security Assessment:</p>
                      <div className="flex items-center gap-2">
                        <Badge variant={analysis.dangerScore.securityScore === 'safe' ? 'default' : 'destructive'}>
                          {analysis.dangerScore.securityScore.toUpperCase()}
                        </Badge>
                        <span className="text-sm text-muted-foreground">
                          This IP is classified as {analysis.dangerScore.securityScore}
                        </span>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

            {/* Detailed Analysis */}
            <Tabs defaultValue="overview" className="w-full">
              <TabsList>
                <TabsTrigger value="overview">Overview</TabsTrigger>
                <TabsTrigger value="packets">Packet History</TabsTrigger>
                <TabsTrigger value="analytics">Analytics</TabsTrigger>
              </TabsList>
              
              <TabsContent value="overview" className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <Clock className="h-5 w-5" />
                        Timeline
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-muted-foreground">First Seen:</span>
                        <span className="text-sm font-medium">{formatTimestamp(analysis.stats.firstSeen)}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-muted-foreground">Last Seen:</span>
                        <span className="text-sm font-medium">{formatTimestamp(analysis.stats.lastSeen)}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-muted-foreground">Active Duration:</span>
                        <span className="text-sm font-medium">
                          {Math.round((analysis.stats.lastSeen.getTime() - analysis.stats.firstSeen.getTime()) / (1000 * 60 * 60 * 24))} days
                        </span>
                      </div>
                    </CardContent>
                  </Card>
                  
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <BarChart3 className="h-5 w-5" />
                        Top Ports
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-2">
                        {analysis.stats.topPorts.map((item, index) => (
                          <div key={item.port} className="flex justify-between items-center">
                            <span className="text-sm">Port {item.port}</span>
                            <div className="flex items-center gap-2">
                              <div className="w-20 bg-gray-200 rounded-full h-2">
                                <div 
                                  className="bg-blue-500 h-2 rounded-full" 
                                  style={{ width: `${(item.count / analysis.stats.topPorts[0].count) * 100}%` }}
                                />
                              </div>
                              <span className="text-sm font-medium">{item.count}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                </div>
                
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <PieChart className="h-5 w-5" />
                      Protocol Distribution
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      {analysis.stats.protocols.map((item) => (
                        <div key={item.protocol} className="text-center">
                          <div className="text-2xl font-bold">{item.count}</div>
                          <div className="text-sm text-muted-foreground">{item.protocol}</div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>
              
              <TabsContent value="packets">
                <Card>
                  <CardHeader>
                    <CardTitle>Recent Packet Activity</CardTitle>
                    <CardDescription>
                      Last {analysis.packets.length} packets involving this IP address
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="p-0">
                    <div className="rounded-md border overflow-hidden">
                      <div className="h-[400px] overflow-auto">
                        <table className="w-full caption-bottom text-sm">
                          <thead className="sticky top-0 z-10 bg-background">
                            <tr className="border-b transition-colors hover:bg-muted/50">
                              <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground sticky top-0 bg-background first:rounded-tl-md">Timestamp</th>
                              <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground sticky top-0 bg-background">Source</th>
                              <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground sticky top-0 bg-background">Destination</th>
                              <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground sticky top-0 bg-background">Protocol</th>
                              <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground sticky top-0 bg-background">Port</th>
                              <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground sticky top-0 bg-background last:rounded-tr-md">Size</th>
                            </tr>
                          </thead>
                          <tbody className="[&_tr:last-child]:border-0">
                            {analysis.packets.map((packet) => (
                              <tr key={packet.id} className="border-b transition-colors hover:bg-muted/50 last:border-0">
                                <td className="p-4 align-middle text-xs font-mono">{formatTimestamp(packet.timestamp)}</td>
                                <td className="p-4 align-middle font-mono text-sm">
                                  <span className={packet.sourceIp === analysis.ipAddress ? "text-blue-600 font-semibold" : ""}>
                                    {packet.sourceIp}
                                  </span>
                                </td>
                                <td className="p-4 align-middle font-mono text-sm">
                                  <span className={packet.destinationIp === analysis.ipAddress ? "text-blue-600 font-semibold" : ""}>
                                    {packet.destinationIp}
                                  </span>
                                </td>
                                <td className="p-4 align-middle">
                                  <Badge variant="outline">{packet.protocol}</Badge>
                                </td>
                                <td className="p-4 align-middle">{packet.port}</td>
                                <td className="p-4 align-middle">{packet.size ? `${packet.size}B` : 'N/A'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>
              
              <TabsContent value="analytics">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Activity className="h-5 w-5" />
                      24-Hour Activity Pattern
                    </CardTitle>
                    <CardDescription>
                      Hourly packet distribution for this IP address
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-12 gap-1 h-32">
                      {analysis.stats.hourlyActivity.map((item) => {
                        const maxCount = Math.max(...analysis.stats.hourlyActivity.map(h => h.count));
                        const height = maxCount > 0 ? (item.count / maxCount) * 100 : 0;
                        return (
                          <div key={item.hour} className="flex flex-col items-center">
                            <div className="flex-1 flex items-end">
                              <div 
                                className="w-full bg-blue-500 rounded-sm min-h-[2px]" 
                                style={{ height: `${height}%` }}
                                title={`${item.hour}:00 - ${item.count} packets`}
                              />
                            </div>
                            <div className="text-xs text-muted-foreground mt-1">
                              {item.hour.toString().padStart(2, '0')}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                    <div className="mt-4 text-center text-sm text-muted-foreground">
                      Hour of Day (24-hour format)
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          </div>
        )}

        {/* No Analysis State */}
        {!analysis && !loading && (
          <Card>
            <CardContent className="p-12 text-center">
              <Brain className="h-16 w-16 mx-auto text-muted-foreground mb-4" />
              <h3 className="text-lg font-semibold mb-2">Start IP Analysis</h3>
              <p className="text-muted-foreground mb-4">
                Enter an IP address above to begin comprehensive analysis including packet statistics, 
                traffic patterns, and AI-powered threat assessment.
              </p>
              <div className="flex flex-wrap justify-center gap-2">
                <Badge variant="outline">Packet Statistics</Badge>
                <Badge variant="outline">AI Threat Scoring</Badge>
                <Badge variant="outline">Traffic Analysis</Badge>
                <Badge variant="outline">Historical Data</Badge>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </DashboardLayout>
  );
}