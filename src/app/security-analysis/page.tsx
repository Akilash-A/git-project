"use client";

import { useState, useEffect } from "react";
import { Search, Shield, AlertTriangle, CheckCircle, Loader2, Activity, TrendingUp } from "lucide-react";

import { DashboardLayout } from "@/components/layout/dashboard-layout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { getIpSecurityScore } from "@/app/actions";
import { cn } from "@/lib/utils";
import type { IpAddressSecurityScoringOutput } from "@/ai/flows/ip-address-security-scoring";

interface ScoredIP {
  ip: string;
  score: IpAddressSecurityScoringOutput;
  timestamp: Date;
  source: "manual" | "auto";
}

// Mock function to simulate getting recent threat IPs from monitoring
// In a real app, this would connect to your packet monitoring system
const getRecentThreatIPs = (): string[] => {
  // These would come from your actual monitoring system
  return [
    "185.220.101.32",  // Example Tor exit node
    "45.147.229.23",   // Example suspicious IP
    "197.246.171.83",  // Example malicious IP
  ];
};

export default function ScoreboardPage() {
  const [ipInput, setIpInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [autoAnalyzing, setAutoAnalyzing] = useState(false);
  const [scoredIPs, setScoredIPs] = useState<ScoredIP[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState("manual");

  // Auto-analyze recent threat IPs on component mount
  useEffect(() => {
    const autoAnalyzeThreatIPs = async () => {
      setAutoAnalyzing(true);
      const threatIPs = getRecentThreatIPs();
      
      for (const ip of threatIPs.slice(0, 3)) { // Limit to 3 for demo
        try {
          const result = await getIpSecurityScore({ ipAddress: ip });
          const newScoredIP: ScoredIP = {
            ip,
            score: result,
            timestamp: new Date(),
            source: "auto"
          };
          setScoredIPs(prev => [...prev, newScoredIP]);
          // Small delay between requests
          await new Promise(resolve => setTimeout(resolve, 1000));
        } catch (err) {
          console.error(`Failed to analyze threat IP ${ip}:`, err);
        }
      }
      setAutoAnalyzing(false);
    };

    autoAnalyzeThreatIPs();
  }, []);

  const analyzeIP = async () => {
    if (!ipInput.trim()) return;

    // Basic IP validation
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ipInput.trim())) {
      setError("Please enter a valid IP address format (e.g., 192.168.1.1)");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const result = await getIpSecurityScore({ ipAddress: ipInput.trim() });
      
      const newScoredIP: ScoredIP = {
        ip: ipInput.trim(),
        score: result,
        timestamp: new Date(),
        source: "manual"
      };

      setScoredIPs(prev => [newScoredIP, ...prev.slice(0, 19)]); // Keep last 20 results
      setIpInput("");
    } catch (err) {
      setError("Failed to analyze IP address. Please try again.");
      console.error("IP analysis error:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      analyzeIP();
    }
  };

  const getRiskLevel = (securityScore: string) => {
    return securityScore.toLowerCase() === "safe" ? "safe" : "unsafe";
  };

  const getRiskColor = (securityScore: string) => {
    return securityScore.toLowerCase() === "safe" ? "bg-green-500" : "bg-red-500";
  };

  const getRiskIcon = (securityScore: string) => {
    return securityScore.toLowerCase() === "safe" ? CheckCircle : AlertTriangle;
  };

  const getSourceBadge = (source: string) => {
    return source === "auto" ? (
      <Badge variant="outline" className="text-xs">
        <Activity className="h-3 w-3 mr-1" />
        Auto-detected
      </Badge>
    ) : (
      <Badge variant="outline" className="text-xs">
        <Search className="h-3 w-3 mr-1" />
        Manual
      </Badge>
    );
  };

  const manualIPs = scoredIPs.filter(ip => ip.source === "manual");
  const autoIPs = scoredIPs.filter(ip => ip.source === "auto");
  const unsafeCount = scoredIPs.filter(ip => getRiskLevel(ip.score.securityScore) === "unsafe").length;
  const safeCount = scoredIPs.filter(ip => getRiskLevel(ip.score.securityScore) === "safe").length;

  const renderIPList = (ips: ScoredIP[]) => (
    <div className="space-y-4">
      {ips.map((item, index) => {
        const riskLevel = getRiskLevel(item.score.securityScore);
        const RiskIcon = getRiskIcon(item.score.securityScore);
        
        return (
          <div
            key={`${item.ip}-${item.timestamp.getTime()}`}
            className="flex items-start gap-4 p-4 border rounded-lg"
          >
            <div className="flex items-center gap-2">
              <div className={`flex h-8 w-8 items-center justify-center rounded-full ${getRiskColor(item.score.securityScore)}/10`}>
                <RiskIcon className={`h-4 w-4 ${getRiskColor(item.score.securityScore).replace('bg-', 'text-')}`} />
              </div>
            </div>
            
            <div className="flex-1 space-y-2">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-mono font-semibold">{item.ip}</span>
                <Badge 
                  variant={riskLevel === "safe" ? "outline" : "destructive"}
                  className={cn(
                    "uppercase",
                    riskLevel === "safe" && "border-green-500 text-green-500 bg-green-500/10"
                  )}
                >
                  {riskLevel}
                </Badge>
                {getSourceBadge(item.source)}
                <span className="text-xs text-muted-foreground">
                  {item.timestamp.toLocaleString()}
                </span>
              </div>
              
              <div className="text-sm text-muted-foreground">
                <p className="font-medium mb-1">AI Analysis:</p>
                <p>{item.score.analysisDetails}</p>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );

  return (
    <DashboardLayout>
      <div className="flex flex-1 flex-col gap-4 p-4 md:gap-8 md:p-8">
        <div className="mx-auto grid w-full max-w-6xl gap-2">
          <h1 className="text-3xl font-semibold">IP Security Analysis</h1>
          <p className="text-muted-foreground">
            Analyze IP addresses using AI to determine their security risk level and get detailed threat intelligence.
          </p>
        </div>

        <div className="mx-auto grid w-full max-w-6xl items-start gap-6">
          {/* Statistics Overview */}
          <div className="grid gap-4 md:grid-cols-3">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Total Analyzed</CardTitle>
                <TrendingUp className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{scoredIPs.length}</div>
                <p className="text-xs text-muted-foreground">
                  IP addresses scored
                </p>
              </CardContent>
            </Card>
            
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Unsafe IPs</CardTitle>
                <AlertTriangle className="h-4 w-4 text-red-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-red-500">{unsafeCount}</div>
                <p className="text-xs text-muted-foreground">
                  Threat indicators found
                </p>
              </CardContent>
            </Card>
            
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Safe IPs</CardTitle>
                <CheckCircle className="h-4 w-4 text-green-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-green-500">{safeCount}</div>
                <p className="text-xs text-muted-foreground">
                  Clean reputation
                </p>
              </CardContent>
            </Card>
          </div>

          {/* IP Analysis Input */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5" />
                Analyze IP Address
              </CardTitle>
              <CardDescription>
                Enter an IP address to get its security score and threat analysis powered by AI.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-2">
                <Input
                  placeholder="Enter IP address (e.g., 192.168.1.1)"
                  value={ipInput}
                  onChange={(e) => setIpInput(e.target.value)}
                  onKeyPress={handleKeyPress}
                  disabled={loading}
                />
                <Button onClick={analyzeIP} disabled={loading || !ipInput.trim()}>
                  {loading ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Search className="h-4 w-4" />
                  )}
                  {loading ? "Analyzing..." : "Analyze"}
                </Button>
              </div>
              
              {error && (
                <Alert variant="destructive">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}
            </CardContent>
          </Card>

          {/* Results Tabs */}
          {scoredIPs.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Analysis Results</CardTitle>
                <CardDescription>
                  IP security analysis results with AI-powered threat intelligence.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Tabs value={activeTab} onValueChange={setActiveTab}>
                  <TabsList className="grid w-full grid-cols-3">
                    <TabsTrigger value="all">All Results ({scoredIPs.length})</TabsTrigger>
                    <TabsTrigger value="manual">Manual ({manualIPs.length})</TabsTrigger>
                    <TabsTrigger value="auto">
                      Auto-detected ({autoIPs.length})
                      {autoAnalyzing && <Loader2 className="h-3 w-3 ml-1 animate-spin" />}
                    </TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="all" className="mt-4">
                    {renderIPList(scoredIPs)}
                  </TabsContent>
                  
                  <TabsContent value="manual" className="mt-4">
                    {manualIPs.length > 0 ? renderIPList(manualIPs) : (
                      <div className="text-center text-muted-foreground py-8">
                        No manually analyzed IPs yet. Use the search above to analyze an IP address.
                      </div>
                    )}
                  </TabsContent>
                  
                  <TabsContent value="auto" className="mt-4">
                    {autoIPs.length > 0 ? renderIPList(autoIPs) : autoAnalyzing ? (
                      <div className="text-center text-muted-foreground py-8">
                        <Loader2 className="h-6 w-6 animate-spin mx-auto mb-2" />
                        Analyzing detected threat IPs...
                      </div>
                    ) : (
                      <div className="text-center text-muted-foreground py-8">
                        No auto-detected threat IPs to analyze.
                      </div>
                    )}
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          )}

          {/* Instructions */}
          {scoredIPs.length === 0 && !autoAnalyzing && (
            <Card>
              <CardHeader>
                <CardTitle>How to Use</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-4">
                  <div className="flex items-start gap-3">
                    <div className="flex h-6 w-6 items-center justify-center rounded-full bg-blue-500/10 text-blue-500 text-xs font-semibold">
                      1
                    </div>
                    <div>
                      <h4 className="font-semibold">Auto-Detection</h4>
                      <p className="text-sm text-muted-foreground">
                        The system automatically analyzes IP addresses detected as threats in your network monitoring.
                      </p>
                    </div>
                  </div>
                  
                  <div className="flex items-start gap-3">
                    <div className="flex h-6 w-6 items-center justify-center rounded-full bg-blue-500/10 text-blue-500 text-xs font-semibold">
                      2
                    </div>
                    <div>
                      <h4 className="font-semibold">Manual Analysis</h4>
                      <p className="text-sm text-muted-foreground">
                        Enter any IP address manually to get immediate AI-powered security analysis.
                      </p>
                    </div>
                  </div>
                  
                  <div className="flex items-start gap-3">
                    <div className="flex h-6 w-6 items-center justify-center rounded-full bg-blue-500/10 text-blue-500 text-xs font-semibold">
                      3
                    </div>
                    <div>
                      <h4 className="font-semibold">Risk Assessment</h4>
                      <p className="text-sm text-muted-foreground">
                        Get detailed security scores, risk levels, and threat intelligence for each IP address.
                      </p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {autoAnalyzing && scoredIPs.length === 0 && (
            <Card>
              <CardContent className="py-8">
                <div className="text-center">
                  <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4" />
                  <h3 className="font-semibold mb-2">Analyzing Threat IPs</h3>
                  <p className="text-muted-foreground">
                    Our AI is analyzing recently detected threat IPs from your network monitoring...
                  </p>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </DashboardLayout>
  );
}