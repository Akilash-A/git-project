"use client";

import { useState, useEffect } from "react";
import { X, Shield, AlertTriangle, Activity, Eye } from "lucide-react";

import { getIpSecurityScore } from "@/app/actions";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import type { IpAddressSecurityScoringOutput } from "@/ai/flows/ip-address-security-scoring";

interface IpDangerScoreModalProps {
  ipAddress: string | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function IpDangerScoreModal({ ipAddress, open, onOpenChange }: IpDangerScoreModalProps) {
  const [loading, setLoading] = useState(false);
  const [scoreData, setScoreData] = useState<IpAddressSecurityScoringOutput | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open && ipAddress) {
      analyzeDangerScore();
    } else {
      // Reset state when modal closes
      setScoreData(null);
      setError(null);
    }
  }, [open, ipAddress]);

  const analyzeDangerScore = async () => {
    if (!ipAddress) return;

    setLoading(true);
    setError(null);
    setScoreData(null);

    try {
      const result = await getIpSecurityScore({ ipAddress });
      setScoreData(result);
    } catch (err) {
      setError("Failed to analyze IP address. Please try again.");
      console.error("IP danger score analysis error:", err);
    } finally {
      setLoading(false);
    }
  };

  const getDangerLevel = (score: number) => {
    if (score <= 20) return { level: "Very Safe", color: "bg-green-500", textColor: "text-green-500" };
    if (score <= 40) return { level: "Low Risk", color: "bg-yellow-500", textColor: "text-yellow-500" };
    if (score <= 60) return { level: "Medium Risk", color: "bg-orange-500", textColor: "text-orange-500" };
    if (score <= 80) return { level: "High Risk", color: "bg-red-500", textColor: "text-red-500" };
    return { level: "Extreme Danger", color: "bg-red-700", textColor: "text-red-700" };
  };

  const getDangerIcon = (score: number) => {
    if (score <= 40) return Shield;
    if (score <= 60) return Eye;
    return AlertTriangle;
  };

  const getDangerDescription = (score: number) => {
    if (score <= 20) return "This IP address appears to be legitimate and poses minimal security risk.";
    if (score <= 40) return "This IP address shows some indicators but generally appears safe with low risk.";
    if (score <= 60) return "This IP address has concerning indicators and should be monitored carefully.";
    if (score <= 80) return "This IP address shows significant threat indicators and poses high security risk.";
    return "This IP address is extremely dangerous with active threat indicators. Immediate action recommended.";
  };

  if (!ipAddress) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            IP Danger Analysis
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-6">
          {/* IP Address Header */}
          <div className="text-center">
            <div className="font-mono text-lg font-semibold mb-2">{ipAddress}</div>
            <Badge variant="outline" className="text-xs">
              AI-Powered Security Analysis
            </Badge>
          </div>

          {/* Loading State */}
          {loading && (
            <div className="space-y-4">
              <div className="text-center">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-2"></div>
                <p className="text-sm text-muted-foreground">Analyzing IP address...</p>
              </div>
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-20 w-full" />
            </div>
          )}

          {/* Error State */}
          {error && (
            <div className="text-center p-4 border border-red-200 rounded-lg bg-red-50">
              <AlertTriangle className="h-6 w-6 text-red-500 mx-auto mb-2" />
              <p className="text-sm text-red-600">{error}</p>
              <Button 
                variant="outline" 
                size="sm" 
                className="mt-2"
                onClick={analyzeDangerScore}
              >
                Try Again
              </Button>
            </div>
          )}

          {/* Results */}
          {scoreData && (
            <div className="space-y-4">
              {/* Danger Score Display */}
              <div className="text-center p-6 border rounded-lg bg-muted/50">
                <div className="mb-4">
                  <div className="text-3xl font-bold mb-1">
                    {scoreData.dangerScore}
                    <span className="text-lg text-muted-foreground">/100</span>
                  </div>
                  <div className="text-sm text-muted-foreground">Danger Score</div>
                </div>

                {/* Progress Bar */}
                <div className="mb-4">
                  <Progress 
                    value={scoreData.dangerScore} 
                    className="h-3"
                  />
                </div>

                {/* Danger Level Badge */}
                <div className="flex items-center justify-center gap-2">
                  {(() => {
                    const dangerInfo = getDangerLevel(scoreData.dangerScore);
                    const DangerIcon = getDangerIcon(scoreData.dangerScore);
                    return (
                      <>
                        <DangerIcon className={cn("h-4 w-4", dangerInfo.textColor)} />
                        <Badge 
                          variant="outline"
                          className={cn("font-semibold", dangerInfo.textColor)}
                        >
                          {dangerInfo.level}
                        </Badge>
                      </>
                    );
                  })()}
                </div>
              </div>

              {/* Risk Description */}
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold mb-2 flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  Risk Assessment
                </h4>
                <p className="text-sm text-muted-foreground mb-3">
                  {getDangerDescription(scoreData.dangerScore)}
                </p>
                
                {/* Legacy Security Score */}
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">Classification:</span>
                  <Badge 
                    variant={scoreData.securityScore === "safe" ? "outline" : "destructive"}
                    className={cn(
                      "text-xs",
                      scoreData.securityScore === "safe" && "border-green-500 text-green-500 bg-green-500/10"
                    )}
                  >
                    {scoreData.securityScore.toUpperCase()}
                  </Badge>
                </div>
              </div>

              {/* AI Analysis Details */}
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold mb-2 flex items-center gap-2">
                  <Activity className="h-4 w-4" />
                  AI Analysis
                </h4>
                <p className="text-sm text-muted-foreground leading-relaxed">
                  {scoreData.analysisDetails}
                </p>
              </div>

              {/* Action Buttons */}
              <div className="flex gap-2">
                <Button 
                  variant="outline" 
                  size="sm" 
                  className="flex-1"
                  onClick={analyzeDangerScore}
                >
                  Re-analyze
                </Button>
                <Button 
                  variant="default" 
                  size="sm" 
                  className="flex-1"
                  onClick={() => onOpenChange(false)}
                >
                  Close
                </Button>
              </div>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}