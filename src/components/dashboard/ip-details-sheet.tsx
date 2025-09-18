
"use client";

import { useState, useEffect } from "react";
import { Loader2 } from "lucide-react";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { getIpSecurityScore } from "@/app/actions";
import type { IpAddressSecurityScoringOutput } from "@/ai/flows/ip-address-security-scoring";
import { Skeleton } from "@/components/ui/skeleton";

interface IpDetailsSheetProps {
  ipAddress: string | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const LoadingState = () => (
  <div className="space-y-4">
    <Card>
      <CardHeader>
        <Skeleton className="h-6 w-24" />
      </CardHeader>
      <CardContent>
        <Skeleton className="h-8 w-32" />
      </CardContent>
    </Card>
    <Card>
      <CardHeader>
        <Skeleton className="h-6 w-32" />
      </CardHeader>
      <CardContent>
        <div className="space-y-2">
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-3/4" />
        </div>
      </CardContent>
    </Card>
  </div>
);


export function IpDetailsSheet({ ipAddress, open, onOpenChange }: IpDetailsSheetProps) {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<IpAddressSecurityScoringOutput | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open && ipAddress) {
      const fetchScore = async () => {
        setLoading(true);
        setError(null);
        setData(null);
        try {
          const result = await getIpSecurityScore({ ipAddress });
          setData(result);
        } catch (e) {
          setError("Failed to fetch security score. Please try again.");
          console.error(e);
        } finally {
          setLoading(false);
        }
      };
      fetchScore();
    }
  }, [open, ipAddress]);

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="sm:max-w-lg">
        <SheetHeader>
          <SheetTitle className="font-headline">IP Security Analysis</SheetTitle>
          <SheetDescription>
            AI-powered security score for{" "}
            <code className="relative rounded bg-muted px-[0.3rem] py-[0.2rem] font-mono text-sm font-semibold">
              {ipAddress}
            </code>
          </SheetDescription>
        </SheetHeader>
        <div className="py-6">
            {loading && <LoadingState />}
            {error && <p className="text-sm text-destructive">{error}</p>}
            {data && (
                <div className="space-y-4">
                    <Card>
                        <CardHeader>
                            <CardTitle className="text-base font-medium">Security Score</CardTitle>
                        </CardHeader>
                        <CardContent>
                            <Badge variant={data.securityScore === 'safe' ? 'default' : 'destructive'} className="text-lg">
                                {data.securityScore.charAt(0).toUpperCase() + data.securityScore.slice(1)}
                            </Badge>
                        </CardContent>
                    </Card>
                    <Card>
                        <CardHeader>
                            <CardTitle className="text-base font-medium">Analysis Details</CardTitle>
                        </CardHeader>
                        <CardContent>
                            <p className="text-sm text-muted-foreground">{data.analysisDetails}</p>
                        </CardContent>
                    </Card>
                </div>
            )}
        </div>
      </SheetContent>
    </Sheet>
  );
}
