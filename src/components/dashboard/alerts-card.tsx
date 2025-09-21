
import { AlertTriangle, Search, Shield } from "lucide-react";
import { formatDistanceToNow } from "date-fns";

import type { Alert } from "@/lib/types";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

interface AlertsCardProps {
  alerts: Alert[];
  onIpSelect: (ip: string) => void;
  onIpDangerScore?: (ip: string) => void;
}

export function AlertsCard({ alerts, onIpSelect, onIpDangerScore }: AlertsCardProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Alerts</CardTitle>
        <CardDescription>
          Critical security events detected on your network.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        {alerts.length > 0 ? (
          alerts.map((alert, index) => (
            <div key={`${alert.id}-${index}`} className="flex items-start gap-4">
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-destructive/10">
                <AlertTriangle className="h-4 w-4 text-destructive" />
              </div>
              <div className="grid gap-1">
                <div className="flex items-center gap-2">
                    <p className="text-sm font-medium leading-none">
                        {alert.type} Detected
                    </p>
                    <Badge variant="destructive">{alert.type}</Badge>
                </div>
                <p className="text-sm text-muted-foreground">
                  From IP:{" "}
                  <Button variant="link" size="sm" className="p-0 h-auto" onClick={() => onIpSelect(alert.ip)}>
                    {alert.ip} <Search className="ml-2 h-3 w-3" />
                  </Button>
                  {onIpDangerScore && (
                    <>
                      {" • "}
                      <Button 
                        variant="link" 
                        size="sm" 
                        className="p-0 h-auto text-orange-600 hover:text-orange-800" 
                        onClick={() => onIpDangerScore(alert.ip)}
                      >
                        Danger Score <Shield className="ml-1 h-3 w-3" />
                      </Button>
                    </>
                  )}
                </p>
                <p className="text-xs text-muted-foreground">
                  {formatDistanceToNow(new Date(alert.timestamp), {
                    addSuffix: true,
                  })}
                </p>
              </div>
            </div>
          ))
        ) : (
          <div className="flex h-24 flex-col items-center justify-center gap-2 text-center">
            <AlertTriangle className="h-8 w-8 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">No alerts to show.</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
