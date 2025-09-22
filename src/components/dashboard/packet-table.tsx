
import { Pause, Play, Search, Activity } from "lucide-react";
import { formatDistanceToNow } from "date-fns";

import type { Packet } from "@/lib/types";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  CardFooter,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";


interface PacketTableProps {
  packets: Packet[];
  isPaused: boolean;
  onPauseToggle: () => void;
  onIpSelect: (ip: string) => void;
  onIpDangerScore?: (ip: string) => void;
}

export function PacketTable({
  packets,
  isPaused,
  onPauseToggle,
  onIpSelect,
  onIpDangerScore,
}: PacketTableProps) {
  return (
    <Card className="w-full max-w-full max-h-[530px] flex flex-col">
      <CardHeader className="flex flex-row items-center px-6 flex-shrink-0">
        <div className="grid gap-2">
            <CardTitle>Network Monitor</CardTitle>
            <CardDescription>
            {isPaused ? "Live stream paused" : "Live stream of network packets."}
            </CardDescription>
        </div>
        <div className="ml-auto flex items-center gap-2">
            <TooltipProvider>
                <Tooltip>
                    <TooltipTrigger asChild>
                    <Button
                        variant="outline"
                        size="sm"
                        className="h-8 gap-1"
                        onClick={onPauseToggle}
                    >
                        {isPaused ? (
                        <>
                            <Play className="h-3.5 w-3.5" />
                            <span className="sr-only sm:not-sr-only sm:whitespace-nowrap">
                            Resume
                            </span>
                        </>
                        ) : (
                        <>
                            <Pause className="h-3.5 w-3.5" />
                            <span className="sr-only sm:not-sr-only sm:whitespace-nowrap">
                            Pause
                            </span>
                        </>
                        )}
                    </Button>
                    </TooltipTrigger>
                    <TooltipContent>
                    {isPaused ? "Resume live feed" : "Pause live feed"}
                    </TooltipContent>
                </Tooltip>
            </TooltipProvider>
        </div>
      </CardHeader>
      <CardContent className="px-6 pb-6">
        <div className="border rounded-md overflow-hidden">
          <div className="max-h-[400px] overflow-auto">
            <table className="w-full caption-bottom text-sm">
              <thead className="sticky top-0 z-10 bg-background">
                <tr className="border-b transition-colors hover:bg-muted/50">
                  <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground sticky top-0 bg-background first:rounded-tl-md">Source IP</th>
                  <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground sticky top-0 bg-background">Destination IP</th>
                  <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground sticky top-0 bg-background">Protocol</th>
                  <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground sticky top-0 bg-background">Port</th>
                  <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground sticky top-0 bg-background">Size</th>
                  <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground sticky top-0 bg-background">Direction</th>
                  <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground sticky top-0 bg-background">Status</th>
                  <th className="h-12 px-4 text-right align-middle font-medium text-muted-foreground sticky top-0 bg-background last:rounded-tr-md">Time</th>
                </tr>
              </thead>
              <tbody className="[&_tr:last-child]:border-0">
                {packets.length > 0 ? (
                  packets.map((packet) => (
                    <tr key={packet.id} className="border-b transition-colors hover:bg-muted/50 last:border-0">
                      <td className="p-4 align-middle">
                        <div className="flex items-center gap-1">
                          <Button variant="link" size="sm" className="p-0 h-auto" onClick={() => onIpSelect(packet.sourceIp)}>
                            {packet.sourceIp}
                            <Search className="ml-1 h-3 w-3" />
                          </Button>
                          {onIpDangerScore && (
                            <TooltipProvider>
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <Button 
                                    variant="ghost" 
                                    size="sm" 
                                    className="p-1 h-auto w-auto"
                                    onClick={() => onIpDangerScore(packet.sourceIp)}
                                  >
                                    <Activity className="h-3 w-3 text-orange-500" />
                                  </Button>
                                </TooltipTrigger>
                                <TooltipContent>
                                  <p>Check danger score</p>
                                </TooltipContent>
                              </Tooltip>
                            </TooltipProvider>
                          )}
                        </div>
                      </td>
                      <td className="p-4 align-middle">
                        <div className="flex items-center gap-1">
                          <span className="font-mono text-sm">{packet.destinationIp}</span>
                          {onIpDangerScore && (
                            <TooltipProvider>
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <Button 
                                    variant="ghost" 
                                    size="sm" 
                                    className="p-1 h-auto w-auto"
                                    onClick={() => onIpDangerScore(packet.destinationIp)}
                                  >
                                    <Activity className="h-3 w-3 text-orange-500" />
                                  </Button>
                                </TooltipTrigger>
                                <TooltipContent>
                                  <p>Check danger score</p>
                                </TooltipContent>
                              </Tooltip>
                            </TooltipProvider>
                          )}
                        </div>
                      </td>
                      <td className="p-4 align-middle">
                        <Badge variant="outline">{packet.protocol}</Badge>
                      </td>
                      <td className="p-4 align-middle text-muted-foreground">{packet.port}</td>
                      <td className="p-4 align-middle text-muted-foreground">
                        {packet.size ? `${packet.size} bytes` : 'N/A'}
                      </td>
                      <td className="p-4 align-middle">
                        {packet.direction && (
                          <Badge variant={
                            packet.direction === 'incoming' ? 'destructive' : 
                            packet.direction === 'outgoing' ? 'default' : 
                            packet.direction === 'local' ? 'secondary' : 'outline'
                          }>
                            {packet.direction === 'incoming' ? 'Incoming' : 
                             packet.direction === 'outgoing' ? 'Outgoing' : 
                             packet.direction === 'local' ? 'Local' : 'Passing'}
                          </Badge>
                        )}
                      </td>
                      <td className="p-4 align-middle">
                        {packet.attackType ? (
                          <Badge variant="destructive">{packet.attackType}</Badge>
                        ) : (
                          <Badge variant="secondary">Normal</Badge>
                        )}
                      </td>
                      <td className="p-4 align-middle text-right text-muted-foreground">
                        {formatDistanceToNow(new Date(packet.timestamp), {
                          addSuffix: true,
                        })}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td
                      colSpan={8}
                      className="h-24 text-center p-4 align-middle"
                    >
                      Monitoring for network packets...
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <div className="px-4 py-2 border-t bg-muted/20">
            <div className="text-xs text-muted-foreground">
              Showing <strong>1-{packets.length}</strong> of <strong>{packets.length}</strong> packets.
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
