
import { Pause, Play, Search } from "lucide-react";
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
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
}

export function PacketTable({
  packets,
  isPaused,
  onPauseToggle,
  onIpSelect,
}: PacketTableProps) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center">
        <div className="grid gap-2">
            <CardTitle>Network Monitor</CardTitle>
            <CardDescription>
            Live stream of network packets.
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
      <CardContent>
        <div className="max-h-[450px] overflow-auto rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Source IP</TableHead>
                <TableHead>Destination IP</TableHead>
                <TableHead>Protocol</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Time</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {packets.length > 0 ? (
                packets.map((packet) => (
                  <TableRow key={packet.id}>
                    <TableCell>
                      <Button variant="link" size="sm" className="p-0 h-auto" onClick={() => onIpSelect(packet.sourceIp)}>
                        {packet.sourceIp}
                        <Search className="ml-2 h-3 w-3" />
                      </Button>
                    </TableCell>
                    <TableCell>{packet.destinationIp}</TableCell>
                    <TableCell>{packet.protocol}</TableCell>
                    <TableCell>
                      {packet.attackType ? (
                        <Badge variant="destructive">{packet.attackType}</Badge>
                      ) : (
                        <Badge variant="secondary">Normal</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-right text-muted-foreground">
                      {formatDistanceToNow(new Date(packet.timestamp), {
                        addSuffix: true,
                      })}
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell
                    colSpan={5}
                    className="h-24 text-center"
                  >
                    Monitoring for network packets...
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>
      <CardFooter>
        <div className="text-xs text-muted-foreground">
            Showing <strong>1-{packets.length}</strong> of <strong>{packets.length}</strong> packets.
        </div>
      </CardFooter>
    </Card>
  );
}
