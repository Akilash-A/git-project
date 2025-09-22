import { useState } from "react";
import { Wifi, Network, Settings } from "lucide-react";
import type { NetworkInterface, MonitoringOptions } from "@/lib/packet-capture-service";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";

interface NetworkControlsProps {
  networkInterfaces: NetworkInterface[];
  selectedInterface: string;
  onInterfaceChange: (interfaceName: string) => void;
  onMonitoringOptionsChange: (options: MonitoringOptions) => void;
  onToggleMonitoring?: () => void;
  isConnected: boolean;
  isMonitoring: boolean;
}

export function NetworkControls({
  networkInterfaces,
  selectedInterface,
  onInterfaceChange,
  onMonitoringOptionsChange,
  onToggleMonitoring,
  isConnected,
  isMonitoring,
}: NetworkControlsProps) {
  const [isConfigOpen, setIsConfigOpen] = useState(false);
  const [filterIp, setFilterIp] = useState("");
  const [filterPort, setFilterPort] = useState("");
  const [protocol, setProtocol] = useState<"TCP" | "UDP" | "ICMP" | undefined>();

  const selectedInterfaceData = networkInterfaces.find(
    (iface) => iface.name === selectedInterface
  );

  const handleApplyFilters = () => {
    const options: MonitoringOptions = {
      interface: selectedInterface || undefined,
      protocol,
      filterIp: filterIp || undefined,
      filterPort: filterPort ? parseInt(filterPort) : undefined,
    };
    onMonitoringOptionsChange(options);
    setIsConfigOpen(false);
  };

  const clearFilters = () => {
    setFilterIp("");
    setFilterPort("");
    setProtocol(undefined);
    onMonitoringOptionsChange({ interface: selectedInterface || undefined });
  };

  if (!isConnected) {
    return (
      <Card className="w-full">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Network className="h-5 w-5" />
            Network Configuration
          </CardTitle>
          <CardDescription>
            Connect to packet monitor server to configure network interfaces
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="text-center text-muted-foreground">
            <Wifi className="h-8 w-8 mx-auto mb-2 opacity-50" />
            <p>Server offline - using simulated data</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Network className="h-5 w-5" />
          Network Configuration
        </CardTitle>
        <CardDescription>
          Select network interface and configure monitoring options
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Interface Selection */}
        <div className="space-y-2">
          <Label htmlFor="interface-select">Network Interface</Label>
          <Select
            value={selectedInterface}
            onValueChange={onInterfaceChange}
          >
            <SelectTrigger id="interface-select">
              <SelectValue placeholder="Select network interface" />
            </SelectTrigger>
            <SelectContent>
              {networkInterfaces.map((iface) => (
                <SelectItem key={iface.name} value={iface.name}>
                  <div className="flex items-center gap-2">
                    <Wifi className="h-4 w-4" />
                    <span>{iface.name}</span>
                    <Badge variant="outline" className="text-xs">
                      {iface.address}
                    </Badge>
                  </div>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* Selected Interface Info */}
        {selectedInterfaceData && (
          <div className="rounded-lg border p-3 space-y-2">
            <div className="flex items-center gap-2">
              <Wifi className="h-4 w-4" />
              <span className="font-medium">{selectedInterfaceData.name}</span>
            </div>
            <div className="grid grid-cols-2 gap-2 text-sm text-muted-foreground">
              <div>
                <span className="font-medium">IP:</span> {selectedInterfaceData.address}
              </div>
              <div>
                <span className="font-medium">Netmask:</span> {selectedInterfaceData.netmask}
              </div>
              <div className="col-span-2">
                <span className="font-medium">MAC:</span> {selectedInterfaceData.mac}
              </div>
            </div>
          </div>
        )}

        {/* Monitoring Configuration */}
        <div className="flex items-center justify-between">
          <div>
            <h4 className="text-sm font-medium">Monitoring Options</h4>
            <p className="text-xs text-muted-foreground">
              Configure filters and protocols
            </p>
          </div>
          <Dialog open={isConfigOpen} onOpenChange={setIsConfigOpen}>
            <DialogTrigger asChild>
              <Button variant="outline" size="sm">
                <Settings className="h-4 w-4 mr-2" />
                Configure
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Monitoring Configuration</DialogTitle>
                <DialogDescription>
                  Set up filters and options for packet monitoring
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="protocol-select">Protocol Filter</Label>
                  <Select
                    value={protocol || ""}
                    onValueChange={(value) => 
                      setProtocol(value === "" ? undefined : value as "TCP" | "UDP" | "ICMP")
                    }
                  >
                    <SelectTrigger id="protocol-select">
                      <SelectValue placeholder="All protocols" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="">All protocols</SelectItem>
                      <SelectItem value="TCP">TCP</SelectItem>
                      <SelectItem value="UDP">UDP</SelectItem>
                      <SelectItem value="ICMP">ICMP</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="ip-filter">IP Address Filter</Label>
                  <Input
                    id="ip-filter"
                    placeholder="e.g., 192.168.1.100"
                    value={filterIp}
                    onChange={(e) => setFilterIp(e.target.value)}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="port-filter">Port Filter</Label>
                  <Input
                    id="port-filter"
                    type="number"
                    placeholder="e.g., 80, 443"
                    value={filterPort}
                    onChange={(e) => setFilterPort(e.target.value)}
                  />
                </div>

                <div className="flex gap-2">
                  <Button onClick={handleApplyFilters} className="flex-1">
                    Apply Filters
                  </Button>
                  <Button onClick={clearFilters} variant="outline">
                    Clear
                  </Button>
                </div>
              </div>
            </DialogContent>
          </Dialog>
        </div>

        {/* Active Filters Display */}
        {(protocol || filterIp || filterPort) && (
          <div className="space-y-2">
            <h5 className="text-sm font-medium">Active Filters:</h5>
            <div className="flex flex-wrap gap-2">
              {protocol && (
                <Badge variant="secondary">Protocol: {protocol}</Badge>
              )}
              {filterIp && (
                <Badge variant="secondary">IP: {filterIp}</Badge>
              )}
              {filterPort && (
                <Badge variant="secondary">Port: {filterPort}</Badge>
              )}
            </div>
          </div>
        )}

        {/* Status */}
        <div className="flex items-center gap-2 text-sm">
          <div className={`w-2 h-2 rounded-full ${isMonitoring ? 'bg-green-500' : 'bg-gray-400'}`} />
          <span className="text-muted-foreground">
            {isMonitoring ? 'Monitoring active' : 'Monitoring stopped'}
          </span>
        </div>
      </CardContent>
    </Card>
  );
}