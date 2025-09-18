
"use client";

import { useState, useEffect, useCallback } from "react";
import { Gauge, AlertTriangle, ShieldCheck, Wifi, WifiOff } from "lucide-react";

import type { Packet, Alert } from "@/lib/types";
import { generateMockPacket } from "@/lib/mock-data";
import { packetCaptureService, type NetworkInterface, type MonitoringOptions } from "@/lib/packet-capture-service";
import { useToast } from "@/hooks/use-toast";
import { StatsCard } from "@/components/dashboard/stats-card";
import { PacketTable } from "@/components/dashboard/packet-table";
import { AlertsCard } from "@/components/dashboard/alerts-card";
import { IpDetailsSheet } from "@/components/dashboard/ip-details-sheet";
import { NetworkControls } from "@/components/dashboard/network-controls";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

const MAX_PACKETS = 50;
const MAX_ALERTS = 10;

export function DashboardClient() {
  const { toast } = useToast();
  const [packets, setPackets] = useState<Packet[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [totalPackets, setTotalPackets] = useState(0);
  const [attacksDetected, setAttacksDetected] = useState(0);
  const [isPaused, setIsPaused] = useState(false);
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [whitelistedIps, setWhitelistedIps] = useState<string[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [networkInterfaces, setNetworkInterfaces] = useState<NetworkInterface[]>([]);
  const [selectedInterface, setSelectedInterface] = useState<string>("");
  const [useMockData, setUseMockData] = useState(false);

  useEffect(() => {
    const storedIps = localStorage.getItem("whitelistedIps");
    if (storedIps) {
      setWhitelistedIps(JSON.parse(storedIps));
    }
    
    // Initialize packet capture service
    initializePacketCapture();
  }, []);

  const initializePacketCapture = async () => {
    try {
      await packetCaptureService.connect();
      setIsConnected(true);
      
      // Set up packet listener
      packetCaptureService.onPacket(({ packet, alert }) => {
        if (isPaused) return;
        
        // Check if IP is whitelisted
        const isWhitelisted = whitelistedIps.includes(packet.sourceIp);
        if (isWhitelisted && packet.attackType) {
          packet.attackType = null; // Remove attack type for whitelisted IPs
        }
        
        setPackets((prev) => [packet, ...prev].slice(0, MAX_PACKETS));
        setTotalPackets((prev) => prev + 1);

        if (alert && !isWhitelisted) {
          setAlerts((prev) => [alert, ...prev].slice(0, MAX_ALERTS));
          setAttacksDetected((prev) => prev + 1);
          toast({
            variant: "destructive",
            title: "🚨 Attack Detected!",
            description: alert.message,
          });
        }
      });
      
      // Set up network interfaces listener
      packetCaptureService.onNetworkInterfaces((interfaces) => {
        setNetworkInterfaces(interfaces);
        if (interfaces.length > 0 && !selectedInterface) {
          setSelectedInterface(interfaces[0].name);
        }
      });
      
    } catch (error) {
      console.error('Failed to connect to packet monitor:', error);
      setIsConnected(false);
      setUseMockData(true);
      toast({
        title: "Real-time monitoring unavailable",
        description: "Using simulated data. Start the packet monitor server for real-time capture.",
        variant: "destructive",
      });
    }
  };

  // Fallback to mock data when real monitoring is not available
  useEffect(() => {
    if (!useMockData || isPaused || isConnected) return;

    const interval = setInterval(() => {
      const { packet, alert } = generateMockPacket(whitelistedIps);

      setPackets((prev) => [packet, ...prev].slice(0, MAX_PACKETS));
      setTotalPackets((prev) => prev + 1);

      if (alert) {
        setAlerts((prev) => [alert, ...prev].slice(0, MAX_ALERTS));
        setAttacksDetected((prev) => prev + 1);
        toast({
          variant: "destructive",
          title: "🚨 Attack Detected! (Simulated)",
          description: alert.message,
        });
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [isPaused, toast, whitelistedIps, useMockData, isConnected]);

  const toggleMonitoring = () => {
    if (isConnected) {
      try {
        if (isMonitoring) {
          packetCaptureService.stopMonitoring();
          setIsMonitoring(false);
          toast({
            title: "Monitoring stopped",
            description: "Real-time packet capture has been stopped.",
          });
        } else {
          const options: MonitoringOptions = {
            interface: selectedInterface || undefined,
          };
          packetCaptureService.startMonitoring(options);
          setIsMonitoring(true);
          toast({
            title: "Monitoring started",
            description: "Real-time packet capture is now active.",
          });
        }
      } catch (error) {
        console.error('Monitoring control error:', error);
        toast({
          title: "Error",
          description: "Failed to control monitoring state.",
          variant: "destructive",
        });
      }
    }
  };

  const handleIpSelect = useCallback((ip: string) => {
    setSelectedIp(ip);
  }, []);

  const handleInterfaceChange = (interfaceName: string) => {
    setSelectedInterface(interfaceName);
  };

  const handleMonitoringOptionsChange = (options: MonitoringOptions) => {
    if (isConnected && isMonitoring) {
      try {
        packetCaptureService.stopMonitoring();
        packetCaptureService.startMonitoring(options);
        toast({
          title: "Monitoring updated",
          description: "Applied new monitoring configuration.",
        });
      } catch (error) {
        console.error('Error updating monitoring options:', error);
        toast({
          title: "Error",
          description: "Failed to update monitoring configuration.",
          variant: "destructive",
        });
      }
    }
  };

  return (
    <>
      {/* Connection Status & Controls */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-4 rounded-lg border p-4">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            {isConnected ? (
              <Wifi className="h-5 w-5 text-green-600" />
            ) : (
              <WifiOff className="h-5 w-5 text-red-600" />
            )}
            <span className="font-medium">
              {isConnected ? "Real-time Monitoring" : "Simulated Data"}
            </span>
            <Badge variant={isConnected ? "default" : "secondary"}>
              {isConnected ? "Connected" : "Offline"}
            </Badge>
          </div>
          {useMockData && (
            <Badge variant="outline">Demo Mode</Badge>
          )}
        </div>
        
        <div className="flex items-center gap-2">
          {isConnected && (
            <>
              <Button
                onClick={toggleMonitoring}
                variant={isMonitoring ? "destructive" : "default"}
                size="sm"
              >
                {isMonitoring ? "Stop Monitoring" : "Start Monitoring"}
              </Button>
              <Button
                onClick={() => setIsPaused(!isPaused)}
                variant="outline"
                size="sm"
              >
                {isPaused ? "Resume" : "Pause"}
              </Button>
            </>
          )}
          {!isConnected && (
            <Button
              onClick={() => setIsPaused(!isPaused)}
              variant="outline"
              size="sm"
            >
              {isPaused ? "Resume Demo" : "Pause Demo"}
            </Button>
          )}
        </div>
      </div>

      {/* Network Configuration */}
      <div className="mb-6">
        <NetworkControls
          networkInterfaces={networkInterfaces}
          selectedInterface={selectedInterface}
          onInterfaceChange={handleInterfaceChange}
          onMonitoringOptionsChange={handleMonitoringOptionsChange}
          isConnected={isConnected}
          isMonitoring={isMonitoring}
        />
      </div>

      <div className="grid gap-4 md:grid-cols-2 md:gap-8 lg:grid-cols-3">
        <StatsCard
          title="Total Packets"
          value={totalPackets.toLocaleString()}
          icon={Gauge}
          description="Total packets processed since session start."
        />
        <StatsCard
          title="Attacks Detected"
          value={attacksDetected.toLocaleString()}
          icon={AlertTriangle}
          description="Potential threats identified in the network."
          variant="destructive"
        />
        <StatsCard
          title="Whitelisted IPs"
          value={whitelistedIps.length.toLocaleString()}
          icon={ShieldCheck}
          description="Trusted IP addresses, exempt from alerts."
          variant="default"
        />
      </div>
      <div className="grid gap-4 md:gap-8 lg:grid-cols-2 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <PacketTable
            packets={packets}
            onPauseToggle={() => setIsPaused(!isPaused)}
            isPaused={isPaused}
            onIpSelect={handleIpSelect}
          />
        </div>
        <div>
          <AlertsCard alerts={alerts} onIpSelect={handleIpSelect} />
        </div>
      </div>
      <IpDetailsSheet
        ipAddress={selectedIp}
        open={!!selectedIp}
        onOpenChange={(isOpen) => {
          if (!isOpen) {
            setSelectedIp(null);
          }
        }}
      />
    </>
  );
}
