
"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { Gauge, AlertTriangle, ShieldCheck, Wifi, WifiOff } from "lucide-react";

import type { Packet, Alert } from "@/lib/types";
import { generateMockPacket } from "@/lib/mock-data";
import { packetCaptureService, type NetworkInterface, type MonitoringOptions } from "@/lib/packet-capture-service";
import { useToast } from "@/hooks/use-toast";
import { StatsCard } from "@/components/dashboard/stats-card";
import { PacketTable } from "@/components/dashboard/packet-table";
import { AlertsCard } from "@/components/dashboard/alerts-card";
import { IpDetailsSheet } from "@/components/dashboard/ip-details-sheet";
import { IpDangerScoreModal } from "@/components/dashboard/ip-danger-score-modal";
import { NetworkControls } from "@/components/dashboard/network-controls";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

const MAX_PACKETS = 50;
const MAX_ALERTS = 10;

// Unique ID generator for alerts
let alertIdCounter = 0;
const generateUniqueAlertId = () => {
  alertIdCounter += 1;
  return Date.now() * 1000 + alertIdCounter; // Ensures uniqueness even with rapid calls
};

export function DashboardClient() {
  const { toast } = useToast();
  
  // Initialize with empty arrays to avoid hydration mismatch
  const [packets, setPackets] = useState<Packet[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [totalPackets, setTotalPackets] = useState(0);
  const [attacksDetected, setAttacksDetected] = useState(0);
  const [isHydrated, setIsHydrated] = useState(false);
  
  const packetIdsRef = useRef(new Set<string | number>()); // Track packet IDs to prevent duplicates
  const [isPaused, setIsPaused] = useState(false);
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [dangerScoreIp, setDangerScoreIp] = useState<string | null>(null);
  const [whitelistedIps, setWhitelistedIps] = useState<string[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [isMonitoring, setIsMonitoring] = useState(() => {
    // Initialize from localStorage to persist monitoring state across navigation
    if (typeof window !== 'undefined') {
      return localStorage.getItem('netguardian-monitoring') === 'true';
    }
    return false;
  });
  const [networkInterfaces, setNetworkInterfaces] = useState<NetworkInterface[]>([]);
  const [selectedInterface, setSelectedInterface] = useState<string>("");
  const [useMockData, setUseMockData] = useState(false);
  
  // Use useRef to track isPaused and isMonitoring state for the packet listener closure
  const isPausedRef = useRef(isPaused);
  const isMonitoringRef = useRef(isMonitoring);
  
  useEffect(() => {
    isPausedRef.current = isPaused;
  }, [isPaused]);

  useEffect(() => {
    isMonitoringRef.current = isMonitoring;
  }, [isMonitoring]);

  useEffect(() => {
    const storedIps = localStorage.getItem("whitelistedIps");
    if (storedIps) {
      setWhitelistedIps(JSON.parse(storedIps));
    }
    
    // Load persisted data after hydration
    const loadPersistedData = () => {
      try {
        const storedPackets = localStorage.getItem('netguardian-packets');
        const storedAlerts = localStorage.getItem('netguardian-alerts');
        const storedTotalPackets = localStorage.getItem('netguardian-total-packets');
        const storedAttacksDetected = localStorage.getItem('netguardian-attacks-detected');
        
        if (storedPackets) {
          const parsedPackets = JSON.parse(storedPackets);
          setPackets(parsedPackets);
          // Restore packet ID tracking
          packetIdsRef.current = new Set(parsedPackets.map((p: Packet) => p.id));
        }
        
        if (storedAlerts) {
          setAlerts(JSON.parse(storedAlerts));
        }
        
        if (storedTotalPackets) {
          setTotalPackets(parseInt(storedTotalPackets));
        }
        
        if (storedAttacksDetected) {
          setAttacksDetected(parseInt(storedAttacksDetected));
        }
        
        setIsHydrated(true);
      } catch (error) {
        console.error('Failed to load persisted data:', error);
        setIsHydrated(true);
      }
    };
    
    loadPersistedData();
    
    // Initialize packet capture service
    initializePacketCapture();
  }, []);

  // Persist packets data to localStorage (debounced to avoid excessive writes)
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const timeoutId = setTimeout(() => {
        localStorage.setItem('netguardian-packets', JSON.stringify(packets));
      }, 500); // Debounce by 500ms
      
      return () => clearTimeout(timeoutId);
    }
  }, [packets]);

  // Persist alerts data to localStorage (debounced)
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const timeoutId = setTimeout(() => {
        localStorage.setItem('netguardian-alerts', JSON.stringify(alerts));
      }, 500);
      
      return () => clearTimeout(timeoutId);
    }
  }, [alerts]);

  // Persist counters to localStorage
  useEffect(() => {
    if (typeof window !== 'undefined') {
      localStorage.setItem('netguardian-total-packets', totalPackets.toString());
    }
  }, [totalPackets]);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      localStorage.setItem('netguardian-attacks-detected', attacksDetected.toString());
    }
  }, [attacksDetected]);

  // Restore monitoring state after connection is established
  useEffect(() => {
    if (isConnected && isMonitoring) {
      // Restore monitoring if it was previously active
      try {
        const options: MonitoringOptions = {
          interface: selectedInterface || undefined,
        };
        packetCaptureService.startMonitoring(options);
        toast({
          title: "Monitoring restored",
          description: "Real-time packet monitoring has been automatically restored.",
        });
      } catch (error) {
        console.error('Failed to restore monitoring state:', error);
        // Reset state if restoration fails
        setIsMonitoring(false);
        localStorage.setItem('netguardian-monitoring', 'false');
        toast({
          title: "Monitoring restoration failed",
          description: "Unable to restore previous monitoring state.",
          variant: "destructive",
        });
      }
    }
  }, [isConnected, selectedInterface, toast]);

  const initializePacketCapture = async () => {
    try {
      await packetCaptureService.connect();
      setIsConnected(true);
      setUseMockData(false); // Ensure mock data is disabled when real connection is established
      
      // Set up packet listener
      packetCaptureService.onPacket(({ packet, alert }) => {
        // Use ref to get current paused and monitoring state instead of stale closure values
        if (isPausedRef.current || !isMonitoringRef.current) return;
        
        // Check if IP is whitelisted
        const isWhitelisted = whitelistedIps.includes(packet.sourceIp);
        if (isWhitelisted && packet.attackType) {
          packet.attackType = null; // Remove attack type for whitelisted IPs
        }
        
        // Add packet with deduplication check
        setPackets((prev) => {
          // Check if packet already exists by ID
          if (packetIdsRef.current.has(packet.id)) {
            return prev; // Skip duplicate
          }
          
          // Add new packet ID to tracking set
          packetIdsRef.current.add(packet.id);
          
          const newPackets = [packet, ...prev].slice(0, MAX_PACKETS);
          
          // Clean up tracking set - remove IDs that are no longer in the displayed packets
          const currentIds = new Set(newPackets.map(p => p.id));
          packetIdsRef.current = currentIds;
          
          return newPackets;
        });
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
      
      // Set up critical attack alerts
      packetCaptureService.onCriticalAttack((criticalAlert) => {
        // Only process critical alerts if monitoring is active and not paused
        if (isPausedRef.current || !isMonitoringRef.current) return;
        
        setAlerts((prev) => [{
          id: generateUniqueAlertId(),
          timestamp: criticalAlert.timestamp,
          message: criticalAlert.message,
          ip: criticalAlert.sourceIp,
          type: criticalAlert.attackType
        }, ...prev].slice(0, MAX_ALERTS));
        
        setAttacksDetected((prev) => prev + 1);
        
        // Show urgent toast for critical attacks
        toast({
          variant: "destructive",
          title: "🚨 CRITICAL ATTACK DETECTED!",
          description: `${criticalAlert.attackType} targeting YOUR IP from ${criticalAlert.sourceIp}`,
          duration: 10000, // Show longer for critical alerts
        });
        
        // Play alert sound (if available)
        if (typeof Audio !== 'undefined') {
          try {
            const audio = new Audio('data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmEcBzVdmcPy2YU2Bhdr0O3XiTIGHm/E7+OVFVX'); 
            audio.play();
          } catch (e) {
            console.log('Audio notification not available');
          }
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
    // Only use mock data if explicitly enabled AND not connected AND not paused AND monitoring is active
    if (!useMockData || isPaused || isConnected || !isMonitoring) return;

    const interval = setInterval(() => {
      const { packet, alert } = generateMockPacket(whitelistedIps);

      // Add packet with deduplication check
      setPackets((prev) => {
        // Check if packet already exists by ID
        if (packetIdsRef.current.has(packet.id)) {
          return prev; // Skip duplicate
        }
        
        // Add new packet ID to tracking set
        packetIdsRef.current.add(packet.id);
        
        const newPackets = [packet, ...prev].slice(0, MAX_PACKETS);
        
        // Clean up tracking set - remove IDs that are no longer in the displayed packets
        const currentIds = new Set(newPackets.map(p => p.id));
        packetIdsRef.current = currentIds;
        
        return newPackets;
      });
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
  }, [isPaused, toast, whitelistedIps, useMockData, isConnected, isMonitoring]);

  // Cleanup effect to handle component unmount and page refresh
  useEffect(() => {
    const handleBeforeUnload = () => {
      // Save current monitoring state before page closes
      if (isMonitoring) {
        localStorage.setItem('netguardian-monitoring', 'true');
      } else {
        localStorage.setItem('netguardian-monitoring', 'false');
      }
    };

    window.addEventListener('beforeunload', handleBeforeUnload);
    
    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, [isMonitoring]);

  const toggleMonitoring = () => {
    if (isConnected) {
      try {
        if (isMonitoring) {
          packetCaptureService.stopMonitoring();
          setIsMonitoring(false);
          localStorage.setItem('netguardian-monitoring', 'false');
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
          localStorage.setItem('netguardian-monitoring', 'true');
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
    } else if (useMockData) {
      // Handle mock data monitoring toggle
      if (isMonitoring) {
        setIsMonitoring(false);
        localStorage.setItem('netguardian-monitoring', 'false');
        toast({
          title: "Monitoring stopped",
          description: "Simulated packet capture has been stopped.",
        });
      } else {
        setIsMonitoring(true);
        localStorage.setItem('netguardian-monitoring', 'true');
        toast({
          title: "Monitoring started (Simulated)",
          description: "Using simulated data for demonstration.",
        });
      }
    } else {
      toast({
        title: "Connection required",
        description: "Please connect to the packet monitor server to start monitoring.",
        variant: "destructive",
      });
    }
  };

  const handleIpSelect = useCallback((ip: string) => {
    setSelectedIp(ip);
  }, []);

  const handleIpDangerScore = useCallback((ip: string) => {
    setDangerScoreIp(ip);
  }, []);

  const clearStoredData = () => {
    setPackets([]);
    setAlerts([]);
    setTotalPackets(0);
    setAttacksDetected(0);
    packetIdsRef.current.clear();
    
    // Clear from localStorage
    if (typeof window !== 'undefined') {
      localStorage.removeItem('netguardian-packets');
      localStorage.removeItem('netguardian-alerts');
      localStorage.removeItem('netguardian-total-packets');
      localStorage.removeItem('netguardian-attacks-detected');
    }
    
    toast({
      title: "Data cleared",
      description: "All packet and alert data has been cleared.",
    });
  };

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
                className="border-2 border-border/50 hover:border-primary transition-colors"
              >
                {isMonitoring ? "Stop Monitoring" : "Start Monitoring"}
              </Button>
              <Button
                onClick={() => setIsPaused(!isPaused)}
                variant="outline"
                size="sm"
                className="border-2 border-border/50 hover:border-primary transition-colors"
              >
                {isPaused ? "Resume" : "Pause"}
              </Button>
            </>
          )}
          {!isConnected && (
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
                {isPaused ? "Resume Demo" : "Pause Demo"}
              </Button>
            </>
          )}
        </div>
      </div>

      {/* Network Configuration */}
      <div className="mb-6 space-y-4">
        <NetworkControls
          networkInterfaces={networkInterfaces}
          selectedInterface={selectedInterface}
          onInterfaceChange={handleInterfaceChange}
          onMonitoringOptionsChange={handleMonitoringOptionsChange}
          onToggleMonitoring={toggleMonitoring}
          isConnected={isConnected}
          isMonitoring={isMonitoring}
        />
        
        {/* Data Management Controls */}
        {isHydrated && (packets.length > 0 || alerts.length > 0) && (
          <div className="flex gap-2 justify-end">
            <Button 
              variant="outline" 
              size="sm" 
              onClick={clearStoredData}
              className="text-orange-600 border-orange-200 hover:bg-orange-50"
            >
              Clear Data ({packets.length + alerts.length} items)
            </Button>
          </div>
        )}
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
            onIpDangerScore={handleIpDangerScore}
          />
        </div>
        <div>
          <AlertsCard alerts={alerts} onIpSelect={handleIpSelect} onIpDangerScore={handleIpDangerScore} />
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
      <IpDangerScoreModal
        ipAddress={dangerScoreIp}
        open={!!dangerScoreIp}
        onOpenChange={(isOpen) => {
          if (!isOpen) {
            setDangerScoreIp(null);
          }
        }}
      />
    </>
  );
}
