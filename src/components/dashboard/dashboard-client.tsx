
"use client";

import { useState, useEffect, useCallback } from "react";
import { Gauge, AlertTriangle, ShieldCheck } from "lucide-react";

import type { Packet, Alert } from "@/lib/types";
import { generateMockPacket } from "@/lib/mock-data";
import { useToast } from "@/hooks/use-toast";
import { StatsCard } from "@/components/dashboard/stats-card";
import { PacketTable } from "@/components/dashboard/packet-table";
import { AlertsCard } from "@/components/dashboard/alerts-card";
import { IpDetailsSheet } from "@/components/dashboard/ip-details-sheet";

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

  useEffect(() => {
    const storedIps = localStorage.getItem("whitelistedIps");
    if (storedIps) {
      setWhitelistedIps(JSON.parse(storedIps));
    }
  }, []);

  useEffect(() => {
    if (isPaused) return;

    const interval = setInterval(() => {
      const { packet, alert } = generateMockPacket(whitelistedIps);

      setPackets((prev) => [packet, ...prev].slice(0, MAX_PACKETS));
      setTotalPackets((prev) => prev + 1);

      if (alert) {
        setAlerts((prev) => [alert, ...prev].slice(0, MAX_ALERTS));
        setAttacksDetected((prev) => prev + 1);
        toast({
          variant: "destructive",
          title: "🚨 Attack Detected!",
          description: alert.message,
        });
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [isPaused, toast, whitelistedIps]);

  const handleIpSelect = useCallback((ip: string) => {
    setSelectedIp(ip);
  }, []);

  return (
    <>
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
