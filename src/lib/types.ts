export type AttackType = "DDoS" | "Port Scan" | "Malware" | "Brute Force" | "Internal Threat" | "Connection Flood" | "Unauthorized Access" | "Known Threat" | null;

export type Packet = {
  id: number;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  protocol: "TCP" | "UDP" | "ICMP";
  port: number;
  attackType: AttackType;
  size?: number;
  direction?: "incoming" | "outgoing" | "local" | "passing";
  // Detailed attack detection fields
  isDdosAttack?: boolean | number;
  isPortScan?: boolean | number;
  isBruteForce?: boolean | number;
  isMalware?: boolean | number;
  isConnectionFlood?: boolean | number;
  isUnauthorizedAccess?: boolean | number;
  isKnownThreat?: boolean | number;
  threatScore?: number;
  attackDetails?: string;
};

export type Alert = {
  id: number;
  timestamp: string;
  message: string;
  ip: string;
  type: AttackType;
};
