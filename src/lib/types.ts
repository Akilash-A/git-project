export type AttackType = "DDoS" | "Port Scan" | "Malware" | null;

export type Packet = {
  id: number;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  protocol: "TCP" | "UDP" | "ICMP";
  port: number;
  attackType: AttackType;
};

export type Alert = {
  id: number;
  timestamp: string;
  message: string;
  ip: string;
  type: AttackType;
};
