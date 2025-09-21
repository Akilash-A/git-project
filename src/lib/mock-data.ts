import type { Packet, Alert, AttackType } from "./types";

let packetIdCounter = 0;
let alertIdCounter = 0;

const generateUniqueAlertId = () => {
  alertIdCounter += 1;
  return Date.now() * 1000 + alertIdCounter;
};

const randomIp = () =>
  `${Math.floor(Math.random() * 255) + 1}.${Math.floor(
    Math.random() * 255
  )}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;

const protocols: Array<"TCP" | "UDP" | "ICMP"> = ["TCP", "UDP", "ICMP"];
const attackTypes: Array<AttackType> = ["DDoS", "Port Scan", "Malware"];

export const generateMockPacket = (whitelistedIps: string[]): { packet: Packet; alert: Alert | null } => {
  const sourceIp = randomIp();
  const isAttack = Math.random() < 0.05; // 5% chance of being an attack
  const isWhitelisted = whitelistedIps.includes(sourceIp);

  const attackType =
    isAttack && !isWhitelisted
      ? attackTypes[Math.floor(Math.random() * attackTypes.length)]
      : null;

  const packet: Packet = {
    id: packetIdCounter++,
    timestamp: new Date().toISOString(),
    sourceIp,
    destinationIp: randomIp(),
    protocol: protocols[Math.floor(Math.random() * protocols.length)],
    port: Math.floor(Math.random() * 65535),
    attackType,
  };

  let alert: Alert | null = null;
  if (attackType) {
    alert = {
      id: generateUniqueAlertId(),
      timestamp: packet.timestamp,
      message: `${attackType} detected from ${sourceIp}`,
      ip: sourceIp,
      type: attackType
    };
  }

  return { packet, alert };
};
