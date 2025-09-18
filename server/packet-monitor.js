const { Server } = require('socket.io');
const { createServer } = require('http');
const netstat = require('node-netstat');
const { exec } = require('child_process');
const os = require('os');

class PacketMonitor {
  constructor(port = 3001) {
    this.port = port;
    this.server = createServer();
    this.io = new Server(this.server, {
      cors: {
        origin: "*",
        methods: ["GET", "POST"]
      }
    });
    
    this.packetIdCounter = 0;
    this.isMonitoring = false;
    this.monitoringInterval = null;
    this.connectedClients = new Set();
    
    this.setupSocketHandlers();
    this.getNetworkInterfaces();
  }

  setupSocketHandlers() {
    this.io.on('connection', (socket) => {
      console.log('Client connected:', socket.id);
      this.connectedClients.add(socket);
      
      // Send initial network interfaces
      socket.emit('network-interfaces', this.networkInterfaces);
      
      socket.on('start-monitoring', (options = {}) => {
        console.log('Starting packet monitoring with options:', options);
        this.startMonitoring(options);
      });
      
      socket.on('stop-monitoring', () => {
        console.log('Stopping packet monitoring');
        this.stopMonitoring();
      });
      
      socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
        this.connectedClients.delete(socket);
        
        // Stop monitoring if no clients connected
        if (this.connectedClients.size === 0) {
          this.stopMonitoring();
        }
      });
    });
  }

  getNetworkInterfaces() {
    this.networkInterfaces = [];
    const interfaces = os.networkInterfaces();
    
    for (const [name, addresses] of Object.entries(interfaces)) {
      const ipv4 = addresses.find(addr => addr.family === 'IPv4' && !addr.internal);
      if (ipv4) {
        this.networkInterfaces.push({
          name,
          address: ipv4.address,
          netmask: ipv4.netmask,
          mac: ipv4.mac
        });
      }
    }
    
    console.log('Available network interfaces:', this.networkInterfaces);
  }

  startMonitoring(options = {}) {
    if (this.isMonitoring) {
      this.stopMonitoring();
    }
    
    this.isMonitoring = true;
    
    // Monitor network connections using netstat
    this.monitoringInterval = setInterval(() => {
      this.captureNetworkConnections(options);
    }, 1000); // Capture every second
    
    // Also monitor using ss command for more detailed info
    this.monitorWithSS(options);
  }

  stopMonitoring() {
    this.isMonitoring = false;
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = null;
    }
  }

  captureNetworkConnections(options) {
    netstat({
      filter: {
        pid: 0,
        protocol: options.protocol || undefined
      },
      limit: 50
    }, (data) => {
      if (data && data.local && data.foreign) {
        const packet = this.parseNetstatData(data);
        if (packet) {
          this.emitPacket(packet);
        }
      }
    });
  }

  monitorWithSS(options) {
    if (!this.isMonitoring) return;
    
    // Use ss command to get real-time socket information
    const cmd = 'ss -tuln4';
    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        console.error('SS command error:', error);
        return;
      }
      
      if (stdout) {
        this.parseSSOutput(stdout, options);
      }
      
      // Schedule next capture
      setTimeout(() => {
        if (this.isMonitoring) {
          this.monitorWithSS(options);
        }
      }, 2000);
    });
  }

  parseSSOutput(output, options) {
    const lines = output.split('\n').slice(1); // Skip header
    
    lines.forEach(line => {
      if (line.trim()) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 4) {
          const [proto, recvQ, sendQ, localAddr, foreignAddr] = parts;
          
          if (localAddr && localAddr.includes(':')) {
            const packet = this.createPacketFromSS(proto, localAddr, foreignAddr);
            if (packet) {
              this.emitPacket(packet);
            }
          }
        }
      }
    });
  }

  createPacketFromSS(protocol, localAddr, foreignAddr) {
    try {
      const [localIp, localPort] = localAddr.split(':');
      const [foreignIp, foreignPort] = foreignAddr ? foreignAddr.split(':') : ['0.0.0.0', '0'];
      
      // Skip localhost and internal addresses for demo
      if (localIp === '127.0.0.1' || localIp.startsWith('127.')) {
        return null;
      }
      
      const packet = {
        id: this.packetIdCounter++,
        timestamp: new Date().toISOString(),
        sourceIp: localIp,
        destinationIp: foreignIp || 'N/A',
        protocol: protocol.toUpperCase(),
        port: parseInt(localPort) || 0,
        attackType: this.detectAttack(localIp, foreignIp, parseInt(localPort)),
        size: Math.floor(Math.random() * 1500) + 64, // Simulated packet size
        direction: 'incoming'
      };
      
      return packet;
    } catch (error) {
      console.error('Error parsing SS data:', error);
      return null;
    }
  }

  parseNetstatData(data) {
    try {
      const localParts = data.local.address.split(':');
      const foreignParts = data.foreign ? data.foreign.address.split(':') : ['0.0.0.0', '0'];
      
      const sourceIp = localParts[0];
      const destinationIp = foreignParts[0];
      const port = parseInt(localParts[1]) || 0;
      
      // Skip localhost connections
      if (sourceIp === '127.0.0.1' || destinationIp === '127.0.0.1') {
        return null;
      }
      
      const packet = {
        id: this.packetIdCounter++,
        timestamp: new Date().toISOString(),
        sourceIp: sourceIp,
        destinationIp: destinationIp,
        protocol: data.protocol.toUpperCase(),
        port: port,
        attackType: this.detectAttack(sourceIp, destinationIp, port),
        size: Math.floor(Math.random() * 1500) + 64, // Simulated packet size
        direction: data.state === 'LISTEN' ? 'incoming' : 'outgoing'
      };
      
      return packet;
    } catch (error) {
      console.error('Error parsing netstat data:', error);
      return null;
    }
  }

  detectAttack(sourceIp, destinationIp, port) {
    // Simple attack detection logic
    const suspiciousPorts = [23, 135, 139, 445, 1433, 3389]; // Telnet, RPC, NetBIOS, SMB, SQL, RDP
    const commonAttackPorts = [21, 22, 80, 443, 993, 995];
    
    // Check for suspicious ports
    if (suspiciousPorts.includes(port)) {
      return Math.random() < 0.3 ? 'Port Scan' : null;
    }
    
    // Check for private IP ranges (potential internal attacks)
    if (this.isPrivateIP(sourceIp) && this.isPrivateIP(destinationIp)) {
      return Math.random() < 0.05 ? 'Internal Threat' : null;
    }
    
    // Random attack detection for demo purposes
    if (Math.random() < 0.02) { // 2% chance
      const attacks = ['DDoS', 'Port Scan', 'Malware', 'Brute Force'];
      return attacks[Math.floor(Math.random() * attacks.length)];
    }
    
    return null;
  }

  isPrivateIP(ip) {
    const privateBRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./
    ];
    
    return privateBRanges.some(range => range.test(ip));
  }

  emitPacket(packet) {
    if (this.connectedClients.size > 0) {
      const alert = packet.attackType ? {
        id: packet.id,
        timestamp: packet.timestamp,
        message: `${packet.attackType} detected from ${packet.sourceIp}`,
        ip: packet.sourceIp,
        type: packet.attackType
      } : null;
      
      this.io.emit('new-packet', { packet, alert });
    }
  }

  start() {
    this.server.listen(this.port, () => {
      console.log(`Packet Monitor Server running on port ${this.port}`);
      console.log(`WebSocket endpoint: ws://localhost:${this.port}`);
    });
  }
}

// Start the server
const monitor = new PacketMonitor(3001);
monitor.start();

module.exports = PacketMonitor;