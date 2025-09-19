const { Server } = require('socket.io');
const { createServer } = require('http');
const { spawn, exec } = require('child_process');
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
    this.tsharkProcess = null;
    this.tcpdumpProcess = null;
    this.connectedClients = new Set();
    this.selectedInterface = null;
    this.captureMethod = 'tshark'; // 'tshark' or 'tcpdump'
    
    this.setupSocketHandlers();
    this.getNetworkInterfaces();
    this.checkCaptureTools();
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
    console.log('Starting real-time packet monitoring...');
    
    // Monitor network connections using netstat
    this.monitoringInterval = setInterval(() => {
      this.captureNetworkConnections(options);
    }, 1000); // Capture every second
    
    // Generate some simulated traffic for demonstration
    // In a real implementation, you would use tcpdump, wireshark, or pcap libraries
    this.simulateTrafficInterval = setInterval(() => {
      this.generateRealisticPackets(options);
    }, 500); // Generate realistic packets every 500ms
    
    // Also monitor using ss command for more detailed info
    this.monitorWithSS(options);
  }

  stopMonitoring() {
    this.isMonitoring = false;
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = null;
    }
    if (this.simulateTrafficInterval) {
      clearInterval(this.simulateTrafficInterval);
      this.simulateTrafficInterval = null;
    }
    console.log('Packet monitoring stopped');
  }

  captureNetworkConnections(options) {
    // Try to capture real network activity using netstat
    netstat({
      filter: {
        pid: 0,
        protocol: options.protocol || undefined
      },
      limit: 20
    }, (data) => {
      if (data && data.local && data.foreign && data.state === 'ESTABLISHED') {
        const packet = this.parseNetstatData(data);
        if (packet && this.shouldIncludePacket(packet, options)) {
          this.emitPacket(packet);
        }
      }
    });

    // Also try to monitor network activity using system commands
    this.captureSystemNetworkActivity(options);
  }

  captureSystemNetworkActivity(options) {
    // Monitor active network connections
    const cmd = 'netstat -tuln 2>/dev/null | head -20';
    exec(cmd, (error, stdout, stderr) => {
      if (!error && stdout) {
        this.parseNetstatOutput(stdout, options);
      }
    });
  }

  parseNetstatOutput(output, options) {
    const lines = output.split('\n').slice(2); // Skip headers
    
    lines.forEach(line => {
      if (line.trim() && line.includes(':')) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 4) {
          const [proto, recvQ, sendQ, localAddr, foreignAddr, state] = parts;
          
          if (localAddr && localAddr.includes(':')) {
            const packet = this.createPacketFromNetstat(proto, localAddr, foreignAddr || '0.0.0.0:0', state);
            if (packet && this.shouldIncludePacket(packet, options)) {
              // Only emit if there's activity (not just listening)
              if (Math.random() < 0.1) { // 10% chance for listening ports to show activity
                this.emitPacket(packet);
              }
            }
          }
        }
      }
    });
  }

  createPacketFromNetstat(protocol, localAddr, foreignAddr, state) {
    try {
      const [localIp, localPort] = localAddr.split(':');
      const [foreignIp, foreignPort] = foreignAddr.split(':');
      
      // Skip localhost and internal addresses for cleaner demo
      if (localIp === '127.0.0.1' || localIp.startsWith('127.') || localIp === '::1') {
        return null;
      }
      
      const packet = {
        id: this.packetIdCounter++,
        timestamp: new Date().toISOString(),
        sourceIp: foreignIp === '0.0.0.0' ? this.getRandomPublicIP() : foreignIp,
        destinationIp: localIp,
        protocol: protocol.toUpperCase(),
        port: parseInt(localPort) || 0,
        attackType: this.detectAttack(foreignIp, localIp, parseInt(localPort)),
        size: this.getRealisticPacketSize(protocol.toUpperCase()),
        direction: state === 'LISTEN' ? 'incoming' : 'bidirectional'
      };
      
      return packet;
    } catch (error) {
      console.error('Error parsing netstat data:', error);
      return null;
    }
  }

  shouldIncludePacket(packet, options) {
    if (options.filterIp && 
        !packet.sourceIp.includes(options.filterIp) && 
        !packet.destinationIp.includes(options.filterIp)) {
      return false;
    }
    
    if (options.filterPort && packet.port !== options.filterPort) {
      return false;
    }
    
    if (options.protocol && packet.protocol !== options.protocol) {
      return false;
    }
    
    return true;
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

  generateRealisticPackets(options) {
    if (!this.isMonitoring || this.connectedClients.size === 0) return;
    
    // Generate realistic network traffic patterns
    const patterns = [
      // Web traffic
      { sourceIp: this.getRandomPublicIP(), destIp: this.getLocalIP(), protocol: 'TCP', port: 443, direction: 'incoming' },
      { sourceIp: this.getLocalIP(), destIp: this.getRandomPublicIP(), protocol: 'TCP', port: 80, direction: 'outgoing' },
      // DNS requests
      { sourceIp: this.getLocalIP(), destIp: '8.8.8.8', protocol: 'UDP', port: 53, direction: 'outgoing' },
      { sourceIp: '8.8.8.8', destIp: this.getLocalIP(), protocol: 'UDP', port: 53, direction: 'incoming' },
      // Local network traffic
      { sourceIp: this.getRandomLocalIP(), destIp: this.getLocalIP(), protocol: 'TCP', port: 22, direction: 'incoming' },
      // HTTPS traffic
      { sourceIp: this.getRandomPublicIP(), destIp: this.getLocalIP(), protocol: 'TCP', port: 443, direction: 'incoming' },
    ];
    
    // Apply filters if specified
    let filteredPatterns = patterns;
    if (options.protocol) {
      filteredPatterns = filteredPatterns.filter(p => p.protocol === options.protocol);
    }
    if (options.filterIp) {
      filteredPatterns = filteredPatterns.filter(p => 
        p.sourceIp.includes(options.filterIp) || p.destIp.includes(options.filterIp)
      );
    }
    if (options.filterPort) {
      filteredPatterns = filteredPatterns.filter(p => p.port === options.filterPort);
    }
    
    // Generate 1-3 packets per call to simulate realistic traffic
    const numPackets = Math.floor(Math.random() * 3) + 1;
    for (let i = 0; i < numPackets; i++) {
      if (Math.random() < 0.7) { // 70% chance to generate a packet
        const pattern = filteredPatterns[Math.floor(Math.random() * filteredPatterns.length)];
        if (pattern) {
          const packet = this.createRealisticPacket(pattern);
          this.emitPacket(packet);
        }
      }
    }
  }

  createRealisticPacket(pattern) {
    const packet = {
      id: this.packetIdCounter++,
      timestamp: new Date().toISOString(),
      sourceIp: pattern.sourceIp,
      destinationIp: pattern.destIp,
      protocol: pattern.protocol,
      port: pattern.port,
      size: this.getRealisticPacketSize(pattern.protocol),
      direction: pattern.direction,
      attackType: this.detectAttack(pattern.sourceIp, pattern.destIp, pattern.port)
    };
    
    return packet;
  }

  getLocalIP() {
    return this.networkInterfaces.length > 0 ? this.networkInterfaces[0].address : '192.168.1.100';
  }

  getRandomPublicIP() {
    const publicRanges = [
      () => `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
    ];
    return publicRanges[0]();
  }

  getRandomLocalIP() {
    const localIP = this.getLocalIP();
    const parts = localIP.split('.');
    return `${parts[0]}.${parts[1]}.${parts[2]}.${Math.floor(Math.random() * 254) + 1}`;
  }

  getRealisticPacketSize(protocol) {
    switch(protocol) {
      case 'TCP':
        return Math.floor(Math.random() * 1400) + 100; // 100-1500 bytes
      case 'UDP':
        return Math.floor(Math.random() * 500) + 50;   // 50-550 bytes
      case 'ICMP':
        return Math.floor(Math.random() * 100) + 28;   // 28-128 bytes
      default:
        return Math.floor(Math.random() * 1000) + 64;
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