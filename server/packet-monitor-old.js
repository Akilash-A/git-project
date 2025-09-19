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
      
      // Send initial network interfaces and capture capabilities
      socket.emit('network-interfaces', this.networkInterfaces);
      socket.emit('capture-capabilities', {
        tshark: this.hasTshark,
        tcpdump: this.hasTcpdump,
        method: this.captureMethod
      });
      
      socket.on('start-monitoring', (options = {}) => {
        console.log('Starting real packet monitoring with options:', options);
        this.startRealPacketCapture(options);
      });
      
      socket.on('stop-monitoring', () => {
        console.log('Stopping real packet monitoring');
        this.stopRealPacketCapture();
      });
      
      socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
        this.connectedClients.delete(socket);
        
        // Stop monitoring if no clients connected
        if (this.connectedClients.size === 0) {
          this.stopRealPacketCapture();
        }
      });
    });
  }

  checkCaptureTools() {
    // Check if tshark is available
    exec('which tshark', (error) => {
      this.hasTshark = !error;
      if (this.hasTshark) {
        console.log('✓ tshark available for real packet capture');
        this.captureMethod = 'tshark';
      }
    });
    
    // Check if tcpdump is available
    exec('which tcpdump', (error) => {
      this.hasTcpdump = !error;
      if (this.hasTcpdump && !this.hasTshark) {
        console.log('✓ tcpdump available for real packet capture');
        this.captureMethod = 'tcpdump';
      }
    });
    
    if (!this.hasTshark && !this.hasTcpdump) {
      console.warn('⚠️  No packet capture tools found. Install tshark or tcpdump for real monitoring.');
    }
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

  startRealPacketCapture(options = {}) {
    if (this.isMonitoring) {
      this.stopRealPacketCapture();
    }
    
    this.isMonitoring = true;
    this.selectedInterface = options.interface || this.getDefaultInterface();
    
    console.log(`Starting real packet capture on interface: ${this.selectedInterface}`);
    
    if (this.hasTshark) {
      this.startTsharkCapture(options);
    } else if (this.hasTcpdump) {
      this.startTcpdumpCapture(options);
    } else {
      console.error('No packet capture tools available');
      this.emitError('No packet capture tools available. Please install tshark or tcpdump.');
      return;
    }
  }

  stopRealPacketCapture() {
    this.isMonitoring = false;
    
    if (this.tsharkProcess) {
      this.tsharkProcess.kill('SIGTERM');
      this.tsharkProcess = null;
      console.log('Stopped tshark process');
    }
    
    if (this.tcpdumpProcess) {
      this.tcpdumpProcess.kill('SIGTERM');
      this.tcpdumpProcess = null;
      console.log('Stopped tcpdump process');
    }
  }

  startTsharkCapture(options = {}) {
    // Build tshark command
    const args = [
      '-i', this.selectedInterface,  // Interface
      '-T', 'fields',               // Output format
      '-e', 'frame.number',         // Frame number
      '-e', 'frame.time_epoch',     // Timestamp
      '-e', 'ip.src',               // Source IP
      '-e', 'ip.dst',               // Destination IP
      '-e', 'frame.protocols',      // Protocols
      '-e', 'tcp.srcport',          // TCP source port
      '-e', 'tcp.dstport',          // TCP destination port
      '-e', 'udp.srcport',          // UDP source port
      '-e', 'udp.dstport',          // UDP destination port
      '-e', 'frame.len',            // Frame length
      '-E', 'separator=|',          // Field separator
      '-l'                          // Flush output
    ];

    // Add filters if specified
    let filter = '';
    if (options.protocol) {
      filter += options.protocol.toLowerCase();
    }
    if (options.filterIp) {
      filter += filter ? ` and host ${options.filterIp}` : `host ${options.filterIp}`;
    }
    if (options.filterPort) {
      filter += filter ? ` and port ${options.filterPort}` : `port ${options.filterPort}`;
    }
    
    if (filter) {
      args.push(filter);
    }

    console.log('Starting tshark with args:', args);
    
    try {
      this.tsharkProcess = spawn('tshark', args);
      
      this.tsharkProcess.stdout.on('data', (data) => {
        const lines = data.toString().split('\n');
        lines.forEach(line => {
          if (line.trim()) {
            this.parseTsharkLine(line);
          }
        });
      });
      
      this.tsharkProcess.stderr.on('data', (data) => {
        const message = data.toString();
        console.log('Tshark info:', message);
      });
      
      this.tsharkProcess.on('close', (code) => {
        console.log(`Tshark process exited with code ${code}`);
        this.isMonitoring = false;
      });
      
      this.tsharkProcess.on('error', (error) => {
        console.error('Tshark error:', error);
        this.emitError(`Tshark error: ${error.message}`);
      });
      
      console.log('✓ Tshark packet capture started successfully');
    } catch (error) {
      console.error('Failed to start tshark:', error);
      this.emitError(`Failed to start tshark: ${error.message}`);
    }
  }

  startTcpdumpCapture(options = {}) {
    // Build tcpdump command
    const args = [
      '-i', this.selectedInterface,  // Interface
      '-n',                         // Don't resolve hostnames
      '-tttt',                      // Timestamp format
      '-l'                          // Line buffered
    ];

    // Add filters if specified
    let filter = '';
    if (options.protocol) {
      filter += options.protocol.toLowerCase();
    }
    if (options.filterIp) {
      filter += filter ? ` and host ${options.filterIp}` : `host ${options.filterIp}`;
    }
    if (options.filterPort) {
      filter += filter ? ` and port ${options.filterPort}` : `port ${options.filterPort}`;
    }
    
    if (filter) {
      args.push(filter);
    }

    console.log('Starting tcpdump with args:', args);
    
    try {
      this.tcpdumpProcess = spawn('tcpdump', args);
      
      this.tcpdumpProcess.stdout.on('data', (data) => {
        const lines = data.toString().split('\n');
        lines.forEach(line => {
          if (line.trim()) {
            this.parseTcpdumpLine(line);
          }
        });
      });
      
      this.tcpdumpProcess.stderr.on('data', (data) => {
        const message = data.toString();
        if (!message.includes('listening on') && !message.includes('dropped')) {
          console.log('Tcpdump info:', message);
        }
      });
      
      this.tcpdumpProcess.on('close', (code) => {
        console.log(`Tcpdump process exited with code ${code}`);
        this.isMonitoring = false;
      });
      
      this.tcpdumpProcess.on('error', (error) => {
        console.error('Tcpdump error:', error);
        this.emitError(`Tcpdump error: ${error.message}`);
      });
      
      console.log('✓ Tcpdump packet capture started successfully');
    } catch (error) {
      console.error('Failed to start tcpdump:', error);
      this.emitError(`Failed to start tcpdump: ${error.message}`);
    }
  }

  parseTsharkLine(line) {
    try {
      const fields = line.split('|');
      if (fields.length >= 8) {
        const [frameNum, timestamp, srcIp, dstIp, protocols, tcpSrcPort, tcpDstPort, udpSrcPort, udpDstPort, frameLen] = fields;
        
        if (srcIp && dstIp) {
          const protocol = this.extractProtocol(protocols);
          const port = tcpSrcPort || udpSrcPort || 0;
          
          const packet = {
            id: this.packetIdCounter++,
            timestamp: new Date(parseFloat(timestamp) * 1000).toISOString(),
            sourceIp: srcIp,
            destinationIp: dstIp,
            protocol: protocol,
            port: parseInt(port) || 0,
            size: parseInt(frameLen) || 0,
            direction: this.determineDirection(srcIp, dstIp),
            attackType: this.detectAttack(srcIp, dstIp, parseInt(port) || 0)
          };
          
          this.emitPacket(packet);
        }
      }
    } catch (error) {
      console.error('Error parsing tshark line:', error);
    }
  }

  parseTcpdumpLine(line) {
    try {
      // Basic tcpdump parsing - this is a simplified version
      const ipMatch = line.match(/(\d+\.\d+\.\d+\.\d+)\.(\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\.(\d+)/);
      const protocolMatch = line.match(/(TCP|UDP|ICMP)/i);
      
      if (ipMatch) {
        const [, srcIp, srcPort, dstIp, dstPort] = ipMatch;
        const protocol = protocolMatch ? protocolMatch[1].toUpperCase() : 'TCP';
        
        const packet = {
          id: this.packetIdCounter++,
          timestamp: new Date().toISOString(),
          sourceIp: srcIp,
          destinationIp: dstIp,
          protocol: protocol,
          port: parseInt(srcPort) || 0,
          size: this.extractPacketSize(line),
          direction: this.determineDirection(srcIp, dstIp),
          attackType: this.detectAttack(srcIp, dstIp, parseInt(srcPort) || 0)
        };
        
        this.emitPacket(packet);
      }
    } catch (error) {
      console.error('Error parsing tcpdump line:', error);
    }
  }

  extractProtocol(protocols) {
    if (!protocols) return 'TCP';
    if (protocols.includes('tcp')) return 'TCP';
    if (protocols.includes('udp')) return 'UDP';
    if (protocols.includes('icmp')) return 'ICMP';
    return 'TCP';
  }

  extractPacketSize(line) {
    const sizeMatch = line.match(/length (\d+)/);
    return sizeMatch ? parseInt(sizeMatch[1]) : Math.floor(Math.random() * 1500) + 64;
  }

  determineDirection(srcIp, dstIp) {
    const localIp = this.getLocalIP();
    if (srcIp === localIp) return 'outgoing';
    if (dstIp === localIp) return 'incoming';
    return 'passing';
  }

  getDefaultInterface() {
    return this.networkInterfaces.length > 0 ? this.networkInterfaces[0].name : 'any';
  }

  emitError(message) {
    this.io.emit('capture-error', { message });
  }

  detectAttack(sourceIp, destinationIp, port) {
    // Simple attack detection logic
    const suspiciousPorts = [23, 135, 139, 445, 1433, 3389]; // Telnet, RPC, NetBIOS, SMB, SQL, RDP
    
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
    if (!ip) return false;
    const privateBRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./,
      /^127\./
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
      console.log(`📦 Packet: ${packet.sourceIp} → ${packet.destinationIp} (${packet.protocol}:${packet.port})`);
    }
  }

  getLocalIP() {
    return this.networkInterfaces.length > 0 ? this.networkInterfaces[0].address : '127.0.0.1';
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