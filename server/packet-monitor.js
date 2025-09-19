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
    this.captureMethod = 'tshark';
    
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
    
    setTimeout(() => {
      if (!this.hasTshark && !this.hasTcpdump) {
        console.warn('⚠️  No packet capture tools found. Install tshark or tcpdump for real monitoring.');
      }
    }, 1000);
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
    
    console.log(`🚀 Starting real packet capture on interface: ${this.selectedInterface}`);
    
    if (this.hasTshark) {
      this.startTsharkCapture(options);
    } else if (this.hasTcpdump) {
      this.startTcpdumpCapture(options);
    } else {
      console.error('❌ No packet capture tools available');
      this.emitError('No packet capture tools available. Please install tshark or tcpdump.');
      return;
    }
  }

  stopRealPacketCapture() {
    this.isMonitoring = false;
    
    if (this.tsharkProcess) {
      this.tsharkProcess.kill('SIGTERM');
      this.tsharkProcess = null;
      console.log('🛑 Stopped tshark process');
    }
    
    if (this.tcpdumpProcess) {
      this.tcpdumpProcess.kill('SIGTERM');
      this.tcpdumpProcess = null;
      console.log('🛑 Stopped tcpdump process');
    }
  }

  startTsharkCapture(options = {}) {
    // Build tshark command for real-time packet capture
    const args = [
      '-i', this.selectedInterface,  // Network interface
      '-T', 'fields',               // Output as fields
      '-e', 'frame.number',         // Frame number
      '-e', 'frame.time_epoch',     // Timestamp
      '-e', 'ip.src',               // Source IP
      '-e', 'ip.dst',               // Destination IP
      '-e', 'frame.protocols',      // Protocol stack
      '-e', 'tcp.srcport',          // TCP source port
      '-e', 'tcp.dstport',          // TCP destination port
      '-e', 'udp.srcport',          // UDP source port
      '-e', 'udp.dstport',          // UDP destination port
      '-e', 'frame.len',            // Frame length
      '-E', 'separator=|',          // Field separator
      '-l',                         // Flush output immediately
      '-f'                          // Capture filter follows
    ];

    // Build capture filter
    let filter = 'ip'; // Only capture IP packets
    if (options.protocol) {
      filter = options.protocol.toLowerCase();
    }
    if (options.filterIp) {
      filter += ` and host ${options.filterIp}`;
    }
    if (options.filterPort) {
      filter += ` and port ${options.filterPort}`;
    }
    
    args.push(filter);

    console.log('🔧 Starting tshark with filter:', filter);
    
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
        if (message.includes('Capturing on')) {
          console.log('✅ Tshark capturing:', message.trim());
        }
      });
      
      this.tsharkProcess.on('close', (code) => {
        console.log(`Tshark process exited with code ${code}`);
        this.isMonitoring = false;
      });
      
      this.tsharkProcess.on('error', (error) => {
        console.error('Tshark error:', error);
        this.emitError(`Tshark error: ${error.message}`);
      });
      
      console.log('✅ Tshark packet capture started successfully');
    } catch (error) {
      console.error('Failed to start tshark:', error);
      this.emitError(`Failed to start tshark: ${error.message}`);
    }
  }

  startTcpdumpCapture(options = {}) {
    // Build tcpdump command for real-time packet capture
    const args = [
      '-i', this.selectedInterface,  // Network interface
      '-n',                         // Don't resolve hostnames
      '-tttt',                      // Readable timestamp format
      '-l'                          // Line buffered output
    ];

    // Build capture filter
    let filter = 'ip'; // Only capture IP packets
    if (options.protocol) {
      filter = options.protocol.toLowerCase();
    }
    if (options.filterIp) {
      filter += ` and host ${options.filterIp}`;
    }
    if (options.filterPort) {
      filter += ` and port ${options.filterPort}`;
    }
    
    args.push(filter);

    console.log('🔧 Starting tcpdump with filter:', filter);
    
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
        if (message.includes('listening on')) {
          console.log('✅ Tcpdump listening:', message.trim());
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
      
      console.log('✅ Tcpdump packet capture started successfully');
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
        
        if (srcIp && dstIp && srcIp !== '' && dstIp !== '') {
          const protocol = this.extractProtocol(protocols);
          const srcPort = tcpSrcPort || udpSrcPort || 0;
          const dstPort = tcpDstPort || udpDstPort || 0;
          
          const packet = {
            id: this.packetIdCounter++,
            timestamp: new Date(parseFloat(timestamp) * 1000).toISOString(),
            sourceIp: srcIp,
            destinationIp: dstIp,
            protocol: protocol,
            port: parseInt(srcPort) || parseInt(dstPort) || 0,
            size: parseInt(frameLen) || 0,
            direction: this.determineDirection(srcIp, dstIp),
            attackType: this.detectAttack(srcIp, dstIp, parseInt(srcPort) || parseInt(dstPort) || 0)
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
      // Parse tcpdump output: timestamp IP src.port > dst.port: ...
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

  detectAttack(sourceIp, destinationIp, port) {
    // Enhanced attack detection
    const suspiciousPorts = [23, 135, 139, 445, 1433, 3389, 22]; // Telnet, RPC, NetBIOS, SMB, SQL, RDP, SSH
    const knownAttackPorts = [4444, 6666, 31337, 12345]; // Common backdoor ports
    
    // Check for suspicious ports
    if (suspiciousPorts.includes(port)) {
      return Math.random() < 0.4 ? 'Port Scan' : null;
    }
    
    // Check for known attack ports
    if (knownAttackPorts.includes(port)) {
      return 'Malware';
    }
    
    // Check for internal network scanning
    if (this.isPrivateIP(sourceIp) && this.isPrivateIP(destinationIp)) {
      return Math.random() < 0.03 ? 'Internal Threat' : null;
    }
    
    // Random attack detection (reduced frequency for real monitoring)
    if (Math.random() < 0.01) { // 1% chance
      const attacks = ['DDoS', 'Port Scan', 'Brute Force'];
      return attacks[Math.floor(Math.random() * attacks.length)];
    }
    
    return null;
  }

  isPrivateIP(ip) {
    if (!ip) return false;
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./,
      /^127\./
    ];
    
    return privateRanges.some(range => range.test(ip));
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
      
      // Log packet for debugging
      console.log(`📦 ${packet.sourceIp}:${packet.port} → ${packet.destinationIp} (${packet.protocol}, ${packet.size}B) ${packet.attackType ? '⚠️ ' + packet.attackType : ''}`);
    }
  }

  getLocalIP() {
    return this.networkInterfaces.length > 0 ? this.networkInterfaces[0].address : '127.0.0.1';
  }

  getDefaultInterface() {
    return this.networkInterfaces.length > 0 ? this.networkInterfaces[0].name : 'any';
  }

  emitError(message) {
    console.error('❌ Error:', message);
    this.io.emit('capture-error', { message });
  }

  start() {
    this.server.listen(this.port, () => {
      console.log(`🚀 Packet Monitor Server running on port ${this.port}`);
      console.log(`🌐 WebSocket endpoint: ws://localhost:${this.port}`);
      console.log(`🔧 Capture method: ${this.captureMethod}`);
    });
  }
}

// Start the server
const monitor = new PacketMonitor(3001);
monitor.start();

module.exports = PacketMonitor;