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
    
    // Advanced attack detection tracking
    this.attackTracking = {
      connectionCounts: new Map(),     // Track connections per IP
      portScanAttempts: new Map(),     // Track port scanning
      ddosCounters: new Map(),         // Track DDoS packets per IP
      bruteForceAttempts: new Map(),   // Track brute force attempts
      suspiciousIPs: new Set(),        // Flagged IPs
      recentPackets: [],               // Recent packet history for analysis
      
      thresholds: {
        ddosPacketsPerSecond: 50,      // DDoS threshold
        portScanPorts: 10,             // Port scan threshold  
        bruteForceAttempts: 5,         // Brute force threshold
        connectionFlood: 100,          // Connection flood threshold
        timeWindow: 10000              // 10 second analysis window
      }
    };
    
    // Clean up tracking data periodically
    setInterval(() => this.cleanupTrackingData(), 30000); // Every 30 seconds
    
    // Advanced attack detection
    this.attackDetection = {
      connectionTracker: new Map(), // Track connections per IP
      portScanTracker: new Map(),   // Track port scanning attempts
      ddosThresholds: {
        packetsPerSecond: 100,      // DDoS detection threshold
        connectionsPerIP: 50,       // Connection flood threshold
        timeWindow: 10000           // 10 second window
      },
      suspiciousIPs: new Set(),     // Known malicious IPs
      localIPs: new Set()           // Your local IPs to protect
    };
    
    this.setupSocketHandlers();
    this.getNetworkInterfaces();
    this.checkCaptureTools();
    this.initializeAttackDetection();
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
        
        // Add to local IPs for attack detection
        this.attackDetection.localIPs.add(ipv4.address);
      }
    }
    
    // Also add localhost for protection
    this.attackDetection.localIPs.add('127.0.0.1');
    
    console.log('Available network interfaces:', this.networkInterfaces);
    console.log('🛡️  Protected local IPs:', Array.from(this.attackDetection.localIPs));
  }

  initializeAttackDetection() {
    // Add your local IPs to protection list
    this.networkInterfaces.forEach(iface => {
      this.attackDetection.localIPs.add(iface.address);
    });
    
    // Add common local network ranges
    this.attackDetection.localIPs.add('127.0.0.1');
    this.attackDetection.localIPs.add('localhost');
    
    console.log('🛡️  Protected IPs:', Array.from(this.attackDetection.localIPs));
    
    // Clean up tracking data every 30 seconds
    setInterval(() => {
      this.cleanupTrackingData();
    }, 30000);
  }

  cleanupTrackingData() {
    const now = Date.now();
    const timeWindow = this.attackDetection.ddosThresholds.timeWindow;
    
    // Clean old connection tracking data
    for (const [ip, data] of this.attackDetection.connectionTracker) {
      data.timestamps = data.timestamps.filter(timestamp => now - timestamp < timeWindow);
      data.ports = data.ports.filter(portData => now - portData.timestamp < timeWindow);
      
      if (data.timestamps.length === 0 && data.ports.length === 0) {
        this.attackDetection.connectionTracker.delete(ip);
      }
    }
    
    // Clean old port scan tracking data
    for (const [ip, data] of this.attackDetection.portScanTracker) {
      data.ports = data.ports.filter(portData => now - portData.timestamp < timeWindow);
      
      if (data.ports.length === 0) {
        this.attackDetection.portScanTracker.delete(ip);
      }
    }
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
    const now = Date.now();
    const isTargetingMyIP = this.attackDetection.localIPs.has(destinationIp);
    const isFromMyIP = this.attackDetection.localIPs.has(sourceIp);
    
    // Track connections for DDoS detection
    this.trackConnection(sourceIp, destinationIp, port, now);
    
    // Enhanced attack detection targeting YOUR IP
    const suspiciousPorts = [23, 135, 139, 445, 1433, 3389, 22, 21, 25, 53, 110, 143]; 
    const knownAttackPorts = [4444, 6666, 31337, 12345, 1337, 8080, 9999];
    const bruteForceports = [22, 21, 23, 25, 110, 143, 993, 995, 3389]; // SSH, FTP, Telnet, SMTP, POP3, IMAP, RDP
    
    // 🚨 CRITICAL: DDoS Detection targeting your IP
    if (isTargetingMyIP) {
      const ddosResult = this.detectDDoS(sourceIp, destinationIp, now);
      if (ddosResult) {
        console.log(`🚨 DDoS ATTACK DETECTED! ${sourceIp} → ${destinationIp}:${port}`);
        this.alertHighSeverityAttack('DDoS', sourceIp, destinationIp, port);
        return ddosResult;
      }
    }
    
    // 🚨 Port Scan Detection targeting your IP
    if (isTargetingMyIP) {
      const portScanResult = this.detectPortScan(sourceIp, destinationIp, port, now);
      if (portScanResult) {
        console.log(`🚨 PORT SCAN DETECTED! ${sourceIp} scanning ${destinationIp}`);
        this.alertHighSeverityAttack('Port Scan', sourceIp, destinationIp, port);
        return portScanResult;
      }
    }
    
    // 🚨 Brute Force Attack Detection
    if (isTargetingMyIP && bruteForceports.includes(port)) {
      const bruteForceResult = this.detectBruteForce(sourceIp, destinationIp, port, now);
      if (bruteForceResult) {
        console.log(`🚨 BRUTE FORCE ATTACK! ${sourceIp} → ${destinationIp}:${port}`);
        this.alertHighSeverityAttack('Brute Force', sourceIp, destinationIp, port);
        return bruteForceResult;
      }
    }
    
    // 🚨 Suspicious Port Access targeting your IP
    if (isTargetingMyIP && suspiciousPorts.includes(port)) {
      console.log(`⚠️  Suspicious port access: ${sourceIp} → ${destinationIp}:${port}`);
      return 'Port Scan';
    }
    
    // 🚨 Known Malicious Ports targeting your IP
    if (isTargetingMyIP && knownAttackPorts.includes(port)) {
      console.log(`🚨 MALWARE DETECTED! ${sourceIp} → ${destinationIp}:${port}`);
      this.alertHighSeverityAttack('Malware', sourceIp, destinationIp, port);
      return 'Malware';
    }
    
    // 🚨 External IP trying to access internal services
    if (isTargetingMyIP && !this.isPrivateIP(sourceIp) && this.isPrivateServicePort(port)) {
      console.log(`🚨 EXTERNAL ACCESS ATTEMPT! ${sourceIp} → ${destinationIp}:${port}`);
      return 'Unauthorized Access';
    }
    
    // 🚨 Known suspicious IP
    if (this.attackDetection.suspiciousIPs.has(sourceIp)) {
      console.log(`🚨 KNOWN THREAT! Suspicious IP ${sourceIp} → ${destinationIp}:${port}`);
      return 'Known Threat';
    }
    
    return null;
  }

  trackConnection(sourceIp, destinationIp, port, timestamp) {
    if (!this.attackDetection.connectionTracker.has(sourceIp)) {
      this.attackDetection.connectionTracker.set(sourceIp, {
        timestamps: [],
        ports: [],
        targetIPs: new Set()
      });
    }
    
    const tracker = this.attackDetection.connectionTracker.get(sourceIp);
    tracker.timestamps.push(timestamp);
    tracker.ports.push({ port, timestamp, targetIP: destinationIp });
    tracker.targetIPs.add(destinationIp);
  }

  detectDDoS(sourceIp, destinationIp, now) {
    const tracker = this.attackDetection.connectionTracker.get(sourceIp);
    if (!tracker) return null;
    
    const timeWindow = this.attackDetection.ddosThresholds.timeWindow;
    const recentConnections = tracker.timestamps.filter(ts => now - ts < timeWindow);
    
    // High volume of packets from single IP to your IP
    if (recentConnections.length > this.attackDetection.ddosThresholds.packetsPerSecond) {
      this.attackDetection.suspiciousIPs.add(sourceIp);
      return 'DDoS';
    }
    
    // Connection flood detection
    if (recentConnections.length > this.attackDetection.ddosThresholds.connectionsPerIP) {
      return 'Connection Flood';
    }
    
    return null;
  }

  detectPortScan(sourceIp, destinationIp, port, now) {
    if (!this.attackDetection.portScanTracker.has(sourceIp)) {
      this.attackDetection.portScanTracker.set(sourceIp, {
        ports: [],
        targets: new Set()
      });
    }
    
    const scanner = this.attackDetection.portScanTracker.get(sourceIp);
    scanner.ports.push({ port, timestamp: now, target: destinationIp });
    scanner.targets.add(destinationIp);
    
    const timeWindow = this.attackDetection.ddosThresholds.timeWindow;
    const recentPorts = scanner.ports.filter(p => now - p.timestamp < timeWindow);
    
    // Multiple ports accessed on your IP in short time
    const uniquePorts = new Set(recentPorts.map(p => p.port));
    if (uniquePorts.size > 10) { // More than 10 different ports
      this.attackDetection.suspiciousIPs.add(sourceIp);
      return 'Port Scan';
    }
    
    return null;
  }

  detectBruteForce(sourceIp, destinationIp, port, now) {
    const tracker = this.attackDetection.connectionTracker.get(sourceIp);
    if (!tracker) return null;
    
    const timeWindow = 60000; // 1 minute window for brute force
    const samePortConnections = tracker.ports.filter(p => 
      p.port === port && 
      p.targetIP === destinationIp && 
      now - p.timestamp < timeWindow
    );
    
    // Multiple rapid connections to same service port
    if (samePortConnections.length > 20) { // More than 20 attempts per minute
      this.attackDetection.suspiciousIPs.add(sourceIp);
      return 'Brute Force';
    }
    
    return null;
  }

  isPrivateServicePort(port) {
    const privateServicePorts = [
      139, 445, // SMB/NetBIOS
      135, 1433, // RPC, SQL Server
      5432, 3306, // PostgreSQL, MySQL
      6379, 11211, // Redis, Memcached
      9200, 9300 // Elasticsearch
    ];
    return privateServicePorts.includes(port);
  }

  alertHighSeverityAttack(attackType, sourceIp, destinationIp, port) {
    // Send immediate high-priority alert
    this.io.emit('critical-attack', {
      severity: 'CRITICAL',
      attackType,
      sourceIp,
      destinationIp,
      port,
      timestamp: new Date().toISOString(),
      message: `🚨 CRITICAL: ${attackType} attack from ${sourceIp} targeting YOUR IP ${destinationIp}:${port}`
    });
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