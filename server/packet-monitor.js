const { Server } = require('socket.io');
const { createServer } = require('http');
const { spawn, exec } = require('child_process');
const os = require('os');
const crypto = require('crypto');
const PacketDatabase = require('./database');

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
    this.alertIdCounter = 0;
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
        packetsPerSecond: 100,      // DDoS detection threshold (increased for normal web traffic)
        connectionsPerIP: 50,       // Connection flood threshold (increased)
        timeWindow: 10000           // 10 second window
      },
      suspiciousIPs: new Set(),     // Known malicious IPs
      localIPs: new Set()           // Your local IPs to protect
    };
    
    // Initialize database
    this.database = new PacketDatabase();
    
    this.setupSocketHandlers();
    this.getNetworkInterfaces();
    this.checkCaptureTools();
    this.initializeAttackDetection();
  }

  // Generate unique IDs using timestamp and random values
  generateUniqueId() {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substr(2, 9);
    return `${timestamp}-${random}`;
  }

  generateUniquePacketId() {
    // Use counter + high precision timestamp + random for extra uniqueness
    const hrTime = process.hrtime.bigint();
    return `packet-${this.packetIdCounter++}-${hrTime}-${Math.random().toString(36).substr(2, 5)}`;
  }

  generateUniqueAlertId() {
    // Use counter + high precision timestamp + random for extra uniqueness
    const hrTime = process.hrtime.bigint();
    return `alert-${this.alertIdCounter++}-${hrTime}-${Math.random().toString(36).substr(2, 5)}`;
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

      // Database operations
      socket.on('get-packets', (options = {}) => {
        const { limit = 100, offset = 0, ip = null } = options;
        let packets;
        
        if (ip) {
          packets = this.database.getPacketsByIp(ip, limit);
        } else {
          packets = this.database.getPackets(limit, offset);
        }
        
        socket.emit('packets-data', packets);
      });

      socket.on('get-alerts', (options = {}) => {
        const { limit = 50, offset = 0 } = options;
        const alerts = this.database.getAlerts(limit, offset);
        socket.emit('alerts-data', alerts);
      });

      socket.on('get-whitelist', () => {
        const whitelist = this.database.getWhitelist();
        socket.emit('whitelist-data', whitelist);
      });

      socket.on('add-to-whitelist', (data) => {
        const { ip, description } = data;
        const success = this.database.addToWhitelist(ip, description);
        socket.emit('whitelist-updated', { success, ip, description });
      });

      socket.on('remove-from-whitelist', (ip) => {
        const success = this.database.removeFromWhitelist(ip);
        socket.emit('whitelist-updated', { success, removed: ip });
      });

      socket.on('get-statistics', () => {
        const stats = this.database.getStatistics();
        socket.emit('statistics-data', stats);
      });

      socket.on('clear-data', (options = {}) => {
        const { table = 'all', daysOld = null } = options;
        let result = { success: false, message: '', cleared: 0 };
        
        try {
          if (table === 'all') {
            this.database.clearAllData();
            result = { success: true, message: 'All data cleared successfully', cleared: 'all' };
          } else if (table === 'packets' && daysOld) {
            const cleared = this.database.deleteOldPackets(daysOld);
            result = { success: true, message: `Cleared ${cleared} old packets`, cleared };
          } else if (table === 'alerts' && daysOld) {
            const cleared = this.database.deleteOldAlerts(daysOld);
            result = { success: true, message: `Cleared ${cleared} old alerts`, cleared };
          } else if (['packets', 'alerts', 'security_analysis', 'whitelist'].includes(table)) {
            const cleared = this.database.clearTable(table);
            result = { success: true, message: `Cleared ${cleared} records from ${table}`, cleared };
          }
        } catch (error) {
          result = { success: false, message: error.message, cleared: 0 };
        }
        
        socket.emit('data-cleared', result);
      });

      socket.on('save-security-analysis', (data) => {
        const { ip, dangerScore, classification, analysisText, source } = data;
        const id = this.database.saveSecurityAnalysis(ip, dangerScore, classification, analysisText, source);
        socket.emit('security-analysis-saved', { success: !!id, id });
      });

      socket.on('get-security-analysis', (ip) => {
        const analysis = this.database.getSecurityAnalysis(ip);
        socket.emit('security-analysis-data', { ip, analysis });
      });

      socket.on('get-ip-attack-stats', (data) => {
        const { ip } = data;
        const stats = this.database.getIpAttackStatistics(ip);
        socket.emit('ip-attack-stats-data', stats);
      });

      // Traffic control operations
      socket.on('add-traffic-rule', (rule) => {
        const id = this.database.addTrafficRule(rule);
        const success = !!id;
        
        if (success && rule.action === 'block') {
          // Apply system-level blocking
          this.applySystemLevelBlocking(rule.ip, 'block');
        }
        
        socket.emit('traffic-rule-added', { success, id, rule });
        
        // Broadcast to all clients that traffic rules have been updated
        this.io.emit('traffic-rules-updated');
      });

      socket.on('get-traffic-rules', () => {
        const rules = this.database.getTrafficRules();
        socket.emit('traffic-rules-data', rules);
      });

      socket.on('update-traffic-rule-status', (data) => {
        const { ruleId, status } = data;
        
        // Get rule details before updating
        const rules = this.database.getTrafficRules();
        const rule = rules.find(r => r.id === ruleId);
        
        const success = this.database.updateTrafficRuleStatus(ruleId, status);
        
        if (success && rule && rule.action === 'block') {
          // Apply or remove system-level blocking based on status
          if (status === 'active') {
            this.applySystemLevelBlocking(rule.ip, 'block');
          } else {
            this.applySystemLevelBlocking(rule.ip, 'unblock');
          }
        }
        
        socket.emit('traffic-rule-status-updated', { success, ruleId, status });
        
        // Broadcast to all clients that traffic rules have been updated
        this.io.emit('traffic-rules-updated');
      });

      socket.on('remove-traffic-rule', (ruleId) => {
        // Get rule details before removing
        const rules = this.database.getTrafficRules();
        const rule = rules.find(r => r.id === ruleId);
        
        const success = this.database.removeTrafficRule(ruleId);
        
        if (success && rule && rule.action === 'block') {
          // Remove system-level blocking
          this.applySystemLevelBlocking(rule.ip, 'unblock');
        }
        
        socket.emit('traffic-rule-removed', { success, ruleId });
        
        // Broadcast to all clients that traffic rules have been updated
        this.io.emit('traffic-rules-updated');
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
      
      // Add the entire subnet as trusted (like 10.185.126.x for your network)
      const ip = iface.address;
      const netmask = iface.netmask;
      if (ip && netmask) {
        // Calculate network address and add common gateway IPs
        const ipParts = ip.split('.').map(Number);
        const netmaskParts = netmask.split('.').map(Number);
        
        // Calculate network base
        const networkBase = ipParts.map((part, i) => part & netmaskParts[i]);
        
        // Add common gateway addresses for this network
        const networkBaseStr = networkBase.slice(0, 3).join('.');
        this.attackDetection.localIPs.add(`${networkBaseStr}.1`);    // Common gateway
        this.attackDetection.localIPs.add(`${networkBaseStr}.254`);  // Common gateway
        this.attackDetection.localIPs.add(`${networkBaseStr}.238`);  // Your specific gateway
        
        console.log(`🛡️  Added network ${networkBaseStr}.x to trusted IPs`);
      }
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
      if (fields.length >= 10) {
        const [frameNum, timestamp, srcIp, dstIp, protocols, tcpSrcPort, tcpDstPort, udpSrcPort, udpDstPort, frameLen] = fields;
        
        // Skip lines with empty or invalid IPs
        if (!srcIp || !dstIp || srcIp === '' || dstIp === '' || srcIp === '-' || dstIp === '-') {
          return;
        }
        
        // Clean up IP addresses (remove any extra characters)
        const cleanSrcIp = srcIp.trim();
        const cleanDstIp = dstIp.trim();
        
        // Skip if IPs are not valid IPv4 addresses
        if (!this.isValidIPv4(cleanSrcIp) || !this.isValidIPv4(cleanDstIp)) {
          return;
        }
        
        const protocol = this.extractProtocol(protocols);
        
        // Better port extraction - get the first non-empty port
        let sourcePort = 0;
        let destPort = 0;
        
        if (protocol === 'TCP') {
          sourcePort = parseInt(tcpSrcPort) || 0;
          destPort = parseInt(tcpDstPort) || 0;
        } else if (protocol === 'UDP') {
          sourcePort = parseInt(udpSrcPort) || 0;
          destPort = parseInt(udpDstPort) || 0;
        }
        
        // Use destination port as the primary port for display
        const displayPort = destPort || sourcePort || 0;
        
        // Detect attacks and get detailed information
        const attackInfo = this.detectAttack(cleanSrcIp, cleanDstIp, displayPort);
        
        const packet = {
          id: this.generateUniquePacketId(),
          timestamp: new Date(parseFloat(timestamp) * 1000).toISOString(),
          sourceIp: cleanSrcIp,
          destinationIp: cleanDstIp,
          protocol: protocol,
          port: displayPort,
          size: parseInt(frameLen) || 0,
          direction: this.determineDirection(cleanSrcIp, cleanDstIp),
          attackType: attackInfo ? attackInfo.attackType : null,
          isDdosAttack: attackInfo ? attackInfo.isDdosAttack : 0,
          isPortScan: attackInfo ? attackInfo.isPortScan : 0,
          isBruteForce: attackInfo ? attackInfo.isBruteForce : 0,
          isMalware: attackInfo ? attackInfo.isMalware : 0,
          isConnectionFlood: attackInfo ? attackInfo.isConnectionFlood : 0,
          isUnauthorizedAccess: attackInfo ? attackInfo.isUnauthorizedAccess : 0,
          isKnownThreat: attackInfo ? attackInfo.isKnownThreat : 0,
          threatScore: attackInfo ? attackInfo.threatScore : 0,
          attackDetails: attackInfo ? attackInfo.attackDetails : null
        };
        
        this.emitPacket(packet);
      }
    } catch (error) {
      console.error('Error parsing tshark line:', error, 'Line:', line);
    }
  }

  parseTcpdumpLine(line) {
    try {
      // Parse tcpdump output: timestamp IP src.port > dst.port: ...
      const ipMatch = line.match(/(\d+\.\d+\.\d+\.\d+)\.(\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\.(\d+)/);
      const protocolMatch = line.match(/(TCP|UDP|ICMP)/i);
      
      if (ipMatch) {
        const [, srcIp, srcPort, dstIp, dstPort] = ipMatch;
        
        // Validate IPs
        if (!this.isValidIPv4(srcIp) || !this.isValidIPv4(dstIp)) {
          return;
        }
        
        const protocol = protocolMatch ? protocolMatch[1].toUpperCase() : 'TCP';
        const displayPort = parseInt(dstPort) || parseInt(srcPort) || 0;
        
        // Detect attacks and get detailed information
        const attackInfo = this.detectAttack(srcIp, dstIp, displayPort);
        
        const packet = {
          id: this.generateUniquePacketId(),
          timestamp: new Date().toISOString(),
          sourceIp: srcIp,
          destinationIp: dstIp,
          protocol: protocol,
          port: displayPort,
          size: this.extractPacketSize(line),
          direction: this.determineDirection(srcIp, dstIp),
          attackType: attackInfo ? attackInfo.attackType : null,
          isDdosAttack: attackInfo ? attackInfo.isDdosAttack : 0,
          isPortScan: attackInfo ? attackInfo.isPortScan : 0,
          isBruteForce: attackInfo ? attackInfo.isBruteForce : 0,
          isMalware: attackInfo ? attackInfo.isMalware : 0,
          isConnectionFlood: attackInfo ? attackInfo.isConnectionFlood : 0,
          isUnauthorizedAccess: attackInfo ? attackInfo.isUnauthorizedAccess : 0,
          isKnownThreat: attackInfo ? attackInfo.isKnownThreat : 0,
          threatScore: attackInfo ? attackInfo.threatScore : 0,
          attackDetails: attackInfo ? attackInfo.attackDetails : null
        };
        
        this.emitPacket(packet);
      }
    } catch (error) {
      console.error('Error parsing tcpdump line:', error, 'Line:', line);
    }
  }

  extractProtocol(protocols) {
    if (!protocols) return 'TCP';
    const protocolStr = protocols.toLowerCase();
    if (protocolStr.includes('tcp')) return 'TCP';
    if (protocolStr.includes('udp')) return 'UDP';
    if (protocolStr.includes('icmp')) return 'ICMP';
    if (protocolStr.includes('http')) return 'TCP'; // HTTP runs on TCP
    if (protocolStr.includes('https')) return 'TCP'; // HTTPS runs on TCP
    if (protocolStr.includes('dns')) return 'UDP'; // DNS usually runs on UDP
    return 'TCP'; // Default to TCP
  }
  
  isValidIPv4(ip) {
    if (!ip || typeof ip !== 'string') return false;
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipRegex.test(ip);
  }
  
  isInSameNetwork(ip1, ip2) {
    // Check if two IPs are in the same /24 network (common for home networks)
    if (!ip1 || !ip2) return false;
    const ip1Parts = ip1.split('.');
    const ip2Parts = ip2.split('.');
    
    // Compare first 3 octets for /24 network
    return ip1Parts[0] === ip2Parts[0] && 
           ip1Parts[1] === ip2Parts[1] && 
           ip1Parts[2] === ip2Parts[2];
  }

  extractPacketSize(line) {
    const sizeMatch = line.match(/length (\d+)/);
    return sizeMatch ? parseInt(sizeMatch[1]) : Math.floor(Math.random() * 1500) + 64;
  }

  determineDirection(srcIp, dstIp) {
    const localIps = Array.from(this.attackDetection.localIPs);
    
    // Check if source is local and destination is external
    if (localIps.includes(srcIp) && !localIps.includes(dstIp)) {
      return 'outgoing';
    }
    
    // Check if source is external and destination is local
    if (!localIps.includes(srcIp) && localIps.includes(dstIp)) {
      return 'incoming';
    }
    
    // Check private IP ranges for local network traffic
    const isPrivateIP = (ip) => {
      return ip.startsWith('192.168.') || 
             ip.startsWith('10.') || 
             ip.startsWith('172.16.') || 
             ip.startsWith('172.17.') ||
             ip.startsWith('172.18.') ||
             ip.startsWith('172.19.') ||
             ip.startsWith('172.2') ||
             ip.startsWith('172.30.') ||
             ip.startsWith('172.31.') ||
             ip === '127.0.0.1' ||
             ip === 'localhost';
    };
    
    // If both are private, it's local traffic
    if (isPrivateIP(srcIp) && isPrivateIP(dstIp)) {
      return 'local';
    }
    
    // Default case - traffic passing through
    return 'passing';
  }

  detectAttack(sourceIp, destinationIp, port) {
    const now = Date.now();
    const isTargetingMyIP = this.attackDetection.localIPs.has(destinationIp);
    const isFromMyIP = this.attackDetection.localIPs.has(sourceIp);
    const isFromTrustedLocalIP = this.attackDetection.localIPs.has(sourceIp);
    
    // Initialize detailed attack information
    const attackInfo = {
      attackType: null,
      isDdosAttack: 0,
      isPortScan: 0,
      isBruteForce: 0,
      isMalware: 0,
      isConnectionFlood: 0,
      isUnauthorizedAccess: 0,
      isKnownThreat: 0,
      threatScore: 0,
      attackDetails: []
    };
    
    // Skip threat detection ONLY for normal router/gateway services
    if (isFromTrustedLocalIP && isTargetingMyIP) {
      const normalRouterPorts = [53, 67, 68]; // DNS, DHCP
      if (normalRouterPorts.includes(port)) {
        // This is normal router/gateway traffic (DNS, DHCP)
        return null;
      }
      // For other ports from trusted IPs, still check for attacks but with lower sensitivity
    }
    
    // Track connections for DDoS detection
    this.trackConnection(sourceIp, destinationIp, port, now);
    
    // Enhanced attack detection targeting YOUR IP
    const suspiciousPorts = [23, 135, 139, 445, 1433, 3389, 22, 21, 25, 110, 143]; // Removed 53 (DNS)
    const knownAttackPorts = [4444, 6666, 31337, 12345, 1337, 8080, 9999];
    const bruteForceports = [22, 21, 23, 25, 110, 143, 993, 995, 3389]; // SSH, FTP, Telnet, SMTP, POP3, IMAP, RDP
    
    // 🚨 CRITICAL: DDoS Detection targeting your IP
    if (isTargetingMyIP) {
      const ddosResult = this.detectDDoS(sourceIp, destinationIp, now);
      if (ddosResult) {
        attackInfo.isDdosAttack = 1;
        attackInfo.threatScore += 40;
        attackInfo.attackDetails.push(`DDoS: ${ddosResult}`);
        if (!attackInfo.attackType) attackInfo.attackType = ddosResult;
        
        // Only log attacks from non-trusted IPs
        if (!isFromTrustedLocalIP) {
          // console.log(`🚨 DDoS ATTACK DETECTED! ${sourceIp} → ${destinationIp}:${port}`);
          this.alertHighSeverityAttack('DDoS', sourceIp, destinationIp, port);
        }
      }
    }
    
    // 🚨 Port Scan Detection targeting your IP
    if (isTargetingMyIP) {
      const portScanResult = this.detectPortScan(sourceIp, destinationIp, port, now);
      if (portScanResult) {
        attackInfo.isPortScan = 1;
        attackInfo.threatScore += 25;
        attackInfo.attackDetails.push('Port scanning activity detected');
        if (!attackInfo.attackType) attackInfo.attackType = portScanResult;
        
        // Only log attacks from non-trusted IPs
        if (!isFromTrustedLocalIP) {
          // console.log(`🚨 PORT SCAN DETECTED! ${sourceIp} scanning ${destinationIp}`);
          this.alertHighSeverityAttack('Port Scan', sourceIp, destinationIp, port);
        }
      }
    }
    
    // 🚨 Brute Force Attack Detection
    if (isTargetingMyIP && bruteForceports.includes(port)) {
      const bruteForceResult = this.detectBruteForce(sourceIp, destinationIp, port, now);
      if (bruteForceResult) {
        attackInfo.isBruteForce = 1;
        attackInfo.threatScore += 35;
        attackInfo.attackDetails.push(`Brute force on port ${port}`);
        if (!attackInfo.attackType) attackInfo.attackType = bruteForceResult;
        
        // Only log attacks from non-trusted IPs
        if (!isFromTrustedLocalIP) {
          console.log(`🚨 BRUTE FORCE ATTACK! ${sourceIp} → ${destinationIp}:${port}`);
          this.alertHighSeverityAttack('Brute Force', sourceIp, destinationIp, port);
        }
      }
    }
    
    // 🚨 Suspicious Port Access targeting your IP
    if (isTargetingMyIP && suspiciousPorts.includes(port)) {
      if (!attackInfo.isPortScan) { // Don't double-count if already detected as port scan
        attackInfo.isPortScan = 1;
        attackInfo.threatScore += 20;
        attackInfo.attackDetails.push(`Suspicious port access: ${port}`);
        if (!attackInfo.attackType) attackInfo.attackType = 'Port Scan';
      }
      
      // Only log attacks from non-trusted IPs
      if (!isFromTrustedLocalIP) {
        console.log(`⚠️  Suspicious port access: ${sourceIp} → ${destinationIp}:${port}`);
      }
    }
    
    // 🚨 Known Malicious Ports targeting your IP
    if (isTargetingMyIP && knownAttackPorts.includes(port)) {
      attackInfo.isMalware = 1;
      attackInfo.threatScore += 50;
      attackInfo.attackDetails.push(`Malware communication on port ${port}`);
      if (!attackInfo.attackType) attackInfo.attackType = 'Malware';
      
      // Only log attacks from non-trusted IPs
      if (!isFromTrustedLocalIP) {
        console.log(`🚨 MALWARE DETECTED! ${sourceIp} → ${destinationIp}:${port}`);
        this.alertHighSeverityAttack('Malware', sourceIp, destinationIp, port);
      }
    }
    
    // 🚨 External IP trying to access internal services
    if (isTargetingMyIP && !this.isPrivateIP(sourceIp) && this.isPrivateServicePort(port)) {
      attackInfo.isUnauthorizedAccess = 1;
      attackInfo.threatScore += 30;
      attackInfo.attackDetails.push(`Unauthorized access attempt on port ${port}`);
      if (!attackInfo.attackType) attackInfo.attackType = 'Unauthorized Access';
      
      console.log(`🚨 EXTERNAL ACCESS ATTEMPT! ${sourceIp} → ${destinationIp}:${port}`);
    }
    
    // 🚨 Known suspicious IP
    if (this.attackDetection.suspiciousIPs.has(sourceIp)) {
      attackInfo.isKnownThreat = 1;
      attackInfo.threatScore += 15;
      attackInfo.attackDetails.push('Known malicious IP address');
      if (!attackInfo.attackType) attackInfo.attackType = 'Known Threat';
      
      // Only log attacks from non-trusted IPs
      if (!isFromTrustedLocalIP) {
        // console.log(`🚨 KNOWN THREAT! Suspicious IP ${sourceIp} → ${destinationIp}:${port}`);
      }
    }

    // Cap threat score at 100
    attackInfo.threatScore = Math.min(attackInfo.threatScore, 100);
    
    // Convert attackDetails array to string
    attackInfo.attackDetails = attackInfo.attackDetails.length > 0 ? 
      attackInfo.attackDetails.join('; ') : null;
    
    // Return attack information (or null if no attacks detected)
    if (attackInfo.attackType) {
      return attackInfo;
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
    
    // Check if this is likely web traffic by examining ports
    const webTrafficPorts = [80, 443, 8080, 8443];
    const recentWebConnections = tracker.ports.filter(p => 
      now - p.timestamp < timeWindow && webTrafficPorts.includes(p.port)
    );
    
    // Use higher thresholds for web traffic (normal browsing can generate many packets)
    const isWebTraffic = recentWebConnections.length > recentConnections.length * 0.5;
    const packetsThreshold = isWebTraffic ? 
      this.attackDetection.ddosThresholds.packetsPerSecond * 3 : 
      this.attackDetection.ddosThresholds.packetsPerSecond;
    const connectionsThreshold = isWebTraffic ? 
      this.attackDetection.ddosThresholds.connectionsPerIP * 2 : 
      this.attackDetection.ddosThresholds.connectionsPerIP;
    
    // High volume of packets from single IP to your IP
    if (recentConnections.length > packetsThreshold) {
      // Don't mark trusted IPs as suspicious
      if (!this.attackDetection.localIPs.has(sourceIp)) {
        this.attackDetection.suspiciousIPs.add(sourceIp);
      }
      return 'DDoS';
    }
    
    // Connection flood detection
    if (recentConnections.length > connectionsThreshold) {
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
    if (uniquePorts.size > 15) { // More than 15 different ports (increased for normal web traffic)
      // Don't mark trusted IPs as suspicious
      if (!this.attackDetection.localIPs.has(sourceIp)) {
        this.attackDetection.suspiciousIPs.add(sourceIp);
      }
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
    if (samePortConnections.length > 10) { // More than 10 attempts per minute (lowered from 20)
      // Don't mark trusted IPs as suspicious
      if (!this.attackDetection.localIPs.has(sourceIp)) {
        this.attackDetection.suspiciousIPs.add(sourceIp);
      }
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
    // Only send critical alerts if monitoring is active
    if (!this.isMonitoring) return;
    
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
    // Only emit packets if monitoring is active
    if (!this.isMonitoring) return;

    // Check if source IP is blocked
    const isSourceBlocked = this.database.isIpBlocked(packet.sourceIp);
    const isDestinationBlocked = this.database.isIpBlocked(packet.destinationIp);
    
    // If either source or destination IP is blocked, handle accordingly
    if (isSourceBlocked || isDestinationBlocked) {
      const blockedIp = isSourceBlocked ? packet.sourceIp : packet.destinationIp;
      const direction = isSourceBlocked ? 'from' : 'to';
      
      // Create immediate alert for blocked IP activity
      const blockAlert = {
        id: this.generateUniqueAlertId(),
        timestamp: packet.timestamp,
        message: `🚫 BLOCKED IP ACTIVITY: Traffic ${direction} blocked IP ${blockedIp}`,
        ip: blockedIp,
        type: 'IP_BLOCKED'
      };
      
      // Log the blocked attempt
      console.log(`🚫 BLOCKED: ${packet.sourceIp} → ${packet.destinationIp}:${packet.port} (${packet.protocol})`);
      
      // Save the blocked attempt to database for logging purposes
      const blockedPacket = {
        ...packet,
        attackType: 'IP_BLOCKED',
        threatScore: 100,
        attackDetails: `Traffic blocked - IP ${blockedIp} is in block list`
      };
      this.database.insertPacket(blockedPacket);
      this.database.insertAlert(blockAlert);
      
      // Emit the block alert to clients
      this.io.emit('new-packet', { 
        packet: blockedPacket, 
        alert: blockAlert,
        blocked: true 
      });
      
      // Also emit a critical alert
      this.io.emit('critical-attack', {
        severity: 'BLOCKED',
        attackType: 'IP_BLOCKED',
        sourceIp: packet.sourceIp,
        destinationIp: packet.destinationIp,
        port: packet.port,
        timestamp: packet.timestamp,
        message: `🚫 BLOCKED: Traffic ${direction} blocked IP ${blockedIp}`
      });
      
      return; // Don't process the packet further
    }

    // Check for throttling
    const sourceThrottleDelay = this.database.getIpThrottleDelay(packet.sourceIp);
    const destThrottleDelay = this.database.getIpThrottleDelay(packet.destinationIp);
    
    if (sourceThrottleDelay || destThrottleDelay) {
      const delay = sourceThrottleDelay || destThrottleDelay;
      const throttledIp = sourceThrottleDelay ? packet.sourceIp : packet.destinationIp;
      
      console.log(`⏱️ THROTTLED: ${packet.sourceIp} → ${packet.destinationIp}:${packet.port} (delay: ${delay}ms)`);
      
      // Add throttling information to packet
      packet.throttled = true;
      packet.throttleDelay = delay;
      packet.throttledIp = throttledIp;
      
      // Delay the packet processing
      setTimeout(() => {
        this.processNormalPacket(packet);
      }, delay);
      
      return;
    }
    
    // Process normal packet
    this.processNormalPacket(packet);
  }

  processNormalPacket(packet) {
    // Save packet to database
    this.database.insertPacket(packet);
    
    if (this.connectedClients.size > 0) {
      const alert = packet.attackType ? {
        id: this.generateUniqueAlertId(),
        timestamp: packet.timestamp,
        message: `${packet.attackType} detected from ${packet.sourceIp}`,
        ip: packet.sourceIp,
        type: packet.attackType
      } : null;
      
      // Save alert to database if it exists
      if (alert) {
        this.database.insertAlert(alert);
      }
      
      this.io.emit('new-packet', { packet, alert });
      
      // Enhanced logging for debugging - commented out to reduce terminal noise
      // const direction = packet.direction === 'incoming' ? '⬇️' : 
      //                  packet.direction === 'outgoing' ? '⬆️' : 
      //                  packet.direction === 'local' ? '🏠' : '↔️';
      // 
      // const attackIndicator = packet.attackType ? `⚠️ ${packet.attackType}` : '✅ Normal';
      // 
      // console.log(`📦 ${direction} ${packet.sourceIp}:${packet.port} → ${packet.destinationIp} (${packet.protocol}, ${packet.size}B) ${attackIndicator}`);
    }
  }

  getLocalIP() {
    return this.networkInterfaces.length > 0 ? this.networkInterfaces[0].address : '127.0.0.1';
  }g

  getDefaultInterface() {
    return this.networkInterfaces.length > 0 ? this.networkInterfaces[0].name : 'any';
  }

  emitError(message) {
    console.error('❌ Error:', message);
    this.io.emit('capture-error', { message });
  }

  // System-level IP blocking using iptables (Linux only)
  applySystemLevelBlocking(ip, action = 'block') {
    if (os.platform() !== 'linux') {
      console.log('⚠️  System-level blocking only supported on Linux');
      return false;
    }

    if (action === 'block') {
      // Add iptables rule to block IP
      const command = `sudo iptables -A INPUT -s ${ip} -j DROP`;
      exec(command, (error, stdout, stderr) => {
        if (error) {
          console.error(`Failed to block IP ${ip} at system level:`, error.message);
        } else {
          console.log(`🛡️ System-level block applied for IP: ${ip}`);
        }
      });
    } else if (action === 'unblock') {
      // Remove iptables rule
      const command = `sudo iptables -D INPUT -s ${ip} -j DROP`;
      exec(command, (error, stdout, stderr) => {
        if (error) {
          console.error(`Failed to unblock IP ${ip} at system level:`, error.message);
        } else {
          console.log(`🛡️ System-level block removed for IP: ${ip}`);
        }
      });
    }
  }

  // Apply all active blocking rules at startup
  initializeSystemBlocking() {
    try {
      const blockedIps = this.database.getActiveBlockedIps();
      console.log(`🛡️ Applying system-level blocking for ${blockedIps.length} IPs...`);
      
      blockedIps.forEach(ip => {
        this.applySystemLevelBlocking(ip, 'block');
      });
    } catch (error) {
      console.error('Failed to initialize system blocking:', error);
    }
  }

  start() {
    this.server.listen(this.port, () => {
      console.log(`🚀 Packet Monitor Server running on port ${this.port}`);
      console.log(`🌐 WebSocket endpoint: ws://localhost:${this.port}`);
      console.log(`🔧 Capture method: ${this.captureMethod}`);
      
      // Initialize system-level blocking
      this.initializeSystemBlocking();
    });
  }
}

// Start the server
const monitor = new PacketMonitor(3001);
monitor.start();

module.exports = PacketMonitor;