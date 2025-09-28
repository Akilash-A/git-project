const { Server } = require('socket.io');
const { createServer } = require('http');
const { spawn, exec } = require('child_process');
const os = require('os');
const crypto = require('crypto');
const PacketDatabase = require('./database');
const ChatDatabase = require('./chat-database');

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
    
    // Initialize databases
    this.database = new PacketDatabase();
    this.chatDatabase = new ChatDatabase();
    
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
      this.connectedClients.add(socket);
      
      // Send initial network interfaces and capture capabilities
      socket.emit('network-interfaces', this.networkInterfaces);
      socket.emit('capture-capabilities', {
        tshark: this.hasTshark,
        tcpdump: this.hasTcpdump,
        method: this.captureMethod
      });
      
      socket.on('start-monitoring', (options = {}) => {
        this.startRealPacketCapture(options);
      });
      
      socket.on('stop-monitoring', () => {
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
        
        if (success) {
          // Apply system-level traffic control
          if (rule.action === 'block') {
            this.applySystemLevelTrafficControl(rule.ip, 'block');
          } else if (rule.action === 'throttle') {
            this.applySystemLevelTrafficControl(rule.ip, 'throttle', rule.delay);
          }
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
            this.applySystemLevelTrafficControl(rule.ip, 'block');
          } else if (rule.action === 'throttle') {
            this.applySystemLevelTrafficControl(rule.ip, 'throttle', rule.delay);
          } else {
            this.applySystemLevelTrafficControl(rule.ip, 'unblock');
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
        
        if (success && rule) {
          // Remove system-level traffic control
          if (rule.action === 'block') {
            this.applySystemLevelTrafficControl(rule.ip, 'unblock');
          } else if (rule.action === 'throttle') {
            this.applySystemLevelTrafficControl(rule.ip, 'unthrottle');
          }
        }
        
        socket.emit('traffic-rule-removed', { success, ruleId });
        
        // Broadcast to all clients that traffic rules have been updated
        this.io.emit('traffic-rules-updated');
      });

      // Chat operations
      socket.on('get-chat-conversations', () => {
        const conversations = this.chatDatabase.getConversations();
        socket.emit('chat-conversations-data', conversations);
      });

      socket.on('create-chat-conversation', (conversation) => {
        const success = this.chatDatabase.createConversation(conversation);
        socket.emit('chat-conversation-created', success);
      });

      socket.on('insert-chat-message', (message) => {
        const success = this.chatDatabase.insertMessage(message);
        socket.emit('chat-message-inserted', success);
      });

      socket.on('delete-chat-conversation', (conversationId) => {
        const success = this.chatDatabase.deleteConversation(conversationId);
        socket.emit('chat-conversation-deleted', success);
      });

      socket.on('update-chat-conversation', (data) => {
        const success = this.chatDatabase.updateConversation(data.conversationId, data.updates);
        socket.emit('chat-conversation-updated', success);
      });
      
      socket.on('disconnect', () => {
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
        this.captureMethod = 'tshark';
      }
    });
    
    // Check if tcpdump is available
    exec('which tcpdump', (error) => {
      this.hasTcpdump = !error;
      if (this.hasTcpdump && !this.hasTshark) {
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
      }
    });
    
    // Add common local network ranges
    this.attackDetection.localIPs.add('127.0.0.1');
    this.attackDetection.localIPs.add('localhost');
    
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
    }
    
    if (this.tcpdumpProcess) {
      this.tcpdumpProcess.kill('SIGTERM');
      this.tcpdumpProcess = null;
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
      });
      
      this.tsharkProcess.on('close', (code) => {
        this.isMonitoring = false;
      });
      
      this.tsharkProcess.on('error', (error) => {
        console.error('Tshark error:', error);
        this.emitError(`Tshark error: ${error.message}`);
      });
      
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
      });
      
      this.tcpdumpProcess.on('close', (code) => {
        this.isMonitoring = false;
      });
      
      this.tcpdumpProcess.on('error', (error) => {
        console.error('Tcpdump error:', error);
        this.emitError(`Tcpdump error: ${error.message}`);
      });
      
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

  // System-level traffic control using iptables - Simplified and reliable
  applySystemLevelTrafficControl(ip, action = 'block', delay = null) {
    if (os.platform() !== 'linux') {
      console.log('⚠️  System-level traffic control only supported on Linux');
      return false;
    }

    // Check if running as root or if passwordless sudo is configured
    const isRoot = process.getuid && process.getuid() === 0;
    const sudoPrefix = isRoot ? '' : 'sudo ';

    if (action === 'block') {
      // Simple blocking: just add DROP rule
      const blockCommand = `${sudoPrefix}iptables -I INPUT -s ${ip} -j DROP`;
      exec(blockCommand, { timeout: 5000 }, (error) => {
        if (error) {
          if (error.message.includes('permission denied') || error.message.includes('EACCES')) {
            console.error(`❌ Permission denied: Run with 'sudo npm run dev:full' or configure passwordless sudo for iptables`);
          } else {
            console.error(`❌ Failed to block IP ${ip}:`, error.message);
          }
        }
      });
      
    } else if (action === 'unblock') {
      // Remove blocking rule
      const unblockCommand = `${sudoPrefix}iptables -D INPUT -s ${ip} -j DROP 2>/dev/null`;
      exec(unblockCommand, { timeout: 5000 }, (error) => {
        // IP unblocked
      });
      
    } else if (action === 'throttle' && delay) {
      // Apply cyclic throttling
      this.startCyclicThrottling(ip, delay, sudoPrefix);
      
    } else if (action === 'unthrottle') {
      // Stop cyclic throttling
      this.stopCyclicThrottling(ip);
      const unblockCommand = `${sudoPrefix}iptables -D INPUT -s ${ip} -j DROP 2>/dev/null`;
      exec(unblockCommand, { timeout: 5000 }, () => {
      });
    }
  }

  // Clean up all iptables rules for a specific IP
  cleanupIptablesRulesForIP(ip, sudoPrefix, callback) {
    console.log(`🧹 Cleaning up all iptables rules for IP: ${ip}`);
    
    // Get all rules for this IP and remove them
    const listCommand = `${sudoPrefix}iptables -L INPUT --line-numbers -n | grep ${ip}`;
    
    exec(listCommand, { timeout: 5000 }, (error, stdout, stderr) => {
      if (error || !stdout.trim()) {
        // No rules found, continue
        callback();
        return;
      }
      
      // Parse line numbers and remove rules (from highest to lowest to maintain numbering)
      const lines = stdout.trim().split('\n');
      const lineNumbers = lines.map(line => {
        const match = line.match(/^(\d+)/);
        return match ? parseInt(match[1]) : null;
      }).filter(num => num !== null).sort((a, b) => b - a); // Sort descending
      
      let removedCount = 0;
      
      if (lineNumbers.length === 0) {
        callback();
        return;
      }
      
      lineNumbers.forEach((lineNum, index) => {
        const removeCommand = `${sudoPrefix}iptables -D INPUT ${lineNum}`;
        exec(removeCommand, { timeout: 5000 }, (error) => {
          removedCount++;
          if (removedCount === lineNumbers.length) {
            console.log(`🧹 Removed ${lineNumbers.length} iptables rules for IP: ${ip}`);
            callback();
          }
        });
      });
    });
  }

  // Apply traffic shaping - Now uses cyclic blocking
  applyTrafficShaping(ip, delayMs, sudoPrefix) {
    console.log(`🔧 Applying cyclic blocking throttling for IP: ${ip} with ${delayMs}ms intervals`);
    
    this.startCyclicThrottling(ip, delayMs, sudoPrefix);
  }

  // Unused methods - kept for compatibility but redirect to cyclic throttling
  applyDirectNetemThrottling(ip, delayMs, networkInterface, sudoPrefix) {
    console.log(`🔧 Redirecting to cyclic throttling for ${ip}: ${delayMs}ms`);
    this.startCyclicThrottling(ip, delayMs, sudoPrefix);
  }

  applyInterfaceWideThrottling(ip, delayMs, networkInterface, sudoPrefix) {
    console.log(`🔧 Redirecting to cyclic throttling for ${ip}: ${delayMs}ms`);
    this.startCyclicThrottling(ip, delayMs, sudoPrefix);
  }

  applyHTBBasedThrottling(ip, delayMs, networkInterface, sudoPrefix) {
    console.log(`🔧 Setting up HTB-based throttling for ${ip}: ${delayMs}ms`);
    
    // Step 1: Create a simple HTB root qdisc
    const setupRoot = `${sudoPrefix}tc qdisc add dev ${networkInterface} root handle 1: htb default 30`;
    
    exec(setupRoot, { timeout: 5000 }, (rootError) => {
      if (rootError && !rootError.message.includes('exists')) {
        console.log(`⚠️ Could not setup HTB root, trying prio: ${rootError.message}`);
        this.applyPrioBasedThrottling(ip, delayMs, networkInterface, sudoPrefix);
        return;
      }
      
      // Step 2: Create a class for throttled traffic
      const classId = this.ipToClassId(ip);
      const createClass = `${sudoPrefix}tc class add dev ${networkInterface} parent 1: classid 1:${classId} htb rate 10mbit ceil 10mbit`;
      
      exec(createClass, { timeout: 5000 }, (classError) => {
        // Step 3: Add netem delay to this class
        const addNetem = `${sudoPrefix}tc qdisc add dev ${networkInterface} parent 1:${classId} handle ${classId}0: netem delay ${delayMs}ms`;
        
        exec(addNetem, { timeout: 5000 }, (netemError) => {
          if (netemError) {
            console.log(`⚠️ Netem failed, trying simpler approach: ${netemError.message}`);
            this.applyPrioBasedThrottling(ip, delayMs, networkInterface, sudoPrefix);
            return;
          }
          
          // Step 4: Add filter to direct traffic from/to this IP to the delayed class
          this.addTrafficFilters(ip, networkInterface, classId, sudoPrefix);
        });
      });
    });
  }

  applyPrioBasedThrottling(ip, delayMs, networkInterface, sudoPrefix) {
    console.log(`🔧 Setting up comprehensive priority-based throttling for ${ip}: ${delayMs}ms`);
    
    // Clean up existing rules first
    exec(`${sudoPrefix}tc qdisc del dev ${networkInterface} root 2>/dev/null`, () => {
      
      // Use a comprehensive approach that catches ALL packets
      const setupPrio = `${sudoPrefix}tc qdisc add dev ${networkInterface} root handle 1: prio bands 4 priomap 0 1 2 3 0 1 2 3 0 1 2 3 0 1 2 3`;
      
      exec(setupPrio, { timeout: 5000 }, (prioError) => {
        if (prioError) {
          console.log(`❌ Priority qdisc failed: ${prioError.message}`);
          return;
        }
        
        // Add netem delay to ALL bands that might handle this traffic
        const addNetem1 = `${sudoPrefix}tc qdisc add dev ${networkInterface} parent 1:1 handle 10: netem delay ${delayMs}ms`;
        const addNetem2 = `${sudoPrefix}tc qdisc add dev ${networkInterface} parent 1:2 handle 20: netem delay ${delayMs}ms`;
        const addNetem3 = `${sudoPrefix}tc qdisc add dev ${networkInterface} parent 1:3 handle 30: netem delay ${delayMs}ms`;
        
        exec(addNetem1, { timeout: 5000 }, (netem1Error) => {
          exec(addNetem2, { timeout: 5000 }, (netem2Error) => {
            exec(addNetem3, { timeout: 5000 }, (netem3Error) => {
              
              // Add comprehensive filters that catch packets in both directions and all protocols
              this.addComprehensiveFilters(ip, networkInterface, sudoPrefix);
              
            });
          });
        });
      });
    });
  }

  addComprehensiveFilters(ip, networkInterface, sudoPrefix) {
    console.log(`🔧 Adding comprehensive filters for ${ip} on ${networkInterface}`);
    
    // Add multiple filters to catch all possible packet paths
    const filters = [
      // ICMP packets (ping)
      `${sudoPrefix}tc filter add dev ${networkInterface} protocol ip parent 1: prio 1 u32 match ip src ${ip} match ip protocol 1 0xff flowid 1:1`,
      `${sudoPrefix}tc filter add dev ${networkInterface} protocol ip parent 1: prio 1 u32 match ip dst ${ip} match ip protocol 1 0xff flowid 1:1`,
      
      // TCP packets  
      `${sudoPrefix}tc filter add dev ${networkInterface} protocol ip parent 1: prio 2 u32 match ip src ${ip} match ip protocol 6 0xff flowid 1:2`,
      `${sudoPrefix}tc filter add dev ${networkInterface} protocol ip parent 1: prio 2 u32 match ip dst ${ip} match ip protocol 6 0xff flowid 1:2`,
      
      // UDP packets
      `${sudoPrefix}tc filter add dev ${networkInterface} protocol ip parent 1: prio 3 u32 match ip src ${ip} match ip protocol 17 0xff flowid 1:3`,
      `${sudoPrefix}tc filter add dev ${networkInterface} protocol ip parent 1: prio 3 u32 match ip dst ${ip} match ip protocol 17 0xff flowid 1:3`,
      
      // Catch-all for any remaining packets
      `${sudoPrefix}tc filter add dev ${networkInterface} protocol ip parent 1: prio 4 u32 match ip src ${ip} flowid 1:1`,
      `${sudoPrefix}tc filter add dev ${networkInterface} protocol ip parent 1: prio 4 u32 match ip dst ${ip} flowid 1:1`
    ];
    
    let successCount = 0;
    let totalFilters = filters.length;
    
    filters.forEach((filterCmd, index) => {
      exec(filterCmd, { timeout: 5000 }, (error) => {
        if (!error) successCount++;
        
        // When all filters are processed
        if (index === totalFilters - 1) {
          console.log(`⏱️ Comprehensive throttling applied for IP ${ip} with ${delayMs}ms delay`);
          console.log(`📊 Filter success: ${successCount}/${totalFilters} filters applied`);
          
          // Test the setup
          setTimeout(() => {
            this.testThrottlingSetup(networkInterface, sudoPrefix);
          }, 2000);
        }
      });
    });
  }

  addTrafficFilters(ip, networkInterface, classId, sudoPrefix) {
    // Add filters to match traffic to/from the specific IP
    const filter1 = `${sudoPrefix}tc filter add dev ${networkInterface} protocol ip parent 1: prio 1 u32 match ip src ${ip} flowid 1:${classId}`;
    const filter2 = `${sudoPrefix}tc filter add dev ${networkInterface} protocol ip parent 1: prio 1 u32 match ip dst ${ip} flowid 1:${classId}`;
    
    exec(filter1, { timeout: 5000 }, (f1Error) => {
      exec(filter2, { timeout: 5000 }, (f2Error) => {
        console.log(`⏱️ HTB-based throttling applied for IP ${ip}`);
        console.log(`📊 Filter results: src=${f1Error ? 'FAILED' : 'OK'}, dst=${f2Error ? 'FAILED' : 'OK'}`);
        
        if (f1Error) console.log(`   src filter error: ${f1Error.message}`);
        if (f2Error) console.log(`   dst filter error: ${f2Error.message}`);
        
        // Test the setup
        setTimeout(() => {
          this.testThrottlingSetup(networkInterface, sudoPrefix);
        }, 2000);
      });
    });
  }

  cleanupTrafficControlForInterface(networkInterface, sudoPrefix) {
    // Clean up any existing tc rules
    exec(`${sudoPrefix}tc qdisc del dev ${networkInterface} root 2>/dev/null`, () => {
      // Ignore errors
    });
  }

  // Alternative throttling approach using iptables with more aggressive rate limiting
  applyAlternativeThrottling(ip, delayMs, sudoPrefix) {
    console.log(`🔧 Applying aggressive iptables-based throttling for ${ip}: ${delayMs}ms delay`);
    
    // Convert delay to a very strict rate limit for consistent delays
    // For ping packets, we want to severely limit the rate to simulate delay
    const packetsPerSecond = Math.max(1, Math.floor(500 / delayMs)); // More aggressive calculation
    const burstSize = 1; // Very small burst to ensure consistent delays
    
    // Use iptables with hashlimit module for very strict rate limiting
    const rateLimitRule = `${sudoPrefix}iptables -I INPUT -s ${ip} -m hashlimit --hashlimit-above ${packetsPerSecond}/sec --hashlimit-burst ${burstSize} --hashlimit-mode srcip --hashlimit-name throttle_${ip.replace(/\./g, '_')} -j DROP`;
    
    exec(rateLimitRule, { timeout: 5000 }, (rateLimitError) => {
      if (rateLimitError) {
        console.log(`⚠️ Rate limiting failed: ${rateLimitError.message}`);
        this.applyConnectionBasedThrottling(ip, delayMs, sudoPrefix);
      } else {
        console.log(`⏱️ Aggressive rate limiting applied for IP ${ip}: max ${packetsPerSecond} packets/sec (burst: ${burstSize})`);
      }
    });
    
    // Also apply OUTPUT rate limiting with the same aggressive settings
    const outputRateLimitRule = `${sudoPrefix}iptables -I OUTPUT -d ${ip} -m hashlimit --hashlimit-above ${packetsPerSecond}/sec --hashlimit-burst ${burstSize} --hashlimit-mode dstip --hashlimit-name throttle_out_${ip.replace(/\./g, '_')} -j DROP`;
    
    exec(outputRateLimitRule, { timeout: 5000 }, (outputError) => {
      if (!outputError) {
        console.log(`⏱️ Aggressive output rate limiting applied for IP ${ip}: max ${packetsPerSecond} packets/sec`);
      }
    });

    // Add additional ICMP-specific throttling for ping packets
    this.applyICMPThrottling(ip, delayMs, sudoPrefix);
  }

  // Cyclic blocking throttling - blocks for X seconds, then unblocks for X seconds
  applySimpleIptablesThrottling(ip, delayMs, sudoPrefix) {
    console.log(`� Setting up cyclic blocking throttling for ${ip}: ${delayMs}ms intervals`);
    
    // Clean up any existing rules and intervals for this IP first
    this.cleanupIptablesRulesForIP(ip, sudoPrefix);
    this.stopCyclicThrottling(ip);
    
    // Initialize cyclic intervals storage if not exists
    if (!this.cyclicIntervals) {
      this.cyclicIntervals = {};
    }
    
    const intervalKey = `cyclic_${ip.replace(/\./g, '_')}`;
    let isBlocked = false;
    
    // Function to toggle block/unblock
    const toggleBlock = () => {
      if (isBlocked) {
        // Unblock: Remove DROP rule
        const unblockCmd = `${sudoPrefix}iptables -D INPUT -s ${ip} -j DROP 2>/dev/null || true`;
        exec(unblockCmd, { timeout: 3000 }, (error) => {
          console.log(`🔓 Unblocked ${ip} for ${delayMs}ms (allowing traffic)`);
        });
        isBlocked = false;
      } else {
        // Block: Add DROP rule
        const blockCmd = `${sudoPrefix}iptables -I INPUT -s ${ip} -j DROP`;
        exec(blockCmd, { timeout: 3000 }, (error) => {
          if (!error) {
            console.log(`🔒 Blocked ${ip} for ${delayMs}ms (dropping packets)`);
          } else {
            console.log(`⚠️ Block failed for ${ip}: ${error.message}`);
          }
        });
        isBlocked = true;
      }
    };
    
    // Start the cycling interval
    this.cyclicIntervals[intervalKey] = setInterval(toggleBlock, delayMs);
    
    // Start with unblocked state, then block after a short delay
    setTimeout(toggleBlock, 500);
  }

  applyICMPThrottling(ip, packetsPerSecond, intervalSeconds, sudoPrefix) {
    console.log(`🎯 Applying ICMP throttling for ${ip}: ${packetsPerSecond} packets per ${intervalSeconds}s`);
    
    // Use a very simple approach - for high delays, use very low rates
    let limitString = "1/second"; // Default to 1 per second
    
    if (intervalSeconds >= 5) {
      limitString = "1/minute"; // Very slow for long delays
    } else if (intervalSeconds >= 2) {
      limitString = "1/second"; // 1 per second for medium delays
    } else {
      limitString = `${Math.min(5, packetsPerSecond)}/second`; // Max 5 per second
    }
    
    console.log(`🎯 Using simple iptables limit: ${limitString}`);
    
    // ICMP INPUT throttling (ping responses TO us FROM the target IP)
    const icmpInputRule = `${sudoPrefix}iptables -A INPUT -s ${ip} -p icmp -m limit --limit ${limitString} --limit-burst 1 -j ACCEPT`;
    const icmpInputDrop = `${sudoPrefix}iptables -A INPUT -s ${ip} -p icmp -j DROP`;
    
    // ICMP OUTPUT throttling (ping requests FROM us TO the target IP)  
    const icmpOutputRule = `${sudoPrefix}iptables -A OUTPUT -d ${ip} -p icmp -m limit --limit ${limitString} --limit-burst 1 -j ACCEPT`;
    const icmpOutputDrop = `${sudoPrefix}iptables -A OUTPUT -d ${ip} -p icmp -j DROP`;
    
    // Apply the rules (accept first with limit, then drop the rest)
    exec(icmpInputRule, { timeout: 5000 }, (error1) => {
      exec(icmpInputDrop, { timeout: 5000 }, (error2) => {
        exec(icmpOutputRule, { timeout: 5000 }, (error3) => {
          exec(icmpOutputDrop, { timeout: 5000 }, (error4) => {
            const errors = [error1, error2, error3, error4].filter(e => e);
            if (errors.length === 0) {
              console.log(`✅ ICMP throttling rules applied successfully for ${ip}`);
            } else {
              console.log(`⚠️ Some ICMP rules failed: ${errors.length}/4 errors`);
              errors.forEach(err => console.log(`   Error: ${err.message}`));
            }
            
            // Show what rules were actually applied
            setTimeout(() => {
              exec(`${sudoPrefix}iptables -L INPUT -n | grep ${ip}`, { timeout: 3000 }, (error, stdout) => {
                if (!error && stdout) {
                  console.log(`🔍 Applied INPUT rules for ${ip}:`);
                  console.log(stdout);
                }
              });
            }, 1000);
          });
        });
      });
    });
  }

  applyGeneralTrafficThrottling(ip, packetsPerSecond, intervalSeconds, sudoPrefix) {
    console.log(`🌐 Applying general traffic throttling for ${ip}`);
    
    // Use simple rate limiting for all traffic
    let limitString = "2/second"; // Default
    
    if (intervalSeconds >= 5) {
      limitString = "5/minute"; // Very slow for long delays
    } else if (intervalSeconds >= 2) {
      limitString = "2/second"; // Moderate for medium delays  
    } else {
      limitString = `${Math.min(10, packetsPerSecond * 2)}/second`; // Higher rate for general traffic
    }
    
    // General INPUT throttling (all traffic FROM the target IP)
    const inputRule = `${sudoPrefix}iptables -A INPUT -s ${ip} -m limit --limit ${limitString} --limit-burst 3 -j ACCEPT`;
    const inputDrop = `${sudoPrefix}iptables -A INPUT -s ${ip} -j DROP`;
    
    // General OUTPUT throttling (all traffic TO the target IP)
    const outputRule = `${sudoPrefix}iptables -A OUTPUT -d ${ip} -m limit --limit ${limitString} --limit-burst 3 -j ACCEPT`;
    const outputDrop = `${sudoPrefix}iptables -A OUTPUT -d ${ip} -j DROP`;
    
    exec(inputRule, { timeout: 5000 }, () => {
      exec(inputDrop, { timeout: 5000 }, () => {
        exec(outputRule, { timeout: 5000 }, () => {
          exec(outputDrop, { timeout: 5000 }, () => {
            console.log(`✅ General traffic throttling applied for ${ip}`);
          });
        });
      });
    });
  }

  startCyclicThrottling(ip, delayMs, sudoPrefix) {
    // Initialize cyclic intervals storage if not exists
    if (!this.cyclicIntervals) {
      this.cyclicIntervals = {};
    }
    
    const intervalKey = `cyclic_${ip.replace(/\./g, '_')}`;
    
    // Clear any existing interval for this IP
    if (this.cyclicIntervals[intervalKey]) {
      clearInterval(this.cyclicIntervals[intervalKey]);
    }
    
    let isBlocked = false;
    
    // Function to toggle block/unblock
    const toggleBlock = () => {
      if (isBlocked) {
        // Unblock: Remove DROP rule
        const unblockCmd = `${sudoPrefix}iptables -D INPUT -s ${ip} -j DROP 2>/dev/null`;
        exec(unblockCmd, { timeout: 3000 }, () => {
          // IP unblocked
        });
        isBlocked = false;
      } else {
        // Block: Add DROP rule
        const blockCmd = `${sudoPrefix}iptables -I INPUT -s ${ip} -j DROP`;
        exec(blockCmd, { timeout: 3000 }, (error) => {
          // IP blocked
        });
        isBlocked = true;
      }
    };
    
    // Start the cycling
    this.cyclicIntervals[intervalKey] = setInterval(toggleBlock, delayMs);
    
    // Start with first block after a short delay
    setTimeout(toggleBlock, 500);
  }

  stopCyclicThrottling(ip) {
    if (!this.cyclicIntervals) return;
    
    const intervalKey = `cyclic_${ip.replace(/\./g, '_')}`;
    
    if (this.cyclicIntervals[intervalKey]) {
      clearInterval(this.cyclicIntervals[intervalKey]);
      delete this.cyclicIntervals[intervalKey];
    }
  }

  cleanupIptablesRulesForIP(ip, sudoPrefix) {
    console.log(`🧹 Cleaning up existing iptables rules for ${ip}`);
    
    // Stop any cyclic throttling for this IP
    this.stopCyclicThrottling(ip);
    
    // Remove any existing rules for this IP (ignore errors)
    const cleanupCommands = [
      `${sudoPrefix}iptables -D INPUT -s ${ip} -p icmp -j DROP 2>/dev/null || true`,
      `${sudoPrefix}iptables -D INPUT -s ${ip} -p icmp -m limit -j ACCEPT 2>/dev/null || true`,
      `${sudoPrefix}iptables -D OUTPUT -d ${ip} -p icmp -j DROP 2>/dev/null || true`,
      `${sudoPrefix}iptables -D OUTPUT -d ${ip} -p icmp -m limit -j ACCEPT 2>/dev/null || true`,
      `${sudoPrefix}iptables -D INPUT -s ${ip} -j DROP 2>/dev/null || true`,
      `${sudoPrefix}iptables -D INPUT -s ${ip} -m limit -j ACCEPT 2>/dev/null || true`,
      `${sudoPrefix}iptables -D OUTPUT -d ${ip} -j DROP 2>/dev/null || true`,
      `${sudoPrefix}iptables -D OUTPUT -d ${ip} -m limit -j ACCEPT 2>/dev/null || true`
    ];
    
    cleanupCommands.forEach(cmd => {
      exec(cmd, { timeout: 3000 }, () => {
        // Ignore all errors during cleanup
      });
    });
  }

  // Connection-based throttling using iptables connlimit
  applyConnectionBasedThrottling(ip, delayMs, sudoPrefix) {
    console.log(`🔧 Applying connection-based throttling for ${ip}`);
    
    // Limit concurrent connections based on delay
    const maxConnections = Math.max(1, Math.floor(10000 / delayMs));
    
    const connLimitRule = `${sudoPrefix}iptables -A INPUT -s ${ip} -m connlimit --connlimit-above ${maxConnections} -j REJECT --reject-with tcp-reset`;
    
    exec(connLimitRule, { timeout: 5000 }, (connError) => {
      if (connError) {
        console.log(`⚠️ Connection throttling failed: ${connError.message}`);
        console.log(`🔧 Falling back to application-level throttling only`);
      } else {
        console.log(`⏱️ Connection-based throttling applied for IP ${ip}: max ${maxConnections} connections`);
      }
    });
  }

  // Remove traffic shaping - Simplified for cyclic blocking
  removeTrafficShaping(ip, sudoPrefix) {
    console.log(`🔧 Removing throttling for IP: ${ip}`);
    
    // Stop cyclic throttling and remove any blocking rules
    this.stopCyclicThrottling(ip);
    
    // Remove any remaining DROP rules for this IP
    const unblockCommand = `${sudoPrefix}iptables -D INPUT -s ${ip} -j DROP 2>/dev/null || true`;
    exec(unblockCommand, { timeout: 5000 }, () => {
      console.log(`⏱️ Throttling completely removed for IP: ${ip}`);
    });
  }

  showCurrentIptablesRules(sudoPrefix) {
    exec(`${sudoPrefix}iptables -L INPUT -n --line-numbers | head -20`, { timeout: 5000 }, (error, stdout) => {
      if (!error && stdout) {
        console.log(`🔍 Current INPUT rules (first 20):`);
        console.log(stdout);
      }
    });
    
    exec(`${sudoPrefix}iptables -L OUTPUT -n --line-numbers | head -20`, { timeout: 5000 }, (error, stdout) => {
      if (!error && stdout) {
        console.log(`🔍 Current OUTPUT rules (first 20):`);
        console.log(stdout);
      }
    });
  }

  // Convert IP address to a unique class ID (simplified)
  ipToClassId(ip) {
    const parts = ip.split('.');
    return parseInt(parts[parts.length - 1]) + 100; // Simple mapping using last octet
  }

  // Convert IP address to a unique handle for tc
  ipToHandle(ip) {
    const parts = ip.split('.');
    return parseInt(parts[parts.length - 1]) + 200; // Different range from classId
  }

  // Convert IP address to a unique mark for iptables
  ipToMark(ip) {
    const parts = ip.split('.');
    return parseInt(parts[parts.length - 1]) + 1000; // Different range for marks
  }

  // Convert IP address to a unique mark value (same as ipToMark but clearer name)
  ipToMarkValue(ip) {
    return this.ipToMark(ip);
  }

  // Test if throttling setup is working
  testThrottlingSetup(networkInterface, sudoPrefix) {
    const testCommand = `${sudoPrefix}tc qdisc show dev ${networkInterface}`;
    exec(testCommand, { timeout: 5000 }, (error, stdout, stderr) => {
      if (error) {
        console.log(`⚠️ Could not verify throttling setup: ${error.message}`);
      } else {
        console.log(`🔍 Traffic control status for ${networkInterface}:`);
        console.log(stdout);
      }
    });
  }

  // Determine which network interface an IP routes through
  getInterfaceForIP(ip, callback) {
    const routeCommand = `ip route get ${ip}`;
    exec(routeCommand, { timeout: 3000 }, (error, stdout, stderr) => {
      if (error) {
        console.log(`⚠️ Could not determine route for ${ip}: ${error.message}`);
        callback(null);
        return;
      }
      
      // Parse the output to extract the interface name
      // Example output: "8.8.8.8 via 192.168.1.1 dev wlo1 src 192.168.1.4"
      const match = stdout.match(/dev\s+(\w+)/);
      if (match && match[1]) {
        const interfaceName = match[1];
        console.log(`🔍 IP ${ip} routes through interface: ${interfaceName}`);
        callback(interfaceName);
      } else {
        console.log(`⚠️ Could not parse interface from route output: ${stdout}`);
        callback(null);
      }
    });
  }

  // Get the primary network interface (not loopback)
  getPrimaryNetworkInterface() {
    // Try to find the interface from our stored network interfaces
    for (const iface of this.networkInterfaces) {
      if (iface.name !== 'lo' && !iface.name.startsWith('virbr') && !iface.name.startsWith('docker')) {
        return iface.name;
      }
    }
    
    // Fallback: try common interface names
    const commonInterfaces = ['eth0', 'wlan0', 'wlo1', 'enp0s3', 'ens33'];
    for (const ifaceName of commonInterfaces) {
      try {
        const interfaces = require('os').networkInterfaces();
        if (interfaces[ifaceName]) {
          return ifaceName;
        }
      } catch (error) {
        // Continue to next interface
      }
    }
    
    return null;
  }

  // Debug method to show current traffic control rules
  debugTrafficControl(interfaceName, sudoPrefix) {
    console.log(`🔍 Debugging traffic control rules on ${interfaceName}:`);
    
    // Show tc qdisc rules
    exec(`${sudoPrefix}tc qdisc show dev ${interfaceName}`, { timeout: 5000 }, (error, stdout) => {
      if (!error && stdout.trim()) {
        console.log('📋 tc qdisc rules:');
        console.log(stdout);
      }
    });
    
    exec(`${sudoPrefix}tc class show dev ${interfaceName}`, { timeout: 5000 }, (error, stdout) => {
      if (!error && stdout.trim()) {
        console.log('📋 tc class rules:');
        console.log(stdout);
      }
    });
    
    exec(`${sudoPrefix}tc filter show dev ${interfaceName}`, { timeout: 5000 }, (error, stdout) => {
      if (!error && stdout.trim()) {
        console.log('📋 tc filter rules:');
        console.log(stdout);
      }
    });
    
    // Test with ping to see if delay is working
    setTimeout(() => {
      console.log('🧪 Testing if traffic control is working...');
      console.log('💡 Try: ping [throttled_ip] to test delays');
      console.log('💡 Or: curl -w "@timing.txt" http://[throttled_ip] (if it\'s a web server)');
    }, 2000);
  }

  // Clean up any existing NetGuardian iptables and traffic control rules
  cleanupSystemRules() {
    if (os.platform() !== 'linux') return;

    const isRoot = process.getuid && process.getuid() === 0;
    const sudoPrefix = isRoot ? '' : 'sudo ';

    // Clean up iptables rules
    const listCommand = `${sudoPrefix}iptables -L INPUT --line-numbers -n`;
    exec(listCommand, { timeout: 10000 }, (error, stdout, stderr) => {
      if (error) {
        console.log('⚠️  Could not list iptables rules for cleanup (may need sudo)');
        return;
      }

      // Parse output to find rules that drop specific IPs (our rules)
      const lines = stdout.split('\n');
      const rulesToRemove = [];

      lines.forEach((line, index) => {
        // Look for DROP rules with specific source IPs
        if (line.includes('DROP') && line.includes('/32')) {
          const match = line.match(/(\d+)\s+DROP\s+all\s+--\s+(\d+\.\d+\.\d+\.\d+)/);
          if (match) {
            rulesToRemove.push({
              lineNumber: parseInt(match[1]),
              ip: match[2]
            });
          }
        }
      });

      // Remove rules in reverse order (highest line number first)
      rulesToRemove.sort((a, b) => b.lineNumber - a.lineNumber);
      
      if (rulesToRemove.length > 0) {
        console.log(`🧹 Cleaning up ${rulesToRemove.length} existing IP blocking rules...`);
        rulesToRemove.forEach(rule => {
          const removeCommand = `${sudoPrefix}iptables -D INPUT ${rule.lineNumber}`;
          exec(removeCommand, { timeout: 5000 }, (error) => {
            if (!error) {
              console.log(`🧹 Removed old iptables rule for IP: ${rule.ip}`);
            }
          });
        });
      }
    });

    // Clean up traffic control rules on primary interface
    const primaryInterface = this.getPrimaryNetworkInterface();
    if (primaryInterface) {
      const tcCleanupCommands = [
        `${sudoPrefix}tc qdisc del dev ${primaryInterface} root 2>/dev/null || true`,
        `${sudoPrefix}tc qdisc del dev ${primaryInterface} ingress 2>/dev/null || true`,
        `${sudoPrefix}tc qdisc del dev ifb0 root 2>/dev/null || true`
      ];
      
      tcCleanupCommands.forEach((command, index) => {
        exec(command, { timeout: 5000 }, (error) => {
          if (!error && index === 0) {
            console.log(`🧹 Cleaned up existing traffic control rules on ${primaryInterface}`);
          }
        });
      });
    }
  }

  // Apply all active blocking rules at startup
  initializeSystemBlocking() {
    try {
      // Clean up any existing rules first
      this.cleanupSystemRules();

      // Wait a bit for cleanup to complete, then apply new rules
      setTimeout(() => {
        const blockedIps = this.database.getActiveBlockedIps();
        
        blockedIps.forEach(ip => {
          this.applySystemLevelTrafficControl(ip, 'block');
        });
        
        // Also apply throttling rules
        const throttledIps = this.database.getActiveThrottledIps();
        throttledIps.forEach(({ip, delay}) => {
          this.applySystemLevelTrafficControl(ip, 'throttle', delay);
        });
      }, 2000);
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

  shutdown() {
    console.log('🔄 Shutting down Packet Monitor Server...');
    
    // Stop monitoring if active
    if (this.isMonitoring) {
      this.stopMonitoring();
    }
    
    // Close databases
    if (this.database) {
      this.database.close();
      console.log('✓ Packet database closed');
    }
    
    if (this.chatDatabase) {
      this.chatDatabase.close();
      console.log('✓ Chat database closed');
    }
    
    // Close server
    this.server.close(() => {
      console.log('✓ Server shutdown complete');
    });
  }
}

// Start the server
const monitor = new PacketMonitor(3001);
monitor.start();

// Graceful shutdown handling
process.on('SIGINT', () => {
  console.log('\n🛑 Received SIGINT. Gracefully shutting down...');
  monitor.shutdown();
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Received SIGTERM. Gracefully shutting down...');
  monitor.shutdown();
  process.exit(0);
});

module.exports = PacketMonitor;