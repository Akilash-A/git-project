const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

class PacketDatabase {
  constructor() {
    // Create database directory if it doesn't exist
    const dbDir = path.join(__dirname, '../data');
    if (!fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
    }
    
    // Initialize database
    this.db = new Database(path.join(dbDir, 'packets.db'));
    this.initializeTables();
    
    console.log('✓ Database initialized successfully');
  }

  initializeTables() {
    // Create packets table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS packets (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        destination_ip TEXT NOT NULL,
        protocol TEXT NOT NULL,
        port INTEGER NOT NULL,
        size INTEGER NOT NULL,
        direction TEXT NOT NULL,
        attack_type TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create alerts table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        message TEXT NOT NULL,
        ip TEXT NOT NULL,
        type TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create whitelist table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE NOT NULL,
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create security analysis table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS security_analysis (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        danger_score INTEGER NOT NULL,
        classification TEXT NOT NULL,
        analysis_text TEXT,
        source TEXT NOT NULL, -- 'manual' or 'auto'
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create settings table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create indexes for better performance
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_packets_source_ip ON packets(source_ip)`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(ip)`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_security_analysis_ip ON security_analysis(ip)`);
  }

  // Packet operations
  insertPacket(packet) {
    const stmt = this.db.prepare(`
      INSERT INTO packets (id, timestamp, source_ip, destination_ip, protocol, port, size, direction, attack_type)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    try {
      stmt.run(
        packet.id,
        packet.timestamp,
        packet.sourceIp,
        packet.destinationIp,
        packet.protocol,
        packet.port,
        packet.size,
        packet.direction,
        packet.attackType || null
      );
    } catch (error) {
      console.error('Error inserting packet:', error.message);
    }
  }

  getPackets(limit = 100, offset = 0) {
    const stmt = this.db.prepare(`
      SELECT id, timestamp, source_ip as sourceIp, destination_ip as destinationIp, 
             protocol, port, size, direction, attack_type as attackType
      FROM packets 
      ORDER BY timestamp DESC 
      LIMIT ? OFFSET ?
    `);
    return stmt.all(limit, offset);
  }

  getPacketsByIp(ip, limit = 50) {
    const stmt = this.db.prepare(`
      SELECT id, timestamp, source_ip as sourceIp, destination_ip as destinationIp, 
             protocol, port, size, direction, attack_type as attackType
      FROM packets 
      WHERE source_ip = ? OR destination_ip = ?
      ORDER BY timestamp DESC 
      LIMIT ?
    `);
    return stmt.all(ip, ip, limit);
  }

  deleteOldPackets(daysOld = 30) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysOld);
    
    const stmt = this.db.prepare(`
      DELETE FROM packets 
      WHERE datetime(timestamp) < datetime(?)
    `);
    const result = stmt.run(cutoffDate.toISOString());
    return result.changes;
  }

  // Alert operations
  insertAlert(alert) {
    const stmt = this.db.prepare(`
      INSERT INTO alerts (id, timestamp, message, ip, type)
      VALUES (?, ?, ?, ?, ?)
    `);
    
    try {
      stmt.run(alert.id, alert.timestamp, alert.message, alert.ip, alert.type);
    } catch (error) {
      console.error('Error inserting alert:', error.message);
    }
  }

  getAlerts(limit = 50, offset = 0) {
    const stmt = this.db.prepare(`
      SELECT id, timestamp, message, ip, type
      FROM alerts 
      ORDER BY timestamp DESC 
      LIMIT ? OFFSET ?
    `);
    return stmt.all(limit, offset);
  }

  deleteOldAlerts(daysOld = 7) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysOld);
    
    const stmt = this.db.prepare(`
      DELETE FROM alerts 
      WHERE datetime(timestamp) < datetime(?)
    `);
    const result = stmt.run(cutoffDate.toISOString());
    return result.changes;
  }

  // Whitelist operations
  addToWhitelist(ip, description = '') {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO whitelist (ip, description)
      VALUES (?, ?)
    `);
    
    try {
      stmt.run(ip, description);
      return true;
    } catch (error) {
      console.error('Error adding to whitelist:', error.message);
      return false;
    }
  }

  removeFromWhitelist(ip) {
    const stmt = this.db.prepare(`DELETE FROM whitelist WHERE ip = ?`);
    const result = stmt.run(ip);
    return result.changes > 0;
  }

  getWhitelist() {
    const stmt = this.db.prepare(`
      SELECT ip, description, created_at
      FROM whitelist 
      ORDER BY created_at DESC
    `);
    return stmt.all();
  }

  isWhitelisted(ip) {
    const stmt = this.db.prepare(`SELECT 1 FROM whitelist WHERE ip = ?`);
    return stmt.get(ip) !== undefined;
  }

  // Security analysis operations
  saveSecurityAnalysis(ip, dangerScore, classification, analysisText, source) {
    const stmt = this.db.prepare(`
      INSERT INTO security_analysis (ip, danger_score, classification, analysis_text, source)
      VALUES (?, ?, ?, ?, ?)
    `);
    
    try {
      const result = stmt.run(ip, dangerScore, classification, analysisText, source);
      return result.lastInsertRowid;
    } catch (error) {
      console.error('Error saving security analysis:', error.message);
      return null;
    }
  }

  getSecurityAnalysis(ip) {
    const stmt = this.db.prepare(`
      SELECT ip, danger_score, classification, analysis_text, source, created_at
      FROM security_analysis 
      WHERE ip = ?
      ORDER BY created_at DESC
      LIMIT 1
    `);
    return stmt.get(ip);
  }

  getAllSecurityAnalyses(limit = 100, offset = 0) {
    const stmt = this.db.prepare(`
      SELECT ip, danger_score, classification, analysis_text, source, created_at
      FROM security_analysis 
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `);
    return stmt.all(limit, offset);
  }

  // Statistics
  getStatistics() {
    const packetsCount = this.db.prepare(`SELECT COUNT(*) as count FROM packets`).get().count;
    const alertsCount = this.db.prepare(`SELECT COUNT(*) as count FROM alerts`).get().count;
    const whitelistCount = this.db.prepare(`SELECT COUNT(*) as count FROM whitelist`).get().count;
    const analysisCount = this.db.prepare(`SELECT COUNT(*) as count FROM security_analysis`).get().count;
    
    const lastHourPackets = this.db.prepare(`
      SELECT COUNT(*) as count FROM packets 
      WHERE datetime(timestamp) > datetime('now', '-1 hour')
    `).get().count;
    
    const uniqueIPs = this.db.prepare(`
      SELECT COUNT(DISTINCT source_ip) as count FROM packets
    `).get().count;

    return {
      totalPackets: packetsCount,
      totalAlerts: alertsCount,
      whitelistedIPs: whitelistCount,
      securityAnalyses: analysisCount,
      packetsLastHour: lastHourPackets,
      uniqueIPs: uniqueIPs
    };
  }

  // Settings operations
  setSetting(key, value) {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO settings (key, value, updated_at)
      VALUES (?, ?, CURRENT_TIMESTAMP)
    `);
    stmt.run(key, JSON.stringify(value));
  }

  getSetting(key, defaultValue = null) {
    const stmt = this.db.prepare(`SELECT value FROM settings WHERE key = ?`);
    const result = stmt.get(key);
    if (result) {
      try {
        return JSON.parse(result.value);
      } catch (error) {
        return result.value;
      }
    }
    return defaultValue;
  }

  getAllSettings() {
    const stmt = this.db.prepare(`SELECT key, value FROM settings`);
    const results = stmt.all();
    const settings = {};
    
    results.forEach(row => {
      try {
        settings[row.key] = JSON.parse(row.value);
      } catch (error) {
        settings[row.key] = row.value;
      }
    });
    
    return settings;
  }

  // Database maintenance
  clearAllData() {
    const tables = ['packets', 'alerts', 'security_analysis'];
    tables.forEach(table => {
      this.db.prepare(`DELETE FROM ${table}`).run();
    });
    
    // Reset auto-increment counters
    this.db.prepare(`DELETE FROM sqlite_sequence WHERE name IN ('security_analysis')`).run();
    
    return true;
  }

  clearTable(tableName) {
    const allowedTables = ['packets', 'alerts', 'security_analysis', 'whitelist'];
    if (!allowedTables.includes(tableName)) {
      throw new Error(`Table ${tableName} is not allowed to be cleared`);
    }
    
    const stmt = this.db.prepare(`DELETE FROM ${tableName}`);
    const result = stmt.run();
    return result.changes;
  }

  vacuum() {
    this.db.exec('VACUUM');
  }

  close() {
    this.db.close();
  }
}

module.exports = PacketDatabase;