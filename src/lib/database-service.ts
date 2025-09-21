import { io, Socket } from 'socket.io-client';

class DatabaseService {
  private socket: Socket | null = null;
  private serverUrl = 'http://localhost:3001';

  constructor() {
    this.connect();
  }

  private connect() {
    if (typeof window === 'undefined') return; // Only run on client side
    
    this.socket = io(this.serverUrl);
    
    this.socket.on('connect', () => {
      console.log('Connected to database service');
    });

    this.socket.on('disconnect', () => {
      console.log('Disconnected from database service');
    });
  }

  // Packet operations
  async getPackets(options: { limit?: number; offset?: number; ip?: string } = {}): Promise<any[]> {
    return new Promise((resolve) => {
      if (!this.socket) {
        resolve([]);
        return;
      }

      this.socket.emit('get-packets', options);
      this.socket.once('packets-data', (packets) => {
        resolve(packets);
      });
    });
  }

  // Alert operations
  async getAlerts(options: { limit?: number; offset?: number } = {}): Promise<any[]> {
    return new Promise((resolve) => {
      if (!this.socket) {
        resolve([]);
        return;
      }

      this.socket.emit('get-alerts', options);
      this.socket.once('alerts-data', (alerts) => {
        resolve(alerts);
      });
    });
  }

  // Whitelist operations
  async getWhitelist(): Promise<any[]> {
    return new Promise((resolve) => {
      if (!this.socket) {
        resolve([]);
        return;
      }

      this.socket.emit('get-whitelist');
      this.socket.once('whitelist-data', (whitelist) => {
        resolve(whitelist);
      });
    });
  }

  async addToWhitelist(ip: string, description: string): Promise<boolean> {
    return new Promise((resolve) => {
      if (!this.socket) {
        resolve(false);
        return;
      }

      this.socket.emit('add-to-whitelist', { ip, description });
      this.socket.once('whitelist-updated', (result) => {
        resolve(result.success);
      });
    });
  }

  async removeFromWhitelist(ip: string): Promise<boolean> {
    return new Promise((resolve) => {
      if (!this.socket) {
        resolve(false);
        return;
      }

      this.socket.emit('remove-from-whitelist', ip);
      this.socket.once('whitelist-updated', (result) => {
        resolve(result.success);
      });
    });
  }

  // Statistics
  async getStatistics(): Promise<any> {
    return new Promise((resolve) => {
      if (!this.socket) {
        resolve({
          totalPackets: 0,
          totalAlerts: 0,
          whitelistedIPs: 0,
          securityAnalyses: 0,
          packetsLastHour: 0,
          uniqueIPs: 0
        });
        return;
      }

      this.socket.emit('get-statistics');
      this.socket.once('statistics-data', (stats) => {
        resolve(stats);
      });
    });
  }

  // Data clearing operations
  async clearData(options: { table?: string; daysOld?: number } = {}): Promise<any> {
    return new Promise((resolve) => {
      if (!this.socket) {
        resolve({ success: false, message: 'Not connected to server' });
        return;
      }

      this.socket.emit('clear-data', options);
      this.socket.once('data-cleared', (result) => {
        resolve(result);
      });
    });
  }

  // Security analysis operations
  async saveSecurityAnalysis(data: {
    ip: string;
    dangerScore: number;
    classification: string;
    analysisText: string;
    source: string;
  }): Promise<boolean> {
    return new Promise((resolve) => {
      if (!this.socket) {
        resolve(false);
        return;
      }

      this.socket.emit('save-security-analysis', data);
      this.socket.once('security-analysis-saved', (result) => {
        resolve(result.success);
      });
    });
  }

  async getSecurityAnalysis(ip: string): Promise<any> {
    return new Promise((resolve) => {
      if (!this.socket) {
        resolve(null);
        return;
      }

      this.socket.emit('get-security-analysis', ip);
      this.socket.once('security-analysis-data', (result) => {
        resolve(result.analysis);
      });
    });
  }

  // Real-time packet streaming (existing functionality)
  onNewPacket(callback: (data: { packet: any; alert?: any }) => void) {
    if (!this.socket) return;
    this.socket.on('new-packet', callback);
  }

  offNewPacket(callback?: (data: { packet: any; alert?: any }) => void) {
    if (!this.socket) return;
    if (callback) {
      this.socket.off('new-packet', callback);
    } else {
      this.socket.off('new-packet');
    }
  }

  // Start/stop monitoring
  startMonitoring(options: any = {}) {
    if (!this.socket) return;
    this.socket.emit('start-monitoring', options);
  }

  stopMonitoring() {
    if (!this.socket) return;
    this.socket.emit('stop-monitoring');
  }

  // Disconnect
  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
  }
}

// Export singleton instance
const databaseService = new DatabaseService();
export default databaseService;