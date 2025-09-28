import { io, Socket } from 'socket.io-client';

class ServerDatabaseService {
  private socket: Socket | null = null;
  private serverUrl = 'http://localhost:3001';
  private connectionPromise: Promise<void> | null = null;

  constructor() {
    this.connectionPromise = this.connect();
  }

  private async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      console.log('Server-side: Attempting to connect to database service...');
      
      this.socket = io(this.serverUrl, {
        transports: ['polling', 'websocket'], // Ensure compatibility
        timeout: 10000,
        forceNew: true
      });
      
      this.socket.on('connect', () => {
        console.log('Server-side: Successfully connected to database service');
        resolve();
      });

      this.socket.on('disconnect', () => {
        console.log('Server-side: Disconnected from database service');
      });

      this.socket.on('connect_error', (error) => {
        console.error('Server-side: Connection error:', error.message);
        reject(error);
      });

      // Set a timeout for connection
      setTimeout(() => {
        if (!this.socket?.connected) {
          console.error('Server-side: Connection timeout after 10 seconds');
          reject(new Error('Connection timeout'));
        }
      }, 10000);
    });
  }

  private async ensureConnection(): Promise<void> {
    if (this.connectionPromise) {
      await this.connectionPromise;
    }
  }

  // Chat operations
  async getChatConversations(): Promise<any[]> {
    await this.ensureConnection();
    
    return new Promise((resolve) => {
      if (!this.socket) {
        resolve([]);
        return;
      }

      this.socket.emit('get-chat-conversations');
      this.socket.once('chat-conversations-data', (conversations) => {
        resolve(conversations);
      });

      // Timeout fallback
      setTimeout(() => resolve([]), 5000);
    });
  }

  async createChatConversation(conversation: any): Promise<boolean> {
    await this.ensureConnection();
    
    return new Promise((resolve) => {
      if (!this.socket) {
        resolve(false);
        return;
      }

      this.socket.emit('create-chat-conversation', conversation);
      this.socket.once('chat-conversation-created', (success) => {
        resolve(success);
      });

      // Timeout fallback
      setTimeout(() => resolve(false), 5000);
    });
  }

  async insertChatMessage(message: any): Promise<boolean> {
    await this.ensureConnection();
    
    return new Promise((resolve) => {
      if (!this.socket) {
        resolve(false);
        return;
      }

      this.socket.emit('insert-chat-message', message);
      this.socket.once('chat-message-inserted', (success) => {
        resolve(success);
      });

      // Timeout fallback
      setTimeout(() => resolve(false), 5000);
    });
  }

  async deleteChatConversation(conversationId: string): Promise<boolean> {
    await this.ensureConnection();
    
    return new Promise((resolve) => {
      if (!this.socket) {
        resolve(false);
        return;
      }

      this.socket.emit('delete-chat-conversation', conversationId);
      this.socket.once('chat-conversation-deleted', (success) => {
        resolve(success);
      });

      // Timeout fallback
      setTimeout(() => resolve(false), 5000);
    });
  }

  async updateChatConversation(conversationId: string, updates: any): Promise<boolean> {
    await this.ensureConnection();
    
    return new Promise((resolve) => {
      if (!this.socket) {
        resolve(false);
        return;
      }

      this.socket.emit('update-chat-conversation', { conversationId, updates });
      this.socket.once('chat-conversation-updated', (success) => {
        resolve(success);
      });

      // Timeout fallback
      setTimeout(() => resolve(false), 5000);
    });
  }

  // Packet operations for IP analysis
  async getPackets(options: { limit?: number; offset?: number; ip?: string } = {}): Promise<any[]> {
    await this.ensureConnection();
    
    return new Promise((resolve) => {
      if (!this.socket) {
        resolve([]);
        return;
      }

      this.socket.emit('get-packets', options);
      this.socket.once('packets-data', (packets) => {
        resolve(packets);
      });

      // Timeout fallback
      setTimeout(() => resolve([]), 5000);
    });
  }

  // Disconnect
  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
  }
}

// Export singleton instance for server-side use
let serverDatabaseService: ServerDatabaseService | null = null;

export function getServerDatabaseService(): ServerDatabaseService {
  if (!serverDatabaseService) {
    serverDatabaseService = new ServerDatabaseService();
  }
  return serverDatabaseService;
}

export default ServerDatabaseService;