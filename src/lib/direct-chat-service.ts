import path from 'path';

interface ChatConversation {
  id: string;
  title: string;
  createdAt: string;
  updatedAt: string;
}

interface ChatMessage {
  id: string;
  conversationId: string;
  content: string;
  role: string;
  timestamp: string;
}

class DirectChatService {
  private chatDatabase: any;

  constructor() {
    try {
      // Try multiple possible paths for the ChatDatabase
      const possiblePaths = [
        path.join(process.cwd(), 'server', 'chat-database'),
        path.join(process.cwd(), '..', 'server', 'chat-database'),
        path.resolve(__dirname, '../../server/chat-database'),
        path.resolve(__dirname, '../../../server/chat-database')
      ];

      let ChatDatabase = null;
      for (const dbPath of possiblePaths) {
        try {
          ChatDatabase = require(dbPath);
          console.log(`DirectChatService: Found ChatDatabase at ${dbPath}`);
          break;
        } catch (e) {
          console.log(`DirectChatService: Failed to load from ${dbPath}`);
        }
      }

      if (!ChatDatabase) {
        throw new Error('Could not find ChatDatabase module');
      }

      this.chatDatabase = new ChatDatabase();
      console.log('DirectChatService: Initialized with chat database');
    } catch (error) {
      console.error('Failed to initialize DirectChatService:', error);
      throw error;
    }
  }

  async getChatConversations(): Promise<any[]> {
    try {
      return this.chatDatabase.getConversations();
    } catch (error) {
      console.error('Error getting conversations:', error);
      return [];
    }
  }

  async createChatConversation(conversation: ChatConversation): Promise<boolean> {
    try {
      return this.chatDatabase.createConversation(conversation);
    } catch (error) {
      console.error('Error creating conversation:', error);
      return false;
    }
  }

  async insertChatMessage(message: ChatMessage): Promise<boolean> {
    try {
      return this.chatDatabase.insertMessage(message);
    } catch (error) {
      console.error('Error inserting message:', error);
      return false;
    }
  }

  async updateChatConversation(conversationId: string, updates: any): Promise<boolean> {
    try {
      return this.chatDatabase.updateConversation(conversationId, updates);
    } catch (error) {
      console.error('Error updating conversation:', error);
      return false;
    }
  }

  async deleteChatConversation(conversationId: string): Promise<boolean> {
    try {
      return this.chatDatabase.deleteConversation(conversationId);
    } catch (error) {
      console.error('Error deleting conversation:', error);
      return false;
    }
  }

  // For IP analysis, we still need to connect to packet database via socket
  // This is a simplified version that returns empty data for now
  async getPackets(options: any = {}): Promise<any[]> {
    // For now, return empty array - we can enhance this later to connect to socket
    return [];
  }

  close(): void {
    if (this.chatDatabase) {
      this.chatDatabase.close();
    }
  }
}

// Export singleton
let directChatService: DirectChatService | null = null;

export function getDirectChatService(): DirectChatService {
  if (!directChatService) {
    directChatService = new DirectChatService();
  }
  return directChatService;
}

export default DirectChatService;